package gin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// blockApp builds a Gin router with block-mode Arcis middleware.
func blockApp() *gin.Engine {
	r := gin.New()
	cfg := DefaultConfig()
	cfg.RateLimit = false
	cfg.Block = true
	r.Use(MiddlewareWithConfig(cfg))
	r.POST("/echo", func(c *gin.Context) {
		var body map[string]interface{}
		_ = c.ShouldBindJSON(&body)
		c.JSON(http.StatusOK, gin.H{"received": body})
	})
	r.GET("/items", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return r
}

func TestBlock_CleanRequestPasses(t *testing.T) {
	r := blockApp()
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/items", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestBlock_AttackPayloads(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		vector string
	}{
		{"xss", `{"q":"<script>alert(1)</script>"}`, "xss"},
		{"sql", `{"q":"1' OR '1'='1'"}`, "sql"},
		{"path", `{"q":"../../etc/passwd"}`, "path"},
		{"command", `{"q":"$(whoami)"}`, "command"},
		{"nosql", `{"$where":"function(){return true}"}`, "nosql"},
		{"prototype", `{"__proto__":{"x":1}}`, "prototype"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := blockApp()
			req := httptest.NewRequest(http.MethodPost, "/echo", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != http.StatusForbidden {
				t.Fatalf("expected 403, got %d (body=%s)", w.Code, w.Body.String())
			}
			var resp map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("invalid json: %v", err)
			}
			if resp["code"] != "SECURITY_THREAT" {
				t.Errorf("expected SECURITY_THREAT code, got %v", resp["code"])
			}
			if resp["vector"] != tc.vector {
				t.Errorf("expected vector %q, got %v", tc.vector, resp["vector"])
			}
		})
	}
}

func TestBlock_QueryStringXSS(t *testing.T) {
	r := blockApp()
	req := httptest.NewRequest(http.MethodGet, "/items?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestBlock_DisabledByDefault(t *testing.T) {
	r := gin.New()
	cfg := DefaultConfig()
	cfg.RateLimit = false
	// Block omitted (defaults to false)
	r.Use(MiddlewareWithConfig(cfg))
	r.POST("/echo", func(c *gin.Context) {
		var body map[string]interface{}
		_ = c.ShouldBindJSON(&body)
		c.JSON(http.StatusOK, gin.H{"received": body})
	})
	req := httptest.NewRequest(http.MethodPost, "/echo",
		strings.NewReader(`{"q":"<script>alert(1)</script>"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 in default mode, got %d", w.Code)
	}
}

func TestBlock_DryRunPreservesRequestBody(t *testing.T) {
	r := gin.New()
	cfg := DefaultConfig()
	cfg.RateLimit = false
	cfg.Block = true
	cfg.DryRun = true
	r.Use(MiddlewareWithConfig(cfg))
	r.POST("/echo", func(c *gin.Context) {
		var body map[string]interface{}
		_ = c.ShouldBindJSON(&body)
		c.JSON(http.StatusOK, gin.H{"received": body})
	})

	original := `{"note":"Use the -- flag; it works","path":"docs/../README.md"}`
	req := httptest.NewRequest(http.MethodPost, "/echo", strings.NewReader(original))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 in dry-run mode, got %d", w.Code)
	}
	var response struct {
		Received map[string]interface{} `json:"received"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("invalid response json: %v", err)
	}
	if response.Received["note"] != "Use the -- flag; it works" {
		t.Fatalf("dry-run changed note: %v", response.Received["note"])
	}
	if response.Received["path"] != "docs/../README.md" {
		t.Fatalf("dry-run changed path: %v", response.Received["path"])
	}
}

func TestBlock_DryRunDoesNotEnforceRateLimit(t *testing.T) {
	r := gin.New()
	cfg := DefaultConfig()
	cfg.Block = false
	cfg.DryRun = true
	cfg.RateLimitMax = 1
	r.Use(MiddlewareWithConfig(cfg))
	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"reached": true})
	})

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		req.Header.Set("Accept", "text/html")
		req.Header.Set("Accept-Language", "en-US")
		req.Header.Set("Accept-Encoding", "gzip")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200 in dry-run mode, got %d", i+1, w.Code)
		}
		if w.Header().Get("Retry-After") != "" {
			t.Fatalf("request %d: dry-run must not emit Retry-After", i+1)
		}
	}
}

func TestBlock_DryRunDoesNotDenyBot(t *testing.T) {
	r := gin.New()
	cfg := DefaultConfig()
	cfg.Block = false
	cfg.DryRun = true
	cfg.RateLimit = false
	r.Use(MiddlewareWithConfig(cfg))
	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"reached": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", "sqlmap/1.7")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected bot request to reach handler in dry-run mode, got %d", w.Code)
	}
}
