package chi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Block-mode wireup for the chi adapter: confirm the middleware actually
// scans the request body and returns 403 on an attack, mirroring the echo
// adapter's block_test.go. Previously chi had no block test, so nothing
// verified that block mode is wired through the adapter at all.

func blockChiRouter() http.Handler {
	cfg := DefaultConfig()
	cfg.RateLimit = false
	cfg.Block = true
	r := newRouter(MiddlewareWithConfig(cfg))
	r.Post("/echo", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	r.Get("/items", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	return r
}

func TestBlock_CleanRequestPasses(t *testing.T) {
	r := blockChiRouter()
	req := httptest.NewRequest(http.MethodGet, "/items", nil)
	req.Header.Set("User-Agent", realBrowserUA)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%s)", w.Code, w.Body.String())
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
		{"nosql_key", `{"$where":"function(){return true}"}`, "nosql"},
		{"nosql_string", `{"q":"$where: 1==1"}`, "nosql"},
		{"prototype", `{"__proto__":{"x":1}}`, "prototype"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := blockChiRouter()
			req := httptest.NewRequest(http.MethodPost, "/echo", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("User-Agent", realBrowserUA)
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

func TestBlock_DisabledByDefault(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RateLimit = false
	r := newRouter(MiddlewareWithConfig(cfg))
	r.Post("/echo", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodPost, "/echo",
		strings.NewReader(`{"q":"<script>alert(1)</script>"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", realBrowserUA)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 in default (non-block) mode, got %d", w.Code)
	}
}
