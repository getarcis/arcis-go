package gin

// v1.7 W5 SSRF body-URL validation integration tests for gin.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func newRouterSSRF(cfg Config) *gin.Engine {
	cfg.RateLimit = false
	r := gin.New()
	r.Use(MiddlewareWithConfig(cfg))
	r.POST("/fetch", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return r
}

func postURL(r *gin.Engine, body interface{}) int {
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/fetch", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", browserUA)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Language", "en-US")
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code
}

func TestSSRF_DefaultBlocksBenchPayloads(t *testing.T) {
	r := newRouterSSRF(DefaultConfig())
	urls := map[string]string{
		"loopback":       "http://127.0.0.1:8080/admin",
		"aws-metadata":   "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
		"gcp-metadata":   "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
		"azure-metadata": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
		"decimal-ip":     "http://2130706433/admin",
		"hex-ip":         "http://0x7f000001/admin",
		"file-scheme":    "file:///etc/passwd",
		"gopher-smtp":    "gopher://127.0.0.1:25/_EHLO",
	}
	for name, u := range urls {
		if got := postURL(r, map[string]string{"url": u}); got != http.StatusForbidden {
			t.Errorf("%s (%s): expected 403, got %d", name, u, got)
		}
	}
}

func TestSSRF_AllowsPublicURLs(t *testing.T) {
	r := newRouterSSRF(DefaultConfig())
	urls := []string{
		"https://example.com/page",
		"https://api.github.com/repos/x/y",
		"http://cdn.example.org/asset.png",
		// ftp to a public host is a legit fetch scheme, not SSRF.
		"ftp://files.example.com/public/manual.pdf",
		// localhost hostname is common dev config; allowed (loopback IPs are not).
		"http://localhost:3000/api/health",
	}
	for _, u := range urls {
		if got := postURL(r, map[string]string{"url": u}); got != http.StatusOK {
			t.Errorf("public %q: expected 200, got %d", u, got)
		}
	}
}

func TestSSRF_NestedPrivateURLCaught(t *testing.T) {
	r := newRouterSSRF(DefaultConfig())
	body := map[string]interface{}{"config": map[string]interface{}{"webhook": map[string]interface{}{"url": "http://169.254.169.254/"}}}
	if got := postURL(r, body); got != http.StatusForbidden {
		t.Errorf("nested private URL: expected 403, got %d", got)
	}
}

func TestSSRF_NoURLFieldPasses(t *testing.T) {
	r := newRouterSSRF(DefaultConfig())
	if got := postURL(r, map[string]interface{}{"name": "alice", "count": 3}); got != http.StatusOK {
		t.Errorf("no-url body: expected 200, got %d", got)
	}
}

func TestSSRF_OptOut(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SSRF = false
	r := newRouterSSRF(cfg)
	if got := postURL(r, map[string]string{"url": "http://127.0.0.1:8080/admin"}); got != http.StatusOK {
		t.Errorf("SSRF=false should allow loopback, got %d", got)
	}
}
