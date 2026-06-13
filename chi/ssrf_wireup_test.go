package chi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// SSRF body-URL validation wire-up for the chi adapter (mirrors gin's
// ssrf_wireup_test). The block_test covers the scanThreats body scan
// (xss/sql/...); SSRF is a separate cfg.SSRF step that validates URLs found in
// JSON bodies, so it needs its own coverage. chi's pipeline is a distinct copy
// from gin's (the ~4k-line adapter duplication), so this guards against drift.
// net/http delegates to chi's MiddlewareWithConfig, so this covers it too.

func postSSRF(t *testing.T, h http.Handler, body interface{}) int {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/fetch", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", realBrowserUA)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Language", "en-US")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w.Code
}

func ssrfRouter() http.Handler {
	cfg := DefaultConfig()
	cfg.RateLimit = false
	r := newRouter(MiddlewareWithConfig(cfg))
	r.Post("/fetch", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	return r
}

func TestSSRF_ChiBlocksPrivateAndSchemes(t *testing.T) {
	r := ssrfRouter()
	for name, u := range map[string]string{
		"loopback":     "http://127.0.0.1:8080/admin",
		"aws-metadata": "http://169.254.169.254/latest/meta-data/",
		"decimal-ip":   "http://2130706433/admin",
		"file-scheme":  "file:///etc/passwd",
	} {
		if got := postSSRF(t, r, map[string]string{"url": u}); got != http.StatusForbidden {
			t.Errorf("%s (%s): expected 403, got %d", name, u, got)
		}
	}
}

func TestSSRF_ChiAllowsPublic(t *testing.T) {
	r := ssrfRouter()
	for _, u := range []string{"https://example.com/page", "http://localhost:3000/api/health"} {
		if got := postSSRF(t, r, map[string]string{"url": u}); got != http.StatusOK {
			t.Errorf("public %q: expected 200, got %d", u, got)
		}
	}
}

func TestSSRF_ChiOptOut(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RateLimit = false
	cfg.SSRF = false
	r := newRouter(MiddlewareWithConfig(cfg))
	r.Post("/fetch", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	if got := postSSRF(t, r, map[string]string{"url": "http://127.0.0.1:8080/admin"}); got != http.StatusOK {
		t.Errorf("SSRF=false should allow loopback, got %d", got)
	}
}
