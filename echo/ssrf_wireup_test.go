package echo

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

// SSRF body-URL validation wire-up for the echo adapter. echo carries its own
// copy of the middleware pipeline, so this guards against drift in echo's
// cfg.SSRF step independently of gin/chi/fiber.

const ssrfBrowserUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

func postSSRFEcho(t *testing.T, e *echo.Echo, body interface{}) int {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/fetch", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", ssrfBrowserUA)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Language", "en-US")
	w := httptest.NewRecorder()
	e.ServeHTTP(w, req)
	return w.Code
}

func ssrfEcho(cfg Config) *echo.Echo {
	cfg.RateLimit = false
	e := echo.New()
	e.Use(MiddlewareWithConfig(cfg))
	e.POST("/fetch", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]bool{"ok": true})
	})
	return e
}

func TestSSRF_EchoBlocksPrivateAndSchemes(t *testing.T) {
	e := ssrfEcho(DefaultConfig())
	for name, u := range map[string]string{
		"loopback":     "http://127.0.0.1:8080/admin",
		"aws-metadata": "http://169.254.169.254/latest/meta-data/",
		"decimal-ip":   "http://2130706433/admin",
		"file-scheme":  "file:///etc/passwd",
	} {
		if got := postSSRFEcho(t, e, map[string]string{"url": u}); got != http.StatusForbidden {
			t.Errorf("%s (%s): expected 403, got %d", name, u, got)
		}
	}
}

func TestSSRF_EchoAllowsPublic(t *testing.T) {
	e := ssrfEcho(DefaultConfig())
	for _, u := range []string{"https://example.com/page", "http://localhost:3000/api/health"} {
		if got := postSSRFEcho(t, e, map[string]string{"url": u}); got != http.StatusOK {
			t.Errorf("public %q: expected 200, got %d", u, got)
		}
	}
}

func TestSSRF_EchoOptOut(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SSRF = false
	e := ssrfEcho(cfg)
	if got := postSSRFEcho(t, e, map[string]string{"url": "http://127.0.0.1:8080/admin"}); got != http.StatusOK {
		t.Errorf("SSRF=false should allow loopback, got %d", got)
	}
}
