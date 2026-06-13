package fiber_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"

	arcisfiber "github.com/getarcis/arcis-go/fiber"
)

// SSRF body-URL validation wire-up for the fiber adapter. fiber carries its own
// copy of the middleware pipeline, so this guards against drift in fiber's
// cfg.SSRF step independently of gin/chi/echo.

const ssrfBrowserUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

func postSSRFFiber(t *testing.T, app *fiber.App, body interface{}) int {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/fetch", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", ssrfBrowserUA)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Language", "en-US")
	res, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	return res.StatusCode
}

func ssrfFiber(cfg arcisfiber.Config) *fiber.App {
	cfg.RateLimit = false
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(arcisfiber.MiddlewareWithConfig(cfg))
	app.Post("/fetch", func(c *fiber.Ctx) error { return c.SendString("ok") })
	return app
}

func TestSSRF_FiberBlocksPrivateAndSchemes(t *testing.T) {
	defer arcisfiber.Cleanup()
	app := ssrfFiber(arcisfiber.DefaultConfig())
	for name, u := range map[string]string{
		"loopback":     "http://127.0.0.1:8080/admin",
		"aws-metadata": "http://169.254.169.254/latest/meta-data/",
		"decimal-ip":   "http://2130706433/admin",
		"file-scheme":  "file:///etc/passwd",
	} {
		if got := postSSRFFiber(t, app, map[string]string{"url": u}); got != http.StatusForbidden {
			t.Errorf("%s (%s): expected 403, got %d", name, u, got)
		}
	}
}

func TestSSRF_FiberAllowsPublic(t *testing.T) {
	defer arcisfiber.Cleanup()
	app := ssrfFiber(arcisfiber.DefaultConfig())
	for _, u := range []string{"https://example.com/page", "http://localhost:3000/api/health"} {
		if got := postSSRFFiber(t, app, map[string]string{"url": u}); got != http.StatusOK {
			t.Errorf("public %q: expected 200, got %d", u, got)
		}
	}
}

func TestSSRF_FiberOptOut(t *testing.T) {
	defer arcisfiber.Cleanup()
	cfg := arcisfiber.DefaultConfig()
	cfg.SSRF = false
	app := ssrfFiber(cfg)
	if got := postSSRFFiber(t, app, map[string]string{"url": "http://127.0.0.1:8080/admin"}); got != http.StatusOK {
		t.Errorf("SSRF=false should allow loopback, got %d", got)
	}
}
