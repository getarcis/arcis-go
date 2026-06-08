package fiber_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"

	arcis "github.com/getarcis/arcis-go"
	arcisfiber "github.com/getarcis/arcis-go/fiber"
)

// protectApp builds a fiber app mounting ProtectLogin on /login with the
// supplied window. The handler reflects the parsed body back so tests can
// confirm the body survived the factory's read.
func protectApp(win *arcis.CorrelationWindow) *fiber.App {
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Post("/login", arcisfiber.ProtectLogin(arcisfiber.ProtectOptions{Window: win}), func(c *fiber.Ctx) error {
		var body map[string]interface{}
		_ = c.BodyParser(&body)
		return c.JSON(fiber.Map{"received": body})
	})
	return app
}

func postJSON(t *testing.T, app *fiber.App, path, body, xff string) *http.Response {
	t.Helper()
	req := httptest.NewRequest("POST", path, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	res, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	return res
}

func TestProtectLogin_LegitRequestPasses(t *testing.T) {
	win := arcis.NewCorrelationWindow(arcis.NewCorrelationWindowOptions())
	app := protectApp(win)

	res := postJSON(t, app, "/login", `{"username":"alice"}`, "")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
}

func TestProtectLogin_BodyReadableDownstream(t *testing.T) {
	win := arcis.NewCorrelationWindow(arcis.NewCorrelationWindowOptions())
	app := protectApp(win)

	res := postJSON(t, app, "/login", `{"username":"bob","extra":"value"}`, "")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
	raw, _ := io.ReadAll(res.Body)
	var resp struct {
		Received map[string]interface{} `json:"received"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("invalid json: %v (body=%s)", err, string(raw))
	}
	if resp.Received["username"] != "bob" || resp.Received["extra"] != "value" {
		t.Fatalf("downstream handler did not see the body: %#v", resp.Received)
	}
}

func TestProtectLogin_TripsCredentialStuffing(t *testing.T) {
	win := arcis.NewCorrelationWindow(arcis.NewCorrelationWindowOptions())
	app := protectApp(win)

	// 10 distinct usernames from one client trip the default threshold.
	// fiber's c.IP() returns the test RemoteAddr (0.0.0.0) for all of
	// these, which is a stable correlation key for the run.
	var lastCode int
	for i := 0; i < 10; i++ {
		res := postJSON(t, app, "/login", fmt.Sprintf(`{"username":"user%d"}`, i), "")
		lastCode = res.StatusCode
	}
	if lastCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on credential-stuffing trip, got %d", lastCode)
	}
}

func TestProtectLogin_HonorsXForwardedFor(t *testing.T) {
	win := arcis.NewCorrelationWindow(arcis.NewCorrelationWindowOptions())
	app := protectApp(win)

	// All requests share the same XFF first hop; the protect helper keys
	// off it directly, so they aggregate and trip even though fiber's
	// default c.IP() ignores XFF.
	var lastCode int
	var lastBody []byte
	for i := 0; i < 10; i++ {
		res := postJSON(t, app, "/login", fmt.Sprintf(`{"username":"cred%d"}`, i), "192.0.2.55, 10.0.0.1")
		lastCode = res.StatusCode
		lastBody, _ = io.ReadAll(res.Body)
	}
	if lastCode != http.StatusTooManyRequests {
		t.Fatalf("expected XFF-aggregated requests to trip 429, got %d (body=%s)", lastCode, string(lastBody))
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(lastBody, &resp); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if resp["credential_stuffing"] != true {
		t.Errorf("expected credential_stuffing=true, got %v", resp["credential_stuffing"])
	}
}

func TestProtectApi_NilWindowPassThrough(t *testing.T) {
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Post("/api", arcisfiber.ProtectApi(arcisfiber.ProtectOptions{}), func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"ok": true})
	})

	res := postJSON(t, app, "/api", `{"username":"x"}`, "")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected pass-through 200, got %d", res.StatusCode)
	}
}
