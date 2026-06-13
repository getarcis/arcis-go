package fiber_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"

	arcisfiber "github.com/getarcis/arcis-go/fiber"
)

// Block-mode wireup for the fiber adapter: confirm the middleware scans the
// request body and returns 403 on an attack. Previously fiber had no block
// test, so nothing verified block mode is wired through the adapter.

func blockFiberConfig() arcisfiber.Config {
	cfg := arcisfiber.DefaultConfig()
	cfg.RateLimit = false
	cfg.Block = true
	return cfg
}

func TestBlockFiber_CleanRequestPasses(t *testing.T) {
	defer arcisfiber.Cleanup()
	app := makeApp(blockFiberConfig())
	res := sendJSON(t, app, http.MethodGet, "/echo", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
}

func TestBlockFiber_AttackPayloads(t *testing.T) {
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
			defer arcisfiber.Cleanup()
			app := makeApp(blockFiberConfig())
			res := sendRawJSON(t, app, http.MethodPost, "/echo", tc.body)
			if res.StatusCode != http.StatusForbidden {
				t.Fatalf("expected 403, got %d", res.StatusCode)
			}
			var body map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
				t.Fatalf("invalid json: %v", err)
			}
			if body["code"] != "SECURITY_THREAT" {
				t.Errorf("expected SECURITY_THREAT code, got %v", body["code"])
			}
			if body["vector"] != tc.vector {
				t.Errorf("expected vector %q, got %v", tc.vector, body["vector"])
			}
		})
	}
}

func TestBlockFiber_DisabledByDefault(t *testing.T) {
	defer arcisfiber.Cleanup()
	cfg := arcisfiber.DefaultConfig()
	cfg.RateLimit = false
	app := makeApp(cfg)
	res := sendRawJSON(t, app, http.MethodPost, "/echo", `{"q":"<script>alert(1)</script>"}`)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 in default (non-block) mode, got %d", res.StatusCode)
	}
}

// sendRawJSON posts a raw JSON string body (the existing sendJSON marshals a
// value; block tests need exact byte payloads like the unbalanced quote in the
// sql case).
func sendRawJSON(t *testing.T, app *fiber.App, method, path, raw string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	res, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	return res
}
