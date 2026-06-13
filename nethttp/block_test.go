package nethttp_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	archttp "github.com/getarcis/arcis-go/nethttp"
)

// Block-mode wireup for the net/http adapter: confirm the middleware scans
// the request body and returns 403 on an attack. Previously nethttp had no
// block test, so nothing verified block mode is wired through the adapter.

func blockServer() *httptest.Server {
	cfg := archttp.DefaultConfig()
	cfg.RateLimit = false
	cfg.Block = true
	h := archttp.MiddlewareWithConfig(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	return httptest.NewServer(h)
}

func TestBlockNethttp_CleanRequestPasses(t *testing.T) {
	srv := blockServer()
	defer srv.Close()
	defer archttp.Cleanup()

	resp, err := realGet(srv.URL + "/items")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestBlockNethttp_AttackPayloads(t *testing.T) {
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
	srv := blockServer()
	defer srv.Close()
	defer archttp.Cleanup()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := realPost(srv.URL+"/echo", "application/json", strings.NewReader(tc.body))
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("expected 403, got %d", resp.StatusCode)
			}
			var body map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
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

func TestBlockNethttp_DisabledByDefault(t *testing.T) {
	cfg := archttp.DefaultConfig()
	cfg.RateLimit = false
	h := archttp.MiddlewareWithConfig(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv := httptest.NewServer(h)
	defer srv.Close()
	defer archttp.Cleanup()

	resp, err := realPost(srv.URL+"/echo", "application/json",
		strings.NewReader(`{"q":"<script>alert(1)</script>"}`))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 in default (non-block) mode, got %d", resp.StatusCode)
	}
}
