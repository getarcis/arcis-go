package gin

// v1.7 W4 mass-assignment field detection integration tests for gin.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func newRouterMassAssign(cfg Config) *gin.Engine {
	cfg.RateLimit = false
	r := gin.New()
	r.Use(MiddlewareWithConfig(cfg))
	r.POST("/users", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return r
}

func postJSON(r *gin.Engine, body interface{}) int {
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/users", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", browserUA)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Language", "en-US")
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code
}

func TestMassAssign_DefaultBlocksBenchPayloads(t *testing.T) {
	r := newRouterMassAssign(DefaultConfig())
	cases := map[string]interface{}{
		"isAdmin": map[string]interface{}{"name": "john", "email": "j@x.com", "isAdmin": true},
		"role":    map[string]interface{}{"username": "j", "role": "superadmin"},
		"nested":  map[string]interface{}{"profile": map[string]interface{}{"name": "j", "permissions": []string{"admin", "billing"}}},
	}
	for name, body := range cases {
		if got := postJSON(r, body); got != http.StatusForbidden {
			t.Errorf("%s: expected 403, got %d", name, got)
		}
	}
}

func TestMassAssign_AllowsOrdinaryBodies(t *testing.T) {
	r := newRouterMassAssign(DefaultConfig())
	legit := []interface{}{
		map[string]interface{}{"name": "Alice", "email": "alice@example.com"},
		map[string]interface{}{"profile": map[string]interface{}{"displayName": "Al", "bio": "hello world"}},
		map[string]interface{}{"user": map[string]interface{}{"name": "Bob", "address": map[string]interface{}{"city": "NYC", "zip": "10001"}}},
		map[string]interface{}{"items": []interface{}{map[string]interface{}{"sku": "A1", "qty": 2}}, "total": 49.99},
		map[string]interface{}{},
	}
	for i, body := range legit {
		if got := postJSON(r, body); got != http.StatusOK {
			t.Errorf("legit case %d: expected 200, got %d", i, got)
		}
	}
}

func TestMassAssign_OptOut(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MassAssign = false
	r := newRouterMassAssign(cfg)
	body := map[string]interface{}{"name": "j", "isAdmin": true}
	if got := postJSON(r, body); got != http.StatusOK {
		t.Errorf("MassAssign=false should allow isAdmin, got %d", got)
	}
}

func TestMassAssign_CaseSeparatorInsensitivity(t *testing.T) {
	r := newRouterMassAssign(DefaultConfig())
	for _, key := range []string{"is_admin", "IS_ADMIN", "is-admin", "isAdmin"} {
		body := map[string]interface{}{"name": "j", key: true}
		if got := postJSON(r, body); got != http.StatusForbidden {
			t.Errorf("variant %q: expected 403, got %d", key, got)
		}
	}
}
