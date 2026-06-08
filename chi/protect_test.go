package chi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	arcis "github.com/getarcis/arcis-go"
)

// protectHandler wraps the supplied final handler with ProtectLogin using
// the given window. Chi middleware is stdlib func(http.Handler)
// http.Handler, so we compose directly.
func protectHandler(win *arcis.CorrelationWindow, final http.HandlerFunc) http.Handler {
	return ProtectLogin(ProtectOptions{Window: win})(final)
}

// echoBody is a handler that reads the body and reflects it back so tests
// can confirm the body survived the factory's read.
func echoBody(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var body map[string]interface{}
	_ = json.Unmarshal(raw, &body)
	writeJSON(w, http.StatusOK, map[string]interface{}{"received": body})
}

func TestProtectLogin_LegitRequestPasses(t *testing.T) {
	win := arcis.NewCorrelationWindow(arcis.NewCorrelationWindowOptions())
	h := protectHandler(win, echoBody)

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{"username":"alice"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.10:1234"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}
}

func TestProtectLogin_BodyReadableDownstream(t *testing.T) {
	win := arcis.NewCorrelationWindow(arcis.NewCorrelationWindowOptions())
	h := protectHandler(win, echoBody)

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{"username":"bob","extra":"value"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.11:1234"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp struct {
		Received map[string]interface{} `json:"received"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if resp.Received["username"] != "bob" || resp.Received["extra"] != "value" {
		t.Fatalf("downstream handler did not see the body: %#v", resp.Received)
	}
}

func TestProtectLogin_TripsCredentialStuffing(t *testing.T) {
	win := arcis.NewCorrelationWindow(arcis.NewCorrelationWindowOptions())
	h := protectHandler(win, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
	})

	for i := 0; i < 9; i++ {
		body := fmt.Sprintf(`{"username":"user%d"}`, i)
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "198.51.100.5:5555"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d (body=%s)", i, w.Code, w.Body.String())
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{"username":"user9"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100.5:5555"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on credential-stuffing trip, got %d (body=%s)", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if resp["credential_stuffing"] != true {
		t.Errorf("expected credential_stuffing=true, got %v", resp["credential_stuffing"])
	}
}

func TestProtectLogin_HonorsXForwardedFor(t *testing.T) {
	win := arcis.NewCorrelationWindow(arcis.NewCorrelationWindowOptions())
	h := protectHandler(win, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
	})

	var lastCode int
	var lastBody string
	for i := 0; i < 10; i++ {
		body := fmt.Sprintf(`{"username":"cred%d"}`, i)
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", "192.0.2.55, 10.0.0.1")
		req.RemoteAddr = fmt.Sprintf("10.0.0.%d:9000", i+2)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		lastCode = w.Code
		lastBody = w.Body.String()
	}

	if lastCode != http.StatusTooManyRequests {
		t.Fatalf("expected XFF-aggregated requests to trip 429, got %d (body=%s)", lastCode, lastBody)
	}
}

func TestProtectClientIP_FirstHop(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "192.0.2.7, 10.0.0.1")
	req.RemoteAddr = "10.0.0.9:1234"
	if got := protectClientIP(req); got != "192.0.2.7" {
		t.Fatalf("expected first XFF hop 192.0.2.7, got %q", got)
	}
}

func TestProtectApi_NilWindowPassThrough(t *testing.T) {
	h := ProtectApi(ProtectOptions{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
	}))

	req := httptest.NewRequest(http.MethodPost, "/api", strings.NewReader(`{"username":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected pass-through 200, got %d", w.Code)
	}
}
