package nethttp_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	arcis "github.com/getarcis/arcis-go"
	archttp "github.com/getarcis/arcis-go/nethttp"
)

func TestProtectLogin_LegitRequestPassesAndBodyReadable(t *testing.T) {
	win := arcis.NewCorrelationWindow(arcis.NewCorrelationWindowOptions())
	h := archttp.ProtectLogin(archttp.ProtectOptions{Window: win})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]interface{}
		_ = json.Unmarshal(raw, &body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"received": body})
	}))

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{"username":"alice","extra":"v"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.10:1234"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	var resp struct {
		Received map[string]interface{} `json:"received"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if resp.Received["username"] != "alice" || resp.Received["extra"] != "v" {
		t.Fatalf("downstream handler did not see the body: %#v", resp.Received)
	}
}

func TestProtectLogin_TripsCredentialStuffing(t *testing.T) {
	win := arcis.NewCorrelationWindow(arcis.NewCorrelationWindowOptions())
	h := archttp.ProtectLogin(archttp.ProtectOptions{Window: win})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	var lastCode int
	for i := 0; i < 10; i++ {
		body := fmt.Sprintf(`{"username":"user%d"}`, i)
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "198.51.100.5:5555"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		lastCode = w.Code
	}

	if lastCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on credential-stuffing trip, got %d", lastCode)
	}
}

func TestProtectSignup_HonorsXForwardedFor(t *testing.T) {
	win := arcis.NewCorrelationWindow(arcis.NewCorrelationWindowOptions())
	h := archttp.ProtectSignup(archttp.ProtectOptions{Window: win})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	var lastCode int
	for i := 0; i < 10; i++ {
		body := fmt.Sprintf(`{"username":"cred%d"}`, i)
		req := httptest.NewRequest(http.MethodPost, "/signup", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", "192.0.2.55, 10.0.0.1")
		req.RemoteAddr = fmt.Sprintf("10.0.0.%d:9000", i+2)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		lastCode = w.Code
	}

	if lastCode != http.StatusTooManyRequests {
		t.Fatalf("expected XFF-aggregated requests to trip 429, got %d", lastCode)
	}
}

func TestProtectApi_NilWindowPassThrough(t *testing.T) {
	h := archttp.ProtectApi(archttp.ProtectOptions{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api", strings.NewReader(`{"username":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected pass-through 200, got %d", w.Code)
	}
}
