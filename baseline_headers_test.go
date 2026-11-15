package arcis

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewWithConfigBaselineNonce(t *testing.T) {
	config := DefaultConfig()
	config.HeaderProfile = HeaderProfileBaseline
	config.BaselineHeaders.ContentSecurityPolicy.Nonce = true
	s := NewWithConfig(config)
	t.Cleanup(s.Close)

	var seen string
	handler := s.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = CSPNonce(r.Context())
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if seen == "" || !strings.Contains(rec.Header().Get("Content-Security-Policy"), "'nonce-"+seen+"'") {
		t.Errorf("handler nonce %q not in CSP %q", seen, rec.Header().Get("Content-Security-Policy"))
	}
	if rec.Header().Get("X-Frame-Options") != "SAMEORIGIN" || rec.Header().Get("Cache-Control") != "" {
		t.Errorf("baseline profile not applied: %v", rec.Header())
	}
}

func TestNewWithConfigPanicsOnInvalidBaseline(t *testing.T) {
	config := DefaultConfig()
	config.HeaderProfile = HeaderProfileBaseline
	config.BaselineHeaders.XFrameOptions = "allow-from"
	defer func() {
		if r := recover(); r == nil || !strings.Contains(r.(string), "invalid action") {
			t.Errorf("expected a construction panic naming the problem, got %v", r)
		}
	}()
	NewWithConfig(config)
}
