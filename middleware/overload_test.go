package middleware

import (
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestOverload_EMAStep(t *testing.T) {
	cases := []struct {
		prior, measured, alpha, want float64
	}{
		{0, 100, 0.3, 30},
		{30, 100, 0.3, 51},
		{100, 0, 0.3, 70},
		{50, 50, 0.5, 50},
	}
	for _, c := range cases {
		got := emaStep(c.prior, c.measured, c.alpha)
		if math.Abs(got-c.want) > 1e-9 {
			t.Errorf("emaStep(%v,%v,%v)=%v want %v", c.prior, c.measured, c.alpha, got, c.want)
		}
	}
}

func TestOverload_Defaults(t *testing.T) {
	o := NewOverload(OverloadConfig{})
	defer o.Close()
	if o.cfg.MaxLagMs != 500 || o.cfg.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("unexpected defaults: maxLag=%v status=%d", o.cfg.MaxLagMs, o.cfg.StatusCode)
	}
	if o.cfg.Alpha != 0.3 || o.cfg.RetryAfterSeconds != 5 {
		t.Errorf("unexpected defaults: alpha=%v retry=%d", o.cfg.Alpha, o.cfg.RetryAfterSeconds)
	}
}

func TestOverload_InvalidAlphaClampsToDefault(t *testing.T) {
	o := NewOverload(OverloadConfig{Alpha: 5})
	defer o.Close()
	if o.cfg.Alpha != 0.3 {
		t.Errorf("alpha out of (0,1] should clamp to 0.3, got %v", o.cfg.Alpha)
	}
}

// setLag deterministically sets the smoothed lag. Safe because the test uses a
// very long SampleInterval, so the sampler goroutine never ticks during the
// test and cannot overwrite the value.
func setLag(o *Overload, v float64) {
	o.mu.Lock()
	o.smoothed = v
	o.mu.Unlock()
}

func TestOverload_HandlerShedsWhenOverloaded(t *testing.T) {
	o := NewOverload(OverloadConfig{MaxLagMs: 500, SampleInterval: time.Hour})
	defer o.Close()

	h := o.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Healthy: under threshold -> pass.
	setLag(o, 100)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("under threshold should pass, got %d", w.Code)
	}

	// Saturated: over threshold -> 503 + Retry-After.
	setLag(o, 600)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("over threshold should shed with 503, got %d", w.Code)
	}
	if w.Header().Get("Retry-After") != "5" {
		t.Errorf("expected Retry-After: 5, got %q", w.Header().Get("Retry-After"))
	}
}

func TestOverload_ExposeLagHeader(t *testing.T) {
	o := NewOverload(OverloadConfig{MaxLagMs: 1000, SampleInterval: time.Hour, ExposeLagHeader: true})
	defer o.Close()
	setLag(o, 42)
	h := o.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if got := w.Header().Get("X-EventLoop-Lag"); got != "42" {
		t.Errorf("expected X-EventLoop-Lag: 42, got %q", got)
	}
}

func TestOverload_Overloaded(t *testing.T) {
	o := NewOverload(OverloadConfig{MaxLagMs: 200, SampleInterval: time.Hour})
	defer o.Close()
	setLag(o, 150)
	if o.Overloaded() {
		t.Error("150ms should be under the 200ms threshold")
	}
	setLag(o, 250)
	if !o.Overloaded() {
		t.Error("250ms should exceed the 200ms threshold")
	}
}

func TestOverload_CloseStopsSampler(t *testing.T) {
	o := NewOverload(OverloadConfig{SampleInterval: time.Millisecond})
	o.Close()
	// Should not panic; a second Close is a no-op via context cancellation.
	o.Close()
}
