package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBruteForce_Defaults(t *testing.T) {
	b := NewBruteForce(BruteForceConfig{})
	defer b.Close()
	if b.cfg.FastPoints != 5 || b.cfg.SlowPoints != 20 {
		t.Errorf("expected default points 5/20, got %d/%d", b.cfg.FastPoints, b.cfg.SlowPoints)
	}
	if b.cfg.StatusCode != http.StatusTooManyRequests {
		t.Errorf("expected default status 429, got %d", b.cfg.StatusCode)
	}
}

func TestBruteForce_FastWindowDeniesWithoutBlock(t *testing.T) {
	// FastPoints small, SlowPoints large => the fast 429 trips first and no
	// semi-permanent block is set.
	b := NewBruteForce(BruteForceConfig{FastPoints: 3, SlowPoints: 100,
		FastDuration: time.Minute, SlowDuration: time.Hour})
	defer b.Close()

	for i := 1; i <= 3; i++ {
		if r := b.CheckKey("ip1"); !r.Allowed {
			t.Fatalf("attempt %d should be allowed", i)
		}
	}
	r := b.CheckKey("ip1")
	if r.Allowed {
		t.Fatal("4th attempt should be denied by the fast window")
	}
	if b.IsBlocked("ip1") {
		t.Error("fast-window denial must not set a semi-permanent block")
	}
}

func TestBruteForce_SlowWindowTripsBlock(t *testing.T) {
	// SlowPoints small, FastPoints large => the slow window trips a block.
	b := NewBruteForce(BruteForceConfig{FastPoints: 100, SlowPoints: 2,
		FastDuration: time.Hour, SlowDuration: time.Hour, BlockDuration: 30 * time.Minute})
	defer b.Close()

	_ = b.CheckKey("ip1") // slow=1
	_ = b.CheckKey("ip1") // slow=2
	r := b.CheckKey("ip1") // slow=3 > 2 => block
	if r.Allowed {
		t.Fatal("3rd attempt should trip the slow-window block")
	}
	if !b.IsBlocked("ip1") {
		t.Error("expected a block after slow-window exhaustion")
	}
	if r.RetryAfter < 25*time.Minute {
		t.Errorf("RetryAfter should reflect BlockDuration, got %v", r.RetryAfter)
	}
	// Subsequent requests stay blocked.
	if b.CheckKey("ip1").Allowed {
		t.Error("a blocked key must keep being denied")
	}
}

func TestBruteForce_ResetClearsCounters(t *testing.T) {
	b := NewBruteForce(BruteForceConfig{FastPoints: 2, SlowPoints: 100,
		FastDuration: time.Hour, SlowDuration: time.Hour})
	defer b.Close()

	b.CheckKey("ip1")
	b.CheckKey("ip1")
	if b.CheckKey("ip1").Allowed {
		t.Fatal("3rd should be denied before reset")
	}
	b.Reset("ip1")
	if !b.CheckKey("ip1").Allowed {
		t.Error("after Reset the key should be allowed again")
	}
}

func TestBruteForce_ManualBlock(t *testing.T) {
	b := NewBruteForce(BruteForceConfig{})
	defer b.Close()
	b.Block("ip1", time.Hour)
	if !b.IsBlocked("ip1") {
		t.Fatal("expected ip1 to be blocked after Block()")
	}
	if b.CheckKey("ip1").Allowed {
		t.Error("a manually blocked key must be denied")
	}
}

func TestBruteForce_PerKeyIsolation(t *testing.T) {
	b := NewBruteForce(BruteForceConfig{FastPoints: 1, SlowPoints: 100,
		FastDuration: time.Hour, SlowDuration: time.Hour})
	defer b.Close()
	b.CheckKey("ip1")
	if b.CheckKey("ip1").Allowed {
		t.Fatal("ip1 should be denied after exhausting its budget")
	}
	if !b.CheckKey("ip2").Allowed {
		t.Error("ip2 must have its own independent budget")
	}
}

func TestBruteForce_Handler(t *testing.T) {
	b := NewBruteForce(BruteForceConfig{FastPoints: 2, SlowPoints: 100,
		FastDuration: time.Hour, SlowDuration: time.Hour,
		KeyFunc: func(*http.Request) string { return "fixed" }})
	defer b.Close()

	h := b.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := 1; i <= 2; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/login", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("attempt %d should pass, got %d", i, w.Code)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/login", nil))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after budget exhausted, got %d", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("expected a Retry-After header on the 429")
	}
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid json body: %v", err)
	}
	if _, ok := body["retryAfter"]; !ok {
		t.Error("expected retryAfter in the response body")
	}
}

func TestBruteForce_SkipBypasses(t *testing.T) {
	b := NewBruteForce(BruteForceConfig{FastPoints: 1, SlowPoints: 1,
		Skip: func(*http.Request) bool { return true }})
	defer b.Close()
	for i := 0; i < 5; i++ {
		if !b.Check(httptest.NewRequest(http.MethodGet, "/", nil)).Allowed {
			t.Fatal("Skip should bypass the limiter entirely")
		}
	}
}
