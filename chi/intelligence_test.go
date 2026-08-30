package chi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path"
	"sync/atomic"
	"testing"
	"time"

	"github.com/getarcis/arcis-go/intelligence"
	"github.com/getarcis/arcis-go/telemetry"
)

const (
	publicIP = "203.0.113.50"
	cleanIP  = "198.51.100.20"
)

// intelStub serves an IP-reputation verdict per IP (last path segment).
func intelStub(verdicts map[string]int, hits *int32) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			atomic.AddInt32(hits, 1)
		}
		ip := path.Base(r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		sev, ok := verdicts[ip]
		if !ok {
			_ = json.NewEncoder(w).Encode(map[string]any{"ip": ip, "found": false})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ip": ip, "found": true, "severity": sev,
			"categories": []string{"botnet"}, "sources": []string{"tor-exit"},
		})
	}))
}

// intelHandler builds the chi (stdlib) middleware around a 200 handler.
func intelHandler(cfg Config) http.Handler {
	final := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	return MiddlewareWithConfig(cfg)(final)
}

func statusFor(h http.Handler, ip string) int {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", ip) // pipeline.ClientIP reads this first
	req.Header.Set("User-Agent", "Mozilla/5.0")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w.Code
}

func pollFor(h http.Handler, ip string, want, tries int) bool {
	for i := 0; i < tries; i++ {
		if statusFor(h, ip) == want {
			return true
		}
		time.Sleep(15 * time.Millisecond)
	}
	return false
}

func TestChiIntelBlocksKnownBadAfterWarmup(t *testing.T) {
	srv := intelStub(map[string]int{publicIP: 9}, nil)
	defer srv.Close()
	client, err := intelligence.NewClient(intelligence.Options{Endpoint: srv.URL, CloudDecisions: []string{"ip-rep"}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	h := intelHandler(Config{Intelligence: client, IntelligenceBlockThreshold: 7})

	if got := statusFor(h, publicIP); got != http.StatusOK {
		t.Fatalf("first (cache-miss) request: got %d, want 200", got)
	}
	if !pollFor(h, publicIP, http.StatusForbidden, 60) {
		t.Fatal("expected 403 after the background refresh warms the cache")
	}
}

func TestChiIntelNeverBlocksCleanIP(t *testing.T) {
	srv := intelStub(map[string]int{publicIP: 9}, nil)
	defer srv.Close()
	client, _ := intelligence.NewClient(intelligence.Options{Endpoint: srv.URL, CloudDecisions: []string{"ip-rep"}})
	defer client.Close()
	h := intelHandler(Config{Intelligence: client, IntelligenceBlockThreshold: 7})

	for i := 0; i < 5; i++ {
		if got := statusFor(h, cleanIP); got != http.StatusOK {
			t.Fatalf("clean IP got %d, want 200", got)
		}
		time.Sleep(15 * time.Millisecond)
	}
}

func TestChiIntelFailsOpenWhenUnreachable(t *testing.T) {
	srv := intelStub(nil, nil)
	url := srv.URL
	srv.Close() // unreachable
	client, _ := intelligence.NewClient(intelligence.Options{Endpoint: url, CloudDecisions: []string{"ip-rep"}, Timeout: 300 * time.Millisecond})
	defer client.Close()
	h := intelHandler(Config{Intelligence: client, IntelligenceBlockThreshold: 1})

	if pollFor(h, publicIP, http.StatusForbidden, 8) {
		t.Fatal("unreachable service must never block (fail-open)")
	}
}

func TestChiIntelInertWithoutCloudDecisions(t *testing.T) {
	var hits int32
	srv := intelStub(map[string]int{publicIP: 9}, &hits)
	defer srv.Close()
	client, _ := intelligence.NewClient(intelligence.Options{Endpoint: srv.URL}) // no CloudDecisions -> inert
	defer client.Close()
	h := intelHandler(Config{Intelligence: client, IntelligenceBlockThreshold: 1})

	for i := 0; i < 4; i++ {
		if got := statusFor(h, publicIP); got != http.StatusOK {
			t.Fatalf("got %d, want 200", got)
		}
		time.Sleep(15 * time.Millisecond)
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatalf("expected no lookups, got %d", hits)
	}
}

func TestChiIntelDryRunObservesCachedBadIPAndEmitsWouldDeny(t *testing.T) {
	srv := intelStub(map[string]int{publicIP: 9}, nil)
	defer srv.Close()
	client, err := intelligence.NewClient(intelligence.Options{
		Endpoint:       srv.URL,
		CloudDecisions: []string{"ip-rep"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.Check(publicIP)
	deadline := time.Now().Add(time.Second)
	for client.CacheSize() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if client.CacheSize() == 0 {
		t.Fatal("timed out warming the IP-reputation cache")
	}

	telemetryURL, telemetryRequests := recordingServer(t)
	tc, err := telemetry.NewClient(telemetry.Options{
		Endpoint:      telemetryURL,
		BatchSize:     1,
		FlushInterval: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	h := intelHandler(Config{
		Intelligence:               client,
		IntelligenceBlockThreshold: 7,
		DryRun:                     true,
		Telemetry:                  tc,
	})
	defer Cleanup()

	if got := statusFor(h, publicIP); got != http.StatusOK {
		t.Errorf("dry-run status = %d, want 200", got)
	}
	if err := tc.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	event := decodeFirstEvent(t, mustReceiveBody(t, telemetryRequests, time.Second))
	if event.Decision != telemetry.DecisionWouldDeny {
		t.Errorf("Decision = %q, want would_deny", event.Decision)
	}
	if event.Vector != "ip-reputation" {
		t.Errorf("Vector = %q, want ip-reputation", event.Vector)
	}
	if event.Rule != "ip-reputation/known-bad" {
		t.Errorf("Rule = %q, want ip-reputation/known-bad", event.Rule)
	}
	if event.Status != http.StatusOK {
		t.Errorf("Status = %d, want 200", event.Status)
	}
}
