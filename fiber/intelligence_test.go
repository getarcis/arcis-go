package fiber

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"

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

// intelApp builds a fiber app whose c.IP() reads X-Forwarded-For (ProxyHeader),
// so the test can drive the looked-up IP.
func intelApp(cfg Config) *fiber.App {
	app := fiber.New(fiber.Config{DisableStartupMessage: true, ProxyHeader: fiber.HeaderXForwardedFor})
	app.Use(MiddlewareWithConfig(cfg))
	app.Get("/", func(c *fiber.Ctx) error { return c.JSON(fiber.Map{"ok": true}) })
	return app
}

func statusFor(t *testing.T, app *fiber.App, ip string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", ip)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	res, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	return res.StatusCode
}

func pollFor(t *testing.T, app *fiber.App, ip string, want, tries int) bool {
	t.Helper()
	for i := 0; i < tries; i++ {
		if statusFor(t, app, ip) == want {
			return true
		}
		time.Sleep(15 * time.Millisecond)
	}
	return false
}

func TestFiberIntelBlocksKnownBadAfterWarmup(t *testing.T) {
	srv := intelStub(map[string]int{publicIP: 9}, nil)
	defer srv.Close()
	client, err := intelligence.NewClient(intelligence.Options{Endpoint: srv.URL, CloudDecisions: []string{"ip-rep"}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	app := intelApp(Config{Intelligence: client, IntelligenceBlockThreshold: 7})

	if got := statusFor(t, app, publicIP); got != http.StatusOK {
		t.Fatalf("first (cache-miss) request: got %d, want 200", got)
	}
	if !pollFor(t, app, publicIP, http.StatusForbidden, 60) {
		t.Fatal("expected 403 after the background refresh warms the cache")
	}
}

func TestFiberIntelNeverBlocksCleanIP(t *testing.T) {
	srv := intelStub(map[string]int{publicIP: 9}, nil)
	defer srv.Close()
	client, _ := intelligence.NewClient(intelligence.Options{Endpoint: srv.URL, CloudDecisions: []string{"ip-rep"}})
	defer client.Close()
	app := intelApp(Config{Intelligence: client, IntelligenceBlockThreshold: 7})

	for i := 0; i < 5; i++ {
		if got := statusFor(t, app, cleanIP); got != http.StatusOK {
			t.Fatalf("clean IP got %d, want 200", got)
		}
		time.Sleep(15 * time.Millisecond)
	}
}

func TestFiberIntelFailsOpenWhenUnreachable(t *testing.T) {
	srv := intelStub(nil, nil)
	url := srv.URL
	srv.Close() // unreachable
	client, _ := intelligence.NewClient(intelligence.Options{Endpoint: url, CloudDecisions: []string{"ip-rep"}, Timeout: 300 * time.Millisecond})
	defer client.Close()
	app := intelApp(Config{Intelligence: client, IntelligenceBlockThreshold: 1})

	if pollFor(t, app, publicIP, http.StatusForbidden, 8) {
		t.Fatal("unreachable service must never block (fail-open)")
	}
}

func TestFiberIntelInertWithoutCloudDecisions(t *testing.T) {
	var hits int32
	srv := intelStub(map[string]int{publicIP: 9}, &hits)
	defer srv.Close()
	client, _ := intelligence.NewClient(intelligence.Options{Endpoint: srv.URL}) // no CloudDecisions -> inert
	defer client.Close()
	app := intelApp(Config{Intelligence: client, IntelligenceBlockThreshold: 1})

	for i := 0; i < 4; i++ {
		if got := statusFor(t, app, publicIP); got != http.StatusOK {
			t.Fatalf("got %d, want 200", got)
		}
		time.Sleep(15 * time.Millisecond)
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatalf("expected no lookups, got %d", hits)
	}
}

func TestFiberIntelDryRunObservesCachedBadIPAndEmitsWouldDeny(t *testing.T) {
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

	telemetryRequests := make(chan []byte, 1)
	telemetryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		telemetryRequests <- body
		w.WriteHeader(http.StatusOK)
	}))
	defer telemetryServer.Close()
	tc, err := telemetry.NewClient(telemetry.Options{
		Endpoint:      telemetryServer.URL,
		BatchSize:     1,
		FlushInterval: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	app := intelApp(Config{
		Intelligence:               client,
		IntelligenceBlockThreshold: 7,
		DryRun:                     true,
		Telemetry:                  tc,
	})
	defer Cleanup()

	if got := statusFor(t, app, publicIP); got != http.StatusOK {
		t.Errorf("dry-run status = %d, want 200", got)
	}
	if err := tc.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var telemetryBody []byte
	select {
	case telemetryBody = <-telemetryRequests:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for telemetry POST")
	}
	var envelope struct {
		Events []telemetry.Event `json:"events"`
	}
	if err := json.Unmarshal(telemetryBody, &envelope); err != nil {
		t.Fatalf("decode telemetry batch: %v (body=%q)", err, telemetryBody)
	}
	if len(envelope.Events) != 1 {
		t.Fatalf("got %d events, want 1", len(envelope.Events))
	}
	event := envelope.Events[0]
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
