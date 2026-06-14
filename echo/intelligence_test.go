package echo

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path"
	"sync/atomic"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/getarcis/arcis-go/intelligence"
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

func intelApp(cfg Config) *echo.Echo {
	e := echo.New()
	e.Use(MiddlewareWithConfig(cfg))
	e.GET("/", func(c echo.Context) error { return c.JSON(http.StatusOK, map[string]bool{"ok": true}) })
	return e
}

func statusFor(e *echo.Echo, ip string) int {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", ip) // echo c.RealIP() reads this
	req.Header.Set("User-Agent", "Mozilla/5.0")
	w := httptest.NewRecorder()
	e.ServeHTTP(w, req)
	return w.Code
}

func pollFor(e *echo.Echo, ip string, want, tries int) bool {
	for i := 0; i < tries; i++ {
		if statusFor(e, ip) == want {
			return true
		}
		time.Sleep(15 * time.Millisecond)
	}
	return false
}

func TestEchoIntelBlocksKnownBadAfterWarmup(t *testing.T) {
	srv := intelStub(map[string]int{publicIP: 9}, nil)
	defer srv.Close()
	client, err := intelligence.NewClient(intelligence.Options{Endpoint: srv.URL, CloudDecisions: []string{"ip-rep"}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	e := intelApp(Config{Intelligence: client, IntelligenceBlockThreshold: 7})

	if got := statusFor(e, publicIP); got != http.StatusOK {
		t.Fatalf("first (cache-miss) request: got %d, want 200", got)
	}
	if !pollFor(e, publicIP, http.StatusForbidden, 60) {
		t.Fatal("expected 403 after the background refresh warms the cache")
	}
}

func TestEchoIntelNeverBlocksCleanIP(t *testing.T) {
	srv := intelStub(map[string]int{publicIP: 9}, nil)
	defer srv.Close()
	client, _ := intelligence.NewClient(intelligence.Options{Endpoint: srv.URL, CloudDecisions: []string{"ip-rep"}})
	defer client.Close()
	e := intelApp(Config{Intelligence: client, IntelligenceBlockThreshold: 7})

	for i := 0; i < 5; i++ {
		if got := statusFor(e, cleanIP); got != http.StatusOK {
			t.Fatalf("clean IP got %d, want 200", got)
		}
		time.Sleep(15 * time.Millisecond)
	}
}

func TestEchoIntelFailsOpenWhenUnreachable(t *testing.T) {
	srv := intelStub(nil, nil)
	url := srv.URL
	srv.Close() // unreachable
	client, _ := intelligence.NewClient(intelligence.Options{Endpoint: url, CloudDecisions: []string{"ip-rep"}, Timeout: 300 * time.Millisecond})
	defer client.Close()
	e := intelApp(Config{Intelligence: client, IntelligenceBlockThreshold: 1})

	if pollFor(e, publicIP, http.StatusForbidden, 8) {
		t.Fatal("unreachable service must never block (fail-open)")
	}
}

func TestEchoIntelInertWithoutCloudDecisions(t *testing.T) {
	var hits int32
	srv := intelStub(map[string]int{publicIP: 9}, &hits)
	defer srv.Close()
	client, _ := intelligence.NewClient(intelligence.Options{Endpoint: srv.URL}) // no CloudDecisions -> inert
	defer client.Close()
	e := intelApp(Config{Intelligence: client, IntelligenceBlockThreshold: 1})

	for i := 0; i < 4; i++ {
		if got := statusFor(e, publicIP); got != http.StatusOK {
			t.Fatalf("got %d, want 200", got)
		}
		time.Sleep(15 * time.Millisecond)
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatalf("expected no lookups, got %d", hits)
	}
}
