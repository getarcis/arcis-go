package gin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

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

func intelEngine(t *testing.T, cfg Config) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(MiddlewareWithConfig(cfg))
	r.GET("/", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })
	return r
}

func getStatus(r *gin.Engine, ip string) int {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", ip)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code
}

func pollStatus(r *gin.Engine, ip string, want int, tries int) bool {
	for i := 0; i < tries; i++ {
		if getStatus(r, ip) == want {
			return true
		}
		time.Sleep(15 * time.Millisecond)
	}
	return false
}

func TestGinBlocksKnownBadAfterWarmup(t *testing.T) {
	srv := intelStub(map[string]int{publicIP: 9}, nil)
	defer srv.Close()
	client, err := intelligence.NewClient(intelligence.Options{
		Endpoint: srv.URL, CloudDecisions: []string{"ip-rep"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	r := intelEngine(t, Config{Intelligence: client, IntelligenceBlockThreshold: 7})

	// First request is a cache miss -> allowed.
	if got := getStatus(r, publicIP); got != http.StatusOK {
		t.Fatalf("first request: got %d, want 200", got)
	}
	// After the background refresh warms the cache, the IP is blocked.
	if !pollStatus(r, publicIP, http.StatusForbidden, 60) {
		t.Fatal("expected a 403 after warm-up")
	}
}

func TestGinNeverBlocksCleanIP(t *testing.T) {
	srv := intelStub(map[string]int{publicIP: 9}, nil)
	defer srv.Close()
	client, _ := intelligence.NewClient(intelligence.Options{
		Endpoint: srv.URL, CloudDecisions: []string{"ip-rep"},
	})
	defer client.Close()
	r := intelEngine(t, Config{Intelligence: client, IntelligenceBlockThreshold: 7})

	for i := 0; i < 5; i++ {
		if got := getStatus(r, cleanIP); got != http.StatusOK {
			t.Fatalf("clean IP got %d, want 200", got)
		}
		time.Sleep(15 * time.Millisecond)
	}
}

func TestGinFailsOpenWhenUnreachable(t *testing.T) {
	srv := intelStub(nil, nil)
	url := srv.URL
	srv.Close() // unreachable
	client, _ := intelligence.NewClient(intelligence.Options{
		Endpoint: url, CloudDecisions: []string{"ip-rep"}, Timeout: 300 * time.Millisecond,
	})
	defer client.Close()
	r := intelEngine(t, Config{Intelligence: client, IntelligenceBlockThreshold: 1})

	if pollStatus(r, publicIP, http.StatusForbidden, 8) {
		t.Fatal("unreachable service must never block (fail-open)")
	}
}

func TestGinInertWithoutCloudDecisions(t *testing.T) {
	var hits int32
	srv := intelStub(map[string]int{publicIP: 9}, &hits)
	defer srv.Close()
	client, _ := intelligence.NewClient(intelligence.Options{
		Endpoint: srv.URL, // no CloudDecisions -> inert
	})
	defer client.Close()
	r := intelEngine(t, Config{Intelligence: client, IntelligenceBlockThreshold: 1})

	for i := 0; i < 4; i++ {
		if got := getStatus(r, publicIP); got != http.StatusOK {
			t.Fatalf("got %d, want 200", got)
		}
		time.Sleep(15 * time.Millisecond)
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatalf("expected no lookups, got %d", hits)
	}
}

func TestGinDryRunNeverBlocks(t *testing.T) {
	srv := intelStub(map[string]int{publicIP: 10}, nil)
	defer srv.Close()
	client, _ := intelligence.NewClient(intelligence.Options{
		Endpoint: srv.URL, CloudDecisions: []string{"ip-rep"},
	})
	defer client.Close()
	r := intelEngine(t, Config{
		Intelligence: client, IntelligenceBlockThreshold: 1, Block: true, DryRun: true,
	})

	getStatus(r, publicIP) // warm
	time.Sleep(100 * time.Millisecond)
	if pollStatus(r, publicIP, http.StatusForbidden, 6) {
		t.Fatal("dry-run must never block")
	}
}
