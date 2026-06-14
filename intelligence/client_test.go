package intelligence

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path"
	"sync/atomic"
	"testing"
	"time"
)

func waitFor(cond func() bool, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

// stubServer serves a verdict per IP (last path segment). It bumps hits and,
// if capture is non-nil, records the inbound headers of the first request.
func stubServer(verdicts map[string]Reputation, hits *int32, capture *http.Header) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		if capture != nil && len(*capture) == 0 {
			*capture = r.Header.Clone()
		}
		ip := path.Base(r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		v, ok := verdicts[ip]
		if !ok {
			_ = json.NewEncoder(w).Encode(Reputation{IP: ip, Found: false})
			return
		}
		v.IP = ip
		v.Found = true
		_ = json.NewEncoder(w).Encode(v)
	}))
}

func newTestClient(t *testing.T, endpoint string, opts Options) *Client {
	t.Helper()
	opts.Endpoint = endpoint
	if opts.CloudDecisions == nil {
		opts.CloudDecisions = []string{"ip-rep"}
	}
	c, err := NewClient(opts)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func TestNewClientRequiresEndpoint(t *testing.T) {
	if _, err := NewClient(Options{}); err == nil {
		t.Fatal("expected error for empty endpoint")
	}
}

func TestCheckSkipsPrivateAndUnknown(t *testing.T) {
	var hits int32
	srv := stubServer(nil, &hits, nil)
	defer srv.Close()
	c := newTestClient(t, srv.URL, Options{})
	defer c.Close()

	for _, ip := range []string{"127.0.0.1", "10.0.0.5", "192.168.1.1", "::1", "unknown", ""} {
		if c.Check(ip).Found {
			t.Fatalf("Check(%q) should be Found=false", ip)
		}
	}
	time.Sleep(40 * time.Millisecond)
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatalf("expected no HTTP hits, got %d", hits)
	}
}

func TestCheckInertWithoutIPRep(t *testing.T) {
	var hits int32
	srv := stubServer(nil, &hits, nil)
	defer srv.Close()
	c := newTestClient(t, srv.URL, Options{CloudDecisions: []string{}})
	defer c.Close()

	if c.Check("203.0.113.7").Found {
		t.Fatal("expected Found=false when ip-rep disabled")
	}
	time.Sleep(40 * time.Millisecond)
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatalf("expected no HTTP hits, got %d", hits)
	}
}

func TestCheckMissThenCachedHit(t *testing.T) {
	var hits int32
	srv := stubServer(map[string]Reputation{
		"203.0.113.7": {Severity: 6, Categories: []string{"tor"}, Sources: []string{"tor-exit"}},
	}, &hits, nil)
	defer srv.Close()
	c := newTestClient(t, srv.URL, Options{})
	defer c.Close()

	if c.Check("203.0.113.7").Found {
		t.Fatal("first Check should be a miss (Found=false)")
	}
	if !waitFor(func() bool { return c.CacheSize() == 1 }, time.Second) {
		t.Fatal("cache never warmed")
	}
	rep := c.Check("203.0.113.7")
	if !rep.Found || rep.Severity != 6 || len(rep.Categories) != 1 || rep.Categories[0] != "tor" {
		t.Fatalf("unexpected cached verdict: %+v", rep)
	}
}

func TestCheckDedupesConcurrentRefreshes(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		time.Sleep(50 * time.Millisecond) // widen the in-flight window
		_ = json.NewEncoder(w).Encode(Reputation{Found: false})
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL, Options{})
	defer c.Close()

	c.Check("203.0.113.9")
	c.Check("203.0.113.9")
	c.Check("203.0.113.9")
	waitFor(func() bool { return atomic.LoadInt32(&hits) >= 1 }, time.Second)
	time.Sleep(120 * time.Millisecond)
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("expected 1 fetch (deduped), got %d", got)
	}
}

func TestLookupNormalizesFoundVerdict(t *testing.T) {
	srv := stubServer(map[string]Reputation{
		"203.0.113.7": {
			Severity:   8,
			Categories: []string{"tor", "abuse"},
			Sources:    []string{"tor-exit", "abuseipdb"},
			FirstSeen:  "2026-06-01",
			LastSeen:   "2026-06-11",
			Matched:    "203.0.113.0/24",
		},
	}, new(int32), nil)
	defer srv.Close()
	c := newTestClient(t, srv.URL, Options{})
	defer c.Close()

	rep := c.Lookup("203.0.113.7")
	if !rep.Found || rep.Severity != 8 || rep.FirstSeen != "2026-06-01" ||
		rep.LastSeen != "2026-06-11" || rep.Matched != "203.0.113.0/24" {
		t.Fatalf("unexpected verdict: %+v", rep)
	}
}

func TestLookupSendsAuthHeaders(t *testing.T) {
	var captured http.Header
	srv := stubServer(map[string]Reputation{"203.0.113.7": {Severity: 5}}, new(int32), &captured)
	defer srv.Close()
	c := newTestClient(t, srv.URL, Options{APIKey: "ak_test", WorkspaceID: "ws1"})
	defer c.Close()

	c.Lookup("203.0.113.7")
	if captured.Get("Authorization") != "Bearer ak_test" {
		t.Fatalf("missing/incorrect Authorization: %q", captured.Get("Authorization"))
	}
	if captured.Get("X-Workspace-Id") != "ws1" {
		t.Fatalf("missing/incorrect X-Workspace-Id: %q", captured.Get("X-Workspace-Id"))
	}
}

func TestLookupFailsOpenOn500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	var errCount int32
	c := newTestClient(t, srv.URL, Options{OnError: func(error) { atomic.AddInt32(&errCount, 1) }})
	defer c.Close()

	if c.Lookup("203.0.113.7").Found {
		t.Fatal("expected Found=false on HTTP 500")
	}
	if atomic.LoadInt32(&errCount) != 1 {
		t.Fatalf("expected OnError once, got %d", errCount)
	}
}

func TestLookupFailsOpenOnUnreachable(t *testing.T) {
	srv := stubServer(nil, new(int32), nil)
	url := srv.URL
	srv.Close() // now unreachable
	var errCount int32
	c := newTestClient(t, url, Options{OnError: func(error) { atomic.AddInt32(&errCount, 1) }})
	defer c.Close()

	if c.Lookup("203.0.113.7").Found {
		t.Fatal("expected Found=false when service is unreachable")
	}
	if atomic.LoadInt32(&errCount) != 1 {
		t.Fatalf("expected OnError once, got %d", errCount)
	}
}

func TestLookupSkipsPrivate(t *testing.T) {
	var hits int32
	srv := stubServer(nil, &hits, nil)
	defer srv.Close()
	c := newTestClient(t, srv.URL, Options{})
	defer c.Close()

	if c.Lookup("10.1.2.3").Found {
		t.Fatal("expected Found=false for private IP")
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatalf("expected no HTTP hits, got %d", hits)
	}
}

func TestCleanVerdictIsCached(t *testing.T) {
	var hits int32
	srv := stubServer(nil, &hits, nil) // every IP -> found:false
	defer srv.Close()
	c := newTestClient(t, srv.URL, Options{})
	defer c.Close()

	c.Check("203.0.113.50")
	if !waitFor(func() bool { return c.CacheSize() == 1 }, time.Second) {
		t.Fatal("clean verdict never cached")
	}
	c.Check("203.0.113.50") // cache hit, no new fetch
	time.Sleep(40 * time.Millisecond)
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("expected 1 fetch, got %d", got)
	}
}

func TestEvictionBeyondCacheMax(t *testing.T) {
	srv := stubServer(nil, new(int32), nil)
	defer srv.Close()
	c := newTestClient(t, srv.URL, Options{CacheMax: 2})
	defer c.Close()

	for _, ip := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
		c.Check(ip)
		time.Sleep(30 * time.Millisecond) // serialize for deterministic order
	}
	if !waitFor(func() bool { return c.CacheSize() <= 2 }, time.Second) {
		t.Fatalf("cache not evicted, size=%d", c.CacheSize())
	}
}

func TestRequeryAfterTTL(t *testing.T) {
	var hits int32
	srv := stubServer(nil, &hits, nil)
	defer srv.Close()
	c := newTestClient(t, srv.URL, Options{CacheTTL: 50 * time.Millisecond})
	defer c.Close()

	c.Check("203.0.113.7")
	if !waitFor(func() bool { return atomic.LoadInt32(&hits) == 1 }, time.Second) {
		t.Fatal("first fetch never happened")
	}
	time.Sleep(70 * time.Millisecond) // expire the entry
	c.Check("203.0.113.7")            // stale -> schedules a fresh fetch
	if !waitFor(func() bool { return atomic.LoadInt32(&hits) == 2 }, time.Second) {
		t.Fatalf("expected re-query after TTL, hits=%d", hits)
	}
}

func TestNoFetchAfterClose(t *testing.T) {
	var hits int32
	srv := stubServer(nil, &hits, nil)
	defer srv.Close()
	c := newTestClient(t, srv.URL, Options{})
	c.Close()

	if c.Check("203.0.113.7").Found {
		t.Fatal("expected Found=false after Close")
	}
	time.Sleep(40 * time.Millisecond)
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatalf("expected no HTTP hits after Close, got %d", hits)
	}
}

func TestReputationSeverityTier(t *testing.T) {
	cases := map[int]string{10: "critical", 9: "critical", 8: "high", 5: "medium", 2: "low", 0: "low"}
	for sev, want := range cases {
		if got := ReputationSeverityTier(sev); got != want {
			t.Fatalf("ReputationSeverityTier(%d) = %q, want %q", sev, got, want)
		}
	}
}

func TestShouldBlock(t *testing.T) {
	srv := stubServer(map[string]Reputation{"203.0.113.7": {Severity: 9}}, new(int32), nil)
	defer srv.Close()
	c := newTestClient(t, srv.URL, Options{})
	defer c.Close()

	// Warm the cache.
	c.Check("203.0.113.7")
	if !waitFor(func() bool { return c.CacheSize() == 1 }, time.Second) {
		t.Fatal("cache never warmed")
	}
	if _, block := ShouldBlock(c, 7, "203.0.113.7"); !block {
		t.Fatal("expected block at threshold 7 for severity 9")
	}
	if _, block := ShouldBlock(c, 10, "203.0.113.7"); block {
		t.Fatal("expected no block at threshold 10 for severity 9")
	}
	if _, block := ShouldBlock(c, 0, "203.0.113.7"); block {
		t.Fatal("threshold 0 means observe-only, should not block")
	}
}
