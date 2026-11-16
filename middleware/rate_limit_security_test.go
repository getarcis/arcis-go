package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/getarcis/arcis-go/core"
	"github.com/getarcis/arcis-go/stores"
)

// ─── test stores ─────────────────────────────────────────────────────────────

type failingStore struct{ err error }

func (f failingStore) Increment(context.Context, string, time.Duration) (core.RateLimitEntry, error) {
	return core.RateLimitEntry{}, f.err
}
func (f failingStore) Decrement(context.Context, string) error { return f.err }
func (f failingStore) ResetKey(context.Context, string) error  { return f.err }

// countingStore records every Increment and fails like a network store would
// when its context is cancelled.
type countingStore struct {
	*stores.MemoryStore
	increments atomic.Int32
	keys       sync.Map
}

func newCountingStore() *countingStore {
	return &countingStore{MemoryStore: stores.NewMemoryStore(0)}
}

func (c *countingStore) Increment(ctx context.Context, key string, window time.Duration) (core.RateLimitEntry, error) {
	if err := ctx.Err(); err != nil {
		return core.RateLimitEntry{}, err
	}
	c.increments.Add(1)
	c.keys.Store(key, true)
	return c.MemoryStore.Increment(ctx, key, window)
}

func requestFrom(remoteAddr, xff string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = remoteAddr
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	return req
}

// ─── validation ──────────────────────────────────────────────────────────────

func TestRateLimiterOptions_Validation(t *testing.T) {
	invalid := []RateLimiterOptions{
		{Max: 5, Window: 0},
		{Max: 5, Window: -time.Second},
		{Max: 5, Window: 500 * time.Microsecond},
		{Max: 5, Window: 1500 * time.Microsecond},
		{Max: 5, Window: MaxRateLimitWindow + time.Millisecond},
		{Max: -1, Window: time.Minute},
		{Max: 5, Window: time.Minute, TrustedProxies: []string{"not-a-cidr"}},
	}
	for _, opts := range invalid {
		if rl, err := NewRateLimiterWithOptions(opts); err == nil {
			rl.Close()
			t.Errorf("%+v: expected an error", opts)
		}
	}
	valid := []RateLimiterOptions{
		{Max: 0, Window: time.Millisecond},
		{Max: 1, Window: MaxRateLimitWindow},
	}
	for _, opts := range valid {
		rl, err := NewRateLimiterWithOptions(opts)
		if err != nil {
			t.Errorf("%+v: unexpected error %v", opts, err)
			continue
		}
		rl.Close()
	}
}

func TestNewRateLimiter_PanicsAtConstructionOnInvalidWindow(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil || !strings.Contains(fmt.Sprint(r), "window") {
			t.Fatalf("expected a construction panic naming the window, got %v", r)
		}
	}()
	NewRateLimiter(10, 0)
}

func TestNewSlidingWindowLimiter_PanicsAtConstructionOnInvalidConfig(t *testing.T) {
	for _, tc := range []struct {
		max    int
		window time.Duration
	}{{10, 0}, {-1, time.Second}} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("max=%d window=%s: expected a panic", tc.max, tc.window)
				}
			}()
			NewSlidingWindowLimiter(tc.max, tc.window)
		}()
	}
}

func TestRateLimiter_MaxZeroBlocksEveryRequest(t *testing.T) {
	rl := NewRateLimiter(0, time.Minute)
	defer rl.Close()
	for i := 0; i < 3; i++ {
		if rl.CheckKey("k").Allowed {
			t.Fatalf("request %d allowed with max 0", i+1)
		}
	}
	sw := NewSlidingWindowLimiter(0, time.Minute)
	defer sw.Close()
	if sw.CheckKey("k").Allowed {
		t.Fatal("sliding window allowed a request with max 0")
	}
}

func TestRateLimiter_MillisecondWindowDoesNotPanic(t *testing.T) {
	rl := NewRateLimiter(1, time.Millisecond)
	defer rl.Close()
	rl.CheckKey("k")
	time.Sleep(3 * time.Millisecond)
	if !rl.CheckKey("k").Allowed {
		t.Fatal("a new 1ms window should allow the request")
	}
}

// ─── counting ────────────────────────────────────────────────────────────────

func TestRateLimiter_ExactlyOneIncrementPerCheck(t *testing.T) {
	store := newCountingStore()
	rl := NewRateLimiterWithStore(3, time.Minute, store)
	defer rl.Close()
	for i := 0; i < 5; i++ {
		rl.Check(requestFrom("203.0.113.9:1000", ""))
	}
	if n := store.increments.Load(); n != 5 {
		t.Fatalf("%d increments for 5 requests, want 5", n)
	}
}

func TestRateLimiter_CancelledRequestIsStillCounted(t *testing.T) {
	store := newCountingStore()
	reports := 0
	rl, _ := NewRateLimiterWithOptions(RateLimiterOptions{
		Max: 1, Window: time.Minute, Store: store,
		OnStoreError: func(error) { reports++ },
	})
	defer rl.Close()

	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // the client already went away
		req := requestFrom("203.0.113.9:1000", "").WithContext(ctx)
		result := rl.Check(req)
		if i == 1 && result.Allowed {
			t.Fatal("a disconnecting client must not bypass the limit")
		}
	}
	if reports != 0 {
		t.Fatalf("cancellation reached the store as an error (%d reports)", reports)
	}
}

func TestRateLimiter_ConcurrentChecksAdmitExactlyMax(t *testing.T) {
	rl := NewRateLimiter(5, time.Minute)
	defer rl.Close()
	var allowed atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rl.CheckKey("same").Allowed {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()
	if allowed.Load() != 5 {
		t.Fatalf("%d allowed, want 5", allowed.Load())
	}
}

// ─── store errors ────────────────────────────────────────────────────────────

func TestRateLimiter_StoreErrorFailsOpenAndReportsOncePerWindow(t *testing.T) {
	storeErr := errors.New("redis down")
	var mu sync.Mutex
	var reported []error
	rl, err := NewRateLimiterWithOptions(RateLimiterOptions{
		Max: 1, Window: 50 * time.Millisecond, Store: failingStore{err: storeErr},
		OnStoreError: func(err error) {
			mu.Lock()
			reported = append(reported, err)
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rl.Close()

	for i := 0; i < 10; i++ {
		if !rl.CheckKey("k").Allowed {
			t.Fatalf("request %d denied while the store fails; want fail open", i+1)
		}
	}
	mu.Lock()
	if len(reported) != 1 || !errors.Is(reported[0], storeErr) {
		t.Fatalf("reports %v, want exactly one store error in the window", reported)
	}
	mu.Unlock()

	time.Sleep(60 * time.Millisecond)
	rl.CheckKey("k")
	mu.Lock()
	defer mu.Unlock()
	if len(reported) != 2 {
		t.Fatalf("%d reports after the window passed, want 2", len(reported))
	}
}

// ─── client keys ─────────────────────────────────────────────────────────────

func TestRateLimiter_PublicPeerRotatingXFFSharesOneBucket(t *testing.T) {
	rl := NewRateLimiter(2, time.Minute)
	defer rl.Close()
	var last bool
	for i := 0; i < 3; i++ {
		last = rl.Check(requestFrom("203.0.113.9:1000", fmt.Sprintf("198.51.100.%d", i))).Allowed
	}
	if last {
		t.Fatal("rotating X-Forwarded-For from a public peer must not mint new buckets")
	}
}

func TestRateLimiter_TrustedProxyGivesDistinctClientsDistinctBuckets(t *testing.T) {
	store := newCountingStore()
	rl := NewRateLimiterWithStore(1, time.Minute, store)
	defer rl.Close()
	for _, client := range []string{"198.51.100.1", "198.51.100.2"} {
		if !rl.Check(requestFrom("10.0.0.2:1000", "1.1.1.1, "+client)).Allowed {
			t.Fatalf("first request from %s should be allowed", client)
		}
	}
	if rl.Check(requestFrom("10.0.0.3:1000", "198.51.100.1")).Allowed {
		t.Fatal("second request from the same client should be limited")
	}
	if _, spoofed := store.keys.Load("1.1.1.1"); spoofed {
		t.Fatal("the client-controlled left-most entry became a key")
	}
}

func TestRateLimiter_ConfiguredTrustedProxies(t *testing.T) {
	rl, err := NewRateLimiterWithOptions(RateLimiterOptions{
		Max: 1, Window: time.Minute, TrustedProxies: []string{"203.0.113.0/24"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rl.Close()
	if !rl.Check(requestFrom("203.0.113.7:1000", "198.51.100.1")).Allowed {
		t.Fatal("first client behind the configured proxy should be allowed")
	}
	if !rl.Check(requestFrom("203.0.113.7:1000", "198.51.100.2")).Allowed {
		t.Fatal("a second client behind the configured proxy has its own bucket")
	}
}

func TestRateLimiter_EmptyTrustedProxiesTrustsNothing(t *testing.T) {
	rl, _ := NewRateLimiterWithOptions(RateLimiterOptions{Max: 1, Window: time.Minute, TrustedProxies: []string{}})
	defer rl.Close()
	rl.Check(requestFrom("127.0.0.1:1000", "198.51.100.1"))
	if rl.Check(requestFrom("127.0.0.1:1000", "198.51.100.2")).Allowed {
		t.Fatal("with no trusted proxies even a loopback peer's header is ignored")
	}
}

func TestRateLimiter_IPv6GroupedBy56(t *testing.T) {
	rl := NewRateLimiter(1, time.Minute)
	defer rl.Close()
	rl.Check(requestFrom("[2001:db8:1234:5601::1]:443", ""))
	if rl.Check(requestFrom("[2001:db8:1234:56ff:ffff::9]:443", "")).Allowed {
		t.Fatal("addresses in one /56 must share a bucket")
	}
	if !rl.Check(requestFrom("[2001:db8:1234:5700::1]:443", "")).Allowed {
		t.Fatal("a different /56 has its own bucket")
	}
}

func TestSlidingAndTokenBucket_IgnoreSpoofedXFF(t *testing.T) {
	sw := NewSlidingWindowLimiter(1, time.Minute)
	defer sw.Close()
	sw.Check(requestFrom("203.0.113.9:1000", "198.51.100.1"))
	if sw.Check(requestFrom("203.0.113.9:1000", "198.51.100.2")).Allowed {
		t.Fatal("sliding window: spoofed XFF minted a new bucket")
	}

	tb := NewTokenBucketLimiter(1, 0.001)
	defer tb.Close()
	tb.Check(requestFrom("203.0.113.9:1000", "198.51.100.1"))
	if tb.Check(requestFrom("203.0.113.9:1000", "198.51.100.2")).Allowed {
		t.Fatal("token bucket: spoofed XFF minted a new bucket")
	}
}

// ─── sliding window boundaries ───────────────────────────────────────────────

func TestSlidingWindow_IdleWindowStartsFromZero(t *testing.T) {
	window := time.Second
	sw := NewSlidingWindowLimiter(3, window)
	defer sw.Close()

	base := time.Unix(1_800_000_000, 0) // aligned to the window
	for i := 0; i < 3; i++ {
		sw.checkAt("k", base.Add(100*time.Millisecond))
	}
	if sw.checkAt("k", base.Add(200*time.Millisecond)).Allowed {
		t.Fatal("fourth request in the window should be limited")
	}

	// Two windows later the old count must not weigh in.
	result := sw.checkAt("k", base.Add(2*window+10*time.Millisecond))
	if !result.Allowed || result.Remaining != 2 {
		t.Fatalf("after an idle window got %+v, want allowed with remaining 2", result)
	}
}

func TestSlidingWindow_ImmediatelyPrecedingWindowStillCounts(t *testing.T) {
	window := time.Second
	sw := NewSlidingWindowLimiter(3, window)
	defer sw.Close()

	base := time.Unix(1_800_000_000, 0)
	for i := 0; i < 3; i++ {
		sw.checkAt("k", base.Add(900*time.Millisecond))
	}
	if sw.checkAt("k", base.Add(window+10*time.Millisecond)).Allowed {
		t.Fatal("the previous window's hits should still weigh in just after the boundary")
	}
}

func TestSlidingWindow_SubSecondWindowBoundaries(t *testing.T) {
	window := 100 * time.Millisecond
	sw := NewSlidingWindowLimiter(1, window)
	defer sw.Close()

	base := time.Unix(1_800_000_000, 0)
	first := sw.checkAt("k", base.Add(10*time.Millisecond))
	if !first.Allowed || first.Reset != 90*time.Millisecond {
		t.Fatalf("got %+v, want allowed with reset 90ms (no whole-second rounding)", first)
	}
	if sw.checkAt("k", base.Add(50*time.Millisecond)).Allowed {
		t.Fatal("second request in the same 100ms window should be limited")
	}
	if !sw.checkAt("k", base.Add(3*window)).Allowed {
		t.Fatal("a request three windows later should be allowed")
	}
}

// ─── brute force ─────────────────────────────────────────────────────────────

func TestBruteForce_IgnoresSpoofedXFFFromPublicPeer(t *testing.T) {
	b := NewBruteForce(BruteForceConfig{FastPoints: 2})
	defer b.Close()
	var last BruteForceResult
	for i := 0; i < 3; i++ {
		last = b.Check(requestFrom("203.0.113.9:1000", fmt.Sprintf("198.51.100.%d", i)))
	}
	if last.Allowed {
		t.Fatal("rotating X-Forwarded-For must not reset brute-force counters")
	}
}

func TestBruteForce_CheckPeerAndKey(t *testing.T) {
	b := NewBruteForce(BruteForceConfig{FastPoints: 1, TrustedProxies: []string{"10.0.0.0/8"}})
	defer b.Close()

	if !b.CheckPeer("10.0.0.2:1000", []string{"198.51.100.1"}).Allowed {
		t.Fatal("first attempt should be allowed")
	}
	if b.CheckPeer("10.0.0.3:1000", []string{"198.51.100.1"}).Allowed {
		t.Fatal("second attempt from the same client should be denied")
	}
	if !b.CheckPeer("10.0.0.2:1000", []string{"198.51.100.2"}).Allowed {
		t.Fatal("a different client behind the trusted proxy has its own counters")
	}

	req := requestFrom("10.0.0.9:1000", "198.51.100.1")
	if got := b.Key(req); got != "198.51.100.1" {
		t.Fatalf("Key = %q, want the resolved client", got)
	}
	b.Reset(b.Key(req))
	if !b.Check(req).Allowed {
		t.Fatal("Reset(Key(r)) should clear the client's counters")
	}
}

func TestBruteForce_InvalidTrustedProxiesPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil || !strings.Contains(fmt.Sprint(r), "TrustedProxies") {
			t.Fatalf("expected a TrustedProxies panic, got %v", r)
		}
	}()
	NewBruteForce(BruteForceConfig{TrustedProxies: []string{"bogus"}})
}
