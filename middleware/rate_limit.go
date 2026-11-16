package middleware

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/getarcis/arcis-go/core"
	"github.com/getarcis/arcis-go/stores"
	"github.com/getarcis/arcis-go/utils"
)

// MaxRateLimitWindow is the longest accepted rate-limit window (2^31-1 ms).
const MaxRateLimitWindow = (1<<31 - 1) * time.Millisecond

// defaultMaxKeys caps the per-key maps of the in-memory limiters.
const defaultMaxKeys = stores.DefaultMemoryStoreMaxKeys

// RateLimiterOptions configures NewRateLimiterWithOptions.
type RateLimiterOptions struct {
	// Max is the number of requests allowed per window per key. 0 blocks
	// every request.
	Max int
	// Window is the window length: a whole number of milliseconds between
	// 1ms and MaxRateLimitWindow. Each key's window starts at its first hit.
	Window time.Duration
	// Store holds the counters. Nil uses a new stores.MemoryStore.
	Store core.RateLimitStore
	// TrustedProxies configures client IP resolution for Check; see
	// core.Config.TrustedProxies. Nil uses the default trust set.
	TrustedProxies []string
	// OnStoreError receives store errors, at most once per window. While the
	// store fails, requests are allowed. Nil logs with the log package.
	OnStoreError func(error)
}

// RateLimiter is a fixed-window rate limiter. Each counted request makes
// exactly one atomic store increment, so several limiters (or instances)
// sharing a store never admit more than the limit per window.
type RateLimiter struct {
	max          int
	window       time.Duration
	store        core.RateLimitStore
	resolver     *utils.ClientIPResolver
	skipFunc     func(*http.Request) bool
	onStoreError func(error)
	reportMu     sync.Mutex
	lastReport   time.Time
	cancel       context.CancelFunc
}

// NewRateLimiterWithOptions validates opts and creates a RateLimiter. It
// returns an error when Max is negative, Window is out of range, or a
// TrustedProxies entry is invalid.
func NewRateLimiterWithOptions(opts RateLimiterOptions) (*RateLimiter, error) {
	if err := validateRateLimit(opts.Max, opts.Window); err != nil {
		return nil, err
	}
	resolver, err := utils.NewClientIPResolver(opts.TrustedProxies)
	if err != nil {
		return nil, fmt.Errorf("arcis: invalid TrustedProxies: %w", err)
	}
	store := opts.Store
	if store == nil {
		store = stores.NewMemoryStore(0)
	}

	ctx, cancel := context.WithCancel(context.Background())
	rl := &RateLimiter{
		max:          opts.Max,
		window:       opts.Window,
		store:        store,
		resolver:     resolver,
		onStoreError: opts.OnStoreError,
		cancel:       cancel,
	}

	// Stores with local state (MemoryStore) are swept so expired keys do not
	// linger until the size cap evicts them.
	if cleaner, ok := store.(interface{ Cleanup() }); ok {
		interval := max(opts.Window, time.Second)
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					cleaner.Cleanup()
				}
			}
		}()
	}

	return rl, nil
}

// NewRateLimiter creates a RateLimiter with the in-memory store and the
// default trusted proxies. It panics on an invalid max or window; use
// NewRateLimiterWithOptions to get an error instead.
func NewRateLimiter(max int, window time.Duration) *RateLimiter {
	return mustRateLimiter(RateLimiterOptions{Max: max, Window: window})
}

// NewRateLimiterWithStore creates a RateLimiter backed by store. It panics on
// an invalid max or window; use NewRateLimiterWithOptions to get an error
// instead.
func NewRateLimiterWithStore(max int, window time.Duration, store core.RateLimitStore) *RateLimiter {
	return mustRateLimiter(RateLimiterOptions{Max: max, Window: window, Store: store})
}

func mustRateLimiter(opts RateLimiterOptions) *RateLimiter {
	rl, err := NewRateLimiterWithOptions(opts)
	if err != nil {
		panic(err.Error())
	}
	return rl
}

// validateRateLimit enforces spec/API_SPEC.md "Validation at construction".
func validateRateLimit(max int, window time.Duration) error {
	if max < 0 {
		return fmt.Errorf("arcis: rate limit max must be 0 or more, got %d", max)
	}
	if window < time.Millisecond || window > MaxRateLimitWindow || window%time.Millisecond != 0 {
		return fmt.Errorf("arcis: rate limit window must be a whole number of milliseconds from 1ms to %dms, got %s", MaxRateLimitWindow.Milliseconds(), window)
	}
	return nil
}

// SetSkipFunc sets a function that determines whether to skip rate limiting.
func (rl *RateLimiter) SetSkipFunc(fn func(*http.Request) bool) {
	rl.skipFunc = fn
}

// Check counts r against its client's limit. The key is the client IP
// resolved with the limiter's trusted proxies, passed through
// utils.RateLimitKey (IPv6 grouped to /56).
func (rl *RateLimiter) Check(r *http.Request) core.RateLimitResult {
	if rl.skipFunc != nil && rl.skipFunc(r) {
		return rl.unlimited()
	}
	// The count must not be skipped because the client went away.
	ctx := context.WithoutCancel(r.Context())
	return rl.check(ctx, utils.RateLimitKey(rl.resolver.ClientIP(r)))
}

// CheckKey counts one request against key.
func (rl *RateLimiter) CheckKey(key string) core.RateLimitResult {
	return rl.check(context.Background(), key)
}

func (rl *RateLimiter) check(ctx context.Context, key string) core.RateLimitResult {
	entry, err := rl.store.Increment(ctx, key, rl.window)
	if err != nil {
		rl.reportStoreError(err)
		return rl.unlimited()
	}
	remaining := max(rl.max-entry.Count, 0)
	reset := max(time.Until(entry.ResetTime), 0)
	return core.RateLimitResult{
		Allowed:   entry.Count <= rl.max,
		Limit:     rl.max,
		Remaining: remaining,
		Reset:     reset,
	}
}

func (rl *RateLimiter) unlimited() core.RateLimitResult {
	return core.RateLimitResult{
		Allowed:   true,
		Limit:     rl.max,
		Remaining: rl.max,
		Reset:     rl.window,
	}
}

// reportStoreError reports at most once per window (fail open).
func (rl *RateLimiter) reportStoreError(err error) {
	now := time.Now()
	rl.reportMu.Lock()
	due := rl.lastReport.IsZero() || now.Sub(rl.lastReport) >= rl.window
	if due {
		rl.lastReport = now
	}
	rl.reportMu.Unlock()
	if !due {
		return
	}
	if rl.onStoreError != nil {
		rl.onStoreError(err)
		return
	}
	log.Printf("arcis: rate limit store error, allowing requests: %v", err)
}

// Close stops the cleanup goroutine and releases resources.
func (rl *RateLimiter) Close() {
	rl.cancel()
}
