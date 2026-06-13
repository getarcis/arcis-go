package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/getarcis/arcis-go/utils"
)

// brute_force.go — brute-force protection middleware, ported from the Node
// SDK's middleware/brute-force.ts for cross-SDK parity.
//
// Designed for login / password-reset endpoints where the defense is not just
// "X requests per minute" but "if this client keeps trying after the
// rate-limit window resets, block it for longer". Two-tier semantics:
//
//   - Fast window: FastPoints attempts per FastDuration. Once exhausted,
//     traffic gets a 429 until the window resets. No semi-permanent block.
//   - Slow window: SlowPoints attempts over SlowDuration trips a BlockDuration
//     semi-permanent block that denies every request until it expires.
//
// Both windows must allow (AND semantics); the slow window is checked first so
// the block-state check happens before the cheap fast check. The application
// resets the counters on a successful login via Reset(key).

// BruteForceConfig configures the brute-force limiter. Zero values fall back
// to the documented defaults.
type BruteForceConfig struct {
	FastPoints    int           // attempts allowed in the fast window (default 5)
	FastDuration  time.Duration // fast window length (default 60s)
	SlowPoints    int           // attempts allowed in the slow window (default 20)
	SlowDuration  time.Duration // slow window length (default 15m)
	BlockDuration time.Duration // block length after slow-window exhaustion (default 15m)
	StatusCode    int           // HTTP status when denied (default 429)
	Message       string        // response message when denied
	KeyFunc       func(*http.Request) string // key resolver (default: client IP)
	Skip          func(*http.Request) bool   // return true to bypass for this request
}

// BruteForceResult is the outcome of a brute-force check.
type BruteForceResult struct {
	Allowed    bool
	RetryAfter time.Duration // when !Allowed, how long until the client may retry
	Remaining  int           // fast-window attempts remaining when Allowed
}

type bfEntry struct {
	count     int
	resetTime time.Time
}

// BruteForce is a two-tier (fast + slow + block) brute-force limiter. It is
// safe for concurrent use.
type BruteForce struct {
	cfg     BruteForceConfig
	fast    map[string]*bfEntry
	slow    map[string]*bfEntry
	blocked map[string]time.Time // key -> time the block expires
	mu      sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
}

// NewBruteForce builds a brute-force limiter, applying defaults for any zero
// config fields and starting a background cleanup goroutine (stopped via
// Close). Mirrors NewRateLimiter's lifecycle.
func NewBruteForce(cfg BruteForceConfig) *BruteForce {
	if cfg.FastPoints <= 0 {
		cfg.FastPoints = 5
	}
	if cfg.FastDuration <= 0 {
		cfg.FastDuration = 60 * time.Second
	}
	if cfg.SlowPoints <= 0 {
		cfg.SlowPoints = 20
	}
	if cfg.SlowDuration <= 0 {
		cfg.SlowDuration = 15 * time.Minute
	}
	if cfg.BlockDuration <= 0 {
		cfg.BlockDuration = 15 * time.Minute
	}
	if cfg.StatusCode == 0 {
		cfg.StatusCode = http.StatusTooManyRequests
	}
	if cfg.Message == "" {
		cfg.Message = "Too many attempts. Please try again later."
	}

	ctx, cancel := context.WithCancel(context.Background())
	b := &BruteForce{
		cfg:     cfg,
		fast:    make(map[string]*bfEntry),
		slow:    make(map[string]*bfEntry),
		blocked: make(map[string]time.Time),
		ctx:     ctx,
		cancel:  cancel,
	}

	// Prune expired entries on the slow-window cadence so the maps stay
	// bounded by the count of recently-active keys.
	go func() {
		ticker := time.NewTicker(cfg.SlowDuration)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				b.cleanup()
			}
		}
	}()

	return b
}

// CheckKey consumes one attempt for key and reports whether it is allowed.
func (b *BruteForce) CheckKey(key string) BruteForceResult {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()

	// 1. Block state first — a tripped block denies everything until it expires.
	if until, ok := b.blocked[key]; ok {
		if now.Before(until) {
			return BruteForceResult{Allowed: false, RetryAfter: until.Sub(now)}
		}
		delete(b.blocked, key)
	}

	// 2. Slow window — exhausting it trips the semi-permanent block.
	if slowCount := bump(b.slow, key, b.cfg.SlowDuration, now); slowCount > b.cfg.SlowPoints {
		b.blocked[key] = now.Add(b.cfg.BlockDuration)
		return BruteForceResult{Allowed: false, RetryAfter: b.cfg.BlockDuration}
	}

	// 3. Fast window — short-term 429, resets on its own, no block.
	fastCount := bump(b.fast, key, b.cfg.FastDuration, now)
	if fastCount > b.cfg.FastPoints {
		return BruteForceResult{Allowed: false, RetryAfter: b.fast[key].resetTime.Sub(now)}
	}

	remaining := b.cfg.FastPoints - fastCount
	if remaining < 0 {
		remaining = 0
	}
	return BruteForceResult{Allowed: true, Remaining: remaining}
}

// Check resolves the key from the request (KeyFunc or client IP) and consumes
// one attempt. Honors Skip.
func (b *BruteForce) Check(r *http.Request) BruteForceResult {
	if b.cfg.Skip != nil && b.cfg.Skip(r) {
		return BruteForceResult{Allowed: true, Remaining: b.cfg.FastPoints}
	}
	key := utils.GetClientIP(r)
	if b.cfg.KeyFunc != nil {
		key = b.cfg.KeyFunc(r)
	}
	return b.CheckKey(key)
}

// Reset clears the failure counters and any block for key. Call this after a
// successful authentication so a legitimate user who fumbled their password is
// not penalized.
func (b *BruteForce) Reset(key string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.fast, key)
	delete(b.slow, key)
	delete(b.blocked, key)
}

// Block manually trips a block for key for the given duration (e.g. after the
// application's own suspicious-activity heuristic fires).
func (b *BruteForce) Block(key string, d time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.blocked[key] = time.Now().Add(d)
}

// StatusCode returns the resolved HTTP status used when a request is denied.
// Framework adapters use it to render the deny response.
func (b *BruteForce) StatusCode() int { return b.cfg.StatusCode }

// Message returns the resolved deny message. Framework adapters use it to
// render the deny response.
func (b *BruteForce) Message() string { return b.cfg.Message }

// IsBlocked reports whether key currently has an active block.
func (b *BruteForce) IsBlocked(key string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	until, ok := b.blocked[key]
	return ok && time.Now().Before(until)
}

// Handler wraps next with brute-force protection: a denied request gets the
// configured status + Retry-After and a JSON body; an allowed request proceeds.
func (b *BruteForce) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res := b.Check(r)
		if !res.Allowed {
			retryAfter := int(res.RetryAfter.Seconds())
			if retryAfter < 1 {
				retryAfter = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(b.cfg.StatusCode)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error":      b.cfg.Message,
				"retryAfter": retryAfter,
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Close stops the background cleanup goroutine.
func (b *BruteForce) Close() {
	b.cancel()
}

func (b *BruteForce) cleanup() {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	for k, e := range b.fast {
		if e.resetTime.Before(now) {
			delete(b.fast, k)
		}
	}
	for k, e := range b.slow {
		if e.resetTime.Before(now) {
			delete(b.slow, k)
		}
	}
	for k, until := range b.blocked {
		if now.After(until) {
			delete(b.blocked, k)
		}
	}
}

// bump increments a windowed counter, resetting it if the window has elapsed.
func bump(m map[string]*bfEntry, key string, dur time.Duration, now time.Time) int {
	e, ok := m[key]
	if !ok || e.resetTime.Before(now) {
		m[key] = &bfEntry{count: 1, resetTime: now.Add(dur)}
		return 1
	}
	e.count++
	return e.count
}
