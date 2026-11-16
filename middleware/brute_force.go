package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/getarcis/arcis-go/internal/lru"
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
	FastPoints    int                        // attempts allowed in the fast window (default 5)
	FastDuration  time.Duration              // fast window length (default 60s)
	SlowPoints    int                        // attempts allowed in the slow window (default 20)
	SlowDuration  time.Duration              // slow window length (default 15m)
	BlockDuration time.Duration              // block length after slow-window exhaustion (default 15m)
	StatusCode    int                        // HTTP status when denied (default 429)
	Message       string                     // response message when denied
	KeyFunc       func(*http.Request) string // key resolver (default: utils.RateLimitKey of the client IP)
	Skip          func(*http.Request) bool   // return true to bypass for this request

	// TrustedProxies configures client IP resolution for the default key;
	// see core.Config.TrustedProxies. Nil uses the default trust set. An
	// invalid entry makes NewBruteForce panic.
	TrustedProxies []string
}

// BruteForceResult is the outcome of a brute-force check.
type BruteForceResult struct {
	Allowed    bool
	RetryAfter time.Duration // when !Allowed, how long until the client may retry
	Remaining  int           // fast-window attempts remaining when Allowed
}

// bfState is one key's fast window, slow window and block.
type bfState struct {
	fastCount    int
	fastReset    time.Time
	slowCount    int
	slowReset    time.Time
	blockedUntil time.Time
}

// expired reports whether the state no longer affects any decision.
func (s *bfState) expired(now time.Time) bool {
	return s.fastReset.Before(now) && s.slowReset.Before(now) && !now.Before(s.blockedUntil)
}

// BruteForce is a two-tier (fast + slow + block) brute-force limiter. It is
// safe for concurrent use. It tracks at most 10,000 keys; at the cap it drops
// keys with no live window or block first, then the least recently used.
type BruteForce struct {
	cfg      BruteForceConfig
	resolver *utils.ClientIPResolver
	states   *lru.Map[*bfState]
	mu       sync.Mutex
	ctx      context.Context
	cancel   context.CancelFunc
}

// NewBruteForce builds a brute-force limiter, applying defaults for any zero
// config fields and starting a background cleanup goroutine (stopped via
// Close). Mirrors NewRateLimiter's lifecycle. It panics when
// cfg.TrustedProxies has an invalid entry.
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

	resolver := utils.MustClientIPResolver(cfg.TrustedProxies)

	ctx, cancel := context.WithCancel(context.Background())
	b := &BruteForce{
		cfg:      cfg,
		resolver: resolver,
		states:   lru.New(defaultMaxKeys, (*bfState).expired),
		ctx:      ctx,
		cancel:   cancel,
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

	st := b.state(key, now)

	// 1. Block state first — a tripped block denies everything until it expires.
	if now.Before(st.blockedUntil) {
		return BruteForceResult{Allowed: false, RetryAfter: st.blockedUntil.Sub(now)}
	}

	// 2. Slow window — exhausting it trips the semi-permanent block.
	if slowCount := bump(&st.slowCount, &st.slowReset, b.cfg.SlowDuration, now); slowCount > b.cfg.SlowPoints {
		st.blockedUntil = now.Add(b.cfg.BlockDuration)
		return BruteForceResult{Allowed: false, RetryAfter: b.cfg.BlockDuration}
	}

	// 3. Fast window — short-term 429, resets on its own, no block.
	fastCount := bump(&st.fastCount, &st.fastReset, b.cfg.FastDuration, now)
	if fastCount > b.cfg.FastPoints {
		return BruteForceResult{Allowed: false, RetryAfter: st.fastReset.Sub(now)}
	}

	remaining := b.cfg.FastPoints - fastCount
	if remaining < 0 {
		remaining = 0
	}
	return BruteForceResult{Allowed: true, Remaining: remaining}
}

// Check resolves the key from the request (see Key) and consumes one attempt.
// Honors Skip.
func (b *BruteForce) Check(r *http.Request) BruteForceResult {
	if b.cfg.Skip != nil && b.cfg.Skip(r) {
		return BruteForceResult{Allowed: true, Remaining: b.cfg.FastPoints}
	}
	return b.CheckKey(b.Key(r))
}

// CheckPeer consumes one attempt for the client resolved from a socket peer
// address and X-Forwarded-For values, for frameworks without an
// *http.Request (Fiber). KeyFunc and Skip are not consulted.
func (b *BruteForce) CheckPeer(peer string, xForwardedFor []string) BruteForceResult {
	return b.CheckKey(utils.RateLimitKey(b.resolver.Resolve(peer, xForwardedFor...)))
}

// Key returns the key Check uses for r: KeyFunc(r) when set, otherwise the
// client IP resolved with TrustedProxies and passed through
// utils.RateLimitKey. Pass it to Reset after a successful login.
func (b *BruteForce) Key(r *http.Request) string {
	if b.cfg.KeyFunc != nil {
		return b.cfg.KeyFunc(r)
	}
	return utils.RateLimitKey(b.resolver.ClientIP(r))
}

// Reset clears the failure counters and any block for key. Call this after a
// successful authentication so a legitimate user who fumbled their password is
// not penalized.
func (b *BruteForce) Reset(key string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.states.Delete(key)
}

// Block manually trips a block for key for the given duration (e.g. after the
// application's own suspicious-activity heuristic fires).
func (b *BruteForce) Block(key string, d time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	b.state(key, now).blockedUntil = now.Add(d)
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
	st, ok := b.states.Peek(key)
	return ok && time.Now().Before(st.blockedUntil)
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
	b.states.RemoveExpired(time.Now())
}

// state returns key's state, creating it if needed. Callers hold b.mu.
func (b *BruteForce) state(key string, now time.Time) *bfState {
	st, ok := b.states.Get(key)
	if !ok {
		st = &bfState{}
		b.states.Put(key, st, now)
	}
	return st
}

// bump increments a windowed counter, resetting it if the window has elapsed.
func bump(count *int, reset *time.Time, dur time.Duration, now time.Time) int {
	if reset.Before(now) {
		*count = 0
		*reset = now.Add(dur)
	}
	*count++
	return *count
}
