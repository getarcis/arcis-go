package middleware

import (
	"context"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/getarcis/arcis-go/core"
	"github.com/getarcis/arcis-go/internal/lru"
	"github.com/getarcis/arcis-go/utils"
)

// SlidingWindowLimiter implements a weighted sliding window rate limiter.
// It provides smoother rate limiting than fixed windows by weighting
// the previous window's count based on how far into the current window we are.
// Only the window immediately before the current one is weighted in, so a key
// idle for a whole window starts from zero. Windows are aligned to multiples
// of the window length at full clock precision.
type SlidingWindowLimiter struct {
	max      int
	window   time.Duration
	states   *lru.Map[*slidingState]
	mu       sync.Mutex
	keyFunc  func(*http.Request) string
	skipFunc func(*http.Request) bool
	ctx      context.Context
	cancel   context.CancelFunc
}

type slidingState struct {
	index     int64 // window number: Unix nanoseconds / window length
	count     int   // requests counted in window index
	prevCount int   // requests counted in window index-1
}

// NewSlidingWindowLimiter creates a new sliding window rate limiter. It keeps
// at most 10,000 keys, evicting idle ones first, then the least recently used.
// It panics when max is negative or window is not a whole number of
// milliseconds between 1ms and MaxRateLimitWindow.
func NewSlidingWindowLimiter(max int, window time.Duration) *SlidingWindowLimiter {
	if err := validateRateLimit(max, window); err != nil {
		panic(err.Error())
	}
	ctx, cancel := context.WithCancel(context.Background())
	windowNs := window.Nanoseconds()
	sw := &SlidingWindowLimiter{
		max:    max,
		window: window,
		states: lru.New(defaultMaxKeys, func(s *slidingState, now time.Time) bool {
			return now.UnixNano()/windowNs-s.index > 1
		}),
		ctx:    ctx,
		cancel: cancel,
	}

	// Cleanup goroutine
	cleanupInterval := window
	if cleanupInterval < 10*time.Second {
		cleanupInterval = 10 * time.Second
	}
	if cleanupInterval > 300*time.Second {
		cleanupInterval = 300 * time.Second
	}

	go func() {
		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sw.cleanup()
			}
		}
	}()

	return sw
}

// SetKeyFunc sets a custom function to extract the rate limit key from requests.
// Use it with a utils.ClientIPResolver when the app sits behind proxies
// outside the default trust set.
func (sw *SlidingWindowLimiter) SetKeyFunc(fn func(*http.Request) string) {
	sw.keyFunc = fn
}

// SetSkipFunc sets a function that determines whether to skip rate limiting.
func (sw *SlidingWindowLimiter) SetSkipFunc(fn func(*http.Request) bool) {
	sw.skipFunc = fn
}

// Check checks if a request is within the rate limit. The default key is
// utils.RateLimitKey(utils.GetClientIP(r)).
func (sw *SlidingWindowLimiter) Check(r *http.Request) core.RateLimitResult {
	if sw.skipFunc != nil && sw.skipFunc(r) {
		return core.RateLimitResult{
			Allowed:   true,
			Limit:     sw.max,
			Remaining: sw.max,
			Reset:     sw.window,
		}
	}

	var key string
	if sw.keyFunc != nil {
		key = sw.keyFunc(r)
	} else {
		key = utils.RateLimitKey(utils.GetClientIP(r))
	}

	return sw.CheckKey(key)
}

// CheckKey checks rate limit for a specific key using the sliding window algorithm.
func (sw *SlidingWindowLimiter) CheckKey(key string) core.RateLimitResult {
	return sw.checkAt(key, time.Now())
}

func (sw *SlidingWindowLimiter) checkAt(key string, now time.Time) core.RateLimitResult {
	nowNs := now.UnixNano()
	windowNs := sw.window.Nanoseconds()
	index := nowNs / windowNs
	windowEnd := (index + 1) * windowNs

	sw.mu.Lock()
	defer sw.mu.Unlock()

	state, ok := sw.states.Get(key)
	if !ok {
		state = &slidingState{index: index}
		sw.states.Put(key, state, now)
	} else if state.index != index {
		// The previous count carries over only from the immediately
		// preceding window.
		if state.index == index-1 {
			state.prevCount = state.count
		} else {
			state.prevCount = 0
		}
		state.index = index
		state.count = 0
	}

	// Weight the previous window by the share of it still inside the
	// sliding window.
	weight := float64(windowEnd-nowNs) / float64(windowNs)
	estimatedCount := float64(state.prevCount)*weight + float64(state.count) + 1
	resetDuration := time.Duration(windowEnd - nowNs)

	if estimatedCount > float64(sw.max) {
		return core.RateLimitResult{
			Allowed:   false,
			Limit:     sw.max,
			Remaining: 0,
			Reset:     resetDuration,
		}
	}

	// Only increment if allowed
	state.count++

	return core.RateLimitResult{
		Allowed:   true,
		Limit:     sw.max,
		Remaining: int(math.Max(0, math.Floor(float64(sw.max)-estimatedCount))),
		Reset:     resetDuration,
	}
}

// Close stops the cleanup goroutine and releases resources.
func (sw *SlidingWindowLimiter) Close() {
	sw.cancel()
}

func (sw *SlidingWindowLimiter) cleanup() {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	sw.states.RemoveExpired(time.Now())
}
