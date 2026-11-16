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

// TokenBucketLimiter implements a token bucket rate limiter.
// It allows bursts up to the bucket capacity, then refills tokens
// at a steady rate. Good for APIs that need to allow short bursts.
type TokenBucketLimiter struct {
	capacity   int
	refillRate float64 // tokens per second
	cost       int     // tokens consumed per request
	buckets    *lru.Map[*tokenBucket]
	mu         sync.Mutex
	keyFunc    func(*http.Request) string
	skipFunc   func(*http.Request) bool
	ctx        context.Context
	cancel     context.CancelFunc
}

type tokenBucket struct {
	tokens     float64
	lastRefill time.Time
}

// NewTokenBucketLimiter creates a new token bucket rate limiter.
// capacity is the max burst size, refillRate is tokens added per second.
func NewTokenBucketLimiter(capacity int, refillRate float64) *TokenBucketLimiter {
	return newTokenBucket(capacity, refillRate, 1)
}

// NewTokenBucketLimiterWithCost creates a token bucket limiter with a custom per-request cost.
func NewTokenBucketLimiterWithCost(capacity int, refillRate float64, cost int) *TokenBucketLimiter {
	if cost < 1 {
		cost = 1
	}
	if cost > capacity {
		cost = capacity
	}
	return newTokenBucket(capacity, refillRate, cost)
}

func newTokenBucket(capacity int, refillRate float64, cost int) *TokenBucketLimiter {
	if capacity < 1 {
		capacity = 1
	}
	if refillRate <= 0 {
		refillRate = 1
	}

	ctx, cancel := context.WithCancel(context.Background())
	staleThreshold := (float64(capacity) / refillRate) * 2
	tb := &TokenBucketLimiter{
		capacity:   capacity,
		refillRate: refillRate,
		cost:       cost,
		// A bucket idle past staleThreshold has refilled completely, so
		// dropping it loses nothing; at the cap the least recently used go.
		buckets: lru.New(defaultMaxKeys, func(b *tokenBucket, now time.Time) bool {
			return now.Sub(b.lastRefill).Seconds() > staleThreshold
		}),
		ctx:    ctx,
		cancel: cancel,
	}

	// Cleanup goroutine every 60 seconds
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				tb.cleanup()
			}
		}
	}()

	return tb
}

// SetKeyFunc sets a custom function to extract the rate limit key from requests.
func (tb *TokenBucketLimiter) SetKeyFunc(fn func(*http.Request) string) {
	tb.keyFunc = fn
}

// SetSkipFunc sets a function that determines whether to skip rate limiting.
func (tb *TokenBucketLimiter) SetSkipFunc(fn func(*http.Request) bool) {
	tb.skipFunc = fn
}

// Check checks if a request is within the rate limit. The default key is
// utils.RateLimitKey(utils.GetClientIP(r)); use SetKeyFunc with a
// utils.ClientIPResolver for proxies outside the default trust set.
func (tb *TokenBucketLimiter) Check(r *http.Request) core.RateLimitResult {
	if tb.skipFunc != nil && tb.skipFunc(r) {
		return core.RateLimitResult{
			Allowed:   true,
			Limit:     tb.capacity,
			Remaining: tb.capacity,
			Reset:     0,
		}
	}

	var key string
	if tb.keyFunc != nil {
		key = tb.keyFunc(r)
	} else {
		key = utils.RateLimitKey(utils.GetClientIP(r))
	}

	return tb.CheckKey(key)
}

// CheckKey checks rate limit for a specific key using the token bucket algorithm.
func (tb *TokenBucketLimiter) CheckKey(key string) core.RateLimitResult {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()

	bucket, exists := tb.buckets.Get(key)
	if !exists {
		bucket = &tokenBucket{
			tokens:     float64(tb.capacity),
			lastRefill: now,
		}
		tb.buckets.Put(key, bucket, now)
	}

	// Refill tokens based on elapsed time
	tb.refill(bucket, now)

	cost := float64(tb.cost)

	if bucket.tokens < cost {
		// Not enough tokens — calculate retry-after
		retryAfter := math.Ceil((cost - bucket.tokens) / tb.refillRate)
		return core.RateLimitResult{
			Allowed:   false,
			Limit:     tb.capacity,
			Remaining: 0,
			Reset:     time.Duration(retryAfter) * time.Second,
		}
	}

	// Consume tokens
	bucket.tokens -= cost
	remaining := int(math.Max(0, math.Floor(bucket.tokens)))

	return core.RateLimitResult{
		Allowed:   true,
		Limit:     tb.capacity,
		Remaining: remaining,
		Reset:     0,
	}
}

// Close stops the cleanup goroutine and releases resources.
func (tb *TokenBucketLimiter) Close() {
	tb.cancel()
}

func (tb *TokenBucketLimiter) refill(bucket *tokenBucket, now time.Time) {
	elapsed := now.Sub(bucket.lastRefill).Seconds()
	if elapsed <= 0 {
		return
	}
	bucket.tokens = math.Min(float64(tb.capacity), bucket.tokens+elapsed*tb.refillRate)
	bucket.lastRefill = now
}

func (tb *TokenBucketLimiter) cleanup() {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.buckets.RemoveExpired(time.Now())
}
