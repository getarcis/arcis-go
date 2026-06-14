package stores

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/getarcis/arcis-go/core"
)

// memoryFallbackStore is a minimal thread-safe in-memory rate-limit store used
// by RedisRateLimitStore when Redis is unreachable. It is NOT the general
// in-memory limiter (that lives in the middleware package and can't be imported
// here without a cycle); it is a small shadow store that keeps rate limiting
// working during a Redis outage instead of pure-bypassing.
//
// Pattern 4 (fail-open) means a Redis outage must not crash the request, but
// "fail-open" must not mean "no protection." Node and Python both fall back to
// an in-memory store on a store error; Go previously returned a count of 1 on
// every failed Increment, which made every request look like the first and
// disabled the limit entirely during an outage. This restores cross-SDK parity.
type memoryFallbackStore struct {
	mu     sync.Mutex
	items  map[string]*core.RateLimitEntry
	window time.Duration
}

func newMemoryFallbackStore(window time.Duration) *memoryFallbackStore {
	return &memoryFallbackStore{
		items:  make(map[string]*core.RateLimitEntry),
		window: window,
	}
}

func (m *memoryFallbackStore) Get(key string) *core.RateLimitEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.items[key]
	if !ok {
		return nil
	}
	if time.Now().After(e.ResetTime) {
		delete(m.items, key)
		return nil
	}
	cp := *e // copy so callers can't mutate the stored entry
	return &cp
}

func (m *memoryFallbackStore) Set(key string, entry *core.RateLimitEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *entry
	m.items[key] = &cp
}

func (m *memoryFallbackStore) Increment(key string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	e, ok := m.items[key]
	if !ok || now.After(e.ResetTime) {
		m.items[key] = &core.RateLimitEntry{Count: 1, ResetTime: now.Add(m.window)}
		return 1
	}
	e.Count++
	return e.Count
}

func (m *memoryFallbackStore) Cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for k, e := range m.items {
		if now.After(e.ResetTime) {
			delete(m.items, k)
		}
	}
}

// RedisClient is a minimal interface for Redis client libraries.
// Compatible with go-redis (v9+), redigo, and similar clients.
// Implementations should return errors for failed operations.
type RedisClient interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key string, value string, expiration time.Duration) error
	Incr(ctx context.Context, key string) (int64, error)
	Expire(ctx context.Context, key string, expiration time.Duration) error
	Del(ctx context.Context, key string) error
	TTL(ctx context.Context, key string) (time.Duration, error)
}

// RedisStoreOptions configures the Redis rate limit store.
type RedisStoreOptions struct {
	Prefix   string        // Key prefix (default: "arcis:rl:")
	WindowMs int           // Window size in milliseconds (default: 60000)
	Window   time.Duration // Window size as Duration (overrides WindowMs if set)
}

// RedisRateLimitStore implements core.RateLimitStore using Redis.
// It is safe for use across multiple application instances.
type RedisRateLimitStore struct {
	client   RedisClient
	prefix   string
	window   time.Duration
	ctx      context.Context
	fallback *memoryFallbackStore
}

// NewRedisRateLimitStore creates a new Redis-backed rate limit store.
func NewRedisRateLimitStore(client RedisClient, opts *RedisStoreOptions) *RedisRateLimitStore {
	prefix := "arcis:rl:"
	window := 60 * time.Second

	if opts != nil {
		if opts.Prefix != "" {
			prefix = opts.Prefix
		}
		if opts.Window > 0 {
			window = opts.Window
		} else if opts.WindowMs > 0 {
			window = time.Duration(opts.WindowMs) * time.Millisecond
		}
	}

	return &RedisRateLimitStore{
		client:   client,
		prefix:   prefix,
		window:   window,
		ctx:      context.Background(),
		fallback: newMemoryFallbackStore(window),
	}
}

// Get retrieves a rate limit entry from Redis.
// On a Redis error it consults the in-memory fallback so the
// Get->Increment flow keeps applying the limit during an outage. During
// normal operation the fallback is empty, so a missing key still returns
// nil (fail-open on missing key is correct; fail-open into a no-op limiter
// during an outage is not — that was the prior bug).
func (s *RedisRateLimitStore) Get(key string) *core.RateLimitEntry {
	fullKey := s.prefix + key

	val, err := s.client.Get(s.ctx, fullKey)
	if err != nil {
		return s.fallback.Get(key)
	}

	count, err := strconv.Atoi(val)
	if err != nil {
		return nil
	}

	ttl, err := s.client.TTL(s.ctx, fullKey)
	if err != nil || ttl <= 0 {
		return nil
	}

	return &core.RateLimitEntry{
		Count:     count,
		ResetTime: time.Now().Add(ttl),
	}
}

// Set stores a rate limit entry in Redis with appropriate TTL.
func (s *RedisRateLimitStore) Set(key string, entry *core.RateLimitEntry) {
	fullKey := s.prefix + key

	ttl := time.Until(entry.ResetTime)
	if ttl <= 0 {
		ttl = s.window
	}

	val := strconv.Itoa(entry.Count)
	if err := s.client.Set(s.ctx, fullKey, val, ttl); err != nil {
		// Redis down: keep the entry in the fallback so a subsequent Get
		// (also failing over to the fallback) sees it and the limit persists.
		s.fallback.Set(key, entry)
	}
}

// Increment atomically increments the counter for a key.
// On first increment, sets TTL to the window duration.
// On a Redis error it increments the in-memory fallback so the counter still
// climbs and the limit trips. Returning 1 here (the prior behavior) made every
// request during a Redis outage look like the first and disabled the limit
// entirely — a pure bypass. Matches Node/Python fail-open-to-memory.
func (s *RedisRateLimitStore) Increment(key string) int {
	fullKey := s.prefix + key

	count, err := s.client.Incr(s.ctx, fullKey)
	if err != nil {
		return s.fallback.Increment(key)
	}

	// Set expiry on first increment
	if count == 1 {
		_ = s.client.Expire(s.ctx, fullKey, s.window)
	}

	return int(count)
}

// Cleanup prunes expired entries from the in-memory fallback. Redis TTL handles
// the Redis side automatically, so this only matters after an outage when the
// fallback may hold stale entries.
func (s *RedisRateLimitStore) Cleanup() {
	s.fallback.Cleanup()
}

// Reset deletes a rate limit entry from Redis.
func (s *RedisRateLimitStore) Reset(key string) error {
	return s.client.Del(s.ctx, s.prefix+key)
}

// Close is a no-op — the caller manages the Redis client lifecycle.
func (s *RedisRateLimitStore) Close() error {
	return nil
}

// Ping tests the Redis connection by performing a SET/GET round-trip.
func (s *RedisRateLimitStore) Ping() error {
	testKey := s.prefix + "__ping__"
	err := s.client.Set(s.ctx, testKey, "1", time.Second)
	if err != nil {
		return fmt.Errorf("redis ping failed: %w", err)
	}
	_ = s.client.Del(s.ctx, testKey)
	return nil
}
