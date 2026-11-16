package stores

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/getarcis/arcis-go/core"
)

// RedisClient is the single Redis operation RedisRateLimitStore needs:
// running a Lua script. Integer replies may be returned as int64, int, string
// or []byte, and array replies as []interface{}. Most clients need a one-line
// adapter; for go-redis v9:
//
//	type goRedisClient struct{ c *redis.Client }
//
//	func (g goRedisClient) Eval(ctx context.Context, script string, keys []string, args ...interface{}) (interface{}, error) {
//		return g.c.Eval(ctx, script, keys, args...).Result()
//	}
type RedisClient interface {
	Eval(ctx context.Context, script string, keys []string, args ...interface{}) (interface{}, error)
}

// RedisStoreOptions configures the Redis rate limit store.
type RedisStoreOptions struct {
	Prefix string // Key prefix (default: "arcis:rl:")
}

// RedisRateLimitStore implements core.RateLimitStore on Redis so several
// application instances share one counter per key. Every operation is one Lua
// script, so each counted request is a single atomic round trip. Errors are
// returned, never swallowed: the limiter fails open and reports them.
type RedisRateLimitStore struct {
	client RedisClient
	prefix string
}

// incrementScript creates the counter and its expiry together: INCR, then
// PEXPIRE when the key has no expiry (its first hit), then PTTL.
const incrementScript = `local hits = redis.call('INCR', KEYS[1])
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
  ttl = tonumber(ARGV[1])
end
return {hits, ttl}`

// decrementScript lowers a live counter by one, never below zero.
const decrementScript = `local hits = tonumber(redis.call('GET', KEYS[1]) or '0')
if hits and hits > 0 then
  return redis.call('DECR', KEYS[1])
end
return 0`

// getScript reads a counter and its remaining TTL without changing them.
const getScript = `local hits = redis.call('GET', KEYS[1])
if not hits then
  return {0, -2}
end
return {tonumber(hits) or 0, redis.call('PTTL', KEYS[1])}`

const resetScript = `return redis.call('DEL', KEYS[1])`

// NewRedisRateLimitStore creates a Redis-backed rate limit store.
func NewRedisRateLimitStore(client RedisClient, opts *RedisStoreOptions) *RedisRateLimitStore {
	prefix := "arcis:rl:"
	if opts != nil && opts.Prefix != "" {
		prefix = opts.Prefix
	}
	return &RedisRateLimitStore{client: client, prefix: prefix}
}

// Increment records one hit for key and returns the window's total hits and
// reset time, in one atomic script.
func (s *RedisRateLimitStore) Increment(ctx context.Context, key string, window time.Duration) (core.RateLimitEntry, error) {
	windowMs := window.Milliseconds()
	if windowMs < 1 {
		return core.RateLimitEntry{}, errors.New("arcis: redis store: window must be at least 1ms")
	}
	reply, err := s.client.Eval(ctx, incrementScript, []string{s.prefix + key}, windowMs)
	if err != nil {
		return core.RateLimitEntry{}, fmt.Errorf("arcis: redis store increment: %w", err)
	}
	hits, ttlMs, err := intPair(reply)
	if err != nil {
		return core.RateLimitEntry{}, fmt.Errorf("arcis: redis store increment: %w", err)
	}
	return core.RateLimitEntry{
		Count:     int(hits),
		ResetTime: time.Now().Add(time.Duration(ttlMs) * time.Millisecond),
	}, nil
}

// Decrement removes one hit from key, never going below zero.
func (s *RedisRateLimitStore) Decrement(ctx context.Context, key string) error {
	if _, err := s.client.Eval(ctx, decrementScript, []string{s.prefix + key}); err != nil {
		return fmt.Errorf("arcis: redis store decrement: %w", err)
	}
	return nil
}

// ResetKey deletes key's counter.
func (s *RedisRateLimitStore) ResetKey(ctx context.Context, key string) error {
	if _, err := s.client.Eval(ctx, resetScript, []string{s.prefix + key}); err != nil {
		return fmt.Errorf("arcis: redis store reset: %w", err)
	}
	return nil
}

// Get returns key's live counter without changing it.
func (s *RedisRateLimitStore) Get(ctx context.Context, key string) (core.RateLimitEntry, bool, error) {
	reply, err := s.client.Eval(ctx, getScript, []string{s.prefix + key})
	if err != nil {
		return core.RateLimitEntry{}, false, fmt.Errorf("arcis: redis store get: %w", err)
	}
	hits, ttlMs, err := intPair(reply)
	if err != nil {
		return core.RateLimitEntry{}, false, fmt.Errorf("arcis: redis store get: %w", err)
	}
	if ttlMs <= 0 {
		return core.RateLimitEntry{}, false, nil
	}
	return core.RateLimitEntry{
		Count:     int(hits),
		ResetTime: time.Now().Add(time.Duration(ttlMs) * time.Millisecond),
	}, true, nil
}

// Close is a no-op; the caller manages the Redis client lifecycle.
func (s *RedisRateLimitStore) Close() error {
	return nil
}

// Ping checks that Redis is reachable and can run scripts.
func (s *RedisRateLimitStore) Ping() error {
	if _, err := s.client.Eval(context.Background(), "return 1", nil); err != nil {
		return fmt.Errorf("redis ping failed: %w", err)
	}
	return nil
}

func intPair(reply interface{}) (int64, int64, error) {
	values, ok := reply.([]interface{})
	if !ok || len(values) != 2 {
		return 0, 0, fmt.Errorf("unexpected script reply %T", reply)
	}
	first, err := toInt64(values[0])
	if err != nil {
		return 0, 0, err
	}
	second, err := toInt64(values[1])
	if err != nil {
		return 0, 0, err
	}
	return first, second, nil
}

func toInt64(v interface{}) (int64, error) {
	switch n := v.(type) {
	case int64:
		return n, nil
	case int:
		return int64(n), nil
	case string:
		return strconv.ParseInt(n, 10, 64)
	case []byte:
		return strconv.ParseInt(string(n), 10, 64)
	default:
		return 0, fmt.Errorf("unexpected integer reply %T", v)
	}
}
