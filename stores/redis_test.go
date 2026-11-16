package stores

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getarcis/arcis-go/core"
)

// fakeRedis emulates the store's Lua scripts in memory so the store logic can
// be unit tested without a server. redis_integration_test.go runs the real
// scripts against Redis.
type fakeRedis struct {
	mu      sync.Mutex
	values  map[string]int64
	expires map[string]time.Time
	err     error
	keys    []string
}

func newFakeRedis() *fakeRedis {
	return &fakeRedis{values: map[string]int64{}, expires: map[string]time.Time{}}
}

func (f *fakeRedis) Eval(_ context.Context, script string, keys []string, args ...interface{}) (interface{}, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	if script == "return 1" {
		return int64(1), nil
	}
	key := keys[0]
	f.keys = append(f.keys, key)
	if exp, ok := f.expires[key]; ok && !time.Now().Before(exp) {
		delete(f.values, key)
		delete(f.expires, key)
	}
	_, exists := f.values[key]
	pttl := func() int64 {
		if !exists {
			return -2
		}
		return time.Until(f.expires[key]).Milliseconds()
	}
	switch script {
	case incrementScript:
		f.values[key]++
		if !exists {
			f.expires[key] = time.Now().Add(time.Duration(args[0].(int64)) * time.Millisecond)
			exists = true
		}
		return []interface{}{f.values[key], pttl()}, nil
	case decrementScript:
		if f.values[key] > 0 {
			f.values[key]--
		}
		return f.values[key], nil
	case getScript:
		if !exists {
			return []interface{}{int64(0), int64(-2)}, nil
		}
		return []interface{}{f.values[key], pttl()}, nil
	case resetScript:
		delete(f.values, key)
		delete(f.expires, key)
		return int64(1), nil
	}
	return nil, errors.New("unknown script")
}

var _ core.RateLimitStore = (*RedisRateLimitStore)(nil)
var _ core.RateLimitStoreGetter = (*RedisRateLimitStore)(nil)

func TestRedisStore_DefaultAndCustomPrefix(t *testing.T) {
	ctx := context.Background()
	fake := newFakeRedis()
	NewRedisRateLimitStore(fake, nil).Increment(ctx, "k", time.Minute)
	NewRedisRateLimitStore(fake, &RedisStoreOptions{Prefix: "custom:"}).Increment(ctx, "k", time.Minute)
	if got := strings.Join(fake.keys, ","); got != "arcis:rl:k,custom:k" {
		t.Fatalf("keys %q", got)
	}
}

func TestRedisStore_IncrementReturnsHitsAndReset(t *testing.T) {
	s := NewRedisRateLimitStore(newFakeRedis(), nil)
	ctx := context.Background()
	for want := 1; want <= 3; want++ {
		e, err := s.Increment(ctx, "k", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if e.Count != want {
			t.Fatalf("count %d, want %d", e.Count, want)
		}
		if until := time.Until(e.ResetTime); until <= 0 || until > time.Minute {
			t.Fatalf("reset in %v, want within one minute", until)
		}
	}
}

func TestRedisStore_RejectsSubMillisecondWindow(t *testing.T) {
	s := NewRedisRateLimitStore(newFakeRedis(), nil)
	if _, err := s.Increment(context.Background(), "k", time.Microsecond); err == nil {
		t.Fatal("expected an error for a window under 1ms")
	}
}

func TestRedisStore_ErrorsAreReturnedNotSwallowed(t *testing.T) {
	fake := newFakeRedis()
	fake.err = errors.New("connection refused")
	s := NewRedisRateLimitStore(fake, nil)
	ctx := context.Background()

	if _, err := s.Increment(ctx, "k", time.Minute); err == nil || !errors.Is(err, fake.err) {
		t.Errorf("Increment error %v, want wrapped %v", err, fake.err)
	}
	if err := s.Decrement(ctx, "k"); err == nil {
		t.Error("Decrement swallowed the error")
	}
	if err := s.ResetKey(ctx, "k"); err == nil {
		t.Error("ResetKey swallowed the error")
	}
	if _, _, err := s.Get(ctx, "k"); err == nil {
		t.Error("Get swallowed the error")
	}
	if err := s.Ping(); err == nil {
		t.Error("Ping swallowed the error")
	}
}

func TestRedisStore_UnexpectedReplyIsAnError(t *testing.T) {
	s := NewRedisRateLimitStore(replyClient{reply: "OK"}, nil)
	if _, err := s.Increment(context.Background(), "k", time.Minute); err == nil {
		t.Fatal("expected an error for a malformed reply")
	}
}

type replyClient struct{ reply interface{} }

func (c replyClient) Eval(context.Context, string, []string, ...interface{}) (interface{}, error) {
	return c.reply, nil
}

func TestRedisStore_AcceptsStringAndByteIntegers(t *testing.T) {
	s := NewRedisRateLimitStore(replyClient{reply: []interface{}{"4", []byte("1500")}}, nil)
	e, err := s.Increment(context.Background(), "k", time.Minute)
	if err != nil || e.Count != 4 {
		t.Fatalf("got %+v, %v", e, err)
	}
}

func TestRedisStore_DecrementGetReset(t *testing.T) {
	s := NewRedisRateLimitStore(newFakeRedis(), nil)
	ctx := context.Background()
	s.Increment(ctx, "k", time.Minute)
	s.Increment(ctx, "k", time.Minute)
	if err := s.Decrement(ctx, "k"); err != nil {
		t.Fatal(err)
	}
	e, ok, err := s.Get(ctx, "k")
	if err != nil || !ok || e.Count != 1 {
		t.Fatalf("Get = %+v, %v, %v; want count 1", e, ok, err)
	}
	if err := s.ResetKey(ctx, "k"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Get(ctx, "k"); ok {
		t.Fatal("key present after ResetKey")
	}
}

func TestRedisStore_PingAndClose(t *testing.T) {
	s := NewRedisRateLimitStore(newFakeRedis(), nil)
	if err := s.Ping(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}
