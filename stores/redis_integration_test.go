package stores_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/getarcis/arcis-go/middleware"
	"github.com/getarcis/arcis-go/stores"
)

// These tests run the store's Lua scripts against a real Redis named by
// REDIS_URL (for example redis://localhost:6379/0). Every key uses the
// "arcis-go-test:" prefix plus a per-run id and is deleted afterwards; the
// database is never flushed because it may be shared.

const testKeyPrefix = "arcis-go-test:"

// respClient is a minimal RESP2 client implementing stores.RedisClient with a
// small connection pool, so concurrent requests really run in parallel.
type respClient struct {
	addr string
	db   int
	pool chan *respConn
}

type respConn struct {
	net.Conn
	r *bufio.Reader
}

type redisError string

func (e redisError) Error() string { return string(e) }

func newRESPClient(t *testing.T, size int) *respClient {
	t.Helper()
	raw := os.Getenv("REDIS_URL")
	if raw == "" {
		t.Skip("REDIS_URL is not set; skipping real Redis tests (example: REDIS_URL=redis://localhost:6379/0)")
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse REDIS_URL: %v", err)
	}
	db := 0
	if path := strings.TrimPrefix(u.Path, "/"); path != "" {
		if db, err = strconv.Atoi(path); err != nil {
			t.Fatalf("REDIS_URL database: %v", err)
		}
	}
	c := &respClient{addr: u.Host, db: db, pool: make(chan *respConn, size)}
	t.Cleanup(func() {
		close(c.pool)
		for conn := range c.pool {
			conn.Close()
		}
	})
	return c
}

func (c *respClient) dial() (*respConn, error) {
	nc, err := net.DialTimeout("tcp", c.addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	conn := &respConn{Conn: nc, r: bufio.NewReader(nc)}
	if c.db != 0 {
		if _, err := conn.do("SELECT", strconv.Itoa(c.db)); err != nil {
			nc.Close()
			return nil, err
		}
	}
	return conn, nil
}

func (c *respClient) Eval(_ context.Context, script string, keys []string, args ...interface{}) (interface{}, error) {
	var conn *respConn
	select {
	case conn = <-c.pool:
	default:
		var err error
		if conn, err = c.dial(); err != nil {
			return nil, err
		}
	}
	cmd := append([]string{"EVAL", script, strconv.Itoa(len(keys))}, keys...)
	for _, a := range args {
		cmd = append(cmd, fmt.Sprint(a))
	}
	reply, err := conn.do(cmd...)
	var redisErr redisError
	if err != nil && !errors.As(err, &redisErr) {
		conn.Close()
		return nil, err
	}
	select {
	case c.pool <- conn:
	default:
		conn.Close()
	}
	return reply, err
}

func (c *respConn) do(args ...string) (interface{}, error) {
	c.SetDeadline(time.Now().Add(5 * time.Second))
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	if _, err := io.WriteString(c.Conn, b.String()); err != nil {
		return nil, err
	}
	return c.read()
}

func (c *respConn) read() (interface{}, error) {
	line, err := c.r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimSuffix(line, "\r\n")
	if line == "" {
		return nil, errors.New("empty RESP line")
	}
	switch line[0] {
	case '+':
		return line[1:], nil
	case '-':
		return nil, redisError(line[1:])
	case ':':
		return strconv.ParseInt(line[1:], 10, 64)
	case '$':
		n, err := strconv.Atoi(line[1:])
		if err != nil || n < 0 {
			return nil, err
		}
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(c.r, buf); err != nil {
			return nil, err
		}
		return string(buf[:n]), nil
	case '*':
		n, err := strconv.Atoi(line[1:])
		if err != nil || n < 0 {
			return nil, err
		}
		items := make([]interface{}, n)
		for i := range items {
			if items[i], err = c.read(); err != nil {
				return nil, err
			}
		}
		return items, nil
	}
	return nil, fmt.Errorf("unexpected RESP line %q", line)
}

// runPrefix isolates one test run's keys from other runs and agents.
func runPrefix(t *testing.T) string {
	return fmt.Sprintf("%s%s:%d:", testKeyPrefix, t.Name(), time.Now().UnixNano())
}

func TestRealRedis_ConcurrentInstancesAdmitExactlyMax(t *testing.T) {
	const instances, requests, max = 5, 50, 5
	prefix := runPrefix(t)

	// Each instance has its own client, store and limiter, as separate
	// application processes sharing one Redis would.
	limiters := make([]*middleware.RateLimiter, instances)
	var firstStore *stores.RedisRateLimitStore
	for i := range limiters {
		store := stores.NewRedisRateLimitStore(newRESPClient(t, requests), &stores.RedisStoreOptions{Prefix: prefix})
		if err := store.Ping(); err != nil {
			t.Fatalf("redis unreachable: %v", err)
		}
		if firstStore == nil {
			firstStore = store
		}
		rl, err := middleware.NewRateLimiterWithOptions(middleware.RateLimiterOptions{
			Max: max, Window: time.Minute, Store: store,
			OnStoreError: func(err error) { t.Errorf("store error: %v", err) },
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(rl.Close)
		limiters[i] = rl
	}
	t.Cleanup(func() { firstStore.ResetKey(context.Background(), "203.0.113.50") })

	var allowed atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = "203.0.113.50:4000"
			// A spoofed header from a public peer must not change the key.
			req.Header.Set("X-Forwarded-For", fmt.Sprintf("198.51.100.%d", i))
			<-start
			if limiters[i%instances].Check(req).Allowed {
				allowed.Add(1)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	if got := allowed.Load(); got != max {
		t.Fatalf("%d of %d concurrent requests allowed across %d instances, want exactly %d", got, requests, instances, max)
	}
	entry, ok, err := firstStore.Get(context.Background(), "203.0.113.50")
	if err != nil || !ok {
		t.Fatalf("Get: ok=%v err=%v", ok, err)
	}
	if entry.Count != requests {
		t.Fatalf("stored hits %d, want one increment per request (%d)", entry.Count, requests)
	}
	if until := time.Until(entry.ResetTime); until <= 0 || until > time.Minute {
		t.Fatalf("expiry %v, want set with the first hit and within the window", until)
	}
}

func TestRealRedis_SharedStoreAcrossLimiters(t *testing.T) {
	const requests, max = 30, 5
	prefix := runPrefix(t)
	store := stores.NewRedisRateLimitStore(newRESPClient(t, requests), &stores.RedisStoreOptions{Prefix: prefix})
	t.Cleanup(func() { store.ResetKey(context.Background(), "shared") })

	limiters := make([]*middleware.RateLimiter, 3)
	for i := range limiters {
		limiters[i] = middleware.NewRateLimiterWithStore(max, time.Minute, store)
		t.Cleanup(limiters[i].Close)
	}

	var allowed atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			if limiters[i%len(limiters)].CheckKey("shared").Allowed {
				allowed.Add(1)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if got := allowed.Load(); got != max {
		t.Fatalf("%d allowed, want exactly %d", got, max)
	}
}

func TestRealRedis_ScriptsExpireDecrementGetReset(t *testing.T) {
	prefix := runPrefix(t)
	store := stores.NewRedisRateLimitStore(newRESPClient(t, 2), &stores.RedisStoreOptions{Prefix: prefix})
	ctx := context.Background()
	t.Cleanup(func() { store.ResetKey(ctx, "k") })

	e, err := store.Increment(ctx, "k", 300*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if e.Count != 1 || time.Until(e.ResetTime) > 300*time.Millisecond {
		t.Fatalf("first hit %+v: want count 1 with the window's expiry", e)
	}
	if e, _ = store.Increment(ctx, "k", 300*time.Millisecond); e.Count != 2 {
		t.Fatalf("second hit count %d, want 2", e.Count)
	}

	store.Decrement(ctx, "k")
	store.Decrement(ctx, "k")
	store.Decrement(ctx, "k")
	got, ok, err := store.Get(ctx, "k")
	if err != nil || !ok || got.Count != 0 {
		t.Fatalf("after decrements Get = %+v ok=%v err=%v; want count 0", got, ok, err)
	}

	time.Sleep(400 * time.Millisecond)
	if _, ok, _ := store.Get(ctx, "k"); ok {
		t.Fatal("key still live after its window")
	}
	if e, _ = store.Increment(ctx, "k", time.Minute); e.Count != 1 {
		t.Fatalf("count %d in a new window, want 1", e.Count)
	}
	if err := store.ResetKey(ctx, "k"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := store.Get(ctx, "k"); ok {
		t.Fatal("key present after ResetKey")
	}
}
