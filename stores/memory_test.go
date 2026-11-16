package stores

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/getarcis/arcis-go/core"
)

var _ core.RateLimitStore = (*MemoryStore)(nil)
var _ core.RateLimitStoreGetter = (*MemoryStore)(nil)

func TestMemoryStore_IncrementCountsWithinWindow(t *testing.T) {
	s := NewMemoryStore(0)
	ctx := context.Background()
	start := time.Now()
	for want := 1; want <= 3; want++ {
		e, err := s.Increment(ctx, "k", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if e.Count != want {
			t.Fatalf("count %d, want %d", e.Count, want)
		}
		if e.ResetTime.Before(start.Add(time.Minute)) || e.ResetTime.After(time.Now().Add(time.Minute)) {
			t.Fatalf("reset time %v not one window after the first hit", e.ResetTime)
		}
	}
}

func TestMemoryStore_NewWindowAfterExpiry(t *testing.T) {
	s := NewMemoryStore(0)
	ctx := context.Background()
	s.Increment(ctx, "k", 20*time.Millisecond)
	s.Increment(ctx, "k", 20*time.Millisecond)
	time.Sleep(30 * time.Millisecond)
	e, _ := s.Increment(ctx, "k", 20*time.Millisecond)
	if e.Count != 1 {
		t.Fatalf("count %d after expiry, want 1", e.Count)
	}
}

func TestMemoryStore_DecrementFloorsAtZeroAndGetResetKey(t *testing.T) {
	s := NewMemoryStore(0)
	ctx := context.Background()
	s.Increment(ctx, "k", time.Minute)
	s.Decrement(ctx, "k")
	s.Decrement(ctx, "k")
	e, ok, err := s.Get(ctx, "k")
	if err != nil || !ok || e.Count != 0 {
		t.Fatalf("Get = %+v, %v, %v; want count 0", e, ok, err)
	}
	s.ResetKey(ctx, "k")
	if _, ok, _ := s.Get(ctx, "k"); ok {
		t.Fatal("key should be gone after ResetKey")
	}
	if _, ok, _ := s.Get(ctx, "missing"); ok {
		t.Fatal("missing key reported present")
	}
}

func TestMemoryStore_AtCapEvictsExpiredFirst(t *testing.T) {
	s := NewMemoryStore(3)
	ctx := context.Background()
	s.Increment(ctx, "live", time.Hour)
	s.Increment(ctx, "short-1", 10*time.Millisecond)
	s.Increment(ctx, "short-2", 10*time.Millisecond)
	time.Sleep(20 * time.Millisecond)

	s.Increment(ctx, "new", time.Hour)

	if _, ok, _ := s.Get(ctx, "live"); !ok {
		t.Fatal("live key evicted while expired keys were available")
	}
	if s.Len() > 3 {
		t.Fatalf("len %d exceeds cap", s.Len())
	}
}

func TestMemoryStore_AtCapNeverStopsLimitingNewKeys(t *testing.T) {
	s := NewMemoryStore(100)
	ctx := context.Background()
	for i := 0; i < 100; i++ {
		s.Increment(ctx, fmt.Sprintf("filler-%d", i), time.Hour)
	}
	// The store is full of live keys; a new key must still be counted.
	for want := 1; want <= 5; want++ {
		e, err := s.Increment(ctx, "attacker", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if e.Count != want {
			t.Fatalf("new key count %d, want %d (store stopped counting)", e.Count, want)
		}
	}
	if s.Len() != 100 {
		t.Fatalf("len %d, want the cap 100", s.Len())
	}
	if _, ok, _ := s.Get(ctx, "filler-0"); ok {
		t.Fatal("least recently used key should have been evicted")
	}
}

func TestMemoryStore_CleanupRemovesExpired(t *testing.T) {
	s := NewMemoryStore(0)
	ctx := context.Background()
	s.Increment(ctx, "a", 5*time.Millisecond)
	s.Increment(ctx, "b", time.Hour)
	time.Sleep(10 * time.Millisecond)
	s.Cleanup()
	if s.Len() != 1 {
		t.Fatalf("len %d after Cleanup, want 1", s.Len())
	}
}
