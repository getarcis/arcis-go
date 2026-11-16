package lru

import (
	"testing"
	"time"
	"unsafe"
)

type item struct{ expires time.Time }

func newTestMap(max int) *Map[*item] {
	return New(max, func(v *item, now time.Time) bool { return !now.Before(v.expires) })
}

func TestMap_EvictsExpiredBeforeLeastRecentlyUsed(t *testing.T) {
	now := time.Now()
	m := newTestMap(3)
	m.Put("old-live", &item{expires: now.Add(time.Hour)}, now)
	m.Put("expired", &item{expires: now.Add(-time.Second)}, now)
	m.Put("new-live", &item{expires: now.Add(time.Hour)}, now)

	m.Put("incoming", &item{expires: now.Add(time.Hour)}, now)

	if _, ok := m.Peek("expired"); ok {
		t.Error("expired entry should be evicted first")
	}
	for _, k := range []string{"old-live", "new-live", "incoming"} {
		if _, ok := m.Peek(k); !ok {
			t.Errorf("live entry %q should be kept", k)
		}
	}
}

func TestMap_EvictsLeastRecentlyUsedWhenAllLive(t *testing.T) {
	now := time.Now()
	m := newTestMap(2)
	m.Put("a", &item{expires: now.Add(time.Hour)}, now)
	m.Put("b", &item{expires: now.Add(time.Hour)}, now)
	m.Get("a") // b is now the least recently used

	m.Put("c", &item{expires: now.Add(time.Hour)}, now)

	if _, ok := m.Peek("b"); ok {
		t.Error("least recently used entry should be evicted")
	}
	if _, ok := m.Peek("a"); !ok {
		t.Error("recently used entry should be kept")
	}
	if _, ok := m.Peek("c"); !ok {
		t.Error("new entry must always be stored")
	}
	if m.Len() != 2 {
		t.Errorf("len %d, want 2", m.Len())
	}
}

func TestMap_CopiesKeys(t *testing.T) {
	// fasthttp hands out strings that alias reusable buffers like this one.
	buf := []byte("key-1")
	m := newTestMap(4)
	m.Put(unsafe.String(&buf[0], len(buf)), &item{expires: time.Now().Add(time.Hour)}, time.Now())
	copy(buf, "XXXXX")
	if _, ok := m.Peek("key-1"); !ok {
		t.Error("stored key changed with the caller's buffer")
	}
}

func TestMap_RemoveExpiredDeleteAndClear(t *testing.T) {
	now := time.Now()
	m := newTestMap(10)
	m.Put("gone", &item{expires: now}, now)
	m.Put("kept", &item{expires: now.Add(time.Hour)}, now)
	m.RemoveExpired(now)
	if m.Len() != 1 {
		t.Fatalf("len %d after RemoveExpired, want 1", m.Len())
	}
	m.Delete("kept")
	if m.Len() != 0 {
		t.Fatalf("len %d after Delete, want 0", m.Len())
	}
	m.Put("x", &item{expires: now.Add(time.Hour)}, now)
	m.Clear()
	if m.Len() != 0 {
		t.Fatalf("len %d after Clear, want 0", m.Len())
	}
}
