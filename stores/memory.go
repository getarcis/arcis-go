package stores

import (
	"context"
	"sync"
	"time"

	"github.com/getarcis/arcis-go/core"
	"github.com/getarcis/arcis-go/internal/lru"
)

// DefaultMemoryStoreMaxKeys is the key cap NewMemoryStore uses when given a
// non-positive value.
const DefaultMemoryStoreMaxKeys = 10000

// MemoryStore is the default in-process core.RateLimitStore: a fixed window
// per key that starts at the key's first hit. It holds at most a fixed number
// of keys; at the cap it evicts expired keys first, then the least recently
// used, so new keys are always counted. Safe for concurrent use.
type MemoryStore struct {
	mu    sync.Mutex
	items *lru.Map[*core.RateLimitEntry]
}

// NewMemoryStore returns a MemoryStore holding at most maxKeys keys
// (DefaultMemoryStoreMaxKeys when maxKeys <= 0).
func NewMemoryStore(maxKeys int) *MemoryStore {
	if maxKeys <= 0 {
		maxKeys = DefaultMemoryStoreMaxKeys
	}
	return &MemoryStore{items: lru.New(maxKeys, entryExpired)}
}

func entryExpired(e *core.RateLimitEntry, now time.Time) bool {
	return !now.Before(e.ResetTime)
}

// Increment records one hit for key and returns the window's total hits and
// reset time. It never returns an error.
func (s *MemoryStore) Increment(_ context.Context, key string, window time.Duration) (core.RateLimitEntry, error) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.items.Get(key)
	if !ok || entryExpired(e, now) {
		e = &core.RateLimitEntry{ResetTime: now.Add(window)}
		s.items.Put(key, e, now)
	}
	e.Count++
	return *e, nil
}

// Decrement removes one hit from key's live window, never going below zero.
func (s *MemoryStore) Decrement(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.items.Peek(key); ok && !entryExpired(e, time.Now()) && e.Count > 0 {
		e.Count--
	}
	return nil
}

// ResetKey deletes key's counter.
func (s *MemoryStore) ResetKey(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items.Delete(key)
	return nil
}

// Get returns key's live counter without changing it.
func (s *MemoryStore) Get(_ context.Context, key string) (core.RateLimitEntry, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.items.Peek(key)
	if !ok || entryExpired(e, time.Now()) {
		return core.RateLimitEntry{}, false, nil
	}
	return *e, true, nil
}

// Cleanup removes expired keys. RateLimiter calls it periodically.
func (s *MemoryStore) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items.RemoveExpired(time.Now())
}

// Len returns the number of keys held, including expired ones not yet removed.
func (s *MemoryStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.items.Len()
}
