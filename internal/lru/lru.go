// Package lru provides the size-capped map used by Arcis's in-memory rate
// limiting state. At the cap it evicts expired entries first, then the least
// recently used ones, so a flood of new keys can never stop limiting.
package lru

import (
	"container/list"
	"strings"
	"time"
)

// sweepInterval bounds how often Put scans the whole map for expired entries
// when the map is full, so a sustained flood of new keys costs O(1) per
// insert instead of O(n).
const sweepInterval = time.Second

// Map is a string-keyed map with a size cap and least-recently-used eviction.
// It is not safe for concurrent use: callers hold their own lock.
type Map[V any] struct {
	max       int
	items     map[string]*list.Element
	order     *list.List // front = most recently used
	expired   func(V, time.Time) bool
	lastSweep time.Time
}

type entry[V any] struct {
	key   string
	value V
}

// New returns a Map holding at most max entries (minimum 1). expired reports
// whether an entry can be dropped at the given time; nil means entries never
// expire on their own.
func New[V any](max int, expired func(V, time.Time) bool) *Map[V] {
	if max < 1 {
		max = 1
	}
	if expired == nil {
		expired = func(V, time.Time) bool { return false }
	}
	return &Map[V]{
		max:     max,
		items:   make(map[string]*list.Element),
		order:   list.New(),
		expired: expired,
	}
}

// Get returns the value for key and marks it as recently used.
func (m *Map[V]) Get(key string) (V, bool) {
	el, ok := m.items[key]
	if !ok {
		var zero V
		return zero, false
	}
	m.order.MoveToFront(el)
	return el.Value.(*entry[V]).value, true
}

// Peek returns the value for key without changing its recency.
func (m *Map[V]) Peek(key string) (V, bool) {
	el, ok := m.items[key]
	if !ok {
		var zero V
		return zero, false
	}
	return el.Value.(*entry[V]).value, true
}

// Put stores value under key as the most recently used entry. When the map is
// full it first removes expired entries, then the least recently used ones.
// The key is copied, so callers may pass strings that alias reusable buffers.
func (m *Map[V]) Put(key string, value V, now time.Time) {
	if el, ok := m.items[key]; ok {
		el.Value.(*entry[V]).value = value
		m.order.MoveToFront(el)
		return
	}
	if len(m.items) >= m.max {
		if now.Sub(m.lastSweep) >= sweepInterval {
			m.lastSweep = now
			m.RemoveExpired(now)
		}
		for len(m.items) >= m.max {
			m.remove(m.order.Back())
		}
	}
	key = strings.Clone(key)
	m.items[key] = m.order.PushFront(&entry[V]{key: key, value: value})
}

// Delete removes key if present.
func (m *Map[V]) Delete(key string) {
	if el, ok := m.items[key]; ok {
		m.remove(el)
	}
}

// RemoveExpired drops every entry the expiry function reports as expired.
func (m *Map[V]) RemoveExpired(now time.Time) {
	for el := m.order.Back(); el != nil; {
		prev := el.Prev()
		if m.expired(el.Value.(*entry[V]).value, now) {
			m.remove(el)
		}
		el = prev
	}
}

// Clear removes every entry.
func (m *Map[V]) Clear() {
	m.items = make(map[string]*list.Element)
	m.order.Init()
}

// Len returns the number of entries.
func (m *Map[V]) Len() int {
	return len(m.items)
}

func (m *Map[V]) remove(el *list.Element) {
	m.order.Remove(el)
	delete(m.items, el.Value.(*entry[V]).key)
}
