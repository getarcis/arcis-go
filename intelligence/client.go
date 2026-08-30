package intelligence

import (
	"container/list"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/getarcis/arcis-go/utils"
)

const (
	defaultCacheMax = 1000
	defaultCacheTTL = time.Hour
	defaultTimeout  = 2 * time.Second
	minTimeout      = 100 * time.Millisecond
)

// Client is a cloud IP-reputation client with a local LRU+TTL cache.
//
// Design rules (parity with the Node/Python clients):
//  1. Check is synchronous and never blocks the request path. On a cache miss
//     it returns Found=false for THIS request and schedules a background
//     refresh (its own goroutine), so the hot path adds ~0ms. Later requests
//     from the same IP read the cached verdict.
//  2. Fail-open: a network error, timeout, or non-2xx resolves to Found=false
//     and never panics into the request path.
//  3. Private / loopback / unresolved IPs are never looked up.
//  4. A clean ("not found") result IS cached so clean IPs are not re-queried;
//     transport errors are NOT cached so they retry.
type Client struct {
	base             string
	apiKey           string
	workspaceID      string
	timeout          time.Duration
	ipRepEnabled     bool
	botCorpusEnabled bool
	onError          func(error)
	httpClient       *http.Client

	cache *lruCache

	inFlightMu sync.Mutex
	inFlight   map[string]struct{}

	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup
}

// NewClient validates Options, applies defaults, and returns a client.
// Returns an error if Endpoint is empty.
func NewClient(opts Options) (*Client, error) {
	if opts.Endpoint == "" {
		return nil, errors.New("intelligence: Endpoint is required")
	}
	cacheMax := opts.CacheMax
	if cacheMax <= 0 {
		cacheMax = defaultCacheMax
	}
	ttl := opts.CacheTTL
	if ttl <= 0 {
		ttl = defaultCacheTTL
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	if timeout < minTimeout {
		timeout = minTimeout
	}
	onError := opts.OnError
	if onError == nil {
		onError = func(error) {}
	}
	ipRep := false
	botCorpus := false
	for _, d := range opts.CloudDecisions {
		switch d {
		case "ip-rep":
			ipRep = true
		case "bot-corpus":
			botCorpus = true
		}
	}
	return &Client{
		base:             strings.TrimRight(opts.Endpoint, "/"),
		apiKey:           opts.APIKey,
		workspaceID:      opts.WorkspaceID,
		timeout:          timeout,
		ipRepEnabled:     ipRep,
		botCorpusEnabled: botCorpus,
		onError:          onError,
		httpClient:       &http.Client{Timeout: timeout},
		cache:            newLRUCache(cacheMax, ttl),
		inFlight:         make(map[string]struct{}),
	}, nil
}

// Check is a synchronous, cache-first read. It never blocks: a cache miss
// returns Found=false and schedules a background refresh.
func (c *Client) Check(ip string) Reputation {
	if !c.ipRepEnabled || c.isClosed() {
		return Reputation{IP: ip, Found: false}
	}
	if ip == "" || ip == "unknown" || utils.IsPrivateIP(ip) {
		return Reputation{IP: ip, Found: false}
	}
	if rep, ok := c.cache.get(ip); ok {
		return rep
	}
	c.scheduleRefresh(ip)
	return Reputation{IP: ip, Found: false}
}

// Lookup performs a blocking lookup. Fail-open: any transport error returns
// Found=false. Used by direct callers and tests; the request path uses Check.
func (c *Client) Lookup(ip string) Reputation {
	if ip == "" || ip == "unknown" || utils.IsPrivateIP(ip) {
		return Reputation{IP: ip, Found: false}
	}
	rep, err := c.fetch(ip)
	if err != nil {
		c.safeError(err)
		return Reputation{IP: ip, Found: false}
	}
	return rep
}

// CacheSize returns the number of cached entries. Useful for tests.
func (c *Client) CacheSize() int {
	return c.cache.size()
}

// BotCorpusEnabled reports whether "bot-corpus" was in CloudDecisions.
func (c *Client) BotCorpusEnabled() bool {
	return c.botCorpusEnabled
}

// FetchBotCorpus fetches the full bot corpus from the intelligence endpoint.
// Fail-open: any transport/parse error returns nil (the caller keeps the
// bundled corpus).
func (c *Client) FetchBotCorpus() []BotCorpusEntry {
	endpoint := c.base + "/v1/intel/bot-corpus/snapshot"
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		c.safeError(err)
		return nil
	}
	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	if c.workspaceID != "" {
		req.Header.Set("X-Workspace-Id", c.workspaceID)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.safeError(err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		c.safeError(fmt.Errorf("bot-corpus fetch returned HTTP %d", resp.StatusCode))
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		c.safeError(err)
		return nil
	}
	var parsed struct {
		Entries []BotCorpusEntry `json:"entries"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		c.safeError(err)
		return nil
	}
	return parsed.Entries
}

// Close stops scheduling refreshes, waits for in-flight refreshes to finish,
// and drops the cache. Idempotent.
func (c *Client) Close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.mu.Unlock()
	c.wg.Wait()
	c.cache.clear()
}

// ── internals ─────────────────────────────────────────────────────────────

func (c *Client) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *Client) scheduleRefresh(ip string) {
	c.inFlightMu.Lock()
	if _, busy := c.inFlight[ip]; busy {
		c.inFlightMu.Unlock()
		return
	}
	if c.isClosed() {
		c.inFlightMu.Unlock()
		return
	}
	c.inFlight[ip] = struct{}{}
	c.wg.Add(1)
	c.inFlightMu.Unlock()

	go func() {
		defer c.wg.Done()
		defer func() {
			c.inFlightMu.Lock()
			delete(c.inFlight, ip)
			c.inFlightMu.Unlock()
		}()
		rep, err := c.fetch(ip)
		if err != nil {
			c.safeError(err)
			return
		}
		// Cache real results (incl. a clean not-found). Errors return above
		// and are not cached, so they retry on the next request.
		if !c.isClosed() {
			c.cache.set(ip, rep)
		}
	}()
}

func (c *Client) fetch(ip string) (Reputation, error) {
	endpoint := fmt.Sprintf("%s/v1/intel/ip-reputation/%s", c.base, url.PathEscape(ip))
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return Reputation{}, err
	}
	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	if c.workspaceID != "" {
		req.Header.Set("X-Workspace-Id", c.workspaceID)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return Reputation{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return Reputation{}, fmt.Errorf("ip-reputation lookup returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Reputation{}, err
	}
	var rep Reputation
	if err := json.Unmarshal(body, &rep); err != nil {
		return Reputation{}, err
	}
	rep.IP = ip
	if !rep.Found {
		// Normalize a not-found into a clean zero-value verdict.
		return Reputation{IP: ip, Found: false}, nil
	}
	return rep, nil
}

func (c *Client) safeError(err error) {
	defer func() { _ = recover() }()
	c.onError(err)
}

// ShouldBlock runs a Check and reports whether the request should be denied:
// the IP was found, threshold is >= 1, and severity >= threshold. Adapters use
// this to keep their per-framework block code small.
func ShouldBlock(c *Client, threshold int, ip string) (Reputation, bool) {
	rep := c.Check(ip)
	block := rep.Found && threshold >= 1 && rep.Severity >= threshold
	return rep, block
}

// ── LRU + TTL cache ─────────────────────────────────────────────────────────

type cacheEntry struct {
	key     string
	value   Reputation
	expires time.Time
}

type lruCache struct {
	mu    sync.Mutex
	max   int
	ttl   time.Duration
	ll    *list.List
	items map[string]*list.Element
}

func newLRUCache(max int, ttl time.Duration) *lruCache {
	return &lruCache{
		max:   max,
		ttl:   ttl,
		ll:    list.New(),
		items: make(map[string]*list.Element),
	}
}

func (l *lruCache) get(key string) (Reputation, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	el, ok := l.items[key]
	if !ok {
		return Reputation{}, false
	}
	ent := el.Value.(*cacheEntry)
	if time.Now().After(ent.expires) {
		l.ll.Remove(el)
		delete(l.items, key)
		return Reputation{}, false
	}
	l.ll.MoveToFront(el)
	return ent.value, true
}

func (l *lruCache) set(key string, value Reputation) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if el, ok := l.items[key]; ok {
		ent := el.Value.(*cacheEntry)
		ent.value = value
		ent.expires = time.Now().Add(l.ttl)
		l.ll.MoveToFront(el)
		return
	}
	el := l.ll.PushFront(&cacheEntry{key: key, value: value, expires: time.Now().Add(l.ttl)})
	l.items[key] = el
	for l.ll.Len() > l.max {
		back := l.ll.Back()
		if back == nil {
			break
		}
		l.ll.Remove(back)
		delete(l.items, back.Value.(*cacheEntry).key)
	}
}

func (l *lruCache) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.ll.Len()
}

func (l *lruCache) clear() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ll.Init()
	l.items = make(map[string]*list.Element)
}
