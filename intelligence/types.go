// Package intelligence provides an optional cloud IP-reputation client with a
// local LRU+TTL cache. Go counterpart of:
//   - packages/arcis-node/src/intelligence/ (TypeScript)
//   - packages/arcis-python/arcis/intelligence/ (Python)
//
// Opt-in: when unconfigured, the SDK does zero network work and stays fully
// local. The data is served by an Arcis intelligence endpoint (the dashboard's
// /v1/intel/* routes). Reputation is one signal in a multi-signal decision,
// never a standalone verdict.
package intelligence

import "time"

// Reputation is the result of an IP reputation lookup. Found is false for
// unknown / clean IPs. The json tags match the dashboard wire shape so a
// response decodes straight into this struct.
type Reputation struct {
	IP         string   `json:"ip"`
	Found      bool     `json:"found"`
	Severity   int      `json:"severity,omitempty"`
	Categories []string `json:"categories,omitempty"`
	Sources    []string `json:"sources,omitempty"`
	FirstSeen  string   `json:"first_seen,omitempty"`
	LastSeen   string   `json:"last_seen,omitempty"`
	Matched    string   `json:"matched,omitempty"`
}

// Options configures the intelligence client.
type Options struct {
	// Endpoint is the base URL of the Arcis intelligence service, e.g.
	// "https://arcis.mycorp.com". The client appends
	// "/v1/intel/ip-reputation/:ip". Required.
	Endpoint string
	// APIKey is sent as "Authorization: Bearer <APIKey>".
	APIKey string
	// WorkspaceID is sent as "X-Workspace-Id".
	WorkspaceID string
	// CloudDecisions lists the enabled cloud decisions. Include "ip-rep" to
	// turn on IP reputation lookups. Empty = inert (no network calls).
	CloudDecisions []string
	// BlockThreshold: block when severity >= this (1-10). <= 0 means
	// observe-only (never block on reputation alone).
	BlockThreshold int
	// CacheMax is the LRU capacity in entries. Default 1000.
	CacheMax int
	// CacheTTL is the per-entry cache lifetime. Default 1 hour.
	CacheTTL time.Duration
	// Timeout is the per-lookup network timeout. Default 2 seconds.
	Timeout time.Duration
	// OnError is invoked on network/HTTP failures. Nil = swallowed silently
	// (fail-open: an unreachable service never affects requests).
	OnError func(error)
}

// BotCorpusEntry is one cloud-served bot-corpus entry, as returned by
// Client.FetchBotCorpus. Field shape matches the dashboard wire format and the
// SDK's bundled corpus, so an entry merges with no transformation.
type BotCorpusEntry struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Category  string   `json:"category"`
	Patterns  []string `json:"patterns"`
	Forbidden []string `json:"forbidden"`
}

// ReputationSeverityTier maps a numeric reputation severity (1-10) to a coarse
// tier string ("critical" | "high" | "medium" | "low").
func ReputationSeverityTier(severity int) string {
	switch {
	case severity >= 9:
		return "critical"
	case severity >= 7:
		return "high"
	case severity >= 4:
		return "medium"
	default:
		return "low"
	}
}
