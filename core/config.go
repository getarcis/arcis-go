package core

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// Version is the current version of Arcis.
const Version = "1.2.0"

// MaxRecursionDepth is the maximum depth for recursive operations.
const MaxRecursionDepth = 10

// DefaultMaxInputSize is the default maximum input size in bytes (1MB).
const DefaultMaxInputSize = 1_000_000

// Config holds Arcis configuration options.
type Config struct {
	// Sanitizer options
	Sanitize      bool
	SanitizeXSS   bool
	SanitizeSQL   bool
	SanitizeNoSQL bool
	SanitizePath  bool
	SanitizeCmd   bool // Command injection protection
	SanitizeSSTI  bool // Server-Side Template Injection protection
	SanitizeXXE   bool // XML External Entity protection
	MaxInputSize  int  // Maximum input size in bytes (default: 1MB)

	// Rate limiter options
	RateLimit       bool
	RateLimitMax    int
	RateLimitWindow time.Duration
	RateLimitSkip   func(*http.Request) bool // Skip rate limiting for certain requests
	RateLimitStore  RateLimitStore           // Optional external store (e.g. Redis)
	// RateLimitOnStoreError receives store errors (the request is allowed),
	// at most once per window. Nil logs through the standard log package.
	RateLimitOnStoreError func(error)

	// TrustedProxies lists the proxy IPs and CIDR ranges whose
	// X-Forwarded-For entries are believed when resolving the client IP
	// (spec/API_SPEC.md "Client IP resolution"). Nil uses the default set
	// (loopback, link-local, private and unique-local ranges); an empty
	// non-nil slice trusts nothing, so the socket peer is always the client.
	TrustedProxies []string

	// Security headers options
	Headers           bool
	CSP               string
	FrameOptions      string // DENY, SAMEORIGIN, or empty to disable
	HSTSMaxAge        int    // Max age in seconds, 0 to disable
	HSTSSubdomains    bool
	ReferrerPolicy    string
	PermissionsPolicy string
	CacheControl      bool   // Enable cache-control headers (default: true)
	CacheControlValue string // Custom Cache-Control value. Empty = use secure default.

	// Cross-origin isolation headers
	CrossOriginOpenerPolicy   string // COOP value. Default: "same-origin". Empty to disable.
	CrossOriginResourcePolicy string // CORP value. Default: "same-origin". Empty to disable.
	CrossOriginEmbedderPolicy string // COEP value. Default: "require-corp". Empty to disable.
	OriginAgentCluster        bool   // Send Origin-Agent-Cluster: ?1 (default: true)
	DNSPrefetchControl        bool   // Send X-DNS-Prefetch-Control: off (default: true)

	// HeaderProfile selects the header defaults. Empty or
	// HeaderProfileLegacy uses the fields above; HeaderProfileBaseline
	// uses BaselineHeaders (Helmet 8 compatible) and ignores them.
	HeaderProfile HeaderProfile
	// BaselineHeaders configures the baseline profile.
	BaselineHeaders BaselineHeaderOptions

	// Error handler options
	IsDev bool // Show error details in development mode
}

// DefaultConfig returns the default Arcis configuration.
// All protections are enabled with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Sanitize:                  true,
		SanitizeXSS:               true,
		SanitizeSQL:               true,
		SanitizeNoSQL:             true,
		SanitizePath:              true,
		SanitizeCmd:               true,
		MaxInputSize:              DefaultMaxInputSize,
		RateLimit:                 true,
		RateLimitMax:              100,
		RateLimitWindow:           time.Minute,
		Headers:                   true,
		CSP:                       "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; object-src 'none'; frame-ancestors 'none';",
		FrameOptions:              "DENY",
		HSTSMaxAge:                31536000,
		HSTSSubdomains:            true,
		ReferrerPolicy:            "strict-origin-when-cross-origin",
		PermissionsPolicy:         "geolocation=(), microphone=(), camera=()",
		CacheControl:              true,
		CrossOriginOpenerPolicy:   "same-origin",
		CrossOriginResourcePolicy: "same-origin",
		CrossOriginEmbedderPolicy: "require-corp",
		OriginAgentCluster:        true,
		DNSPrefetchControl:        true,
		IsDev:                     false,
	}
}

// RateLimitResult holds the result of a rate limit check.
type RateLimitResult struct {
	Allowed   bool
	Limit     int
	Remaining int
	Reset     time.Duration
}

// RateLimitEntry is a key's counter state: the hits recorded in the current
// window and the time the window ends.
type RateLimitEntry struct {
	Count     int
	ResetTime time.Time
}

// RateLimitStore is the counter backend behind RateLimiter
// (spec/API_SPEC.md "Store contract and counting"). The default is the
// in-memory stores.MemoryStore; stores.RedisRateLimitStore shares counters
// across instances.
//
// Implementations must not swallow their own errors: the limiter fails open
// and reports them.
type RateLimitStore interface {
	// Increment records one hit for key in a single atomic operation and
	// returns the total hits in the current window and when it resets. The
	// first hit of a window creates the counter with its expiry set to
	// window from now; a counter whose window has ended starts again at 1.
	Increment(ctx context.Context, key string, window time.Duration) (RateLimitEntry, error)
	// Decrement removes one hit from key, never going below zero.
	Decrement(ctx context.Context, key string) error
	// ResetKey deletes key's counter.
	ResetKey(ctx context.Context, key string) error
}

// RateLimitStoreGetter is optionally implemented by stores that can read a
// counter without changing it. ok is false when key has no live window.
type RateLimitStoreGetter interface {
	Get(ctx context.Context, key string) (entry RateLimitEntry, ok bool, err error)
}

// InputTooLargeError is returned when input exceeds the maximum size.
type InputTooLargeError struct {
	Size    int
	MaxSize int
}

func (e *InputTooLargeError) Error() string {
	return fmt.Sprintf("input size %d exceeds maximum of %d bytes", e.Size, e.MaxSize)
}
