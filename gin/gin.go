/*
Package gin provides Arcis middleware adapters for the Gin web framework.

Usage:

	import (
		"github.com/gin-gonic/gin"
		arcisgin "github.com/getarcis/arcis-go/gin"
	)

	func main() {
		r := gin.Default()

		// Full protection with defaults
		r.Use(arcisgin.Middleware())

		// Or with custom config
		r.Use(arcisgin.MiddlewareWithConfig(arcisgin.Config{
			RateLimitMax:    50,
			RateLimitWindow: time.Minute,
			CSP:             "default-src 'self'",
		}))

		// Granular middleware
		r.Use(arcisgin.Headers())
		r.Use(arcisgin.RateLimit(100, time.Minute))
		r.Use(arcisgin.Sanitizer())

		r.GET("/", handler)
		r.Run(":8080")
	}

# Resource Cleanup

Arcis's rate limiter runs a background goroutine for cleanup. Call Cleanup()
when your application shuts down to stop this goroutine and release resources:

	import (
		"context"
		"os/signal"
		"syscall"
		arcisgin "github.com/getarcis/arcis-go/gin"
	)

	func main() {
		r := gin.Default()
		r.Use(arcisgin.Middleware())

		// Graceful shutdown
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()

		go r.Run(":8080")

		<-ctx.Done()
		arcisgin.Cleanup() // Stop rate limiter background goroutines
	}

Alternatively, register cleanup with a defer or shutdown hook:

	func main() {
		defer arcisgin.Cleanup()
		// ... rest of setup
	}
*/
package gin

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	arcis "github.com/getarcis/arcis-go"
	"github.com/getarcis/arcis-go/intelligence"
	"github.com/getarcis/arcis-go/pipeline"
	"github.com/getarcis/arcis-go/telemetry"
	"github.com/getarcis/arcis-go/utils"
)

// Config holds Arcis middleware configuration for Gin.
type Config struct {
	// Sanitizer options
	Sanitize      bool
	SanitizeXSS   bool
	SanitizeSQL   bool
	SanitizeNoSQL bool
	SanitizePath  bool
	SanitizeCmd   bool
	MaxInputSize  int

	// Block: when true, scan request body / query / URL path for attack
	// patterns and abort with 403 instead of letting the request through
	// to the handler. Opt-in (default false).
	Block bool

	// DryRun: when true (and Block is also true), run the block-mode
	// detection pipeline but do NOT abort with 403. The threat is logged
	// + the OnSanitize callback fires + telemetry records the would-have-
	// blocked decision. Use for safe rollout: turn on Block=true +
	// DryRun=true, watch the telemetry stream for false positives, then
	// flip DryRun=false once confident.
	// Ignored when Block=false.
	DryRun bool

	// OnSanitize fires when a threat is detected in block mode (regardless
	// of DryRun). Receives a SanitizeEvent describing the vector + path.
	// Useful for log aggregation and alerting. Must not panic; the
	// middleware ignores panics from this callback via defer/recover.
	OnSanitize func(SanitizeEvent)

	// Rate limiter options
	RateLimit       bool
	RateLimitMax    int
	RateLimitWindow time.Duration
	RateLimitSkip   func(*gin.Context) bool
	RateLimitStore  arcis.RateLimitStore // Optional external store (e.g. Redis)

	// Bot UA classification (v1.7 W1 wire-up). When Bot is true (the
	// default), the middleware classifies the User-Agent against the
	// 695-entry corpus and denies categories in BotDeny with 403.
	// BotDeny defaults to {AUTOMATED, SCRAPER} to catch curl /
	// python-requests / sqlmap / nikto / nuclei out of the box.
	Bot     bool
	BotDeny []arcis.BotCategory

	// Scanner-path probe blocking (v1.7 W2 wire-up). When ScannerPaths
	// is true (the default), requests against well-known probe paths
	// (/.env, /.git, /wp-admin, /phpmyadmin, etc) are denied with 403.
	// Set to false on apps with legitimate overlapping routes.
	ScannerPaths bool

	// GraphQL inspection (v1.7 W3 wire-up). When GraphQL is true (the
	// default), JSON request bodies with a `query` field are inspected
	// for depth-bomb, alias-bomb, fragment cycle, and introspection
	// abuse. GraphQLOptions overrides the tightened wire-up defaults
	// (MaxAliases: 10). Set GraphQL=false to disable.
	GraphQL        bool
	GraphQLOptions arcis.GraphqlGuardOptions

	// MassAssign field detection (v1.7 W4 wire-up). When MassAssign is
	// true (the default), JSON bodies are scanned recursively for
	// privilege-escalation field names (isAdmin, role, permissions, ...)
	// and denied with 403 when one is present. Set MassAssign=false on
	// admin APIs that legitimately accept those fields.
	MassAssign bool

	// SSRF body-URL validation (v1.7 W5 wire-up). When SSRF is true (the
	// default), JSON bodies are walked for URL-shaped strings and each is
	// validated; private/loopback/metadata/file/gopher URLs are denied,
	// public URLs pass. Set SSRF=false to disable.
	SSRF bool

	// PromptInjection detection on body strings (v1.7 W6 wire-up). When
	// true (the default), JSON body string values are scanned for
	// prompt-injection / jailbreak / tool-call-forgery signatures and
	// denied at or above MinPromptSeverity (default "medium"). Set
	// PromptInjection=false to disable.
	PromptInjection   bool
	MinPromptSeverity string

	// ForwardedHeaders inspection (v1.7 W7). When true, a loopback address
	// in a forwarded/client-IP header is denied (spoofing). TrustedHosts,
	// if set, also rejects Host / X-Forwarded-Host not in the allowlist.
	ForwardedHeaders bool
	TrustedHosts     []string

	// Security headers options
	Headers           bool
	CSP               string
	FrameOptions      string
	HSTSMaxAge        int
	HSTSSubdomains    bool
	ReferrerPolicy    string
	PermissionsPolicy string
	CacheControl      bool
	CacheControlValue string // Custom Cache-Control value. Empty = use secure default.

	// Error handler options
	IsDev bool

	// Telemetry, if non-nil, receives one Event per request after the
	// middleware decision. Nil = zero overhead (no defer registered, no
	// allocations) per spec/API_SPEC.md §9 Guarantees.
	Telemetry *telemetry.Client

	// Intelligence, if non-nil, enables opt-in cloud IP reputation. On each
	// request the client IP is looked up (cache-first, non-blocking); when the
	// verdict severity is at or above IntelligenceBlockThreshold, the request
	// is denied with 403. Nil = no IP-reputation work. Reputation is a signal,
	// not a default gate: a threshold of 0 (or omitted) is observe-only.
	Intelligence               *intelligence.Client
	IntelligenceBlockThreshold int
}

// SanitizeEvent is the payload passed to Config.OnSanitize when a
// block-mode scan matches a threat. The DryRun field indicates whether
// the request was actually denied or only logged (mirrors the Python
// FastAPI ArcisMiddleware on_sanitize callback shape).
type SanitizeEvent struct {
	Vector  string
	Rule    string
	Matched string
	Path    string
	DryRun  bool
}

// DefaultConfig returns the default Arcis configuration for Gin.
func DefaultConfig() Config {
	return Config{
		Sanitize:          true,
		SanitizeXSS:       true,
		SanitizeSQL:       true,
		SanitizeNoSQL:     true,
		SanitizePath:      true,
		SanitizeCmd:       true,
		MaxInputSize:      1000000,
		RateLimit:         true,
		RateLimitMax:      100,
		RateLimitWindow:   time.Minute,
		Bot:               true,
		BotDeny:           []arcis.BotCategory{arcis.BotCategoryAutomated, arcis.BotCategorySecurityScanner},
		ScannerPaths:      true,
		GraphQL:           true,
		GraphQLOptions:    arcis.DefaultGraphqlWireupOptions(),
		MassAssign:        true,
		SSRF:              true,
		PromptInjection:   true,
		MinPromptSeverity: "medium",
		ForwardedHeaders:  true,
		Headers:           true,
		CSP:               "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; object-src 'none'; frame-ancestors 'none';",
		FrameOptions:      "DENY",
		HSTSMaxAge:        31536000,
		HSTSSubdomains:    true,
		ReferrerPolicy:    "strict-origin-when-cross-origin",
		PermissionsPolicy: "geolocation=(), microphone=(), camera=()",
		CacheControl:      true,
		IsDev:             false,
	}
}

// arcisInstance holds the Arcis components for cleanup.
type arcisInstance struct {
	rateLimiter *arcis.RateLimiter
}

// Close cleans up Arcis resources, stopping the rate limiter's
// background cleanup goroutine.
func (s *arcisInstance) Close() {
	if s.rateLimiter != nil {
		s.rateLimiter.Close()
	}
}

// activeInstances tracks Arcis instances for cleanup.
var (
	activeInstances   []*arcisInstance
	activeInstancesMu sync.Mutex
)

// Cleanup closes all active Arcis middleware instances and releases resources.
// This stops the background goroutines used by rate limiters for automatic
// cleanup of expired entries.
//
// Call Cleanup() when your application shuts down to prevent goroutine leaks.
// This is especially important in long-running applications or when using
// hot-reloading during development.
//
// Example:
//
//	func main() {
//		defer arcisgin.Cleanup()
//		r := gin.Default()
//		r.Use(arcisgin.Middleware())
//		r.Run(":8080")
//	}
//
// For graceful shutdown with signal handling:
//
//	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
//	defer stop()
//	go r.Run(":8080")
//	<-ctx.Done()
//	arcisgin.Cleanup()
func Cleanup() {
	activeInstancesMu.Lock()
	defer activeInstancesMu.Unlock()
	for _, instance := range activeInstances {
		instance.Close()
	}
	activeInstances = nil
}

// registerInstance safely adds an instance to the active instances list.
func registerInstance(instance *arcisInstance) {
	activeInstancesMu.Lock()
	defer activeInstancesMu.Unlock()
	activeInstances = append(activeInstances, instance)
}

// RateLimitOption configures a standalone rate-limit middleware
// (RateLimit, RateLimitWithStore, RateLimitWithSkip). Use WithTelemetry
// to attach a telemetry client.
type RateLimitOption func(*rateLimitOpts)

type rateLimitOpts struct {
	telemetry *telemetry.Client
}

// WithTelemetry returns a RateLimitOption that attaches a telemetry
// client to a standalone rate-limit middleware. On 429, one
// TelemetryEvent is emitted with vector="rate-limit",
// rule="rate-limit/exceeded", severity="medium" — matching the
// MiddlewareWithConfig wire format.
//
// Standalone helpers emit only on deny. Allow events come from
// MiddlewareWithConfig; emitting them here would duplicate when
// composing RateLimit + Sanitizer + Validate with telemetry on each.
func WithTelemetry(tc *telemetry.Client) RateLimitOption {
	return func(o *rateLimitOpts) { o.telemetry = tc }
}

// emitRateLimitDeny ships one TelemetryEvent for a 429 from a standalone
// rate-limit helper. Callers register a deferred call so the latency
// includes the JSON write, matching MiddlewareWithConfig's measurement.
func emitRateLimitDeny(tc *telemetry.Client, c *gin.Context, start time.Time) {
	if tc == nil {
		return
	}
	latency := float64(time.Since(start)) / float64(time.Millisecond)
	if latency < 0 {
		latency = 0
	}
	tc.Send(telemetry.Event{
		Ts:        time.Now().UTC().Format(time.RFC3339),
		IP:        c.ClientIP(),
		Method:    c.Request.Method,
		Path:      c.Request.URL.Path,
		Decision:  telemetry.DecisionDeny,
		Vector:    "rate-limit",
		Rule:      "rate-limit/exceeded",
		Severity:  telemetry.SeverityMedium,
		Reason:    "Rate limit exceeded",
		UserAgent: c.GetHeader("User-Agent"),
		Status:    http.StatusTooManyRequests,
		LatencyMs: latency,
	})
}

// Middleware returns a Gin middleware with default Arcis configuration.
func Middleware() gin.HandlerFunc {
	return MiddlewareWithConfig(DefaultConfig())
}

// MiddlewareWithConfig returns a Gin middleware with custom configuration.
func MiddlewareWithConfig(config Config) gin.HandlerFunc {
	// Convert to core Arcis config
	arcisConfig := arcis.Config{
		Sanitize:          config.Sanitize,
		SanitizeXSS:       config.SanitizeXSS,
		SanitizeSQL:       config.SanitizeSQL,
		SanitizeNoSQL:     config.SanitizeNoSQL,
		SanitizePath:      config.SanitizePath,
		SanitizeCmd:       config.SanitizeCmd,
		MaxInputSize:      config.MaxInputSize,
		RateLimit:         config.RateLimit,
		RateLimitMax:      config.RateLimitMax,
		RateLimitWindow:   config.RateLimitWindow,
		Headers:           config.Headers,
		CSP:               config.CSP,
		FrameOptions:      config.FrameOptions,
		HSTSMaxAge:        config.HSTSMaxAge,
		HSTSSubdomains:    config.HSTSSubdomains,
		ReferrerPolicy:    config.ReferrerPolicy,
		PermissionsPolicy: config.PermissionsPolicy,
		CacheControl:      config.CacheControl,
		CacheControlValue: config.CacheControlValue,
		IsDev:             config.IsDev,
	}

	sanitizer := arcis.NewSanitizer(arcisConfig)
	instance := &arcisInstance{}

	var rateLimiter *arcis.RateLimiter
	if config.RateLimit {
		if config.RateLimitStore != nil {
			rateLimiter = arcis.NewRateLimiterWithStore(config.RateLimitMax, config.RateLimitWindow, config.RateLimitStore)
		} else {
			rateLimiter = arcis.NewRateLimiter(config.RateLimitMax, config.RateLimitWindow)
		}
		instance.rateLimiter = rateLimiter
	}

	var securityHeaders *arcis.SecurityHeaders
	if config.Headers {
		securityHeaders = arcis.NewSecurityHeaders(arcisConfig)
	}

	registerInstance(instance)

	// Bot-corpus cloud refresh (Phase C). When the intelligence client has
	// "bot-corpus" enabled, fetch the corpus once on startup (background
	// goroutine) and merge it on top of the bundled corpus, so newly-curated
	// scanners / AI crawlers are classified without an SDK release. Fail-open:
	// FetchBotCorpus returns nil on error, leaving the bundled corpus intact.
	if config.Intelligence != nil && config.Intelligence.BotCorpusEnabled() {
		go func() {
			entries := config.Intelligence.FetchBotCorpus()
			if len(entries) == 0 {
				return
			}
			merged := make([]arcis.BotCorpusEntry, len(entries))
			for i, e := range entries {
				merged[i] = arcis.BotCorpusEntry{
					ID: e.ID, Name: e.Name, Category: e.Category,
					Patterns: e.Patterns, Forbidden: e.Forbidden,
				}
			}
			arcis.MergeBotPatterns(merged)
		}()
	}

	return func(c *gin.Context) {
		start := time.Now()
		// Per-request telemetry locals. Deny branches mutate these before
		// returning; the deferred emit (registered only when Telemetry is
		// configured) reads them on function exit.
		var (
			decision    = telemetry.DecisionAllow
			evtVector   string
			evtRule     string
			evtMatched  string
			evtReason   string
			evtSeverity telemetry.Severity
		)
		if config.Telemetry != nil {
			defer func() {
				status := c.Writer.Status()
				if status == 0 {
					status = http.StatusOK
				}
				latency := float64(time.Since(start)) / float64(time.Millisecond)
				if latency < 0 {
					latency = 0
				}
				config.Telemetry.Send(telemetry.Event{
					Ts:             time.Now().UTC().Format(time.RFC3339),
					IP:             c.ClientIP(),
					Method:         c.Request.Method,
					Path:           c.Request.URL.Path,
					Decision:       decision,
					Vector:         evtVector,
					Rule:           evtRule,
					MatchedPattern: evtMatched,
					Reason:         evtReason,
					Severity:       evtSeverity,
					UserAgent:      c.GetHeader("User-Agent"),
					Status:         status,
					LatencyMs:      latency,
				})
			}()
		}

		// Forwarded-header inspection (v1.7 W7). Loopback in a forwarded /
		// client-IP header is a spoof; optional trusted-host allowlist.
		if config.ForwardedHeaders {
			if arcis.DetectForwardedSpoof(c.GetHeader) {
				decision = telemetry.DecisionDeny
				evtVector = "header"
				evtRule = "header/forwarded-loopback-spoof"
				evtSeverity = telemetry.SeverityHigh
				evtReason = "Loopback address in forwarded header"
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error": "Request blocked for security reasons", "code": "SECURITY_THREAT",
					"vector": "header", "rule": "header/forwarded-loopback-spoof",
				})
				return
			}
			if arcis.IsUntrustedHost(c.GetHeader, c.Request.Host, config.TrustedHosts) {
				decision = telemetry.DecisionDeny
				evtVector = "header"
				evtRule = "header/untrusted-host"
				evtSeverity = telemetry.SeverityHigh
				evtReason = "Untrusted Host header"
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error": "Request blocked for security reasons", "code": "SECURITY_THREAT",
					"vector": "header", "rule": "header/untrusted-host",
				})
				return
			}
		}

		// Cloud IP reputation (opt-in). Runs after forwarded-header inspection
		// and before scanner/bot/rate-limit so a known-bad IP is blocked before
		// consuming quota. Cache-first and non-blocking: a miss never adds
		// latency, and an unreachable service fails open. Skipped in dry-run.
		if config.Intelligence != nil && !config.DryRun {
			ip := utils.DetectClientIP(c.Request, nil)
			rep, block := intelligence.ShouldBlock(config.Intelligence, config.IntelligenceBlockThreshold, ip)
			if block {
				decision = telemetry.DecisionDeny
				evtVector = "ip-reputation"
				evtRule = "ip-reputation/known-bad"
				evtSeverity = telemetry.Severity(intelligence.ReputationSeverityTier(rep.Severity))
				evtReason = "IP reputation severity exceeds threshold"
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error": "Request blocked for security reasons", "code": "SECURITY_THREAT",
					"vector": "ip-reputation", "rule": "ip-reputation/known-bad",
				})
				return
			}
		}

		// Scanner-path probe blocking (v1.7 W2). Runs BEFORE bot detection.
		if config.ScannerPaths {
			if matched := arcis.DetectSensitivePath(c.Request.URL.Path, nil); matched != "" {
				decision = telemetry.DecisionDeny
				evtVector = "scanner-path"
				evtRule = "scanner-path/probe"
				evtMatched = matched
				evtSeverity = telemetry.SeverityHigh
				evtReason = "Scanner probe path"
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error":  "Access denied.",
					"code":   "SECURITY_THREAT",
					"vector": "scanner-path",
				})
				return
			}
		}

		// Bot UA classification (v1.7 W1). Runs BEFORE rate-limit so bots
		// don't consume legitimate-traffic quota. Skipped if Bot=false or
		// BotDeny is empty.
		if config.Bot && len(config.BotDeny) > 0 {
			result := arcis.DetectBot(c.Request)
			if result.IsBot {
				denied := false
				for _, denyCat := range config.BotDeny {
					if result.Category == denyCat {
						denied = true
						break
					}
				}
				if denied {
					decision = telemetry.DecisionDeny
					evtVector = "bot"
					evtRule = "bot/" + strings.ToLower(string(result.Category))
					evtSeverity = telemetry.SeverityMedium
					evtReason = "Bot detected"
					if result.Name != "" {
						evtReason = "Bot detected: " + result.Name
					}

					c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
						"error": "Access denied.",
					})
					return
				}
			}
		}

		// Skip function check for rate limiting
		skipRateLimit := config.RateLimitSkip != nil && config.RateLimitSkip(c)

		if !skipRateLimit && rateLimiter != nil {
			result := rateLimiter.Check(c.Request)

			c.Header("X-RateLimit-Limit", strconv.Itoa(result.Limit))
			c.Header("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
			c.Header("X-RateLimit-Reset", strconv.Itoa(int(result.Reset.Seconds())))

			if !result.Allowed {
				decision = telemetry.DecisionDeny
				evtVector = "rate-limit"
				evtRule = "rate-limit/exceeded"
				evtSeverity = telemetry.SeverityMedium
				evtReason = "Rate limit exceeded"

				c.Header("Retry-After", strconv.Itoa(int(result.Reset.Seconds())))
				c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
					"error":      "Too many requests, please try again later.",
					"retryAfter": int(result.Reset.Seconds()),
				})
				return
			}
		}

		// Body-driven checks (v1.7 W3 + W4 + W5 + W6). Read + restore the
		// JSON body once, then run GraphQL inspection, mass-assignment
		// detection, SSRF URL validation, and prompt-injection detection
		// off the same bytes. All run regardless of Block mode; skipped
		// in dry-run.
		if (config.GraphQL || config.MassAssign || config.SSRF || config.PromptInjection) && !config.DryRun {
			ct := c.Request.Header.Get("Content-Type")
			if c.Request.Body != nil && strings.HasPrefix(ct, "application/json") {
				raw, err := io.ReadAll(c.Request.Body)
				if err == nil {
					c.Request.Body = io.NopCloser(bytes.NewReader(raw))
					c.Request.ContentLength = int64(len(raw))
					if config.GraphQL {
						if gqlRes := arcis.InspectGraphqlRequestBody(raw, config.GraphQLOptions); gqlRes.Blocked {
							decision = telemetry.DecisionDeny
							evtVector = "graphql"
							evtRule = "graphql/" + gqlRes.Reason
							evtSeverity = telemetry.SeverityHigh
							evtReason = "GraphQL " + gqlRes.Reason + " limit exceeded"
							c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
								"error":  "Request blocked for security reasons",
								"code":   "SECURITY_THREAT",
								"vector": "graphql",
								"rule":   "graphql/" + gqlRes.Reason,
							})
							return
						}
					}
					if config.MassAssign {
						if maRes := arcis.DetectMassAssignmentJSON(raw, nil); maRes.Detected {
							decision = telemetry.DecisionDeny
							evtVector = "mass-assignment"
							evtRule = "mass-assignment/sensitive-field"
							evtSeverity = telemetry.SeverityHigh
							evtReason = "Mass-assignment field: " + maRes.Field
							c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
								"error":  "Request blocked for security reasons",
								"code":   "SECURITY_THREAT",
								"vector": "mass-assignment",
								"rule":   "mass-assignment/sensitive-field",
							})
							return
						}
					}
					if config.SSRF {
						if ssrfRes := arcis.ScanForSSRFJSON(raw, nil); ssrfRes.Detected {
							decision = telemetry.DecisionDeny
							evtVector = "ssrf"
							evtRule = "ssrf/blocked-url"
							evtSeverity = telemetry.SeverityHigh
							evtReason = "SSRF: " + ssrfRes.Reason
							c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
								"error":  "Request blocked for security reasons",
								"code":   "SECURITY_THREAT",
								"vector": "ssrf",
								"rule":   "ssrf/blocked-url",
							})
							return
						}
					}
					if config.PromptInjection {
						if arcis.ScanPromptInjectionJSON(raw, config.MinPromptSeverity) {
							decision = telemetry.DecisionDeny
							evtVector = "prompt-injection"
							evtRule = "prompt-injection/detected"
							evtSeverity = telemetry.SeverityHigh
							evtReason = "Prompt injection detected"
							c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
								"error":  "Request blocked for security reasons",
								"code":   "SECURITY_THREAT",
								"vector": "prompt-injection",
								"rule":   "prompt-injection/detected",
							})
							return
						}
					}
				}
			}
		}

		// Block mode: scan body / query / path for attack patterns.
		if config.Block {
			if hit := pipeline.ScanRequestForThreats(c.Request); hit != nil {
				// In dry-run mode the telemetry decision is "would_deny"
				// so dashboards can graph false-positive rate before the
				// switch flips. In real-deny mode it's "deny".
				if config.DryRun {
					decision = telemetry.Decision("would_deny")
				} else {
					decision = telemetry.DecisionDeny
				}
				evtVector = hit.Vector
				evtRule = hit.Rule
				evtMatched = hit.MatchedPattern
				evtSeverity = telemetry.SeverityHigh
				evtReason = "Detected " + hit.Vector + " pattern"

				// Fire the OnSanitize callback so operators can wire
				// log aggregation / alerting without subscribing to the
				// telemetry stream. Defer/recover so a panicking
				// callback can't crash the middleware.
				if config.OnSanitize != nil {
					func() {
						defer func() { _ = recover() }()
						config.OnSanitize(SanitizeEvent{
							Vector:  hit.Vector,
							Rule:    hit.Rule,
							Matched: hit.MatchedPattern,
							Path:    c.Request.URL.Path,
							DryRun:  config.DryRun,
						})
					}()
				}

				// Dry-run: skip the 403 and let the handler run. The
				// telemetry record above still reflects the would-have-
				// blocked decision.
				if !config.DryRun {
					c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
						"error":  "Request blocked for security reasons",
						"code":   "SECURITY_THREAT",
						"vector": hit.Vector,
					})
					return
				}
			}
		}

		// Security headers
		if securityHeaders != nil {
			for key, value := range securityHeaders.GetHeaders() {
				c.Header(key, value)
			}
		}

		// Store sanitizer in context for use in handlers
		c.Set("arcis_sanitizer", sanitizer)

		c.Next()

		// Remove fingerprinting headers after handler runs
		c.Writer.Header().Del("Server")
		c.Writer.Header().Del("X-Powered-By")
	}
}

// Headers returns a middleware that only sets security headers.
func Headers() gin.HandlerFunc {
	return HeadersWithConfig(DefaultConfig())
}

// HeadersWithConfig returns a headers middleware with custom configuration.
func HeadersWithConfig(config Config) gin.HandlerFunc {
	arcisConfig := arcis.Config{
		CSP:               config.CSP,
		FrameOptions:      config.FrameOptions,
		HSTSMaxAge:        config.HSTSMaxAge,
		HSTSSubdomains:    config.HSTSSubdomains,
		ReferrerPolicy:    config.ReferrerPolicy,
		PermissionsPolicy: config.PermissionsPolicy,
		CacheControl:      config.CacheControl,
		CacheControlValue: config.CacheControlValue,
	}

	headers := arcis.NewSecurityHeaders(arcisConfig)

	return func(c *gin.Context) {
		for key, value := range headers.GetHeaders() {
			c.Header(key, value)
		}
		c.Next()
		c.Writer.Header().Del("Server")
		c.Writer.Header().Del("X-Powered-By")
	}
}

// RateLimit returns a middleware for rate limiting with specified limits.
// Pass arcisgin.WithTelemetry(tc) to emit a TelemetryEvent on 429.
func RateLimit(max int, window time.Duration, opts ...RateLimitOption) gin.HandlerFunc {
	return RateLimitWithSkip(max, window, nil, opts...)
}

// RateLimitWithStore returns a rate limiting middleware backed by a custom store.
// Use this to plug in a distributed backend such as Redis. Pass
// arcisgin.WithTelemetry(tc) to emit a TelemetryEvent on 429.
//
// Example:
//
//	store := myredis.NewStore(redisClient)
//	r.Use(arcisgin.RateLimitWithStore(100, time.Minute, store))
func RateLimitWithStore(max int, window time.Duration, store arcis.RateLimitStore, opts ...RateLimitOption) gin.HandlerFunc {
	var o rateLimitOpts
	for _, opt := range opts {
		opt(&o)
	}

	limiter := arcis.NewRateLimiterWithStore(max, window, store)
	instance := &arcisInstance{rateLimiter: limiter}
	registerInstance(instance)

	return func(c *gin.Context) {
		start := time.Now()
		var didDeny bool
		if o.telemetry != nil {
			defer func() {
				if didDeny {
					emitRateLimitDeny(o.telemetry, c, start)
				}
			}()
		}

		result := limiter.Check(c.Request)

		c.Header("X-RateLimit-Limit", strconv.Itoa(result.Limit))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
		c.Header("X-RateLimit-Reset", strconv.Itoa(int(result.Reset.Seconds())))

		if !result.Allowed {
			didDeny = true
			c.Header("Retry-After", strconv.Itoa(int(result.Reset.Seconds())))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":      "Too many requests, please try again later.",
				"retryAfter": int(result.Reset.Seconds()),
			})
			return
		}

		c.Next()
	}
}

// RateLimitWithSkip returns a rate limiting middleware with custom skip function.
// Pass arcisgin.WithTelemetry(tc) to emit a TelemetryEvent on 429.
func RateLimitWithSkip(max int, window time.Duration, skip func(*gin.Context) bool, opts ...RateLimitOption) gin.HandlerFunc {
	var o rateLimitOpts
	for _, opt := range opts {
		opt(&o)
	}

	limiter := arcis.NewRateLimiter(max, window)
	instance := &arcisInstance{rateLimiter: limiter}
	registerInstance(instance)

	return func(c *gin.Context) {
		start := time.Now()
		var didDeny bool
		if o.telemetry != nil {
			defer func() {
				if didDeny {
					emitRateLimitDeny(o.telemetry, c, start)
				}
			}()
		}

		if skip != nil && skip(c) {
			c.Next()
			return
		}

		result := limiter.Check(c.Request)

		c.Header("X-RateLimit-Limit", strconv.Itoa(result.Limit))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
		c.Header("X-RateLimit-Reset", strconv.Itoa(int(result.Reset.Seconds())))

		if !result.Allowed {
			didDeny = true
			c.Header("Retry-After", strconv.Itoa(int(result.Reset.Seconds())))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":      "Too many requests, please try again later.",
				"retryAfter": int(result.Reset.Seconds()),
			})
			return
		}

		c.Next()
	}
}

// BruteForce returns standalone brute-force protection middleware for login /
// password-reset routes. Build the limiter once and keep the reference so the
// app can call b.Reset(key) after a successful authentication and b.Close() on
// shutdown:
//
//	bf := arcis.NewBruteForce(arcis.BruteForceConfig{})
//	defer bf.Close()
//	r.POST("/login", arcisgin.BruteForce(bf), loginHandler)
func BruteForce(b *arcis.BruteForce) gin.HandlerFunc {
	return func(c *gin.Context) {
		res := b.Check(c.Request)
		if !res.Allowed {
			retryAfter := int(res.RetryAfter.Seconds())
			if retryAfter < 1 {
				retryAfter = 1
			}
			c.Header("Retry-After", strconv.Itoa(retryAfter))
			c.AbortWithStatusJSON(b.StatusCode(), gin.H{
				"error":      b.Message(),
				"retryAfter": retryAfter,
			})
			return
		}
		c.Next()
	}
}

// Overload returns standalone runtime-overload protection middleware that sheds
// requests with 503 when the server is saturated. Build it once and Close() it
// on shutdown:
//
//	ol := arcis.NewOverload(arcis.OverloadConfig{})
//	defer ol.Close()
//	r.Use(arcisgin.Overload(ol))
func Overload(o *arcis.Overload) gin.HandlerFunc {
	return func(c *gin.Context) {
		if o.ExposeLagHeaderEnabled() {
			c.Header("X-EventLoop-Lag", strconv.Itoa(int(o.CurrentLagMs()+0.5)))
		}
		if o.Overloaded() {
			c.Header("Retry-After", strconv.Itoa(o.RetryAfterSeconds()))
			c.AbortWithStatusJSON(o.StatusCode(), gin.H{
				"error":      o.Message(),
				"retryAfter": o.RetryAfterSeconds(),
			})
			return
		}
		c.Next()
	}
}

// Sanitizer returns a middleware that provides sanitization utilities.
func Sanitizer() gin.HandlerFunc {
	return SanitizerWithConfig(DefaultConfig())
}

// SanitizerWithConfig returns a sanitizer middleware with custom configuration.
func SanitizerWithConfig(config Config) gin.HandlerFunc {
	arcisConfig := arcis.Config{
		SanitizeXSS:   config.SanitizeXSS,
		SanitizeSQL:   config.SanitizeSQL,
		SanitizeNoSQL: config.SanitizeNoSQL,
		SanitizePath:  config.SanitizePath,
		SanitizeCmd:   config.SanitizeCmd,
		MaxInputSize:  config.MaxInputSize,
	}

	sanitizer := arcis.NewSanitizer(arcisConfig)

	return func(c *gin.Context) {
		c.Set("arcis_sanitizer", sanitizer)
		c.Next()
	}
}

// GetSanitizer retrieves the Arcis sanitizer from the Gin context.
func GetSanitizer(c *gin.Context) *arcis.Sanitizer {
	if s, exists := c.Get("arcis_sanitizer"); exists {
		return s.(*arcis.Sanitizer)
	}
	return arcis.NewSanitizer(arcis.DefaultConfig())
}

// SanitizeJSON sanitizes JSON data using the sanitizer from context.
//
// Example:
//
//	func handler(c *gin.Context) {
//	    var data map[string]interface{}
//	    if err := c.ShouldBindJSON(&data); err != nil {
//	        c.JSON(400, gin.H{"error": err.Error()})
//	        return
//	    }
//	    data = arcisgin.SanitizeJSON(c, data)
//	    // Use sanitized data...
//	}
func SanitizeJSON(c *gin.Context, data map[string]interface{}) map[string]interface{} {
	sanitizer := GetSanitizer(c)
	return sanitizer.SanitizeMap(data)
}

// SanitizeString sanitizes a string value using the sanitizer from context.
func SanitizeString(c *gin.Context, value string) string {
	sanitizer := GetSanitizer(c)
	return sanitizer.SanitizeString(value)
}

// Validate creates a validation middleware using Arcis's validator.
func Validate(schema arcis.ValidationSchema) gin.HandlerFunc {
	validator := arcis.NewValidator(schema)

	return func(c *gin.Context) {
		var data map[string]interface{}
		if err := c.ShouldBindJSON(&data); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"errors": []string{"Invalid JSON"},
			})
			return
		}

		validated, validationErr := validator.Validate(data)
		if validationErr != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"errors": validationErr.Errors,
			})
			return
		}

		c.Set("validated_body", validated)
		c.Next()
	}
}

// GetValidatedBody retrieves the validated request body from the context.
func GetValidatedBody(c *gin.Context) map[string]interface{} {
	if v, exists := c.Get("validated_body"); exists {
		return v.(map[string]interface{})
	}
	return nil
}

// CsrfProtection returns a Gin middleware for CSRF protection using double-submit cookie.
func CsrfProtection(opts arcis.CsrfOptions) gin.HandlerFunc {
	csrf := arcis.NewCsrfProtection(opts)

	return func(c *gin.Context) {
		method := c.Request.Method

		// Wrap the handler
		handler := csrf.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Copy headers set by CSRF middleware to gin response
			for key, values := range w.Header() {
				for _, v := range values {
					c.Writer.Header().Add(key, v)
				}
			}
			c.Next()
		}))

		rec := &ginResponseCapture{header: http.Header{}}
		handler.ServeHTTP(rec, c.Request)

		if rec.status == http.StatusForbidden {
			// CSRF validation failed
			for key, values := range rec.header {
				for _, v := range values {
					c.Writer.Header().Set(key, v)
				}
			}
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":   "CSRF token validation failed",
				"message": "Invalid or missing CSRF token. Include the token from the cookie in the X-CSRF-Token header.",
			})
			return
		}

		// Copy Set-Cookie headers from CSRF middleware
		for _, cookie := range rec.header.Values("Set-Cookie") {
			c.Writer.Header().Add("Set-Cookie", cookie)
		}

		// Only proceed if not a safe method that was already handled
		if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
			c.Next()
		}
	}
}

// ginResponseCapture captures response status/headers from net/http handlers.
type ginResponseCapture struct {
	header http.Header
	status int
}

func (g *ginResponseCapture) Header() http.Header         { return g.header }
func (g *ginResponseCapture) Write(b []byte) (int, error) { return len(b), nil }
func (g *ginResponseCapture) WriteHeader(statusCode int)  { g.status = statusCode }

// SecureCookies returns a Gin middleware that enforces secure cookie defaults.
func SecureCookies(opts arcis.SecureCookieOptions) gin.HandlerFunc {
	sc := arcis.NewSecureCookieDefaults(opts)

	return func(c *gin.Context) {
		c.Next()

		// Enforce on all Set-Cookie headers after handler runs
		cookies := c.Writer.Header().Values("Set-Cookie")
		if len(cookies) > 0 {
			c.Writer.Header().Del("Set-Cookie")
			for _, cookie := range cookies {
				c.Writer.Header().Add("Set-Cookie", sc.Enforce(cookie))
			}
		}
	}
}

// Cors returns a Gin middleware for safe CORS handling.
func Cors(opts arcis.CorsOptions) gin.HandlerFunc {
	cors := arcis.NewSafeCors(opts)

	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		headers := cors.GetHeaders(origin, c.Request.Method)

		for key, value := range headers {
			c.Header(key, value)
		}

		// Handle preflight
		if c.Request.Method == http.MethodOptions && origin != "" {
			if _, ok := headers["Access-Control-Allow-Origin"]; ok {
				c.AbortWithStatus(http.StatusNoContent)
				return
			}
		}

		c.Next()
	}
}

// ErrorHandler returns a Gin error handler middleware.
func ErrorHandler(isDev bool) gin.HandlerFunc {
	handler := arcis.NewErrorHandler(isDev)

	return func(c *gin.Context) {
		c.Next()

		if len(c.Errors) > 0 {
			err := c.Errors.Last().Err
			statusCode := c.Writer.Status()
			if statusCode == 0 || statusCode == http.StatusOK {
				statusCode = http.StatusInternalServerError
			}
			handler.Handle(c.Writer, err, statusCode)
		}
	}
}
