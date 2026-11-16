/*
Package fiber provides Arcis middleware adapters for the gofiber/fiber
v2 web framework (sdk-vectors.md G3 / P2 #27).

Fiber v2's middleware shape is `func(c *fiber.Ctx) error`. This package
ships a bundle middleware that runs the Arcis pipeline (rate limit +
block-mode threat scan + security headers + sanitizer in context) and
standalone RateLimit helpers + WithTelemetry option.

Surface available today: Middleware / MiddlewareWithConfig / RateLimit /
RateLimitWithStore / RateLimitWithSkip / GetSanitizer / WithTelemetry.
The granular Headers / Sanitizer / Validate / CsrfProtection /
SecureCookies / Cors / ErrorHandler helpers that gin / echo / chi expose
are NOT yet ported to the Fiber adapter — they land in v1.7. For
granular composition today, use chi (which is stdlib-compatible with
any router that accepts func(http.Handler) http.Handler).

Usage:

	import (
		"github.com/gofiber/fiber/v2"
		arcisfiber "github.com/getarcis/arcis-go/fiber"
	)

	func main() {
		app := fiber.New()
		cfg := arcisfiber.DefaultConfig()
		cfg.Block = true
		app.Use(arcisfiber.MiddlewareWithConfig(cfg))
		app.Get("/", handler)
		app.Listen(":8080")
	}

# Resource cleanup

Arcis's rate limiter runs a background goroutine for cleanup. Call
Cleanup() at application shutdown to stop it:

	defer arcisfiber.Cleanup()
*/
package fiber

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/adaptor"

	arcis "github.com/getarcis/arcis-go"
	"github.com/getarcis/arcis-go/intelligence"
	"github.com/getarcis/arcis-go/telemetry"
	"github.com/getarcis/arcis-go/utils"
)

// scanFiberCtxForThreats peeks at JSON body, query params, and URL path
// for the block-mode middleware. Returns the first hit or nil.
//
// Duplicates the gin / echo / chi `scanRequestForThreats` helpers.
// The owned-files boundary blocks consolidation here; a future janitor
// pass can extract this into `internal/scanutil/`.
func scanFiberCtxForThreats(c *fiber.Ctx) *arcis.ThreatHit {
	ct := c.Get(fiber.HeaderContentType)
	if strings.HasPrefix(ct, fiber.MIMEApplicationJSON) {
		raw := c.Body()
		if len(raw) > 0 {
			var parsed interface{}
			if json.Unmarshal(raw, &parsed) == nil {
				if hit := arcis.ScanThreats(parsed); hit != nil {
					return hit
				}
			}
		}
	} else if strings.HasPrefix(ct, fiber.MIMEApplicationForm) {
		raw := c.Body()
		if len(raw) > 0 {
			if values, err := url.ParseQuery(string(raw)); err == nil {
				form := make(map[string]interface{}, len(values))
				for k, vals := range values {
					if len(vals) == 1 {
						form[k] = vals[0]
					} else {
						arr := make([]interface{}, len(vals))
						for i, v := range vals {
							arr[i] = v
						}
						form[k] = arr
					}
				}
				if hit := arcis.ScanThreats(form); hit != nil {
					return hit
				}
			}
		}
	}

	// Query string. Fiber surfaces this as a Queries() map of single
	// strings; convert to the interface{} shape ScanThreats expects.
	q := map[string]interface{}{}
	for k, v := range c.Queries() {
		q[k] = v
	}
	if len(q) > 0 {
		if hit := arcis.ScanThreats(q); hit != nil {
			return hit
		}
	}
	if hit := arcis.ScanThreats(c.Path()); hit != nil {
		return hit
	}
	return nil
}

// Config holds Arcis middleware configuration for Fiber.
//
// Mirrors the chi/gin/echo Config one-for-one so users can copy a known-
// good config across adapters without learning a new field set.
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
	// patterns and respond 403 instead of running the handler. Opt-in.
	Block bool

	// DryRun: observe configured bundle enforcement without returning an
	// Arcis 403 or 429. Block-mode threats fire OnSanitize and telemetry
	// records would-have-denied decisions. Use before enforcing in production.
	DryRun bool

	// OnSanitize fires when a threat is detected in block mode. Receives
	// a SanitizeEvent describing the vector + path. Must not panic; the
	// middleware swallows panics via defer/recover.
	OnSanitize func(SanitizeEvent)

	// Rate limiter options
	RateLimit       bool
	RateLimitMax    int
	RateLimitWindow time.Duration
	RateLimitSkip   func(*fiber.Ctx) bool
	RateLimitStore  arcis.RateLimitStore // Optional external store (e.g. Redis)
	// RateLimitOnStoreError receives store errors (the request is allowed),
	// at most once per window. Nil logs through the standard log package.
	RateLimitOnStoreError func(error)

	// TrustedProxies lists the proxy IPs and CIDR ranges whose
	// X-Forwarded-For entries are believed when resolving the client IP
	// for rate limiting, telemetry and IP reputation. The peer is the
	// connection address; fiber's c.IP() and ProxyHeader are not used. Nil
	// uses the default set (loopback, link-local, private and unique-local
	// ranges); an empty non-nil slice trusts nothing. An invalid entry makes
	// MiddlewareWithConfig panic.
	TrustedProxies []string

	// Bot UA classification (v1.7 W1). When Bot is true the middleware
	// classifies the User-Agent and denies categories in BotDeny with 403.
	// Default deny: {AUTOMATED, SCRAPER}.
	Bot     bool
	BotDeny []arcis.BotCategory

	// Scanner-path probe blocking (v1.7 W2). When ScannerPaths is true
	// the middleware denies requests to known probe paths (/.env, /.git,
	// /wp-admin, etc) with 403.
	ScannerPaths bool

	// GraphQL inspection (v1.7 W3). When GraphQL is true, JSON bodies
	// with a `query` field are inspected for depth/alias/cycle/
	// introspection abuse. GraphQLOptions overrides the tightened
	// wire-up defaults (MaxAliases: 10).
	GraphQL        bool
	GraphQLOptions arcis.GraphqlGuardOptions

	// MassAssign field detection (v1.7 W4). When true, JSON bodies are
	// scanned for privilege-escalation field names and denied with 403.
	MassAssign bool

	// SSRF body-URL validation (v1.7 W5). When true, JSON bodies are
	// walked for URL-shaped strings; private/metadata/file URLs denied.
	SSRF bool

	// PromptInjection detection on body strings (v1.7 W6). When true,
	// JSON body strings are scanned for prompt-injection signatures and
	// denied at or above MinPromptSeverity (default "medium").
	PromptInjection   bool
	MinPromptSeverity string

	// ForwardedHeaders inspection (v1.7 W7). Loopback in a forwarded
	// header is denied; TrustedHosts (if set) gates Host/X-Forwarded-Host.
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
	CacheControlValue string

	// Cross-origin isolation headers (legacy profile), as in arcis.Config.
	CrossOriginOpenerPolicy   string
	CrossOriginResourcePolicy string
	CrossOriginEmbedderPolicy string
	OriginAgentCluster        bool
	DNSPrefetchControl        bool

	// HeaderProfile selects the header defaults: empty or
	// arcis.HeaderProfileLegacy uses the fields above;
	// arcis.HeaderProfileBaseline uses BaselineHeaders (Helmet 8
	// compatible). An invalid baseline configuration makes
	// MiddlewareWithConfig panic. With
	// BaselineHeaders.ContentSecurityPolicy.Nonce, handlers read the nonce
	// with arcis.CSPNonce(c.UserContext()). CSP function values receive
	// the request converted to *http.Request.
	HeaderProfile   arcis.HeaderProfile
	BaselineHeaders arcis.BaselineHeaderOptions

	// Error handler options
	IsDev bool

	// Telemetry: optional client. When set, MiddlewareWithConfig emits
	// one TelemetryEvent per request (allow + deny). Standalone
	// RateLimit* helpers wire telemetry via WithTelemetry (deny-only).
	Telemetry *telemetry.Client

	// Intelligence, if non-nil, enables opt-in cloud IP reputation. On each
	// request the client IP (resolved with TrustedProxies) is
	// looked up (cache-first, non-blocking); when the verdict severity is at
	// or above IntelligenceBlockThreshold, the request is denied with 403.
	// Nil = no IP-reputation work. A threshold of 0 (or omitted) is observe-only.
	Intelligence               *intelligence.Client
	IntelligenceBlockThreshold int
}

// DefaultConfig returns the default Arcis configuration for Fiber.
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

		CrossOriginOpenerPolicy:   "same-origin",
		CrossOriginResourcePolicy: "same-origin",
		CrossOriginEmbedderPolicy: "require-corp",
		OriginAgentCluster:        true,
		DNSPrefetchControl:        true,

		IsDev: false,
	}
}

// compileSecurityHeaders compiles the header settings in config. It
// panics on an unknown HeaderProfile or invalid BaselineHeaders, so the
// mistake surfaces when the middleware is built rather than per request.
func compileSecurityHeaders(config Config) *arcis.SecurityHeaders {
	headers, err := arcis.CompileSecurityHeaders(arcis.Config{
		CSP:                       config.CSP,
		FrameOptions:              config.FrameOptions,
		HSTSMaxAge:                config.HSTSMaxAge,
		HSTSSubdomains:            config.HSTSSubdomains,
		ReferrerPolicy:            config.ReferrerPolicy,
		PermissionsPolicy:         config.PermissionsPolicy,
		CacheControl:              config.CacheControl,
		CacheControlValue:         config.CacheControlValue,
		CrossOriginOpenerPolicy:   config.CrossOriginOpenerPolicy,
		CrossOriginResourcePolicy: config.CrossOriginResourcePolicy,
		CrossOriginEmbedderPolicy: config.CrossOriginEmbedderPolicy,
		OriginAgentCluster:        config.OriginAgentCluster,
		DNSPrefetchControl:        config.DNSPrefetchControl,
		HeaderProfile:             config.HeaderProfile,
		BaselineHeaders:           config.BaselineHeaders,
	})
	if err != nil {
		panic("arcis fiber adapter: invalid security header configuration: " + err.Error())
	}
	return headers
}

// applySecurityHeaders sets the security headers before the handler runs,
// so a header the route sets itself wins. A per-request CSP (nonce or
// function values) gets the request converted to *http.Request, and the
// nonce is stored on c.UserContext(). The error comes from a CSP function
// value and should be returned to Fiber's error handler.
func applySecurityHeaders(c *fiber.Ctx, headers *arcis.SecurityHeaders) error {
	var req *http.Request
	if headers.Dynamic() {
		converted, err := adaptor.ConvertRequest(c, false)
		if err != nil {
			return err
		}
		req = converted.WithContext(c.UserContext())
	}
	h := make(http.Header, len(headers.GetHeaders())+1)
	req, err := headers.Apply(h, req)
	if err != nil {
		return err
	}
	if req != nil {
		c.SetUserContext(req.Context())
	}
	for name, values := range h {
		c.Set(name, values[0])
	}
	return nil
}

// stripFingerprintHeaders removes Server, and X-Powered-By unless the
// baseline profile keeps it. headers may be nil (headers disabled).
func stripFingerprintHeaders(c *fiber.Ctx, headers *arcis.SecurityHeaders) {
	c.Response().Header.Del("Server")
	if headers == nil || headers.RemovesPoweredBy() {
		c.Response().Header.Del("X-Powered-By")
	}
}

// SanitizeEvent is the payload passed to Config.OnSanitize when a
// block-mode scan matches a threat. DryRun indicates whether the request
// was actually denied or only logged.
type SanitizeEvent struct {
	Vector  string
	Rule    string
	Matched string
	Path    string
	DryRun  bool
}

// arcisInstance holds the Arcis components for cleanup.
type arcisInstance struct {
	rateLimiter *arcis.RateLimiter
}

func (s *arcisInstance) Close() {
	if s.rateLimiter != nil {
		s.rateLimiter.Close()
	}
}

var (
	activeInstances   []*arcisInstance
	activeInstancesMu sync.Mutex
)

// Cleanup closes all active Arcis middleware instances and releases
// resources. Stops the rate limiter background goroutine. Safe to call
// multiple times.
func Cleanup() {
	activeInstancesMu.Lock()
	defer activeInstancesMu.Unlock()
	for _, inst := range activeInstances {
		inst.Close()
	}
	activeInstances = nil
}

func registerInstance(inst *arcisInstance) {
	activeInstancesMu.Lock()
	defer activeInstancesMu.Unlock()
	activeInstances = append(activeInstances, inst)
}

// RateLimitOption configures a standalone rate-limit middleware. Use
// WithTelemetry to attach a telemetry client.
type RateLimitOption func(*rateLimitOpts)

type rateLimitOpts struct {
	telemetry      *telemetry.Client
	trustedProxies []string
	onStoreError   func(error)
}

// WithTrustedProxies sets the proxy IPs and CIDR ranges whose
// X-Forwarded-For entries a standalone rate-limit middleware believes; see
// Config.TrustedProxies.
func WithTrustedProxies(proxies []string) RateLimitOption {
	return func(o *rateLimitOpts) { o.trustedProxies = proxies }
}

// WithStoreErrorHandler sets the function that receives store errors (at most
// once per window) for a standalone rate-limit middleware. Requests are
// allowed while the store fails.
func WithStoreErrorHandler(fn func(error)) RateLimitOption {
	return func(o *rateLimitOpts) { o.onStoreError = fn }
}

// newRateLimiter builds a limiter, panicking on invalid configuration because
// the middleware constructors cannot return an error.
func newRateLimiter(opts arcis.RateLimiterOptions) *arcis.RateLimiter {
	limiter, err := arcis.NewRateLimiterWithOptions(opts)
	if err != nil {
		panic(err.Error())
	}
	return limiter
}

// peerAddr returns the connection address of c ("ip:port"), never a header.
func peerAddr(c *fiber.Ctx) string {
	return c.Context().RemoteAddr().String()
}

// forwardedFor returns copies of the X-Forwarded-For header values. The copies
// matter: fasthttp reuses the request buffers once the handler returns.
func forwardedFor(c *fiber.Ctx) []string {
	raw := c.Request().Header.PeekAll(fiber.HeaderXForwardedFor)
	values := make([]string, len(raw))
	for i, v := range raw {
		values[i] = string(v)
	}
	return values
}

// clientIP resolves the client IP of c. The result is a fresh string that
// does not alias fasthttp's reusable buffers, so it is safe to keep as a map
// key or hand to background work.
func clientIP(clientIPs *utils.ClientIPResolver, c *fiber.Ctx) string {
	return clientIPs.Resolve(peerAddr(c), forwardedFor(c)...)
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

func emitRateLimitDeny(tc *telemetry.Client, c *fiber.Ctx, ip string, start time.Time) {
	if tc == nil {
		return
	}
	latency := float64(time.Since(start)) / float64(time.Millisecond)
	if latency < 0 {
		latency = 0
	}
	tc.Send(telemetry.Event{
		Ts:        time.Now().UTC().Format(time.RFC3339),
		IP:        ip,
		Method:    c.Method(),
		Path:      c.Path(),
		Decision:  telemetry.DecisionDeny,
		Vector:    "rate-limit",
		Rule:      "rate-limit/exceeded",
		Reason:    "Rate limit exceeded",
		Severity:  telemetry.SeverityMedium,
		UserAgent: c.Get(fiber.HeaderUserAgent),
		Status:    fiber.StatusTooManyRequests,
		LatencyMs: latency,
	})
}

// Middleware returns a Fiber middleware with default Arcis configuration.
func Middleware() fiber.Handler {
	return MiddlewareWithConfig(DefaultConfig())
}

// MiddlewareWithConfig returns a Fiber middleware with custom config.
func MiddlewareWithConfig(config Config) fiber.Handler {
	arcisConfig := arcis.Config{
		Sanitize:        config.Sanitize,
		SanitizeXSS:     config.SanitizeXSS,
		SanitizeSQL:     config.SanitizeSQL,
		SanitizeNoSQL:   config.SanitizeNoSQL,
		SanitizePath:    config.SanitizePath,
		SanitizeCmd:     config.SanitizeCmd,
		MaxInputSize:    config.MaxInputSize,
		RateLimit:       config.RateLimit,
		RateLimitMax:    config.RateLimitMax,
		RateLimitWindow: config.RateLimitWindow,
		IsDev:           config.IsDev,
	}

	// Compile headers first: invalid configuration panics before any
	// background goroutine starts.
	var securityHeaders *arcis.SecurityHeaders
	if config.Headers {
		securityHeaders = compileSecurityHeaders(config)
	}

	sanitizer := arcis.NewSanitizer(arcisConfig)
	instance := &arcisInstance{}
	clientIPs := utils.MustClientIPResolver(config.TrustedProxies)

	var rateLimiter *arcis.RateLimiter
	if config.RateLimit {
		rateLimiter = newRateLimiter(arcis.RateLimiterOptions{
			Max:            config.RateLimitMax,
			Window:         config.RateLimitWindow,
			Store:          config.RateLimitStore,
			TrustedProxies: config.TrustedProxies,
			OnStoreError:   config.RateLimitOnStoreError,
		})
		instance.rateLimiter = rateLimiter
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

	return func(c *fiber.Ctx) (returnedErr error) {
		defer stripFingerprintHeaders(c, securityHeaders)
		if securityHeaders != nil {
			if err := applySecurityHeaders(c, securityHeaders); err != nil {
				return err
			}
		}
		start := time.Now()
		var (
			decision    = telemetry.DecisionAllow
			evtVector   string
			evtRule     string
			evtMatched  string
			evtReason   string
			evtSeverity telemetry.Severity
		)
		applicationPending := false
		if config.Telemetry != nil {
			defer func() {
				status := c.Response().StatusCode()
				if returnedErr != nil || applicationPending {
					// Fiber finalizes returned errors outside this middleware.
					// Its buffered response may still be replaced by the app.
					status = 0
				}
				latency := float64(time.Since(start)) / float64(time.Millisecond)
				if latency < 0 {
					latency = 0
				}
				config.Telemetry.Send(telemetry.Event{
					Ts:             time.Now().UTC().Format(time.RFC3339),
					IP:             clientIP(clientIPs, c),
					Method:         c.Method(),
					Path:           c.Path(),
					Decision:       decision,
					Vector:         evtVector,
					Rule:           evtRule,
					MatchedPattern: evtMatched,
					Reason:         evtReason,
					Severity:       evtSeverity,
					UserAgent:      c.Get(fiber.HeaderUserAgent),
					Status:         status,
					LatencyMs:      latency,
				})
			}()
		}

		// Forwarded-header inspection (v1.7 W7).
		if config.ForwardedHeaders {
			get := func(name string) string { return c.Get(name) }
			if arcis.DetectForwardedSpoof(get) {
				if config.DryRun {
					decision = telemetry.DecisionWouldDeny
				} else {
					decision = telemetry.DecisionDeny
				}
				evtVector = "header"
				evtRule = "header/forwarded-loopback-spoof"
				evtSeverity = telemetry.SeverityHigh
				evtReason = "Loopback address in forwarded header"
				if !config.DryRun {
					return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
						"error": "Request blocked for security reasons", "code": "SECURITY_THREAT",
						"vector": "header", "rule": "header/forwarded-loopback-spoof",
					})
				}
			}
			if arcis.IsUntrustedHost(get, c.Hostname(), config.TrustedHosts) {
				if config.DryRun {
					decision = telemetry.DecisionWouldDeny
				} else {
					decision = telemetry.DecisionDeny
				}
				evtVector = "header"
				evtRule = "header/untrusted-host"
				evtSeverity = telemetry.SeverityHigh
				evtReason = "Untrusted Host header"
				if !config.DryRun {
					return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
						"error": "Request blocked for security reasons", "code": "SECURITY_THREAT",
						"vector": "header", "rule": "header/untrusted-host",
					})
				}
			}
		}

		// Cloud IP reputation (opt-in). After forwarded-header inspection,
		// before scanner/bot/rate-limit so a known-bad IP is blocked before
		// consuming quota. Cache-first + non-blocking; fails open. Dry-run
		// observes cached decisions without returning an Arcis response. The
		// resolved IP never aliases fasthttp buffers, so the client's
		// background cache-miss refresh can keep it.
		if config.Intelligence != nil {
			ip := clientIP(clientIPs, c)
			rep, block := intelligence.ShouldBlock(config.Intelligence, config.IntelligenceBlockThreshold, ip)
			if block {
				if config.DryRun {
					decision = telemetry.DecisionWouldDeny
				} else {
					decision = telemetry.DecisionDeny
				}
				evtVector = "ip-reputation"
				evtRule = "ip-reputation/known-bad"
				evtSeverity = telemetry.Severity(intelligence.ReputationSeverityTier(rep.Severity))
				evtReason = "IP reputation severity exceeds threshold"
				if !config.DryRun {
					return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
						"error": "Request blocked for security reasons", "code": "SECURITY_THREAT",
						"vector": "ip-reputation", "rule": "ip-reputation/known-bad",
					})
				}
			}
		}

		// Scanner-path probe blocking (v1.7 W2). Runs BEFORE bot detection.
		if config.ScannerPaths {
			if matched := arcis.DetectSensitivePath(c.Path(), nil); matched != "" {
				if config.DryRun {
					decision = telemetry.DecisionWouldDeny
				} else {
					decision = telemetry.DecisionDeny
				}
				evtVector = "scanner-path"
				evtRule = "scanner-path/sensitive"
				evtMatched = matched
				evtSeverity = telemetry.SeverityMedium
				evtReason = "Scanner probe path"
				if !config.DryRun {
					return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
						"error":  "Access denied.",
						"code":   "SECURITY_THREAT",
						"vector": "scanner-path",
					})
				}
			}
		}

		// Bot UA classification (v1.7 W1). Runs BEFORE rate-limit.
		// Build a minimal http.Request shim because arcis.DetectBot reads
		// from net/http headers; fiber uses fasthttp under the hood.
		if config.Bot && len(config.BotDeny) > 0 {
			botHeaders := http.Header{}
			if ua := c.Get("User-Agent"); ua != "" {
				botHeaders.Set("User-Agent", ua)
			}
			if v := c.Get("Accept"); v != "" {
				botHeaders.Set("Accept", v)
			}
			if v := c.Get("Accept-Language"); v != "" {
				botHeaders.Set("Accept-Language", v)
			}
			if v := c.Get("Accept-Encoding"); v != "" {
				botHeaders.Set("Accept-Encoding", v)
			}
			if v := c.Get("Connection"); v != "" {
				botHeaders.Set("Connection", v)
			}
			botRes := arcis.DetectBot(&http.Request{Header: botHeaders})
			if botRes.IsBot {
				denied := false
				for _, denyCat := range config.BotDeny {
					if botRes.Category == denyCat {
						denied = true
						break
					}
				}
				if denied {
					if config.DryRun {
						decision = telemetry.DecisionWouldDeny
					} else {
						decision = telemetry.DecisionDeny
					}
					evtVector = "bot"
					evtRule = "bot/" + strings.ToLower(string(botRes.Category))
					evtSeverity = telemetry.SeverityMedium
					evtReason = "Bot detected"
					if botRes.Name != "" {
						evtReason = "Bot detected: " + botRes.Name
					}
					if !config.DryRun {
						return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
							"error": "Access denied.",
						})
					}
				}
			}
		}

		// Skip function check for rate limiting
		skipRateLimit := config.RateLimitSkip != nil && config.RateLimitSkip(c)

		if !skipRateLimit && rateLimiter != nil {
			// fiber has no *http.Request, so resolve the client from the
			// connection address and trusted X-Forwarded-For entries here.
			// c.IP() is not used: with ProxyHeader set it believes any peer
			// and returns a string aliasing a reused fasthttp buffer.
			result := rateLimiter.CheckKey(utils.RateLimitKey(clientIP(clientIPs, c)))

			c.Set("X-RateLimit-Limit", strconv.Itoa(result.Limit))
			c.Set("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
			c.Set("X-RateLimit-Reset", strconv.Itoa(int(result.Reset.Seconds())))

			if !result.Allowed {
				if config.DryRun {
					decision = telemetry.DecisionWouldDeny
				} else {
					decision = telemetry.DecisionDeny
				}
				evtVector = "rate-limit"
				evtRule = "rate-limit/exceeded"
				evtSeverity = telemetry.SeverityMedium
				evtReason = "Rate limit exceeded"

				if !config.DryRun {
					c.Set("Retry-After", strconv.Itoa(int(result.Reset.Seconds())))
					return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
						"error":      "Too many requests, please try again later.",
						"retryAfter": int(result.Reset.Seconds()),
					})
				}
			}
		}

		// Body-driven checks (v1.7 W3 + W4 + W5 + W6). fasthttp exposes the
		// body via c.Body() (no stream to restore). Run GraphQL inspection
		// + mass-assignment detection + SSRF URL validation +
		// prompt-injection detection off the same bytes. Dry-run observes
		// without returning an Arcis response.
		if config.GraphQL || config.MassAssign || config.SSRF || config.PromptInjection {
			ct := c.Get("Content-Type")
			if strings.HasPrefix(ct, "application/json") {
				raw := c.Body()
				if config.GraphQL {
					if gqlRes := arcis.InspectGraphqlRequestBody(raw, config.GraphQLOptions); gqlRes.Blocked {
						if config.DryRun {
							decision = telemetry.DecisionWouldDeny
						} else {
							decision = telemetry.DecisionDeny
						}
						evtVector = "graphql"
						evtRule = "graphql/" + gqlRes.Reason
						evtSeverity = telemetry.SeverityHigh
						evtReason = "GraphQL " + gqlRes.Reason + " limit exceeded"
						if !config.DryRun {
							return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
								"error":  "Request blocked for security reasons",
								"code":   "SECURITY_THREAT",
								"vector": "graphql",
								"rule":   "graphql/" + gqlRes.Reason,
							})
						}
					}
				}
				if config.MassAssign {
					if maRes := arcis.DetectMassAssignmentJSON(raw, nil); maRes.Detected {
						if config.DryRun {
							decision = telemetry.DecisionWouldDeny
						} else {
							decision = telemetry.DecisionDeny
						}
						evtVector = "mass-assignment"
						evtRule = "mass-assignment/sensitive-field"
						evtSeverity = telemetry.SeverityHigh
						evtReason = "Mass-assignment field: " + maRes.Field
						if !config.DryRun {
							return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
								"error":  "Request blocked for security reasons",
								"code":   "SECURITY_THREAT",
								"vector": "mass-assignment",
								"rule":   "mass-assignment/sensitive-field",
							})
						}
					}
				}
				if config.SSRF {
					if ssrfRes := arcis.ScanForSSRFJSON(raw, nil); ssrfRes.Detected {
						if config.DryRun {
							decision = telemetry.DecisionWouldDeny
						} else {
							decision = telemetry.DecisionDeny
						}
						evtVector = "ssrf"
						evtRule = "ssrf/blocked-url"
						evtSeverity = telemetry.SeverityHigh
						evtReason = "SSRF: " + ssrfRes.Reason
						if !config.DryRun {
							return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
								"error":  "Request blocked for security reasons",
								"code":   "SECURITY_THREAT",
								"vector": "ssrf",
								"rule":   "ssrf/blocked-url",
							})
						}
					}
				}
				if config.PromptInjection {
					if arcis.ScanPromptInjectionJSON(raw, config.MinPromptSeverity) {
						if config.DryRun {
							decision = telemetry.DecisionWouldDeny
						} else {
							decision = telemetry.DecisionDeny
						}
						evtVector = "prompt-injection"
						evtRule = "prompt-injection/detected"
						evtSeverity = telemetry.SeverityHigh
						evtReason = "Prompt injection detected"
						if !config.DryRun {
							return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
								"error":  "Request blocked for security reasons",
								"code":   "SECURITY_THREAT",
								"vector": "prompt-injection",
								"rule":   "prompt-injection/detected",
							})
						}
					}
				}
			}
		}

		if config.Block {
			if hit := scanFiberCtxForThreats(c); hit != nil {
				if config.DryRun {
					decision = telemetry.DecisionWouldDeny
				} else {
					decision = telemetry.DecisionDeny
				}
				evtVector = hit.Vector
				evtRule = hit.Rule
				evtMatched = hit.MatchedPattern
				evtSeverity = telemetry.SeverityHigh
				evtReason = "Detected " + hit.Vector + " pattern"

				if config.OnSanitize != nil {
					func() {
						defer func() { _ = recover() }()
						config.OnSanitize(SanitizeEvent{
							Vector:  hit.Vector,
							Rule:    hit.Rule,
							Matched: hit.MatchedPattern,
							Path:    c.Path(),
							DryRun:  config.DryRun,
						})
					}()
				}

				if !config.DryRun {
					return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
						"error":  "Request blocked for security reasons",
						"code":   "SECURITY_THREAT",
						"vector": hit.Vector,
					})
				}
			}
		}

		// Stash the sanitizer in c.Locals so handlers can pull it back
		// via GetSanitizer(c).
		c.Locals(sanitizerLocalKey, sanitizer)

		applicationPending = true
		err := c.Next()
		applicationPending = false

		return err
	}
}

// sanitizerLocalKey is the c.Locals key for the per-request Sanitizer.
// Exported only as an unexported string to avoid collision with any
// user-set local; the GetSanitizer accessor is the public surface.
const sanitizerLocalKey = "arcis_sanitizer"

// GetSanitizer retrieves the per-request Sanitizer that
// MiddlewareWithConfig stashes on the request context. Returns a
// BruteForce returns standalone brute-force protection middleware for login /
// password-reset routes. Build the limiter once, keep the reference for
// b.Reset(key) after a successful auth, and b.Close() on shutdown. Fiber is
// fasthttp-based (no net/http request), so the key is the client resolved
// from the connection address with the limiter's TrustedProxies
// (b.CheckPeer); cfg.KeyFunc / cfg.Skip (which take *http.Request) are not
// consulted here.
func BruteForce(b *arcis.BruteForce) fiber.Handler {
	return func(c *fiber.Ctx) error {
		res := b.CheckPeer(peerAddr(c), forwardedFor(c))
		if !res.Allowed {
			retryAfter := int(res.RetryAfter.Seconds())
			if retryAfter < 1 {
				retryAfter = 1
			}
			c.Set("Retry-After", strconv.Itoa(retryAfter))
			return c.Status(b.StatusCode()).JSON(fiber.Map{
				"error":      b.Message(),
				"retryAfter": retryAfter,
			})
		}
		return c.Next()
	}
}

// Overload returns standalone runtime-overload protection middleware that sheds
// requests with 503 when the server is saturated. Build it once, Close() on
// shutdown.
func Overload(o *arcis.Overload) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if o.ExposeLagHeaderEnabled() {
			c.Set("X-EventLoop-Lag", strconv.Itoa(int(o.CurrentLagMs()+0.5)))
		}
		if o.Overloaded() {
			c.Set("Retry-After", strconv.Itoa(o.RetryAfterSeconds()))
			return c.Status(o.StatusCode()).JSON(fiber.Map{
				"error":      o.Message(),
				"retryAfter": o.RetryAfterSeconds(),
			})
		}
		return c.Next()
	}
}

// default sanitizer when the middleware was not in the chain (matches
// the gin / echo / chi GetSanitizer behavior — handlers stay
// panic-safe). The default config enables every vector.
func GetSanitizer(c *fiber.Ctx) *arcis.Sanitizer {
	v := c.Locals(sanitizerLocalKey)
	if v == nil {
		return arcis.NewSanitizer(arcis.DefaultConfig())
	}
	if s, ok := v.(*arcis.Sanitizer); ok {
		return s
	}
	return arcis.NewSanitizer(arcis.DefaultConfig())
}

// Standalone rate-limit middleware. Composes with the fiber pipeline
// for users who want fine-grained control: pair `RateLimit` with the
// granular `Headers` / `Sanitizer` helpers (or hand-rolled middleware)
// instead of the bundle `Middleware`.

// RateLimit returns a standalone rate-limit middleware. Optional
// WithTelemetry attaches a telemetry client that emits on 429.
func RateLimit(max int, window time.Duration, opts ...RateLimitOption) fiber.Handler {
	return RateLimitWithStore(max, window, nil, opts...)
}

// RateLimitWithStore returns a rate-limit middleware backed by an
// external store (Redis, etc.). A nil store uses the in-memory store.
func RateLimitWithStore(max int, window time.Duration, store arcis.RateLimitStore, opts ...RateLimitOption) fiber.Handler {
	return rateLimitHandler(max, window, nil, store, opts...)
}

// RateLimitWithSkip returns a rate-limit middleware that skips counting
// requests for which `skip(c)` returns true (e.g., health checks).
func RateLimitWithSkip(max int, window time.Duration, skip func(*fiber.Ctx) bool, opts ...RateLimitOption) fiber.Handler {
	return rateLimitHandler(max, window, skip, nil, opts...)
}

// rateLimitHandler is the shared body of the standalone rate-limit
// helpers: an optional skip function and an optional store (nil uses the
// in-memory store).
func rateLimitHandler(max int, window time.Duration, skip func(*fiber.Ctx) bool, store arcis.RateLimitStore, opts ...RateLimitOption) fiber.Handler {
	options := &rateLimitOpts{}
	for _, opt := range opts {
		opt(options)
	}
	limiter := newRateLimiter(arcis.RateLimiterOptions{
		Max:            max,
		Window:         window,
		Store:          store,
		TrustedProxies: options.trustedProxies,
		OnStoreError:   options.onStoreError,
	})
	clientIPs := utils.MustClientIPResolver(options.trustedProxies)
	instance := &arcisInstance{rateLimiter: limiter}
	registerInstance(instance)

	return func(c *fiber.Ctx) error {
		if skip != nil && skip(c) {
			return c.Next()
		}
		start := time.Now()
		ip := clientIP(clientIPs, c)
		result := limiter.CheckKey(utils.RateLimitKey(ip))
		c.Set("X-RateLimit-Limit", strconv.Itoa(result.Limit))
		c.Set("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
		c.Set("X-RateLimit-Reset", strconv.Itoa(int(result.Reset.Seconds())))
		if !result.Allowed {
			emitRateLimitDeny(options.telemetry, c, ip, start)
			c.Set("Retry-After", strconv.Itoa(int(result.Reset.Seconds())))
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error":      "Too many requests, please try again later.",
				"retryAfter": int(result.Reset.Seconds()),
			})
		}
		return c.Next()
	}
}
