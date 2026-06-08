package gin

import (
	"bytes"
	"io"
	"strings"

	"github.com/gin-gonic/gin"

	arcis "github.com/getarcis/arcis-go"
)

// improvements.md §1.4 (Go variant) — composite protect factories for Gin.
//
// ProtectLogin / ProtectSignup / ProtectApi return gin.HandlerFunc
// middleware that wire the supplied *arcis.CorrelationWindow into the
// request path. They are THIN composites: no new detection logic lives
// here. Each one extracts the client IP + route from the request, pulls
// the username from the JSON body for credential-stuffing tracking,
// records the event in the window, and aborts with the configured status
// (default 429) when the window flags the IP as a scanner, credential
// stuffer, or race probe.
//
// These do NOT mount the main arcis middleware (sanitize / bot /
// rate-limit / headers). Callers still register arcisgin.Middleware() (or
// MiddlewareWithConfig) for the rest of the pipeline; the protect helper
// adds the stateful correlation layer on the specific route:
//
//	win := arcis.NewCorrelationWindow(arcis.NewCorrelationWindowOptions())
//	r.Use(arcisgin.Middleware())
//	r.POST("/login", arcisgin.ProtectLogin(arcisgin.ProtectOptions{Window: win}), loginHandler)

// ProtectOptions configures the Gin protect factories. Aliased to the
// shared arcis.ProtectOptions so one config struct works across every
// adapter.
type ProtectOptions = arcis.ProtectOptions

// protectClientIP returns the request client IP. Honors X-Forwarded-For
// (first hop) per the documented contract, then falls back to gin's
// native ClientIP() (which itself consults the trusted-proxy chain and
// RemoteAddr). Matching the Node reference's left-most X-Forwarded-For
// behavior keeps the correlation key consistent across SDKs.
func protectClientIP(c *gin.Context) string {
	if xff := c.GetHeader("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			if first := strings.TrimSpace(xff[:i]); first != "" {
				return first
			}
		} else if first := strings.TrimSpace(xff); first != "" {
			return first
		}
	}
	return c.ClientIP()
}

// protectUsername reads the JSON request body, pulls the configured
// username field, and restores the body stream.
//
// WARNING: this reads c.Request.Body, which exhausts the stream. The body
// is restored via io.NopCloser(bytes.NewReader(...)) and Content-Length is
// reset so the downstream handler (and gin's ShouldBindJSON) can re-read
// the same bytes.
func protectUsername(c *gin.Context, field string) string {
	req := c.Request
	ct := req.Header.Get("Content-Type")
	if req.Body == nil || !strings.HasPrefix(ct, "application/json") {
		return ""
	}
	raw, err := io.ReadAll(req.Body)
	if err != nil {
		return ""
	}
	req.Body = io.NopCloser(bytes.NewReader(raw))
	req.ContentLength = int64(len(raw))
	return arcis.ExtractUsername(raw, field)
}

// protect builds the shared Gin middleware for a given vector tag.
func protect(vector string, opts ProtectOptions) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := protectClientIP(c)
		username := protectUsername(c, optsUsernameField(opts))
		route := c.FullPath()
		if route == "" {
			route = c.Request.URL.Path
		}
		decision := arcis.ResolveProtect(opts, vector, ip, route, c.Request.Method, username)
		if decision.Block {
			c.AbortWithStatusJSON(decision.StatusCode, gin.H{
				"error":               decision.Message,
				"scanner":             decision.Scanner,
				"credential_stuffing": decision.CredentialStuffing,
				"race_window":         decision.RaceWindow,
			})
			return
		}
		c.Next()
	}
}

// optsUsernameField returns the configured username field or "username".
func optsUsernameField(opts ProtectOptions) string {
	if opts.UsernameField != "" {
		return opts.UsernameField
	}
	return "username"
}

// ProtectLogin returns a Gin middleware that records login attempts in the
// correlation window and refuses the request (default 429) when the IP is
// flagged as a scanner, credential stuffer, or race probe. Records the
// "login" vector. Wire it on the login route alongside the main
// middleware.
func ProtectLogin(opts ProtectOptions) gin.HandlerFunc {
	return protect(arcis.ProtectVectorLogin, opts)
}

// ProtectSignup returns a Gin middleware that records signup attempts in
// the correlation window. Records the "signup" vector. Same block contract
// as ProtectLogin.
func ProtectSignup(opts ProtectOptions) gin.HandlerFunc {
	return protect(arcis.ProtectVectorSignup, opts)
}

// ProtectApi returns a Gin middleware that records generic API requests in
// the correlation window. Records the "api" vector. Same block contract as
// ProtectLogin.
func ProtectApi(opts ProtectOptions) gin.HandlerFunc {
	return protect(arcis.ProtectVectorApi, opts)
}
