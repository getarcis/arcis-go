package echo

import (
	"bytes"
	"io"
	"strings"

	"github.com/labstack/echo/v4"

	arcis "github.com/getarcis/arcis-go"
)

// improvements.md §1.4 (Go variant) — composite protect factories for Echo.
//
// ProtectLogin / ProtectSignup / ProtectApi return echo.MiddlewareFunc
// values that wire the supplied *arcis.CorrelationWindow into the request
// path. They are THIN composites: no new detection logic lives here. Each
// extracts the client IP + route, pulls the username from the JSON body
// for credential-stuffing tracking, records the event, and returns the
// configured status (default 429) when the window flags the IP as a
// scanner, credential stuffer, or race probe.
//
// These do NOT mount the main arcis middleware. Callers still register
// arcisecho.Middleware() for sanitize / bot / rate-limit / headers; the
// protect helper adds the stateful correlation layer on the route:
//
//	win := arcis.NewCorrelationWindow(arcis.NewCorrelationWindowOptions())
//	e.Use(arcisecho.Middleware())
//	e.POST("/login", loginHandler, arcisecho.ProtectLogin(arcisecho.ProtectOptions{Window: win}))

// ProtectOptions configures the Echo protect factories. Aliased to the
// shared arcis.ProtectOptions so one config struct works across adapters.
type ProtectOptions = arcis.ProtectOptions

// protectClientIP returns the request client IP. Honors X-Forwarded-For
// (first hop) per the documented contract, then falls back to echo's
// native RealIP().
func protectClientIP(c echo.Context) string {
	if xff := c.Request().Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			if first := strings.TrimSpace(xff[:i]); first != "" {
				return first
			}
		} else if first := strings.TrimSpace(xff); first != "" {
			return first
		}
	}
	return c.RealIP()
}

// protectUsername reads the JSON request body, pulls the configured
// username field, and restores the body stream.
//
// WARNING: this reads c.Request().Body, exhausting the stream. The body is
// restored via io.NopCloser(bytes.NewReader(...)) and Content-Length is
// reset so the downstream handler (and echo's c.Bind) can re-read it.
func protectUsername(c echo.Context, field string) string {
	req := c.Request()
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

// protectUsernameField returns the configured username field or "username".
func protectUsernameField(opts ProtectOptions) string {
	if opts.UsernameField != "" {
		return opts.UsernameField
	}
	return "username"
}

// protect builds the shared Echo middleware for a given vector tag.
func protect(vector string, opts ProtectOptions) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			ip := protectClientIP(c)
			username := protectUsername(c, protectUsernameField(opts))
			route := c.Path()
			if route == "" {
				route = c.Request().URL.Path
			}
			decision := arcis.ResolveProtect(opts, vector, ip, route, c.Request().Method, username)
			if decision.Block {
				return c.JSON(decision.StatusCode, map[string]interface{}{
					"error":               decision.Message,
					"scanner":             decision.Scanner,
					"credential_stuffing": decision.CredentialStuffing,
					"race_window":         decision.RaceWindow,
				})
			}
			return next(c)
		}
	}
}

// ProtectLogin returns Echo middleware that records login attempts in the
// correlation window and refuses the request (default 429) when the IP is
// flagged. Records the "login" vector.
func ProtectLogin(opts ProtectOptions) echo.MiddlewareFunc {
	return protect(arcis.ProtectVectorLogin, opts)
}

// ProtectSignup returns Echo middleware that records signup attempts in the
// correlation window. Records the "signup" vector.
func ProtectSignup(opts ProtectOptions) echo.MiddlewareFunc {
	return protect(arcis.ProtectVectorSignup, opts)
}

// ProtectApi returns Echo middleware that records generic API requests in
// the correlation window. Records the "api" vector.
func ProtectApi(opts ProtectOptions) echo.MiddlewareFunc {
	return protect(arcis.ProtectVectorApi, opts)
}
