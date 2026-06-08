package fiber

import (
	"strings"

	"github.com/gofiber/fiber/v2"

	arcis "github.com/getarcis/arcis-go"
)

// improvements.md §1.4 (Go variant) — composite protect factories for
// Fiber v2.
//
// ProtectLogin / ProtectSignup / ProtectApi return fiber.Handler values
// that wire the supplied *arcis.CorrelationWindow into the request path.
// They are THIN composites: no new detection logic lives here. Each
// extracts the client IP + route, pulls the username from the JSON body
// for credential-stuffing tracking, records the event, and returns the
// configured status (default 429) when the window flags the IP as a
// scanner, credential stuffer, or race probe.
//
// These do NOT mount the main arcis middleware. Callers still register
// arcisfiber.Middleware() for sanitize / bot / rate-limit / headers; the
// protect helper adds the stateful correlation layer on the route:
//
//	win := arcis.NewCorrelationWindow(arcis.NewCorrelationWindowOptions())
//	app.Use(arcisfiber.Middleware())
//	app.Post("/login", arcisfiber.ProtectLogin(arcisfiber.ProtectOptions{Window: win}), loginHandler)

// ProtectOptions configures the Fiber protect factories. Aliased to the
// shared arcis.ProtectOptions so one config struct works across adapters.
type ProtectOptions = arcis.ProtectOptions

// protectClientIP returns the request client IP. Honors X-Forwarded-For
// (first hop) per the documented contract, then falls back to fiber's
// native c.IP() (which honours fiber's TrustedProxies config).
func protectClientIP(c *fiber.Ctx) string {
	if xff := c.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			if first := strings.TrimSpace(xff[:i]); first != "" {
				return first
			}
		} else if first := strings.TrimSpace(xff); first != "" {
			return first
		}
	}
	return c.IP()
}

// protectUsernameField returns the configured username field or "username".
func protectUsernameField(opts ProtectOptions) string {
	if opts.UsernameField != "" {
		return opts.UsernameField
	}
	return "username"
}

// protect builds the shared Fiber middleware for a given vector tag.
//
// Note: fasthttp buffers the request body, so c.Body() returns the bytes
// without consuming a stream. There is nothing to restore. The username
// extraction reads the same buffer the downstream handler's c.BodyParser
// reads, so the body stays intact.
func protect(vector string, opts ProtectOptions) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ip := protectClientIP(c)
		username := ""
		if strings.HasPrefix(c.Get("Content-Type"), "application/json") {
			username = arcis.ExtractUsername(c.Body(), protectUsernameField(opts))
		}
		route := c.Route().Path
		if route == "" {
			route = c.Path()
		}
		decision := arcis.ResolveProtect(opts, vector, ip, route, c.Method(), username)
		if decision.Block {
			return c.Status(decision.StatusCode).JSON(fiber.Map{
				"error":               decision.Message,
				"scanner":             decision.Scanner,
				"credential_stuffing": decision.CredentialStuffing,
				"race_window":         decision.RaceWindow,
			})
		}
		return c.Next()
	}
}

// ProtectLogin returns a Fiber middleware that records login attempts in
// the correlation window and refuses the request (default 429) when the IP
// is flagged. Records the "login" vector.
func ProtectLogin(opts ProtectOptions) fiber.Handler {
	return protect(arcis.ProtectVectorLogin, opts)
}

// ProtectSignup returns a Fiber middleware that records signup attempts in
// the correlation window. Records the "signup" vector.
func ProtectSignup(opts ProtectOptions) fiber.Handler {
	return protect(arcis.ProtectVectorSignup, opts)
}

// ProtectApi returns a Fiber middleware that records generic API requests
// in the correlation window. Records the "api" vector.
func ProtectApi(opts ProtectOptions) fiber.Handler {
	return protect(arcis.ProtectVectorApi, opts)
}
