package chi

import (
	"bytes"
	"io"
	"net/http"
	"strings"

	arcis "github.com/getarcis/arcis-go"
)

// improvements.md §1.4 (Go variant) — composite protect factories for chi
// (and any router that accepts stdlib func(http.Handler) http.Handler
// middleware, including raw net/http via the nethttp adapter).
//
// ProtectLogin / ProtectSignup / ProtectApi return stdlib middleware that
// wire the supplied *arcis.CorrelationWindow into the request path. They
// are THIN composites: no new detection logic lives here. Each extracts
// the client IP + route, pulls the username from the JSON body for
// credential-stuffing tracking, records the event, and responds with the
// configured status (default 429) when the window flags the IP as a
// scanner, credential stuffer, or race probe.
//
// These do NOT mount the main arcis middleware. Callers still register
// arcischi.Middleware() for sanitize / bot / rate-limit / headers; the
// protect helper adds the stateful correlation layer on the route:
//
//	win := arcis.NewCorrelationWindow(arcis.NewCorrelationWindowOptions())
//	r.Use(arcischi.Middleware())
//	r.With(arcischi.ProtectLogin(arcischi.ProtectOptions{Window: win})).Post("/login", loginHandler)

// ProtectOptions configures the chi protect factories. Aliased to the
// shared arcis.ProtectOptions so one config struct works across adapters.
type ProtectOptions = arcis.ProtectOptions

// protectClientIP returns the request client IP. Honors X-Forwarded-For
// (first hop) per the documented contract, then falls back to the existing
// clientIP helper (X-Real-IP then the host portion of RemoteAddr). clientIP
// already takes the first XFF hop, so this delegates straight to it.
func protectClientIP(r *http.Request) string {
	return clientIP(r)
}

// protectUsername reads the JSON request body, pulls the configured
// username field, and restores the body stream.
//
// WARNING: this reads r.Body, exhausting the stream. The body is restored
// via io.NopCloser(bytes.NewReader(...)) and Content-Length is reset so
// the downstream handler can re-read the same bytes.
func protectUsername(r *http.Request, field string) string {
	ct := r.Header.Get("Content-Type")
	if r.Body == nil || !strings.HasPrefix(ct, "application/json") {
		return ""
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return ""
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	r.ContentLength = int64(len(raw))
	return arcis.ExtractUsername(raw, field)
}

// protectUsernameField returns the configured username field or "username".
func protectUsernameField(opts ProtectOptions) string {
	if opts.UsernameField != "" {
		return opts.UsernameField
	}
	return "username"
}

// protect builds the shared stdlib middleware for a given vector tag.
func protect(vector string, opts ProtectOptions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := protectClientIP(r)
			username := protectUsername(r, protectUsernameField(opts))
			decision := arcis.ResolveProtect(opts, vector, ip, r.URL.Path, r.Method, username)
			if decision.Block {
				writeJSON(w, decision.StatusCode, map[string]interface{}{
					"error":               decision.Message,
					"scanner":             decision.Scanner,
					"credential_stuffing": decision.CredentialStuffing,
					"race_window":         decision.RaceWindow,
				})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ProtectLogin returns stdlib middleware that records login attempts in the
// correlation window and refuses the request (default 429) when the IP is
// flagged. Records the "login" vector.
func ProtectLogin(opts ProtectOptions) func(http.Handler) http.Handler {
	return protect(arcis.ProtectVectorLogin, opts)
}

// ProtectSignup returns stdlib middleware that records signup attempts in
// the correlation window. Records the "signup" vector.
func ProtectSignup(opts ProtectOptions) func(http.Handler) http.Handler {
	return protect(arcis.ProtectVectorSignup, opts)
}

// ProtectApi returns stdlib middleware that records generic API requests in
// the correlation window. Records the "api" vector.
func ProtectApi(opts ProtectOptions) func(http.Handler) http.Handler {
	return protect(arcis.ProtectVectorApi, opts)
}
