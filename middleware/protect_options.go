package middleware

import (
	"encoding/json"
	"time"
)

// improvements.md §1.4 (Go variant) — shared options for the per-framework
// ProtectLogin / ProtectSignup / ProtectApi factory helpers.
//
// These factories are THIN composite wrappers: no new detection logic
// lives here. Each adapter (gin / echo / chi / fiber / nethttp) builds a
// framework-native middleware that:
//
//   - extracts the client IP (X-Forwarded-For first hop, then the
//     framework's native client-IP / RemoteAddr),
//   - extracts the route / path,
//   - pulls a distinct value (username / email) from the configured JSON
//     body field, restoring the body stream so downstream handlers can
//     re-read it,
//   - records the event in the supplied *CorrelationWindow (when one is
//     given) and refuses the request with the configured status when the
//     window flags the IP as a scanner, credential stuffer, or race probe.
//
// The window is the only stateful primitive in the chain. When no window
// is supplied the factory is a pass-through (it still extracts IP / route
// but has nothing to record against), so callers must still mount the
// main arcis middleware for sanitize / bot / rate-limit coverage.

// ProtectOptions configures the correlation wiring shared by every
// adapter's ProtectLogin / ProtectSignup / ProtectApi helper.
//
// Defined once here so all five adapters import the same type (no import
// cycle: adapters already depend on the root arcis package, which
// re-exports this as arcis.ProtectOptions, and each adapter re-exports it
// under its own name for ergonomics).
type ProtectOptions struct {
	// Window is the per-IP correlation window the factory records every
	// request against. When nil the factory becomes a pass-through: it
	// records nothing and never blocks (callers still mount the main
	// arcis middleware for the rest of the pipeline).
	Window *CorrelationWindow

	// UsernameField is the JSON body key whose value is tracked as the
	// distinct value for credential-stuffing detection. Empty defaults to
	// "username".
	UsernameField string

	// StatusCode is the HTTP status written when the window flags the
	// request. Zero defaults to 429 (Too Many Requests).
	StatusCode int

	// Message is the value of the JSON "error" field in the block
	// response. Empty defaults to "Suspicious request pattern detected.".
	Message string
}

// Vector tags recorded in the correlation window per endpoint shape.
const (
	ProtectVectorLogin  = "login"
	ProtectVectorSignup = "signup"
	ProtectVectorApi    = "api"
)

// usernameFieldOr returns the configured username field or the default.
func (o ProtectOptions) usernameFieldOr() string {
	if o.UsernameField != "" {
		return o.UsernameField
	}
	return "username"
}

// statusCodeOr returns the configured status code or the 429 default.
func (o ProtectOptions) statusCodeOr() int {
	if o.StatusCode != 0 {
		return o.StatusCode
	}
	return 429
}

// messageOr returns the configured message or the default.
func (o ProtectOptions) messageOr() string {
	if o.Message != "" {
		return o.Message
	}
	return "Suspicious request pattern detected."
}

// ExtractUsername pulls the distinct value (username / email) out of a
// JSON request body for credential-stuffing tracking. raw is the request
// body bytes; field is the JSON key to read (use usernameFieldOr for the
// default). Returns "" when the body is not a JSON object, the key is
// absent, or the value is not a non-empty string.
//
// This works on raw bytes so each adapter owns its own body read +
// restore: the *http.Request adapters io.ReadAll + reset r.Body, fiber
// reads the already-buffered c.Body(). The function never reads a stream
// itself, so it cannot exhaust one.
func ExtractUsername(raw []byte, field string) string {
	if len(raw) == 0 {
		return ""
	}
	if field == "" {
		field = "username"
	}
	var parsed map[string]interface{}
	if json.Unmarshal(raw, &parsed) != nil {
		return ""
	}
	v, ok := parsed[field]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return ""
	}
	return s
}

// ProtectDecision is the resolved verdict for one request after recording
// it in the correlation window. Adapters call ResolveProtect to compute it
// and then translate Block + the detection booleans into a framework-
// native 429 (or pass the request to the next handler).
type ProtectDecision struct {
	// Block is true when the window flagged the IP. The adapter writes the
	// configured status + JSON body and stops the chain.
	Block bool

	// StatusCode + Message are the resolved response shape (defaults
	// applied) so adapters do not re-derive them.
	StatusCode int
	Message    string

	// The three detection booleans, surfaced in the JSON body so
	// operators can graph which signal fired.
	Scanner            bool
	CredentialStuffing bool
	RaceWindow         bool
}

// ResolveProtect records one request in the options' correlation window
// (when configured) and returns the resulting decision. It is the shared
// core every adapter's ProtectLogin / ProtectSignup / ProtectApi calls so
// the block threshold logic lives in exactly one place.
//
// vector is the endpoint tag (ProtectVectorLogin / Signup / Api). ip /
// route / method are extracted by the adapter from the framework request.
// distinctValue is the username pulled from the body (empty when absent).
//
// When opts.Window is nil, or ip is empty, the request is allowed
// (Block=false) and nothing is recorded.
func ResolveProtect(opts ProtectOptions, vector, ip, route, method, distinctValue string) ProtectDecision {
	decision := ProtectDecision{
		StatusCode: opts.statusCodeOr(),
		Message:    opts.messageOr(),
	}
	if opts.Window == nil || ip == "" {
		return decision
	}
	// Pass the zero time.Time so the window stamps time.Now() itself.
	detections := opts.Window.Record(ip, vector, route, method, distinctValue, time.Time{})
	decision.Scanner = detections.Scanner
	decision.CredentialStuffing = detections.CredentialStuffing
	decision.RaceWindow = detections.RaceWindow
	decision.Block = detections.Scanner || detections.CredentialStuffing || detections.RaceWindow
	return decision
}
