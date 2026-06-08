package nethttp

import (
	"net/http"

	arcis "github.com/getarcis/arcis-go"
	arcischi "github.com/getarcis/arcis-go/chi"
)

// improvements.md §1.4 (Go variant) — composite protect factories for
// plain net/http. Re-exports the chi implementation (which is stdlib-only)
// so net/http users get the same correlation-window wiring without
// importing chi directly.
//
//	win := arcis.NewCorrelationWindow(arcis.NewCorrelationWindowOptions())
//	mux := http.NewServeMux()
//	mux.Handle("/login", archttp.ProtectLogin(archttp.ProtectOptions{Window: win})(loginHandler))

// ProtectOptions configures the net/http protect factories. Aliased to the
// shared arcis.ProtectOptions so one config struct works across adapters.
type ProtectOptions = arcis.ProtectOptions

// ProtectLogin returns stdlib middleware that records login attempts in the
// correlation window and refuses the request (default 429) when the IP is
// flagged as a scanner, credential stuffer, or race probe. Records the
// "login" vector.
func ProtectLogin(opts ProtectOptions) func(http.Handler) http.Handler {
	return arcischi.ProtectLogin(opts)
}

// ProtectSignup returns stdlib middleware that records signup attempts in
// the correlation window. Records the "signup" vector.
func ProtectSignup(opts ProtectOptions) func(http.Handler) http.Handler {
	return arcischi.ProtectSignup(opts)
}

// ProtectApi returns stdlib middleware that records generic API requests in
// the correlation window. Records the "api" vector.
func ProtectApi(opts ProtectOptions) func(http.Handler) http.Handler {
	return arcischi.ProtectApi(opts)
}
