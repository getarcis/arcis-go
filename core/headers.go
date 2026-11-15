package core

import "net/http"

// HeaderProfile selects the security header defaults. See
// spec/API_SPEC.md section "3. Security Headers".
type HeaderProfile string

const (
	// HeaderProfileLegacy is the historical Arcis header set, configured
	// by the CSP, FrameOptions, HSTSMaxAge, ... fields of Config. It is
	// the default; the empty string selects it too.
	HeaderProfileLegacy HeaderProfile = "legacy"

	// HeaderProfileBaseline matches the defaults and options of Helmet
	// 8.3.0 plus Arcis extensions, configured by Config.BaselineHeaders.
	HeaderProfileBaseline HeaderProfile = "baseline"
)

// BaselineHeaderOptions configures the baseline header profile. The zero
// value sends the Helmet 8 defaults:
//
//	Content-Security-Policy: default-src 'self';base-uri 'self';...
//	Cross-Origin-Opener-Policy: same-origin
//	Cross-Origin-Resource-Policy: same-origin
//	Origin-Agent-Cluster: ?1
//	Referrer-Policy: no-referrer
//	Strict-Transport-Security: max-age=31536000; includeSubDomains
//	X-Content-Type-Options: nosniff
//	X-DNS-Prefetch-Control: off
//	X-Download-Options: noopen
//	X-Frame-Options: SAMEORIGIN
//	X-Permitted-Cross-Domain-Policies: none
//	X-XSS-Protection: 0
//
// and removes X-Powered-By. Strict-Transport-Security is sent on every
// response; browsers ignore it over plain HTTP (RFC 6797 section 8.1).
type BaselineHeaderOptions struct {
	// Disable lists headers to leave out, by name (case-insensitive),
	// like passing false for a Helmet option. Listing "X-Powered-By"
	// leaves the application's X-Powered-By header untouched. Unknown
	// names are a configuration error.
	Disable []string

	// ContentSecurityPolicy configures Content-Security-Policy.
	ContentSecurityPolicy CSPOptions

	// CrossOriginEmbedderPolicy is "require-corp", "credentialless" or
	// "unsafe-none". Empty (the default) sends no header, because COEP
	// breaks third-party embeds.
	CrossOriginEmbedderPolicy string

	// CrossOriginOpenerPolicy is "same-origin" (the default when empty),
	// "same-origin-allow-popups", "noopener-allow-popups" or "unsafe-none".
	CrossOriginOpenerPolicy string

	// CrossOriginResourcePolicy is "same-origin" (the default when
	// empty), "same-site" or "cross-origin".
	CrossOriginResourcePolicy string

	// ReferrerPolicy lists Referrer-Policy tokens, joined with ",". Nil
	// sends "no-referrer". A non-nil empty slice is a configuration error.
	ReferrerPolicy []string

	// StrictTransportSecurity configures Strict-Transport-Security.
	StrictTransportSecurity HSTSOptions

	// AllowDNSPrefetch sends "X-DNS-Prefetch-Control: on" instead of "off".
	AllowDNSPrefetch bool

	// XFrameOptions is the X-Frame-Options action: "sameorigin" (the
	// default when empty) or "deny". Case-insensitive; "same-origin" is
	// accepted.
	XFrameOptions string

	// XPermittedCrossDomainPolicies is "none" (the default when empty),
	// "master-only", "by-content-type" or "all".
	XPermittedCrossDomainPolicies string

	// PermissionsPolicy (Arcis extension) sends Permissions-Policy with
	// the features in order. Nil sends no header; a non-nil empty slice
	// is a configuration error.
	PermissionsPolicy []PermissionsPolicyFeature

	// ReportingEndpoints (Arcis extension) sends Reporting-Endpoints with
	// the endpoints in order. Nil sends no header; a non-nil empty slice
	// is a configuration error.
	ReportingEndpoints []ReportingEndpoint
}

// CSPOptions configures Content-Security-Policy in the baseline profile.
// The zero value sends Helmet's default policy.
type CSPOptions struct {
	// DisableDefaults starts from an empty policy instead of the default
	// directives (Helmet useDefaults: false).
	DisableDefaults bool

	// Directives are merged into the policy in order. A directive that
	// overrides a default keeps the default's position; new directives
	// are appended.
	Directives []CSPDirective

	// ReportOnly sends Content-Security-Policy-Report-Only instead.
	ReportOnly bool

	// Nonce generates a fresh nonce (16 random bytes, base64) for every
	// response and appends 'nonce-<value>' to script-src. Handlers read
	// it with arcis.CSPNonce(ctx). Requires a script-src directive.
	Nonce bool

	// DangerouslyDisableDefaultSrc removes default-src from the policy.
	DangerouslyDisableDefaultSrc bool
}

// CSPDirective is one Content-Security-Policy directive.
type CSPDirective struct {
	// Name is the directive name in kebab-case ("script-src") or
	// camelCase ("scriptSrc").
	Name string

	// Values are the directive's source expressions. Keywords such as
	// 'self' and 'none' must be quoted. No values emits the bare name.
	Values []string

	// Funcs are evaluated for every response and appended after Values.
	// An invalid result fails that request through the adapter's error
	// path.
	Funcs []func(*http.Request) string

	// Remove drops a default directive. default-src can only be removed
	// with CSPOptions.DangerouslyDisableDefaultSrc.
	Remove bool
}

// HSTSOptions configures Strict-Transport-Security in the baseline
// profile. The zero value sends "max-age=31536000; includeSubDomains".
type HSTSOptions struct {
	// MaxAge in seconds. Nil uses 31536000 (one year); 0 asks browsers
	// to forget the HSTS policy. Negative values are a configuration error.
	MaxAge *int

	// ExcludeSubDomains omits the includeSubDomains directive.
	ExcludeSubDomains bool

	// Preload adds the preload directive.
	Preload bool
}

// PermissionsPolicyFeature is one Permissions-Policy feature and its
// allowlist. Allowlist entries are "self", "src", "*" or an http(s)
// origin such as "https://maps.example.com". An empty allowlist disables
// the feature: camera=().
type PermissionsPolicyFeature struct {
	Name      string
	Allowlist []string
}

// ReportingEndpoint is one Reporting-Endpoints entry. Name is referenced
// from CSP report-to; URL must be https.
type ReportingEndpoint struct {
	Name string
	URL  string
}
