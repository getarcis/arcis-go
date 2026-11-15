package middleware

import (
	"context"
	"fmt"
	"net/http"

	"github.com/getarcis/arcis-go/core"
)

// SecurityHeaders handles security header configuration and application.
// Build one at startup and call Apply for every response.
type SecurityHeaders struct {
	headers map[string]string

	// csp is set when the baseline CSP differs per response (nonce or
	// function values). Apply renders it; it is not in headers.
	csp *cspPolicy

	// keepPoweredBy is true when the baseline profile disables
	// X-Powered-By removal.
	keepPoweredBy bool
}

// CompileSecurityHeaders builds the header set selected by
// config.HeaderProfile: the legacy profile from the CSP, FrameOptions,
// HSTSMaxAge, ... fields, or the baseline profile from
// config.BaselineHeaders. It returns an error for an unknown profile or
// an invalid baseline configuration.
func CompileSecurityHeaders(config core.Config) (*SecurityHeaders, error) {
	switch config.HeaderProfile {
	case "", core.HeaderProfileLegacy:
		return NewSecurityHeaders(config), nil
	case core.HeaderProfileBaseline:
		return NewBaselineSecurityHeaders(config.BaselineHeaders)
	}
	return nil, fmt.Errorf("security headers received an unknown profile %q", config.HeaderProfile)
}

// NewSecurityHeaders creates a new SecurityHeaders with the given
// configuration. It always builds the legacy profile; use
// CompileSecurityHeaders to honor config.HeaderProfile.
func NewSecurityHeaders(config core.Config) *SecurityHeaders {
	headers := make(map[string]string)

	if config.CSP != "" {
		headers["Content-Security-Policy"] = config.CSP
	}

	headers["X-Content-Type-Options"] = "nosniff"

	if config.FrameOptions != "" {
		headers["X-Frame-Options"] = config.FrameOptions
	}

	// X-XSS-Protection: 0 disables the legacy XSS auditor which was itself
	// an attack vector (could be abused to selectively block legitimate scripts)
	headers["X-XSS-Protection"] = "0"

	if config.HSTSMaxAge > 0 {
		hsts := fmt.Sprintf("max-age=%d", config.HSTSMaxAge)
		if config.HSTSSubdomains {
			hsts += "; includeSubDomains"
		}
		headers["Strict-Transport-Security"] = hsts
	}

	if config.ReferrerPolicy != "" {
		headers["Referrer-Policy"] = config.ReferrerPolicy
	}

	if config.PermissionsPolicy != "" {
		headers["Permissions-Policy"] = config.PermissionsPolicy
	}

	headers["X-Permitted-Cross-Domain-Policies"] = "none"

	// Cross-origin isolation headers (Spectre mitigation)
	if config.CrossOriginOpenerPolicy != "" {
		headers["Cross-Origin-Opener-Policy"] = config.CrossOriginOpenerPolicy
	}

	if config.CrossOriginResourcePolicy != "" {
		headers["Cross-Origin-Resource-Policy"] = config.CrossOriginResourcePolicy
	}

	if config.CrossOriginEmbedderPolicy != "" {
		headers["Cross-Origin-Embedder-Policy"] = config.CrossOriginEmbedderPolicy
	}

	// Request origin-keyed process isolation
	if config.OriginAgentCluster {
		headers["Origin-Agent-Cluster"] = "?1"
	}

	// Prevent DNS prefetching (privacy leak vector)
	if config.DNSPrefetchControl {
		headers["X-DNS-Prefetch-Control"] = "off"
	}

	if config.CacheControl {
		cacheControlValue := config.CacheControlValue
		if cacheControlValue == "" {
			cacheControlValue = "no-store, no-cache, must-revalidate, proxy-revalidate"
		}
		headers["Cache-Control"] = cacheControlValue
		headers["Pragma"] = "no-cache"
		headers["Expires"] = "0"
	}

	return &SecurityHeaders{headers: headers}
}

// GetHeaders returns the security headers as a map. A baseline
// Content-Security-Policy that uses a nonce or function values is
// computed per response by Apply and is not included.
func (sh *SecurityHeaders) GetHeaders() map[string]string {
	return sh.headers
}

// Apply sets the security headers for one response on h, removes
// X-Powered-By unless the profile keeps it, and returns the request the
// next handler should receive. When the CSP nonce is enabled, the
// returned request's context carries a fresh nonce (read it with
// CSPNonce) and the same value is in the header.
//
// r must be non-nil when Dynamic reports true; otherwise it is returned
// unchanged. The error is non-nil only when a CSP function value returns
// an invalid entry; the caller should fail the request.
func (sh *SecurityHeaders) Apply(h http.Header, r *http.Request) (*http.Request, error) {
	for name, value := range sh.headers {
		h.Set(name, value)
	}
	if !sh.keepPoweredBy {
		h.Del("X-Powered-By")
	}
	if sh.csp == nil {
		return r, nil
	}
	var nonce string
	if sh.csp.nonce {
		nonce = newCSPNonce()
		r = r.WithContext(context.WithValue(r.Context(), cspNonceKey{}, nonce))
	}
	value, err := sh.csp.render(r, nonce)
	if err != nil {
		return r, err
	}
	h.Set(sh.csp.headerName, value)
	return r, nil
}

// Dynamic reports whether Apply computes Content-Security-Policy per
// request (baseline nonce or function values) and so needs the request.
func (sh *SecurityHeaders) Dynamic() bool {
	return sh.csp != nil
}

// RemovesPoweredBy reports whether X-Powered-By is stripped from
// responses. It is false only when the baseline profile disables it.
func (sh *SecurityHeaders) RemovesPoweredBy() bool {
	return !sh.keepPoweredBy
}

// SetHeader sets or overrides a specific header.
func (sh *SecurityHeaders) SetHeader(key, value string) {
	sh.headers[key] = value
}

// RemoveHeader removes a specific header.
func (sh *SecurityHeaders) RemoveHeader(key string) {
	delete(sh.headers, key)
}
