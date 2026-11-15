package middleware

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/getarcis/arcis-go/core"
)

// baselineHeaderNames are the headers BaselineHeaderOptions.Disable accepts.
var baselineHeaderNames = []string{
	"Content-Security-Policy",
	"Cross-Origin-Embedder-Policy",
	"Cross-Origin-Opener-Policy",
	"Cross-Origin-Resource-Policy",
	"Origin-Agent-Cluster",
	"Referrer-Policy",
	"Strict-Transport-Security",
	"X-Content-Type-Options",
	"X-DNS-Prefetch-Control",
	"X-Download-Options",
	"X-Frame-Options",
	"X-Permitted-Cross-Domain-Policies",
	"X-Powered-By",
	"X-XSS-Protection",
}

// defaultHSTSMaxAge is one year, in seconds.
const defaultHSTSMaxAge = 31536000

// NewBaselineSecurityHeaders validates opts and returns the baseline
// (Helmet 8 compatible) header set. All configuration errors are
// reported here, so a mistake fails at startup rather than per request.
func NewBaselineSecurityHeaders(opts core.BaselineHeaderOptions) (*SecurityHeaders, error) {
	disabled := make(map[string]bool, len(opts.Disable))
	for _, name := range opts.Disable {
		i := slices.IndexFunc(baselineHeaderNames, func(known string) bool { return strings.EqualFold(known, name) })
		if i < 0 {
			return nil, fmt.Errorf("security headers cannot disable unknown header %q", name)
		}
		disabled[baselineHeaderNames[i]] = true
	}

	sh := &SecurityHeaders{headers: make(map[string]string), keepPoweredBy: disabled["X-Powered-By"]}

	if !disabled["Content-Security-Policy"] {
		csp, err := compileCSP(opts.ContentSecurityPolicy)
		if err != nil {
			return nil, err
		}
		if csp.dynamic() {
			sh.csp = csp
		} else {
			// No function values, so rendering cannot fail.
			sh.headers[csp.headerName], _ = csp.render(nil, "")
		}
	}

	fixed := func(value string) func() (string, error) {
		return func() (string, error) { return value, nil }
	}
	dnsPrefetch := "off"
	if opts.AllowDNSPrefetch {
		dnsPrefetch = "on"
	}
	headers := []struct {
		name  string
		send  bool
		value func() (string, error)
	}{
		{"Cross-Origin-Embedder-Policy", opts.CrossOriginEmbedderPolicy != "", func() (string, error) {
			return oneOf("Cross-Origin-Embedder-Policy", opts.CrossOriginEmbedderPolicy, "", "require-corp", "credentialless", "unsafe-none")
		}},
		{"Cross-Origin-Opener-Policy", true, func() (string, error) {
			return oneOf("Cross-Origin-Opener-Policy", opts.CrossOriginOpenerPolicy, "same-origin", "same-origin", "same-origin-allow-popups", "noopener-allow-popups", "unsafe-none")
		}},
		{"Cross-Origin-Resource-Policy", true, func() (string, error) {
			return oneOf("Cross-Origin-Resource-Policy", opts.CrossOriginResourcePolicy, "same-origin", "same-origin", "same-site", "cross-origin")
		}},
		{"Origin-Agent-Cluster", true, fixed("?1")},
		{"Referrer-Policy", true, func() (string, error) { return referrerPolicyValue(opts.ReferrerPolicy) }},
		// Sent on every response, like Helmet. Browsers ignore HSTS received
		// over plain HTTP (RFC 6797 section 8.1), so no HTTPS detection.
		{"Strict-Transport-Security", true, func() (string, error) { return hstsValue(opts.StrictTransportSecurity) }},
		{"X-Content-Type-Options", true, fixed("nosniff")},
		{"X-DNS-Prefetch-Control", true, fixed(dnsPrefetch)},
		{"X-Download-Options", true, fixed("noopen")},
		{"X-Frame-Options", true, func() (string, error) { return frameOptionsValue(opts.XFrameOptions) }},
		{"X-Permitted-Cross-Domain-Policies", true, func() (string, error) {
			return crossDomainValue(opts.XPermittedCrossDomainPolicies)
		}},
		// "0" disables the legacy XSS auditor, which was itself an attack vector.
		{"X-XSS-Protection", true, fixed("0")},
		{"Permissions-Policy", opts.PermissionsPolicy != nil, func() (string, error) {
			return permissionsPolicyValue(opts.PermissionsPolicy)
		}},
		{"Reporting-Endpoints", opts.ReportingEndpoints != nil, func() (string, error) {
			return reportingEndpointsValue(opts.ReportingEndpoints)
		}},
	}
	for _, header := range headers {
		if !header.send || disabled[header.name] {
			continue
		}
		value, err := header.value()
		if err != nil {
			return nil, err
		}
		sh.headers[header.name] = value
	}
	return sh, nil
}

// oneOf returns value, or fallback when value is empty, if it is allowed.
func oneOf(header, value, fallback string, allowed ...string) (string, error) {
	if value == "" {
		value = fallback
	}
	if !slices.Contains(allowed, value) {
		return "", fmt.Errorf("%s does not support the %q policy", header, value)
	}
	return value, nil
}

var referrerTokens = []string{
	"no-referrer",
	"no-referrer-when-downgrade",
	"same-origin",
	"origin",
	"strict-origin",
	"origin-when-cross-origin",
	"strict-origin-when-cross-origin",
	"unsafe-url",
	"",
}

func referrerPolicyValue(tokens []string) (string, error) {
	if tokens == nil {
		return "no-referrer", nil
	}
	if len(tokens) == 0 {
		return "", errors.New("Referrer-Policy received no policy tokens")
	}
	for i, token := range tokens {
		if !slices.Contains(referrerTokens, token) {
			return "", fmt.Errorf("Referrer-Policy received an unexpected policy token %q", token)
		}
		if slices.Contains(tokens[:i], token) {
			return "", fmt.Errorf("Referrer-Policy received a duplicate policy token %q", token)
		}
	}
	return strings.Join(tokens, ","), nil
}

func hstsValue(opts core.HSTSOptions) (string, error) {
	maxAge := defaultHSTSMaxAge
	if opts.MaxAge != nil {
		maxAge = *opts.MaxAge
	}
	if maxAge < 0 {
		return "", fmt.Errorf("Strict-Transport-Security: %d is not a valid value for MaxAge. Please choose a positive integer", maxAge)
	}
	value := "max-age=" + strconv.Itoa(maxAge)
	if !opts.ExcludeSubDomains {
		value += "; includeSubDomains"
	}
	if opts.Preload {
		value += "; preload"
	}
	return value, nil
}

func frameOptionsValue(action string) (string, error) {
	if action == "" {
		return "SAMEORIGIN", nil
	}
	switch strings.ToUpper(action) {
	case "DENY":
		return "DENY", nil
	case "SAMEORIGIN", "SAME-ORIGIN":
		return "SAMEORIGIN", nil
	}
	return "", fmt.Errorf("X-Frame-Options received an invalid action %q", action)
}

func crossDomainValue(value string) (string, error) {
	if value == "" {
		return "none", nil
	}
	if !slices.Contains([]string{"none", "master-only", "by-content-type", "all"}, value) {
		return "", fmt.Errorf("X-Permitted-Cross-Domain-Policies does not support %q", value)
	}
	return value, nil
}

// Permissions-Policy is a structured-field dictionary: feature=(allowlist).
var permissionsFeatureName = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

func permissionsPolicyValue(features []core.PermissionsPolicyFeature) (string, error) {
	if len(features) == 0 {
		return "", errors.New("Permissions-Policy received no features")
	}
	parts := make([]string, 0, len(features))
	for i, feature := range features {
		if !permissionsFeatureName.MatchString(feature.Name) {
			return "", fmt.Errorf("Permissions-Policy received an invalid feature name %q", feature.Name)
		}
		if slices.ContainsFunc(features[:i], func(f core.PermissionsPolicyFeature) bool { return f.Name == feature.Name }) {
			return "", fmt.Errorf("Permissions-Policy received a duplicate feature %q", feature.Name)
		}
		items := make([]string, 0, len(feature.Allowlist))
		for _, item := range feature.Allowlist {
			switch item {
			case "self", "src", "*":
				items = append(items, item)
				continue
			}
			if !isSerializedOrigin(item) {
				return "", fmt.Errorf("Permissions-Policy received an invalid origin %q", item)
			}
			items = append(items, `"`+item+`"`)
		}
		parts = append(parts, feature.Name+"=("+strings.Join(items, " ")+")")
	}
	return strings.Join(parts, ", "), nil
}

// isSerializedOrigin reports whether value is exactly an http(s) origin
// as browsers serialize it: lowercase host, no default port, no path.
// SECURITY: origins are emitted inside a quoted structured-field string,
// so quotes, spaces and delimiters must never get through.
func isSerializedOrigin(value string) bool {
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.Scheme+"://"+u.Host != value {
		return false
	}
	port := u.Port()
	if strings.HasSuffix(u.Host, ":") || (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		return false
	}
	for _, r := range u.Hostname() {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == ':') {
			return false
		}
	}
	return true
}

var reportingEndpointName = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)

func reportingEndpointsValue(endpoints []core.ReportingEndpoint) (string, error) {
	if len(endpoints) == 0 {
		return "", errors.New("Reporting-Endpoints received no endpoints")
	}
	parts := make([]string, 0, len(endpoints))
	for i, endpoint := range endpoints {
		if !reportingEndpointName.MatchString(endpoint.Name) {
			return "", fmt.Errorf("Reporting-Endpoints received an invalid endpoint name %q", endpoint.Name)
		}
		if slices.ContainsFunc(endpoints[:i], func(e core.ReportingEndpoint) bool { return e.Name == endpoint.Name }) {
			return "", fmt.Errorf("Reporting-Endpoints received a duplicate endpoint %q", endpoint.Name)
		}
		u, err := url.Parse(endpoint.URL)
		if err != nil || u.Host == "" {
			return "", fmt.Errorf("Reporting-Endpoints received an invalid URL for %q", endpoint.Name)
		}
		// Browsers only deliver reports to secure endpoints. The URL is
		// emitted inside a quoted string, so quotes, backslashes and
		// whitespace are rejected.
		if u.Scheme != "https" || strings.ContainsAny(endpoint.URL, `"\`) || strings.IndexFunc(endpoint.URL, unicode.IsSpace) >= 0 {
			return "", fmt.Errorf("Reporting-Endpoints requires an https URL for %q", endpoint.Name)
		}
		parts = append(parts, endpoint.Name+`="`+endpoint.URL+`"`)
	}
	return strings.Join(parts, ", "), nil
}
