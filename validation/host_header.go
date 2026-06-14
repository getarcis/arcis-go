package validation

import (
	"regexp"
	"strings"
)

// host_header.go — Host-header validation (V41 — Host-header poisoning /
// subdomain takeover).
//
// Apps that reflect the Host header into password-reset links, absolute
// redirects, share URLs, or cache keys are vulnerable when an attacker sends
// `Host: attacker.com`. ValidateHost checks the Host against an allowlist.
//
// Default-deny by construction: an empty allowlist rejects everything, so this
// is OPT-IN. Multi-tenant apps either don't use it or list their tenant hosts,
// which avoids false positives. Mirrors the Node/Python validate_host.

// ValidateHostResult is the outcome of ValidateHost.
type ValidateHostResult struct {
	Safe   bool
	Reason string
}

var hostPortSuffix = regexp.MustCompile(`:\d+$`)

// normalizeHost strips a trailing :port and lowercases. IPv6 literals are
// expected in bracket form ([::1]), which this leaves intact.
func normalizeHost(host string) string {
	return hostPortSuffix.ReplaceAllString(strings.ToLower(strings.TrimSpace(host)), "")
}

// ValidateHost validates a Host header against an allowlist. Case-insensitive,
// port-stripped. Supports a single-level leading "*." wildcard: "*.example.com"
// matches "a.example.com" but not "example.com" or "a.b.example.com". An empty
// allowlist is default-deny.
func ValidateHost(host string, allowlist []string) ValidateHostResult {
	if strings.TrimSpace(host) == "" {
		return ValidateHostResult{Safe: false, Reason: "missing Host header"}
	}
	if len(allowlist) == 0 {
		return ValidateHostResult{Safe: false, Reason: "no Host allowlist configured (default-deny)"}
	}
	h := normalizeHost(host)
	for _, entry := range allowlist {
		a := strings.ToLower(strings.TrimSpace(entry))
		if a == "" {
			continue
		}
		if strings.HasPrefix(a, "*.") {
			suffix := a[1:] // ".example.com"
			if strings.HasSuffix(h, suffix) {
				label := h[:len(h)-len(suffix)]
				if label != "" && !strings.Contains(label, ".") {
					return ValidateHostResult{Safe: true}
				}
			}
		} else if h == a {
			return ValidateHostResult{Safe: true}
		}
	}
	return ValidateHostResult{Safe: false, Reason: "Host not in allowlist: " + h}
}

// IsHostAllowed is a boolean convenience wrapper around ValidateHost.
func IsHostAllowed(host string, allowlist []string) bool {
	return ValidateHost(host, allowlist).Safe
}
