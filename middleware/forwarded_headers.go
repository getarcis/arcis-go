package middleware

// v1.7 W7: forwarded-header inspection. A loopback address in a
// forwarded / client-IP header means a client is claiming to be
// localhost to bypass IP allowlists. Private ranges are deliberately NOT
// flagged (internal load balancers add them legitimately). Shared across
// the gin / echo / chi / fiber adapters via a header-getter func so each
// framework passes its own accessor.

import (
	"regexp"
	"strings"
)

// ForwardedHeaderNames are the forwarded / client-IP headers inspected
// for loopback spoofing.
var ForwardedHeaderNames = []string{
	"X-Forwarded-For", "X-Forwarded-Host", "X-Real-IP",
	"Forwarded", "Client-IP", "True-Client-IP",
}

// loopbackHeaderPattern matches a loopback address as a token within a
// forwarded-header value.
var loopbackHeaderPattern = regexp.MustCompile(
	`(?i)(?:^|[\s,@=])(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}|::1|0\.0\.0\.0|localhost)(?::\d+)?(?:$|[\s,;])`,
)

// DetectForwardedSpoof returns true if any forwarded / client-IP header
// (read via get) contains a loopback address. `get` is the framework's
// case-insensitive header accessor (http.Header.Get, gin c.GetHeader, ...).
func DetectForwardedSpoof(get func(string) string) bool {
	for _, h := range ForwardedHeaderNames {
		if v := get(h); v != "" && loopbackHeaderPattern.MatchString(v) {
			return true
		}
	}
	return false
}

// IsUntrustedHost returns true when the Host / X-Forwarded-Host value is
// not in the trusted list. hostFallback supplies the framework's parsed
// Host when the Host header itself is read empty (Go's net/http strips it
// into r.Host). Empty trusted list disables the check (returns false).
func IsUntrustedHost(get func(string) string, hostFallback string, trusted []string) bool {
	if len(trusted) == 0 {
		return false
	}
	for _, hname := range []string{"Host", "X-Forwarded-Host"} {
		v := get(hname)
		if hname == "Host" && v == "" {
			v = hostFallback
		}
		if v == "" {
			continue
		}
		host := strings.ToLower(strings.SplitN(v, ":", 2)[0])
		ok := false
		for _, t := range trusted {
			if host == strings.ToLower(t) {
				ok = true
				break
			}
		}
		if !ok {
			return true
		}
	}
	return false
}
