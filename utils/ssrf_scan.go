package utils

// v1.7 W5: recursively scan a parsed request body for SSRF-shaped URL
// values and validate each with ValidateURL. Mirrors the Node
// scanForSsrf and Python scan_for_ssrf helpers.

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
)

// urlShaped matches a string beginning with a URL scheme + "://" (or
// scheme:/ for the file:///path form). RFC 3986 scheme charset.
var urlShaped = regexp.MustCompile(`(?i)^[a-z][a-z0-9+.\-]*://`)

// ssrfBodyScanProtocols is the body-scan scheme allowlist (v1.7 W5):
// http/https/ftp/ftps pass, file/gopher/dict and other SSRF-amplifying
// schemes are blocked. Mirrors the Node + Python body-scan policy.
var ssrfBodyScanProtocols = []string{"http", "https", "ftp", "ftps"}

// ssrfRelevantSchemes are the schemes the body scan evaluates: the fetchable
// ones plus the classic SSRF-amplifying ones (file, gopher, dict, ...). A
// URL-shaped string with any other scheme is a typo or a custom app scheme
// (lhttps://, myapp://) that no server-side fetch would act on, so it is
// skipped rather than flagged. Dangerous schemes stay here so they keep being
// blocked by ValidateURL's allowlist.
var ssrfRelevantSchemes = map[string]bool{
	"http": true, "https": true, "ftp": true, "ftps": true, "file": true,
	"gopher": true, "dict": true, "ldap": true, "ldaps": true, "tftp": true,
	"sftp": true, "ssh": true, "smb": true, "jar": true, "netdoc": true,
}

// isLocalhostHostname reports whether the URL's host is the literal
// localhost hostname (or *.localhost). Allowed by the body scan because
// it is ubiquitous in dev/config payloads; loopback IP forms are not.
func isLocalhostHostname(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	return host == "localhost" || strings.HasSuffix(host, ".localhost")
}

// SSRFScanResult is the outcome of scanning a body for unsafe URL values.
type SSRFScanResult struct {
	// Detected is true if any URL-shaped string value failed validation.
	Detected bool
	// URL is the offending URL string, or "".
	URL string
	// Reason is why it was blocked (from ValidateURL), or "".
	Reason string
}

// ScanForSSRF recursively walks a parsed body (the result of
// json.Unmarshal into interface{}) and runs ValidateURL on every string
// value that looks like a URL. Returns the first unsafe URL found.
// Public URLs pass, so a body carrying a normal https link is not
// flagged; only private / loopback / link-local / metadata /
// disallowed-scheme URLs trip it.
func ScanForSSRF(body interface{}, opts *ValidateURLOptions) SSRFScanResult {
	const maxDepth = 8
	// Default to the body-scan scheme profile when the caller didn't set
	// AllowedProtocols, so ftp/ftps pass and file/gopher are blocked.
	scanOpts := opts
	if scanOpts == nil {
		scanOpts = &ValidateURLOptions{AllowedProtocols: append([]string(nil), ssrfBodyScanProtocols...)}
	} else if len(scanOpts.AllowedProtocols) == 0 {
		clone := *scanOpts
		clone.AllowedProtocols = append([]string(nil), ssrfBodyScanProtocols...)
		scanOpts = &clone
	}
	if hit := walkSSRF(body, scanOpts, 0, maxDepth); hit != nil {
		return *hit
	}
	return SSRFScanResult{Detected: false}
}

func walkSSRF(value interface{}, opts *ValidateURLOptions, depth, maxDepth int) *SSRFScanResult {
	if depth > maxDepth {
		return nil
	}
	switch v := value.(type) {
	case string:
		trimmed := strings.TrimSpace(v)
		if urlShaped.MatchString(trimmed) {
			// Skip schemes a server-side fetch would never act on (typos like
			// lhttps://, custom app schemes). Not an SSRF vector.
			if i := strings.Index(trimmed, ":"); i > 0 && !ssrfRelevantSchemes[strings.ToLower(trimmed[:i])] {
				return nil
			}
			// localhost hostname allowed (dev config); loopback IPs not.
			if isLocalhostHostname(trimmed) {
				return nil
			}
			if res := ValidateURL(trimmed, opts); !res.Safe {
				reason := res.Reason
				if reason == "" {
					reason = "unsafe URL"
				}
				return &SSRFScanResult{Detected: true, URL: v, Reason: reason}
			}
		}
	case map[string]interface{}:
		for _, child := range v {
			if hit := walkSSRF(child, opts, depth+1, maxDepth); hit != nil {
				return hit
			}
		}
	case []interface{}:
		for _, item := range v {
			if hit := walkSSRF(item, opts, depth+1, maxDepth); hit != nil {
				return hit
			}
		}
	}
	return nil
}

// ScanForSSRFJSON parses raw JSON bytes and runs ScanForSSRF. Returns
// Detected=false on empty input or unparseable JSON. Convenience wrapper
// the adapters call after reading the request body.
func ScanForSSRFJSON(raw []byte, opts *ValidateURLOptions) SSRFScanResult {
	if len(raw) == 0 {
		return SSRFScanResult{Detected: false}
	}
	var parsed interface{}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return SSRFScanResult{Detected: false}
	}
	return ScanForSSRF(parsed, opts)
}
