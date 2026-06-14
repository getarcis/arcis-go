// Package pipeline holds request-scanning logic shared by the net/http-based
// framework adapters (gin, echo, chi, net/http). Each adapter previously kept
// its own copy of these functions, which drifted: chi/net-http scanned XML
// bodies for XXE while gin/echo did not. Centralizing here removes the
// duplication and the drift.
//
// It imports the arcis root package (the re-export hub) for the detectors;
// nothing in arcis or its subpackages imports this package, so there is no
// import cycle. The fasthttp-based fiber adapter is not covered here (it has no
// *http.Request).
package pipeline

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	arcis "github.com/getarcis/arcis-go"
)

// ScanRequestForThreats walks an HTTP request (body, query, URL path) and
// returns the first attack pattern found, or nil. Body content types covered:
// JSON, x-www-form-urlencoded, and XML / text-xml (XXE / YAML-ruby vectors).
// The body is read once and restored unconditionally so the downstream handler
// can re-bind it regardless of the scan outcome.
func ScanRequestForThreats(req *http.Request) *arcis.ThreatHit {
	ct := req.Header.Get("Content-Type")
	if req.Body != nil && (strings.HasPrefix(ct, "application/json") ||
		strings.HasPrefix(ct, "application/x-www-form-urlencoded") ||
		strings.HasPrefix(ct, "application/xml") ||
		strings.HasPrefix(ct, "text/xml")) {
		raw, err := io.ReadAll(req.Body)
		if err == nil {
			// Restore the body + Content-Length unconditionally so frameworks
			// that re-bind (and ones that re-check the header against the
			// bytes) pass through whether or not a threat was found.
			req.Body = io.NopCloser(bytes.NewReader(raw))
			req.ContentLength = int64(len(raw))

			if len(raw) > 0 && (strings.HasPrefix(ct, "application/xml") || strings.HasPrefix(ct, "text/xml")) {
				// XML body (XXE / YAML-ruby vectors): scan the raw markup as a
				// string. Parity with the Python middleware + Node proxy.
				if hit := arcis.ScanThreats(string(raw)); hit != nil {
					return hit
				}
			} else if len(raw) > 0 && strings.HasPrefix(ct, "application/json") {
				var parsed interface{}
				if json.Unmarshal(raw, &parsed) == nil {
					if hit := arcis.ScanThreats(parsed); hit != nil {
						return hit
					}
				}
			} else if len(raw) > 0 && strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
				if values, err := url.ParseQuery(string(raw)); err == nil {
					form := make(map[string]interface{}, len(values))
					for k, vals := range values {
						if len(vals) == 1 {
							form[k] = vals[0]
						} else {
							arr := make([]interface{}, len(vals))
							for i, v := range vals {
								arr[i] = v
							}
							form[k] = arr
						}
					}
					if hit := arcis.ScanThreats(form); hit != nil {
						return hit
					}
				}
			}
		}
	}

	q := map[string]interface{}{}
	for k, vals := range req.URL.Query() {
		if len(vals) == 1 {
			q[k] = vals[0]
		} else {
			arr := make([]interface{}, len(vals))
			for i, v := range vals {
				arr[i] = v
			}
			q[k] = arr
		}
	}
	if len(q) > 0 {
		if hit := arcis.ScanThreats(q); hit != nil {
			return hit
		}
	}
	if hit := arcis.ScanThreats(req.URL.Path); hit != nil {
		return hit
	}
	return nil
}

// ClientIP returns the request's client IP for telemetry. Honors
// X-Forwarded-For (first value), then X-Real-IP, then the host portion of
// RemoteAddr. Mirrors gin's ClientIP() and echo's RealIP().
func ClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		return strings.TrimSpace(xrip)
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
