package middleware

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/getarcis/arcis-go/core"
)

// Content-Security-Policy construction for the baseline header profile.
// Directive handling follows Helmet 8 so existing Helmet policies produce
// the same header. See spec/API_SPEC.md "Baseline profile".

// defaultCSPDirectives are Helmet 8's default directives, in order.
var defaultCSPDirectives = []cspDirective{
	{name: "default-src", values: []string{"'self'"}},
	{name: "base-uri", values: []string{"'self'"}},
	{name: "font-src", values: []string{"'self'", "https:", "data:"}},
	{name: "form-action", values: []string{"'self'"}},
	{name: "frame-ancestors", values: []string{"'self'"}},
	{name: "img-src", values: []string{"'self'", "data:"}},
	{name: "object-src", values: []string{"'none'"}},
	{name: "script-src", values: []string{"'self'"}},
	{name: "script-src-attr", values: []string{"'none'"}},
	{name: "style-src", values: []string{"'self'", "https:", "'unsafe-inline'"}},
	{name: "upgrade-insecure-requests"},
}

// Keywords that are only valid quoted. A bare `self` is a host name, which
// would silently weaken the intended policy.
var cspShouldBeQuoted = map[string]bool{
	"none":                     true,
	"self":                     true,
	"strict-dynamic":           true,
	"report-sample":            true,
	"inline-speculation-rules": true,
	"unsafe-inline":            true,
	"unsafe-eval":              true,
	"unsafe-hashes":            true,
	"wasm-unsafe-eval":         true,
}

// Helmet's directive name rule: lowercase first letter, no trailing hyphen.
var cspDirectiveName = regexp.MustCompile(`^[a-z](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$`)

type cspDirective struct {
	name   string
	values []string
	funcs  []func(*http.Request) string
}

// cspPolicy is a validated policy, rendered once or per response.
type cspPolicy struct {
	headerName string
	directives []cspDirective
	nonce      bool
}

// dynamic reports whether the header differs per response.
func (p *cspPolicy) dynamic() bool {
	if p.nonce {
		return true
	}
	for _, d := range p.directives {
		if len(d.funcs) > 0 {
			return true
		}
	}
	return false
}

func dashify(name string) string {
	var b strings.Builder
	for _, r := range name {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('-')
			b.WriteRune(r + ('a' - 'A'))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// validateCSPEntry rejects entries that could inject extra directives or
// policies (';' and ','), control characters (CR/LF included, which
// would also break the header), and unquoted keywords.
func validateCSPEntry(directive, entry string) error {
	if strings.ContainsAny(entry, ";,") || strings.IndexFunc(entry, isControl) >= 0 {
		return fmt.Errorf("Content-Security-Policy received an invalid directive value for %q", directive)
	}
	if cspShouldBeQuoted[entry] ||
		strings.HasPrefix(entry, "nonce-") ||
		strings.HasPrefix(entry, "sha256-") ||
		strings.HasPrefix(entry, "sha384-") ||
		strings.HasPrefix(entry, "sha512-") {
		return fmt.Errorf("Content-Security-Policy received an invalid directive value for %q. %q should be quoted", directive, entry)
	}
	return nil
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f }

// compileCSP validates options once, at construction.
func compileCSP(options core.CSPOptions) (*cspPolicy, error) {
	var directives []cspDirective
	if !options.DisableDefaults {
		directives = append(directives, defaultCSPDirectives...)
	}
	index := func(name string) int {
		for i, d := range directives {
			if d.name == name {
				return i
			}
		}
		return -1
	}
	if options.DangerouslyDisableDefaultSrc {
		if i := index("default-src"); i >= 0 {
			directives = slices.Delete(directives, i, i+1)
		}
	}

	seen := make(map[string]bool, len(options.Directives))
	for _, raw := range options.Directives {
		if !cspDirectiveName.MatchString(raw.Name) {
			return nil, fmt.Errorf("Content-Security-Policy received an invalid directive name %q", raw.Name)
		}
		name := dashify(raw.Name)
		if seen[name] {
			return nil, fmt.Errorf("Content-Security-Policy received a duplicate directive %q", name)
		}
		seen[name] = true

		if name == "default-src" && options.DangerouslyDisableDefaultSrc {
			return nil, errors.New("Content-Security-Policy received a default-src directive while DangerouslyDisableDefaultSrc is set")
		}
		if raw.Remove {
			if name == "default-src" {
				return nil, errors.New("Content-Security-Policy needs a default-src but it was set to be removed. If you really want to disable it, set ContentSecurityPolicy.DangerouslyDisableDefaultSrc")
			}
			if len(raw.Values) > 0 || len(raw.Funcs) > 0 {
				return nil, fmt.Errorf("Content-Security-Policy directive %q sets Remove together with values", name)
			}
			if i := index(name); i >= 0 {
				directives = slices.Delete(directives, i, i+1)
			}
			continue
		}

		for _, entry := range raw.Values {
			if err := validateCSPEntry(name, entry); err != nil {
				return nil, err
			}
		}
		for _, fn := range raw.Funcs {
			if fn == nil {
				return nil, fmt.Errorf("Content-Security-Policy received a nil function value for %q", name)
			}
		}
		directive := cspDirective{
			name:   name,
			values: append([]string(nil), raw.Values...),
			funcs:  append([]func(*http.Request) string(nil), raw.Funcs...),
		}
		if i := index(name); i >= 0 {
			directives[i] = directive
		} else {
			directives = append(directives, directive)
		}
	}

	if len(directives) == 0 {
		return nil, errors.New("Content-Security-Policy has no directives. Either set some or disable the header")
	}
	if index("default-src") < 0 && !options.DangerouslyDisableDefaultSrc {
		return nil, errors.New("Content-Security-Policy needs a default-src but none was provided. If you really want to disable it, set ContentSecurityPolicy.DangerouslyDisableDefaultSrc")
	}
	if options.Nonce && index("script-src") < 0 {
		return nil, errors.New("Content-Security-Policy nonce requires a script-src directive")
	}

	headerName := "Content-Security-Policy"
	if options.ReportOnly {
		headerName = "Content-Security-Policy-Report-Only"
	}
	return &cspPolicy{headerName: headerName, directives: directives, nonce: options.Nonce}, nil
}

// render builds the header value for one response. r is passed to
// function values; nonce is appended to script-src when non-empty.
func (p *cspPolicy) render(r *http.Request, nonce string) (string, error) {
	var b strings.Builder
	for i, d := range p.directives {
		if i > 0 {
			b.WriteByte(';')
		}
		b.WriteString(d.name)
		for _, value := range d.values {
			b.WriteByte(' ')
			b.WriteString(value)
		}
		for _, fn := range d.funcs {
			value := fn(r)
			if err := validateCSPEntry(d.name, value); err != nil {
				return "", err
			}
			b.WriteByte(' ')
			b.WriteString(value)
		}
		if nonce != "" && d.name == "script-src" {
			b.WriteString(" 'nonce-")
			b.WriteString(nonce)
			b.WriteByte('\'')
		}
	}
	return b.String(), nil
}

// newCSPNonce returns 16 random bytes, base64-encoded with padding.
func newCSPNonce() string {
	var buf [16]byte
	// crypto/rand.Read never returns an error (it aborts the program if
	// the system source fails).
	_, _ = rand.Read(buf[:])
	return base64.StdEncoding.EncodeToString(buf[:])
}

type cspNonceKey struct{}

// CSPNonce returns the Content-Security-Policy nonce that the baseline
// header profile generated for this request, or "" when there is none.
// Use it in inline script tags: <script nonce="...">.
func CSPNonce(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	nonce, _ := ctx.Value(cspNonceKey{}).(string)
	return nonce
}
