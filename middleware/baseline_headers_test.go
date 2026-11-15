package middleware

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/getarcis/arcis-go/core"
)

// ─── Ordered fixture decoding ───────────────────────────────────────────
//
// Object key order is significant in the shared fixtures (CSP directives,
// Permissions-Policy features, reporting endpoints), so objects decode
// into ordered field lists instead of maps.

type jsonField struct {
	key   string
	value any
}

type jsonObject []jsonField

func (o jsonObject) get(key string) any {
	for _, f := range o {
		if f.key == key {
			return f.value
		}
	}
	return nil
}

func decodeOrdered(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return tok, nil // string, json.Number, bool or nil
	}
	switch delim {
	case '{':
		obj := jsonObject{}
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return nil, err
			}
			value, err := decodeOrdered(dec)
			if err != nil {
				return nil, err
			}
			obj = append(obj, jsonField{key: keyTok.(string), value: value})
		}
		_, err = dec.Token()
		return obj, err
	case '[':
		arr := []any{}
		for dec.More() {
			value, err := decodeOrdered(dec)
			if err != nil {
				return nil, err
			}
			arr = append(arr, value)
		}
		_, err = dec.Token()
		return arr, err
	}
	return nil, fmt.Errorf("unexpected delimiter %v", delim)
}

func loadBaselineFixtures(t *testing.T) jsonObject {
	t.Helper()
	f, err := os.Open("../spec/TEST_VECTORS.json")
	if err != nil {
		t.Fatalf("open shared fixtures: %v", err)
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.UseNumber()
	root, err := decodeOrdered(dec)
	if err != nil {
		t.Fatalf("decode shared fixtures: %v", err)
	}
	baseline, ok := root.(jsonObject).get("security_headers").(jsonObject).get("baseline").(jsonObject)
	if !ok {
		t.Fatal("security_headers.baseline fixture is missing")
	}
	return baseline
}

func fixtureList(t *testing.T, baseline jsonObject, key string) []jsonObject {
	t.Helper()
	raw, _ := baseline.get(key).([]any)
	if len(raw) == 0 {
		t.Fatalf("security_headers.baseline.%s is empty", key)
	}
	out := make([]jsonObject, len(raw))
	for i, item := range raw {
		out[i] = item.(jsonObject)
	}
	return out
}

// ─── Translating Node/Helmet option names into BaselineHeaderOptions ────

// Helmet legacy aliases. Go has one field per header, so an alias maps to
// the same field as its option.
var fixtureAliases = map[string]string{
	"hsts":                         "strictTransportSecurity",
	"noSniff":                      "xContentTypeOptions",
	"dnsPrefetchControl":           "xDnsPrefetchControl",
	"ieNoOpen":                     "xDownloadOptions",
	"frameguard":                   "xFrameOptions",
	"permittedCrossDomainPolicies": "xPermittedCrossDomainPolicies",
	"hidePoweredBy":                "xPoweredBy",
	"xssFilter":                    "xXssProtection",
}

var fixtureHeaderNames = map[string]string{
	"contentSecurityPolicy":         "Content-Security-Policy",
	"crossOriginEmbedderPolicy":     "Cross-Origin-Embedder-Policy",
	"crossOriginOpenerPolicy":       "Cross-Origin-Opener-Policy",
	"crossOriginResourcePolicy":     "Cross-Origin-Resource-Policy",
	"originAgentCluster":            "Origin-Agent-Cluster",
	"referrerPolicy":                "Referrer-Policy",
	"strictTransportSecurity":       "Strict-Transport-Security",
	"xContentTypeOptions":           "X-Content-Type-Options",
	"xDnsPrefetchControl":           "X-DNS-Prefetch-Control",
	"xDownloadOptions":              "X-Download-Options",
	"xFrameOptions":                 "X-Frame-Options",
	"xPermittedCrossDomainPolicies": "X-Permitted-Cross-Domain-Policies",
	"xPoweredBy":                    "X-Powered-By",
	"xXssProtection":                "X-XSS-Protection",
}

// skipError marks a fixture that cannot be expressed with Go's typed options.
type skipError struct{ reason string }

func (e skipError) Error() string { return e.reason }

func stringList(value any) []string {
	if s, ok := value.(string); ok {
		return []string{s}
	}
	raw := value.([]any)
	out := make([]string, len(raw))
	for i, item := range raw {
		out[i] = item.(string)
	}
	return out
}

func configKeys(obj jsonObject, header string, allowed ...string) error {
	for _, f := range obj {
		known := false
		for _, a := range allowed {
			known = known || f.key == a
		}
		if !known {
			// Typo keys such as `maxage` cannot occur with typed structs.
			return skipError{fmt.Sprintf("%s option %q has no Go field", header, f.key)}
		}
	}
	return nil
}

func fixtureOptions(options jsonObject) (core.BaselineHeaderOptions, error) {
	var opts core.BaselineHeaderOptions
	seen := map[string]string{}
	for _, field := range options {
		name := field.key
		if primary, ok := fixtureAliases[name]; ok {
			name = primary
		}
		if other, ok := seen[name]; ok {
			// Go has one field per header, so an option and its legacy
			// alias cannot both be set.
			return opts, skipError{fmt.Sprintf("%q and %q map to the same Go field", other, field.key)}
		}
		seen[name] = field.key

		header := fixtureHeaderNames[name]
		switch value := field.value.(type) {
		case bool:
			switch {
			case !value && header != "":
				opts.Disable = append(opts.Disable, header)
			case value && name == "crossOriginEmbedderPolicy":
				opts.CrossOriginEmbedderPolicy = "require-corp"
			case !value || header == "":
				return opts, fmt.Errorf("unhandled boolean option %q", field.key)
			}
			continue
		case jsonObject:
			if err := applyFixtureObject(&opts, name, header, value); err != nil {
				return opts, err
			}
			continue
		}
		return opts, fmt.Errorf("unhandled option %q", field.key)
	}
	return opts, nil
}

func applyFixtureObject(opts *core.BaselineHeaderOptions, name, header string, value jsonObject) error {
	policy, _ := value.get("policy").(string)
	switch name {
	case "contentSecurityPolicy":
		if err := configKeys(value, header, "useDefaults", "directives", "reportOnly", "nonce"); err != nil {
			return err
		}
		csp := &opts.ContentSecurityPolicy
		csp.DisableDefaults = value.get("useDefaults") == false
		csp.ReportOnly = value.get("reportOnly") == true
		csp.Nonce = value.get("nonce") == true
		directives, _ := value.get("directives").(jsonObject)
		for _, d := range directives {
			directive := core.CSPDirective{Name: d.key}
			if d.value == nil {
				directive.Remove = true
			} else {
				directive.Values = stringList(d.value)
			}
			csp.Directives = append(csp.Directives, directive)
		}
	case "crossOriginEmbedderPolicy":
		opts.CrossOriginEmbedderPolicy = policy
	case "crossOriginOpenerPolicy":
		opts.CrossOriginOpenerPolicy = policy
	case "crossOriginResourcePolicy":
		opts.CrossOriginResourcePolicy = policy
	case "referrerPolicy":
		opts.ReferrerPolicy = stringList(value.get("policy"))
	case "strictTransportSecurity":
		if err := configKeys(value, header, "maxAge", "includeSubDomains", "preload"); err != nil {
			return err
		}
		if n, ok := value.get("maxAge").(json.Number); ok {
			f, err := n.Float64()
			if err != nil {
				return err
			}
			// Helmet floors fractional seconds; Go's int field cannot
			// carry a fraction, so the floor happens here.
			maxAge := int(math.Floor(f))
			opts.StrictTransportSecurity.MaxAge = &maxAge
		}
		opts.StrictTransportSecurity.ExcludeSubDomains = value.get("includeSubDomains") == false
		opts.StrictTransportSecurity.Preload = value.get("preload") == true
	case "xDnsPrefetchControl":
		opts.AllowDNSPrefetch = value.get("allow") == true
	case "xFrameOptions":
		opts.XFrameOptions, _ = value.get("action").(string)
	case "xPermittedCrossDomainPolicies":
		opts.XPermittedCrossDomainPolicies, _ = value.get("permittedPolicies").(string)
	case "permissionsPolicy":
		opts.PermissionsPolicy = []core.PermissionsPolicyFeature{}
		for _, f := range value {
			opts.PermissionsPolicy = append(opts.PermissionsPolicy, core.PermissionsPolicyFeature{Name: f.key, Allowlist: stringList(f.value)})
		}
	case "reportingEndpoints":
		opts.ReportingEndpoints = []core.ReportingEndpoint{}
		for _, f := range value {
			opts.ReportingEndpoints = append(opts.ReportingEndpoints, core.ReportingEndpoint{Name: f.key, URL: f.value.(string)})
		}
	default:
		return fmt.Errorf("unhandled option object %q", name)
	}
	return nil
}

// goSpelling maps camelCase option names in fixture error text to the Go
// field names used in Go error messages.
func goSpelling(text string) string {
	return strings.ReplaceAll(text, "maxAge", "MaxAge")
}

// ─── Fixture-driven tests ───────────────────────────────────────────────

const appPoweredBy = "application-framework"

func applyBaseline(t *testing.T, sh *SecurityHeaders) (http.Header, *http.Request) {
	t.Helper()
	h := http.Header{}
	h.Set("X-Powered-By", appPoweredBy)
	req, err := sh.Apply(h, httptest.NewRequest(http.MethodGet, "/", nil))
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	return h, req
}

func TestBaselineSharedCases(t *testing.T) {
	for _, tc := range fixtureList(t, loadBaselineFixtures(t), "cases") {
		name := tc.get("name").(string)
		t.Run(name, func(t *testing.T) {
			opts, err := fixtureOptions(tc.get("options").(jsonObject))
			if err != nil {
				t.Fatalf("translate options: %v", err)
			}
			sh, err := NewBaselineSecurityHeaders(opts)
			if err != nil {
				t.Fatalf("NewBaselineSecurityHeaders: %v", err)
			}
			h, _ := applyBaseline(t, sh)
			for _, f := range tc.get("expected_headers").(jsonObject) {
				if got := h.Values(f.key); len(got) != 1 || got[0] != f.value.(string) {
					t.Errorf("%s = %q, want %q", f.key, got, f.value)
				}
			}
			for _, absent := range stringList(tc.get("expected_absent")) {
				if got := h.Values(absent); len(got) != 0 {
					t.Errorf("%s should be absent, got %q", absent, got)
				}
			}
			removes := tc.get("removes_x_powered_by").(bool)
			if kept := h.Get("X-Powered-By") == appPoweredBy; kept == removes {
				t.Errorf("X-Powered-By kept = %v, want removed = %v", kept, removes)
			}
			if sh.RemovesPoweredBy() != removes {
				t.Errorf("RemovesPoweredBy() = %v, want %v", sh.RemovesPoweredBy(), removes)
			}
		})
	}
}

// Fixtures Go cannot express with typed options. Every other invalid
// fixture must fail construction.
var skippedInvalidFixtures = map[string]bool{
	"hsts_lowercase_maxage_typo":     true, // no `maxage` field on HSTSOptions
	"hsts_lowercase_subdomains_typo": true, // no `includeSubdomains` field on HSTSOptions
	"option_and_alias_both_set":      true, // one Go field per header, no alias
}

func TestBaselineSharedInvalidOptions(t *testing.T) {
	skipped := 0
	for _, tc := range fixtureList(t, loadBaselineFixtures(t), "invalid") {
		name := tc.get("name").(string)
		t.Run(name, func(t *testing.T) {
			opts, err := fixtureOptions(tc.get("options").(jsonObject))
			var skip skipError
			if errors.As(err, &skip) {
				if !skippedInvalidFixtures[name] {
					t.Fatalf("unexpected skip: %v", skip)
				}
				skipped++
				t.Skip(skip.reason)
			}
			if err != nil {
				t.Fatalf("translate options: %v", err)
			}
			if skippedInvalidFixtures[name] {
				t.Fatal("fixture listed as skipped but translated")
			}
			_, err = NewBaselineSecurityHeaders(opts)
			want := goSpelling(tc.get("error_contains").(string))
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("error = %v, want it to contain %q", err, want)
			}
		})
	}
	if skipped != len(skippedInvalidFixtures) {
		t.Errorf("skipped %d fixtures, want %d", skipped, len(skippedInvalidFixtures))
	}
}

// cspDirectives splits a CSP header into name -> full directive text.
func cspDirectives(header string) map[string]string {
	out := map[string]string{}
	for _, d := range strings.Split(header, ";") {
		name, _, _ := strings.Cut(d, " ")
		out[name] = d
	}
	return out
}

func TestBaselineSharedNonce(t *testing.T) {
	baseline := loadBaselineFixtures(t)
	nonce := baseline.get("nonce").(jsonObject)
	pattern := regexp.MustCompile(nonce.get("script_src_pattern").(string))
	opts, err := fixtureOptions(nonce.get("options").(jsonObject))
	if err != nil {
		t.Fatalf("translate options: %v", err)
	}
	sh, err := NewBaselineSecurityHeaders(opts)
	if err != nil {
		t.Fatalf("NewBaselineSecurityHeaders: %v", err)
	}
	if !sh.Dynamic() {
		t.Fatal("a nonce policy must be computed per request")
	}
	if _, ok := sh.GetHeaders()["Content-Security-Policy"]; ok {
		t.Fatal("a per-request CSP must not be in the static header map")
	}

	defaults := fixtureList(t, baseline, "cases")[0]
	if defaults.get("name") != "defaults" {
		t.Fatal("first baseline case is not the defaults case")
	}
	expected := defaults.get("expected_headers").(jsonObject)
	defaultCSP := expected.get("Content-Security-Policy").(string)

	seen := map[string]bool{}
	for i := 0; i < 3; i++ {
		incoming := httptest.NewRequest(http.MethodGet, "/", nil)
		h := http.Header{}
		req, err := sh.Apply(h, incoming)
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		csp := h.Get("Content-Security-Policy")
		directives := cspDirectives(csp)
		m := pattern.FindStringSubmatch(directives["script-src"])
		if m == nil {
			t.Fatalf("script-src %q does not match %s", directives["script-src"], pattern)
		}
		value := m[1]
		if seen[value] {
			t.Fatalf("nonce %q reused across requests", value)
		}
		seen[value] = true
		if got := CSPNonce(req.Context()); got != value {
			t.Errorf("CSPNonce = %q, header nonce = %q", got, value)
		}
		if CSPNonce(incoming.Context()) != "" {
			t.Error("Apply must not mutate the incoming request")
		}
		if directives["style-src"] != "style-src 'self' https: 'unsafe-inline'" {
			t.Errorf("style-src changed: %q", directives["style-src"])
		}
		if stripped := strings.Replace(csp, " 'nonce-"+value+"'", "", 1); stripped != defaultCSP {
			t.Errorf("CSP without nonce = %q, want defaults %q", stripped, defaultCSP)
		}
		for _, f := range expected {
			if f.key != "Content-Security-Policy" && h.Get(f.key) != f.value.(string) {
				t.Errorf("%s = %q, want %q", f.key, h.Get(f.key), f.value)
			}
		}
	}
	if CSPNonce(nil) != "" {
		t.Error("CSPNonce(nil) should be empty")
	}
}

func TestBaselineCSPFunctionValues(t *testing.T) {
	sh, err := NewBaselineSecurityHeaders(core.BaselineHeaderOptions{
		ContentSecurityPolicy: core.CSPOptions{
			Nonce: true,
			Directives: []core.CSPDirective{
				{Name: "styleSrc", Values: []string{"'self'"}, Funcs: []func(*http.Request) string{
					func(r *http.Request) string { return "'nonce-" + CSPNonce(r.Context()) + "'" },
				}},
				{Name: "img-src", Funcs: []func(*http.Request) string{
					func(r *http.Request) string { return r.Header.Get("X-Tenant-CDN") },
				}},
			},
		},
	})
	if err != nil {
		t.Fatalf("NewBaselineSecurityHeaders: %v", err)
	}
	for _, cdn := range []string{"cdn-a.example.com", "cdn-b.example.com"} {
		in := httptest.NewRequest(http.MethodGet, "/", nil)
		in.Header.Set("X-Tenant-CDN", cdn)
		h := http.Header{}
		req, err := sh.Apply(h, in)
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		directives := cspDirectives(h.Get("Content-Security-Policy"))
		nonce := CSPNonce(req.Context())
		if want := "style-src 'self' 'nonce-" + nonce + "'"; directives["style-src"] != want {
			t.Errorf("style-src = %q, want %q", directives["style-src"], want)
		}
		if want := "img-src " + cdn; directives["img-src"] != want {
			t.Errorf("img-src = %q, want %q", directives["img-src"], want)
		}
	}

	for result, want := range map[string]string{
		"self":                    "should be quoted",
		"'self'; object-src *":    "invalid directive value",
		"'self'\r\nX-Injected: 1": "invalid directive value",
	} {
		bad, err := NewBaselineSecurityHeaders(core.BaselineHeaderOptions{
			ContentSecurityPolicy: core.CSPOptions{Directives: []core.CSPDirective{
				{Name: "scriptSrc", Funcs: []func(*http.Request) string{func(*http.Request) string { return result }}},
			}},
		})
		if err != nil {
			t.Fatalf("construction must not evaluate function values: %v", err)
		}
		_, err = bad.Apply(http.Header{}, httptest.NewRequest(http.MethodGet, "/", nil))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("func result %q: error = %v, want %q", result, err, want)
		}
	}
}

func TestBaselineStaticCSPAndGoOnlyValidation(t *testing.T) {
	sh, err := NewBaselineSecurityHeaders(core.BaselineHeaderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if sh.Dynamic() {
		t.Error("default policy should be static")
	}
	if !strings.HasPrefix(sh.GetHeaders()["Content-Security-Policy"], "default-src 'self';") {
		t.Errorf("static CSP missing from GetHeaders: %q", sh.GetHeaders()["Content-Security-Policy"])
	}
	if req, err := sh.Apply(http.Header{}, nil); err != nil || req != nil {
		t.Errorf("static Apply with nil request = %v, %v", req, err)
	}

	maxAge := 0
	sh, err = NewBaselineSecurityHeaders(core.BaselineHeaderOptions{
		Disable:                 []string{"x-dns-prefetch-control", "CONTENT-SECURITY-POLICY"},
		StrictTransportSecurity: core.HSTSOptions{MaxAge: &maxAge, ExcludeSubDomains: true},
		ContentSecurityPolicy:   core.CSPOptions{Directives: []core.CSPDirective{{Name: "bad name"}}},
	})
	if err != nil {
		t.Fatalf("disabled CSP options must not be validated: %v", err)
	}
	h, _ := applyBaseline(t, sh)
	if h.Get("Strict-Transport-Security") != "max-age=0" || h.Get("X-DNS-Prefetch-Control") != "" || h.Get("Content-Security-Policy") != "" {
		t.Errorf("unexpected headers: %v", h)
	}

	for name, opts := range map[string]core.BaselineHeaderOptions{
		"unknown header in Disable": {Disable: []string{"X-Frame-Option"}},
		"remove with values": {ContentSecurityPolicy: core.CSPOptions{Directives: []core.CSPDirective{
			{Name: "styleSrc", Remove: true, Values: []string{"'self'"}},
		}}},
		"default-src with DangerouslyDisableDefaultSrc": {ContentSecurityPolicy: core.CSPOptions{
			DangerouslyDisableDefaultSrc: true,
			Directives:                   []core.CSPDirective{{Name: "defaultSrc", Values: []string{"'self'"}}},
		}},
		"nil function value": {ContentSecurityPolicy: core.CSPOptions{Directives: []core.CSPDirective{
			{Name: "scriptSrc", Funcs: []func(*http.Request) string{nil}},
		}}},
		"duplicate feature": {PermissionsPolicy: []core.PermissionsPolicyFeature{{Name: "camera"}, {Name: "camera"}}},
		"origin with default port": {PermissionsPolicy: []core.PermissionsPolicyFeature{
			{Name: "camera", Allowlist: []string{"https://maps.example.com:443"}},
		}},
		"origin with quote": {PermissionsPolicy: []core.PermissionsPolicyFeature{
			{Name: "camera", Allowlist: []string{`https://a"b.example.com`}},
		}},
		"duplicate endpoint": {ReportingEndpoints: []core.ReportingEndpoint{
			{Name: "csp", URL: "https://a.example.com"}, {Name: "csp", URL: "https://b.example.com"},
		}},
		"empty endpoints":   {ReportingEndpoints: []core.ReportingEndpoint{}},
		"relative endpoint": {ReportingEndpoints: []core.ReportingEndpoint{{Name: "csp", URL: "/csp"}}},
	} {
		if _, err := NewBaselineSecurityHeaders(opts); err == nil {
			t.Errorf("%s: expected a construction error", name)
		}
	}

	sh, err = NewBaselineSecurityHeaders(core.BaselineHeaderOptions{ContentSecurityPolicy: core.CSPOptions{
		DangerouslyDisableDefaultSrc: true,
	}})
	if err != nil {
		t.Fatalf("DangerouslyDisableDefaultSrc: %v", err)
	}
	if csp := sh.GetHeaders()["Content-Security-Policy"]; !strings.HasPrefix(csp, "base-uri 'self';") {
		t.Errorf("default-src not removed: %q", csp)
	}
}

func TestCompileSecurityHeadersProfiles(t *testing.T) {
	config := core.DefaultConfig()
	legacy, err := CompileSecurityHeaders(config)
	if err != nil {
		t.Fatal(err)
	}
	if legacy.GetHeaders()["X-Frame-Options"] != "DENY" || legacy.GetHeaders()["Cache-Control"] == "" {
		t.Errorf("empty profile should be legacy: %v", legacy.GetHeaders())
	}

	config.HeaderProfile = core.HeaderProfileBaseline
	baseline, err := CompileSecurityHeaders(config)
	if err != nil {
		t.Fatal(err)
	}
	if baseline.GetHeaders()["X-Frame-Options"] != "SAMEORIGIN" || baseline.GetHeaders()["Cache-Control"] != "" {
		t.Errorf("baseline profile ignored legacy fields incorrectly: %v", baseline.GetHeaders())
	}

	config.BaselineHeaders.XFrameOptions = "allow-from"
	if _, err := CompileSecurityHeaders(config); err == nil || !strings.Contains(err.Error(), "invalid action") {
		t.Errorf("invalid baseline options should fail: %v", err)
	}

	config.HeaderProfile = "helmet"
	if _, err := CompileSecurityHeaders(config); err == nil || !strings.Contains(err.Error(), "unknown profile") {
		t.Errorf("unknown profile should fail: %v", err)
	}
}
