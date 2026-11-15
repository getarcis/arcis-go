package htmlsanitizer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"testing"
)

// fixtureCase is one entry of spec/html-sanitizer-vectors.json. Expected
// output and removed lists come from DOMPurify 3.4.18 on jsdom 31.0.1.
type fixtureCase struct {
	ID       string                     `json:"id"`
	Source   string                     `json:"source"`
	Title    string                     `json:"title"`
	Config   map[string]json.RawMessage `json:"config"`
	Input    string                     `json:"input"`
	Expected string                     `json:"expected"`
	Removed  []Removed                  `json:"removed"`
}

func loadFixtures(t testing.TB) []fixtureCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "spec", "html-sanitizer-vectors.json"))
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	var file struct {
		Cases []fixtureCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("parse fixtures: %v", err)
	}
	if len(file.Cases) == 0 {
		t.Fatal("fixture file has no cases")
	}
	return file.Cases
}

// fixtureConfig maps a fixture's DOMPurify-style config onto Config.
func fixtureConfig(raw map[string]json.RawMessage) (Config, error) {
	var cfg Config
	lists := map[string]*[]string{
		"ALLOWED_TAGS":        &cfg.AllowedTags,
		"ALLOWED_ATTR":        &cfg.AllowedAttr,
		"ADD_TAGS":            &cfg.AddTags,
		"ADD_ATTR":            &cfg.AddAttr,
		"FORBID_TAGS":         &cfg.ForbidTags,
		"FORBID_ATTR":         &cfg.ForbidAttr,
		"FORBID_CONTENTS":     &cfg.ForbidContents,
		"ADD_FORBID_CONTENTS": &cfg.AddForbidContents,
		"ADD_URI_SAFE_ATTR":   &cfg.AddURISafeAttr,
		"ADD_DATA_URI_TAGS":   &cfg.AddDataURITags,
	}
	optionalBools := map[string]**bool{
		"ALLOW_DATA_ATTR":          &cfg.AllowDataAttr,
		"ALLOW_ARIA_ATTR":          &cfg.AllowARIAAttr,
		"ALLOW_SELF_CLOSE_IN_ATTR": &cfg.AllowSelfCloseInAttr,
		"KEEP_CONTENT":             &cfg.KeepContent,
		"SAFE_FOR_XML":             &cfg.SafeForXML,
		"SANITIZE_DOM":             &cfg.SanitizeDOM,
	}
	bools := map[string]*bool{
		"ALLOW_UNKNOWN_PROTOCOLS": &cfg.AllowUnknownProtocols,
		"SAFE_FOR_TEMPLATES":      &cfg.SafeForTemplates,
		"SANITIZE_NAMED_PROPS":    &cfg.SanitizeNamedProps,
		"WHOLE_DOCUMENT":          &cfg.WholeDocument,
		"FORCE_BODY":              &cfg.ForceBody,
	}

	for key, value := range raw {
		switch {
		case lists[key] != nil:
			if err := json.Unmarshal(value, lists[key]); err != nil {
				return cfg, fmt.Errorf("%s: %w", key, err)
			}
		case optionalBools[key] != nil:
			var b bool
			if err := json.Unmarshal(value, &b); err != nil {
				return cfg, fmt.Errorf("%s: %w", key, err)
			}
			*optionalBools[key] = &b
		case bools[key] != nil:
			if err := json.Unmarshal(value, bools[key]); err != nil {
				return cfg, fmt.Errorf("%s: %w", key, err)
			}
		case key == "ALLOWED_URI_REGEXP":
			var re struct {
				Source string `json:"source"`
				Flags  string `json:"flags"`
			}
			if err := json.Unmarshal(value, &re); err != nil {
				return cfg, fmt.Errorf("%s: %w", key, err)
			}
			pattern := re.Source
			for _, f := range re.Flags {
				switch f {
				case 'i':
					pattern = "(?i)" + pattern
				case 'g':
					// Irrelevant for a match test.
				default:
					return cfg, fmt.Errorf("%s: unsupported flag %q", key, f)
				}
			}
			compiled, err := regexp.Compile(pattern)
			if err != nil {
				return cfg, fmt.Errorf("%s: %w", key, err)
			}
			cfg.AllowedURIRegexp = compiled
		case key == "USE_PROFILES":
			var p struct {
				HTML       bool `json:"html"`
				SVG        bool `json:"svg"`
				SVGFilters bool `json:"svgFilters"`
				MathML     bool `json:"mathMl"`
			}
			if err := json.Unmarshal(value, &p); err != nil {
				return cfg, fmt.Errorf("%s: %w", key, err)
			}
			cfg.UseProfiles = &Profiles{HTML: p.HTML, SVG: p.SVG, SVGFilters: p.SVGFilters, MathML: p.MathML}
		default:
			return cfg, fmt.Errorf("unmapped fixture config key %s", key)
		}
	}
	return cfg, nil
}

func fixtureSanitizer(t testing.TB, c fixtureCase) *Sanitizer {
	t.Helper()
	cfg, err := fixtureConfig(c.Config)
	if err != nil {
		t.Fatalf("%s: %v", c.ID, err)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("%s: New: %v", c.ID, err)
	}
	return s
}

// withoutDocumentEntries drops html, head and body entries, as the public
// Removed list does.
func withoutDocumentEntries(list []Removed) []Removed {
	out := []Removed{}
	for _, r := range list {
		if isDocumentElementName(r.Element) || isDocumentElementName(r.From) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// parserExceptions are fixture cases where x/net/html builds a different
// tree than parse5 and the Go output removes strictly more than DOMPurify.
// Each one fails closed to an empty string.
var parserExceptions = map[string]string{}

func TestFixtures(t *testing.T) {
	cases := loadFixtures(t)
	htmlPass, removedPass := 0, 0
	for _, c := range cases {
		s := fixtureSanitizer(t, c)
		got := s.SanitizeDetailed(c.Input)
		if reason, ok := parserExceptions[c.ID]; ok {
			if got.HTML != "" || c.Expected == "" {
				t.Errorf("%s: documented exception no longer applies (got %q, DOMPurify %q): %s", c.ID, got.HTML, c.Expected, reason)
			}
			continue
		}
		htmlOK := got.HTML == c.Expected
		removedOK := reflect.DeepEqual(got.Removed, withoutDocumentEntries(c.Removed))
		if htmlOK {
			htmlPass++
		} else {
			t.Errorf("%s (%s) html mismatch\ninput:    %q\nexpected: %q\ngot:      %q", c.ID, c.Title, c.Input, c.Expected, got.HTML)
		}
		// The internal list, before html/head/body entries are dropped, must
		// match DOMPurify's complete list too.
		if full := s.run(c.Input).removed; !reflect.DeepEqual(full, c.Removed) && !(len(full) == 0 && len(c.Removed) == 0) {
			t.Errorf("%s (%s) unfiltered removed mismatch\nexpected: %v\ngot:      %v", c.ID, c.Title, c.Removed, full)
		}
		if removedOK {
			removedPass++
		} else {
			t.Errorf("%s (%s) removed mismatch\ninput:    %q\nexpected: %v\ngot:      %v", c.ID, c.Title, c.Input, withoutDocumentEntries(c.Removed), got.Removed)
		}
	}
	t.Logf("fixtures: html %d/%d, removed %d/%d, documented parser exceptions %d",
		htmlPass, len(cases), removedPass, len(cases), len(parserExceptions))
}
