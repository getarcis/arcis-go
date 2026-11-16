package htmlsanitizer

import (
	"fmt"
	"regexp"
	"strings"
)

// Config selects DOMPurify options. The zero value is DOMPurify's default
// configuration. Each field is named after the DOMPurify key it mirrors
// (ALLOWED_TAGS is AllowedTags, USE_PROFILES is UseProfiles) and has the
// same default.
//
// For list fields, nil keeps DOMPurify's default while a non-nil empty slice
// is an explicit empty list, exactly as an empty array is in DOMPurify. Names
// are matched case-insensitively. Options whose DOMPurify default is true are
// *bool, so nil means "default"; use Bool to set them.
//
// DOMPurify options that only apply to browser DOM objects or to other
// parsers (IN_PLACE, RETURN_DOM, PARSER_MEDIA_TYPE, NAMESPACE,
// CUSTOM_ELEMENT_HANDLING and the like) and hooks are not supported.
type Config struct {
	// AllowedTags replaces the default element allowlist (ALLOWED_TAGS).
	AllowedTags []string
	// AllowedAttr replaces the default attribute allowlist (ALLOWED_ATTR).
	AllowedAttr []string
	// AddTags extends the element allowlist (ADD_TAGS).
	AddTags []string
	// AddAttr extends the attribute allowlist (ADD_ATTR).
	AddAttr []string
	// ForbidTags lists elements that are always removed (FORBID_TAGS).
	ForbidTags []string
	// ForbidAttr lists attributes that are always removed (FORBID_ATTR).
	ForbidAttr []string
	// ForbidContents replaces the list of elements whose content is dropped
	// along with them when they are removed (FORBID_CONTENTS).
	ForbidContents []string
	// AddForbidContents extends that list (ADD_FORBID_CONTENTS).
	AddForbidContents []string
	// AddURISafeAttr lists attributes whose values skip URI checks
	// (ADD_URI_SAFE_ATTR).
	AddURISafeAttr []string
	// AddDataURITags lists elements that may carry data: URIs in src and href
	// (ADD_DATA_URI_TAGS).
	AddDataURITags []string
	// AllowedURIRegexp replaces the URI allowlist pattern
	// (ALLOWED_URI_REGEXP). It is matched against attribute values with
	// whitespace removed.
	AllowedURIRegexp *regexp.Regexp
	// UseProfiles, when non-nil, replaces both allowlists with the selected
	// profiles (USE_PROFILES). It overrides AllowedTags and AllowedAttr, as
	// in DOMPurify.
	UseProfiles *Profiles
	// AllowDataAttr allows data-* attributes (ALLOW_DATA_ATTR, default true).
	AllowDataAttr *bool
	// AllowARIAAttr allows aria-* attributes (ALLOW_ARIA_ATTR, default true).
	AllowARIAAttr *bool
	// AllowUnknownProtocols allows URI schemes outside the allowlist unless
	// they are script or data URIs (ALLOW_UNKNOWN_PROTOCOLS).
	AllowUnknownProtocols bool
	// AllowSelfCloseInAttr allows "/>" in attribute values
	// (ALLOW_SELF_CLOSE_IN_ATTR, default true).
	AllowSelfCloseInAttr *bool
	// KeepContent keeps the children of removed elements (KEEP_CONTENT,
	// default true).
	KeepContent *bool
	// SafeForTemplates strips {{ }}, ${ } and <% %> expressions and disables
	// data-* attributes (SAFE_FOR_TEMPLATES).
	SafeForTemplates bool
	// SafeForXML removes comments and attribute values that could break out
	// of their context when the output is embedded in XML-like content
	// (SAFE_FOR_XML, default true).
	SafeForXML *bool
	// SanitizeDOM removes id and name values that would clobber DOM APIs
	// (SANITIZE_DOM, default true).
	SanitizeDOM *bool
	// SanitizeNamedProps prefixes id and name values with "user-content-"
	// (SANITIZE_NAMED_PROPS).
	SanitizeNamedProps bool
	// WholeDocument returns the whole document including <html>
	// (WHOLE_DOCUMENT).
	WholeDocument bool
	// ForceBody parses leading elements such as <style> into the body
	// instead of the head, where they would be dropped (FORCE_BODY).
	ForceBody bool
}

// Profiles selects USE_PROFILES categories.
type Profiles struct {
	// HTML allows the safe HTML elements and attributes.
	HTML bool
	// SVG allows the safe SVG elements and attributes.
	SVG bool
	// SVGFilters allows the safe SVG filter elements.
	SVGFilters bool
	// MathML allows the safe MathML elements and attributes.
	MathML bool
}

// Bool returns a pointer to v, for the *bool fields of Config.
func Bool(v bool) *bool {
	return &v
}

type set map[string]struct{}

func (s set) has(name string) bool {
	_, ok := s[name]
	return ok
}

// add inserts lowercased names, like DOMPurify's addToSet with its default
// stringToLowerCase transform.
func (s set) add(names ...string) {
	for _, n := range names {
		s[strings.ToLower(n)] = struct{}{}
	}
}

func newSet(lists ...[]string) set {
	s := set{}
	for _, l := range lists {
		s.add(l...)
	}
	return s
}

// Defaults and fixed catalogs from purify.ts. They are never mutated after
// package initialization, so sharing them across sanitizers is safe.
var (
	defaultForbidContents = newSet([]string{
		"annotation-xml", "audio", "colgroup", "desc", "foreignobject", "head", "iframe", "math", "mi", "mn",
		"mo", "ms", "mtext", "noembed", "noframes", "noscript", "plaintext", "script", "selectedcontent",
		"style", "svg", "template", "thead", "title", "video", "xmp",
	})
	defaultDataURITags   = []string{"audio", "video", "img", "source", "image", "track"}
	defaultURISafeAttrs  = []string{"alt", "class", "for", "id", "label", "name", "pattern", "placeholder", "role", "summary", "title", "value", "style", "xmlns"}
	allSVGTags           = newSet(svgTags, svgFilterTags, svgDisallowedTags)
	allMathMLTags        = newSet(mathMLTags, mathMLDisallowedTags)
	commonSVGAndHTMLTags = newSet([]string{"title", "style", "font", "a", "script"})
	mathMLTextPoints     = newSet([]string{"mi", "mo", "mn", "ms", "mtext"})
	htmlIntegrationTags  = newSet([]string{"annotation-xml"})
	literalTextElements  = newSet([]string{"style", "script", "xmp", "iframe", "noembed", "noframes", "plaintext", "noscript"})
	clobberSet           = func() map[string]struct{} {
		m := make(map[string]struct{}, len(clobberNames))
		for _, n := range clobberNames {
			m[n] = struct{}{}
		}
		return m
	}()
)

// validate rejects list entries that can never match a parsed node: the
// HTML tokenizer never produces an empty name or one containing ASCII
// whitespace, so such an entry is a caller bug that would silently do
// nothing.
func (cfg *Config) validate() error {
	lists := []struct {
		field string
		names []string
	}{
		{"AllowedTags", cfg.AllowedTags},
		{"AllowedAttr", cfg.AllowedAttr},
		{"AddTags", cfg.AddTags},
		{"AddAttr", cfg.AddAttr},
		{"ForbidTags", cfg.ForbidTags},
		{"ForbidAttr", cfg.ForbidAttr},
		{"ForbidContents", cfg.ForbidContents},
		{"AddForbidContents", cfg.AddForbidContents},
		{"AddURISafeAttr", cfg.AddURISafeAttr},
		{"AddDataURITags", cfg.AddDataURITags},
	}
	for _, l := range lists {
		for _, name := range l.names {
			if name == "" || strings.ContainsAny(name, " \t\n\f\r") {
				return fmt.Errorf("htmlsanitizer: %s entry %q can never match an element or attribute name", l.field, name)
			}
		}
	}
	return nil
}

func boolOr(v *bool, def bool) bool {
	if v == nil {
		return def
	}
	return *v
}

// compile resolves a Config the way DOMPurify's _parseConfig does.
func compile(cfg Config) *Sanitizer {
	s := &Sanitizer{
		allowedTags:           newSet(htmlTags, svgTags, svgFilterTags, mathMLTags, textTags),
		allowedAttr:           newSet(htmlAttrs, svgAttrs, mathMLAttrs, xmlAttrs),
		forbidTags:            newSet(cfg.ForbidTags),
		forbidAttr:            newSet(cfg.ForbidAttr),
		forbidContents:        defaultForbidContents,
		uriSafeAttrs:          newSet(defaultURISafeAttrs, cfg.AddURISafeAttr),
		dataURITags:           newSet(defaultDataURITags, cfg.AddDataURITags),
		allowedURI:            defaultAllowedURI,
		allowDataAttr:         boolOr(cfg.AllowDataAttr, true),
		allowARIAAttr:         boolOr(cfg.AllowARIAAttr, true),
		allowUnknownProtocols: cfg.AllowUnknownProtocols,
		allowSelfCloseInAttr:  boolOr(cfg.AllowSelfCloseInAttr, true),
		keepContent:           boolOr(cfg.KeepContent, true),
		safeForTemplates:      cfg.SafeForTemplates,
		safeForXML:            boolOr(cfg.SafeForXML, true),
		sanitizeDOM:           boolOr(cfg.SanitizeDOM, true),
		sanitizeNamedProps:    cfg.SanitizeNamedProps,
		wholeDocument:         cfg.WholeDocument,
		forceBody:             cfg.ForceBody,
	}
	if cfg.AllowedTags != nil {
		s.allowedTags = newSet(cfg.AllowedTags)
	}
	if cfg.AllowedAttr != nil {
		s.allowedAttr = newSet(cfg.AllowedAttr)
	}
	if cfg.ForbidContents != nil {
		s.forbidContents = newSet(cfg.ForbidContents)
	}
	if cfg.AllowedURIRegexp != nil {
		s.allowedURI = cfg.AllowedURIRegexp
	}
	if s.safeForTemplates {
		s.allowDataAttr = false
	}

	if p := cfg.UseProfiles; p != nil {
		s.allowedTags = newSet(textTags)
		s.allowedAttr = set{}
		if p.HTML {
			s.allowedTags.add(htmlTags...)
			s.allowedAttr.add(htmlAttrs...)
		}
		if p.SVG {
			s.allowedTags.add(svgTags...)
			s.allowedAttr.add(svgAttrs...)
			s.allowedAttr.add(xmlAttrs...)
		}
		if p.SVGFilters {
			s.allowedTags.add(svgFilterTags...)
			s.allowedAttr.add(svgAttrs...)
			s.allowedAttr.add(xmlAttrs...)
		}
		if p.MathML {
			s.allowedTags.add(mathMLTags...)
			s.allowedAttr.add(mathMLAttrs...)
			s.allowedAttr.add(xmlAttrs...)
		}
	}

	s.allowedTags.add(cfg.AddTags...)
	s.allowedAttr.add(cfg.AddAttr...)
	if cfg.AddForbidContents != nil {
		s.forbidContents = newSet(mapKeys(s.forbidContents), cfg.AddForbidContents)
	}
	if s.keepContent {
		s.allowedTags.add("#text")
	}
	if s.wholeDocument {
		s.allowedTags.add("html", "head", "body")
	}
	if s.allowedTags.has("table") {
		s.allowedTags.add("tbody")
		delete(s.forbidTags, "tbody")
	}
	return s
}

func mapKeys(s set) []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	return out
}
