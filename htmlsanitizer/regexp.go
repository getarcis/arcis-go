package htmlsanitizer

import (
	"regexp"
	"strings"
)

// Regular expressions ported from DOMPurify 3.4.18 (src/regexp.ts).
//
// None of the upstream patterns use lookarounds or backreferences, so each
// one has a direct RE2 equivalent. Two JavaScript semantics need care:
//
//   - The /i flag without /u folds case only within ASCII for these
//     patterns, while RE2's (?i) also folds U+017F (long s) with s and U+212A
//     (Kelvin sign) with k. Case-insensitive letters are therefore spelled
//     out as explicit [xX] classes instead of using (?i).
//   - Without /u, JavaScript matches UTF-16 code units, so a class range that
//     ends at \uFFFF also matches both halves of every astral character. The
//     Go ranges run to \x{10FFFF} to match the same strings.
var (
	// /{{[\w\W]*|^[\w\W]*}}/g
	mustacheExpr = regexp.MustCompile(`\{\{[\s\S]*|^[\s\S]*\}\}`)
	// /<%[\w\W]*|^[\w\W]*%>/g
	erbExpr = regexp.MustCompile(`<%[\s\S]*|^[\s\S]*%>`)
	// /\${[\w\W]*/g
	tmplitExpr = regexp.MustCompile(`\$\{[\s\S]*`)
	// /{{|}}|\${|<%|%>|&lt;%|%&gt;/
	tmplMarkerSerialized = regexp.MustCompile(`\{\{|\}\}|\$\{|<%|%>|&lt;%|%&gt;`)
	// /^data-[\-\w.\u00B7-\uFFFF]+$/
	dataAttr = regexp.MustCompile(`^data-[\-\w.\x{00B7}-\x{10FFFF}]+$`)
	// /^aria-[\-\w]+$/
	ariaAttr = regexp.MustCompile(`^aria-[\-\w]+$`)
	// /^(?:(?:(?:f|ht)tps?|mailto|tel|callto|sms|cid|xmpp|matrix):|[^a-z]|[a-z+.\-]+(?:[^a-z+.\-:]|$))/i
	defaultAllowedURI = regexp.MustCompile(`^(?:(?:(?:` + ci("f") + `|` + ci("ht") + `)` + ci("tp") + `[sS]?|` +
		ci("mailto") + `|` + ci("tel") + `|` + ci("callto") + `|` + ci("sms") + `|` + ci("cid") + `|` +
		ci("xmpp") + `|` + ci("matrix") + `):|[^a-zA-Z]|[a-zA-Z+.\-]+(?:[^a-zA-Z+.\-:]|$))`)
	// /^(?:\w+script|data):/i
	isScriptOrData = regexp.MustCompile(`^(?:\w+` + ci("script") + `|` + ci("data") + `):`)
	// /^html$/i
	doctypeName = regexp.MustCompile(`^` + ci("html") + `$`)
	// /<[/\w!]/g
	elementMarkupProbe = regexp.MustCompile(`<[/\w!]`)
	// /<[/\w]/g
	commentMarkupProbe = regexp.MustCompile(`<[/\w]`)
	// /<\/no(script|embed|frames)/i
	fallbackTagClose = regexp.MustCompile(`</` + ci("no") + `(?:` + ci("script") + `|` + ci("embed") + `|` + ci("frames") + `)`)
	// /((--!?|])>)|<\/(style|script|title|xmp|textarea|noscript|iframe|noembed|noframes)/i
	attrValueBreakout = regexp.MustCompile(`(?:--!?|\])>|</(?:` + strings.Join(ciAll(
		"style", "script", "title", "xmp", "textarea", "noscript", "iframe", "noembed", "noframes"), "|") + `)`)
	// /^[\r\n\t ]+/
	leadingWhitespace = regexp.MustCompile(`^[\r\n\t ]+`)
)

// selfClosingTag is DOMPurify's /\/>/i, a plain substring test.
const selfClosingTag = "/>"

// ci spells an ASCII word as a sequence of [xX] classes, the RE2 form of a
// JavaScript /i match without /u.
func ci(word string) string {
	var b strings.Builder
	for i := 0; i < len(word); i++ {
		c := word[i]
		if c >= 'a' && c <= 'z' {
			b.WriteByte('[')
			b.WriteByte(c)
			b.WriteByte(c - 'a' + 'A')
			b.WriteByte(']')
			continue
		}
		b.WriteString(regexp.QuoteMeta(string(c)))
	}
	return b.String()
}

func ciAll(words ...string) []string {
	out := make([]string, len(words))
	for i, w := range words {
		out[i] = ci(w)
	}
	return out
}

// isAttrWhitespace reports whether r is in DOMPurify's ATTR_WHITESPACE class,
// /[\u0000-\u0020\u00A0\u1680\u180E\u2000-\u2029\u205F\u3000]/.
func isAttrWhitespace(r rune) bool {
	switch {
	case r <= 0x20, r == 0xA0, r == 0x1680, r == 0x180E, r == 0x205F, r == 0x3000:
		return true
	case r >= 0x2000 && r <= 0x2029:
		return true
	}
	return false
}

// compactURI removes ATTR_WHITESPACE characters, as DOMPurify does before
// testing a value against the URI allowlist.
func compactURI(value string) string {
	if strings.IndexFunc(value, isAttrWhitespace) < 0 {
		return value
	}
	return strings.Map(func(r rune) rune {
		if isAttrWhitespace(r) {
			return -1
		}
		return r
	}, value)
}

// isJSWhitespace reports whether r is stripped by String.prototype.trim:
// WhiteSpace plus LineTerminator in ECMAScript.
func isJSWhitespace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0xA0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF:
		return true
	}
	return r >= 0x2000 && r <= 0x200A
}

// jsTrim matches String.prototype.trim.
func jsTrim(s string) string {
	return strings.TrimFunc(s, isJSWhitespace)
}

// stripTemplateExpressions replaces mustache, ERB and template literal
// syntax with a space, in that order, like DOMPurify's
// _stripTemplateExpressions.
func stripTemplateExpressions(value string) string {
	value = mustacheExpr.ReplaceAllLiteralString(value, " ")
	value = erbExpr.ReplaceAllLiteralString(value, " ")
	return tmplitExpr.ReplaceAllLiteralString(value, " ")
}
