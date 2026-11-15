package htmlsanitizer

import (
	"regexp"
	"testing"
)

// regexpProbes holds DOMPurify's own regular expressions evaluated by
// JavaScript (Node 26) on probe strings chosen around the places where RE2
// and JavaScript differ: case folding of U+017F and U+212A, astral
// characters, and the Unicode whitespace sets. Columns: test results in the
// order of regexpProbeNames, then the template-expression strip, the
// ATTR_WHITESPACE compaction, String.prototype.trim and the leading
// whitespace match.
var regexpProbes = []struct {
	input   string
	matches [10]bool
	strip   string
	compact string
	trim    string
	leading string
}{
	{"", [10]bool{false, false, false, false, false, false, false, false, false, false}, "", "", "", ""},
	{"javascript:alert(1)", [10]bool{false, true, false, false, false, false, false, false, false, false}, "javascript:alert(1)", "javascript:alert(1)", "javascript:alert(1)", ""},
	{"JavaScript:x", [10]bool{false, true, false, false, false, false, false, false, false, false}, "JavaScript:x", "JavaScript:x", "JavaScript:x", ""},
	{"vbscript:x", [10]bool{false, true, false, false, false, false, false, false, false, false}, "vbscript:x", "vbscript:x", "vbscript:x", ""},
	{"\u017fcript:x", [10]bool{true, false, false, false, false, false, false, false, false, false}, "\u017fcript:x", "\u017fcript:x", "\u017fcript:x", ""},
	{"xmpp:a", [10]bool{true, false, false, false, false, false, false, false, false, false}, "xmpp:a", "xmpp:a", "xmpp:a", ""},
	{"XMPP:a", [10]bool{true, false, false, false, false, false, false, false, false, false}, "XMPP:a", "XMPP:a", "XMPP:a", ""},
	{"matrix:u", [10]bool{true, false, false, false, false, false, false, false, false, false}, "matrix:u", "matrix:u", "matrix:u", ""},
	{"HTTPS://a", [10]bool{true, false, false, false, false, false, false, false, false, false}, "HTTPS://a", "HTTPS://a", "HTTPS://a", ""},
	{"ftp://h", [10]bool{true, false, false, false, false, false, false, false, false, false}, "ftp://h", "ftp://h", "ftp://h", ""},
	{"ftps://h", [10]bool{true, false, false, false, false, false, false, false, false, false}, "ftps://h", "ftps://h", "ftps://h", ""},
	{"mailto:a@b", [10]bool{true, false, false, false, false, false, false, false, false, false}, "mailto:a@b", "mailto:a@b", "mailto:a@b", ""},
	{"tel:1", [10]bool{true, false, false, false, false, false, false, false, false, false}, "tel:1", "tel:1", "tel:1", ""},
	{"callto:x", [10]bool{true, false, false, false, false, false, false, false, false, false}, "callto:x", "callto:x", "callto:x", ""},
	{"sms:1", [10]bool{true, false, false, false, false, false, false, false, false, false}, "sms:1", "sms:1", "sms:1", ""},
	{"cid:x", [10]bool{true, false, false, false, false, false, false, false, false, false}, "cid:x", "cid:x", "cid:x", ""},
	{"foo:bar", [10]bool{false, false, false, false, false, false, false, false, false, false}, "foo:bar", "foo:bar", "foo:bar", ""},
	{"foo", [10]bool{true, false, false, false, false, false, false, false, false, false}, "foo", "foo", "foo", ""},
	{"/rel", [10]bool{true, false, false, false, false, false, false, false, false, false}, "/rel", "/rel", "/rel", ""},
	{"#a", [10]bool{true, false, false, false, false, false, false, false, false, false}, "#a", "#a", "#a", ""},
	{"1:x", [10]bool{true, false, false, false, false, false, false, false, false, false}, "1:x", "1:x", "1:x", ""},
	{"a-b.c+d:e", [10]bool{false, false, false, false, false, false, false, false, false, false}, "a-b.c+d:e", "a-b.c+d:e", "a-b.c+d:e", ""},
	{"a-b.c+d", [10]bool{true, false, false, false, false, false, false, false, false, false}, "a-b.c+d", "a-b.c+d", "a-b.c+d", ""},
	{"ab/c:d", [10]bool{true, false, false, false, false, false, false, false, false, false}, "ab/c:d", "ab/c:d", "ab/c:d", ""},
	{"\u017fms:1", [10]bool{true, false, false, false, false, false, false, false, false, false}, "\u017fms:1", "\u017fms:1", "\u017fms:1", ""},
	{"\u212aelvin:x", [10]bool{true, false, false, false, false, false, false, false, false, false}, "\u212aelvin:x", "\u212aelvin:x", "\u212aelvin:x", ""},
	{"k:x", [10]bool{false, false, false, false, false, false, false, false, false, false}, "k:x", "k:x", "k:x", ""},
	{"data:text/html,x", [10]bool{false, true, false, false, false, false, false, false, false, false}, "data:text/html,x", "data:text/html,x", "data:text/html,x", ""},
	{"DATA:x", [10]bool{false, true, false, false, false, false, false, false, false, false}, "DATA:x", "DATA:x", "DATA:x", ""},
	{"xjavascript:", [10]bool{false, true, false, false, false, false, false, false, false, false}, "xjavascript:", "xjavascript:", "xjavascript:", ""},
	{"data-x", [10]bool{true, false, true, false, false, false, false, false, false, false}, "data-x", "data-x", "data-x", ""},
	{"data-", [10]bool{true, false, false, false, false, false, false, false, false, false}, "data-", "data-", "data-", ""},
	{"data-\u00e9", [10]bool{true, false, true, false, false, false, false, false, false, false}, "data-\u00e9", "data-\u00e9", "data-\u00e9", ""},
	{"data-\U0001f600", [10]bool{true, false, true, false, false, false, false, false, false, false}, "data-\U0001f600", "data-\U0001f600", "data-\U0001f600", ""},
	{"data-a b", [10]bool{true, false, false, false, false, false, false, false, false, false}, "data-a b", "data-ab", "data-a b", ""},
	{"data-a:b", [10]bool{false, false, false, false, false, false, false, false, false, false}, "data-a:b", "data-a:b", "data-a:b", ""},
	{"data-\u00b6", [10]bool{true, false, false, false, false, false, false, false, false, false}, "data-\u00b6", "data-\u00b6", "data-\u00b6", ""},
	{"aria-x", [10]bool{true, false, false, true, false, false, false, false, false, false}, "aria-x", "aria-x", "aria-x", ""},
	{"aria-\u00e9", [10]bool{true, false, false, false, false, false, false, false, false, false}, "aria-\u00e9", "aria-\u00e9", "aria-\u00e9", ""},
	{"aria-", [10]bool{true, false, false, false, false, false, false, false, false, false}, "aria-", "aria-", "aria-", ""},
	{"-->", [10]bool{true, false, false, false, true, false, false, false, false, false}, "-->", "-->", "-->", ""},
	{"--!>", [10]bool{true, false, false, false, true, false, false, false, false, false}, "--!>", "--!>", "--!>", ""},
	{"]>", [10]bool{true, false, false, false, true, false, false, false, false, false}, "]>", "]>", "]>", ""},
	{"a]>b", [10]bool{true, false, false, false, true, false, false, false, false, false}, "a]>b", "a]>b", "a]>b", ""},
	{"</STYLE", [10]bool{true, false, false, false, true, false, true, true, false, false}, "</STYLE", "</STYLE", "</STYLE", ""},
	{"</\u017ftyle", [10]bool{true, false, false, false, false, false, true, true, false, false}, "</\u017ftyle", "</\u017ftyle", "</\u017ftyle", ""},
	{"</noScript", [10]bool{true, false, false, false, true, true, true, true, false, false}, "</noScript", "</noScript", "</noScript", ""},
	{"</NOEMBED", [10]bool{true, false, false, false, true, true, true, true, false, false}, "</NOEMBED", "</NOEMBED", "</NOEMBED", ""},
	{"</noframes", [10]bool{true, false, false, false, true, true, true, true, false, false}, "</noframes", "</noframes", "</noframes", ""},
	{"</no", [10]bool{true, false, false, false, false, false, true, true, false, false}, "</no", "</no", "</no", ""},
	{"<b", [10]bool{true, false, false, false, false, false, true, true, false, false}, "<b", "<b", "<b", ""},
	{"<!x", [10]bool{true, false, false, false, false, false, true, false, false, false}, "<!x", "<!x", "<!x", ""},
	{"</", [10]bool{true, false, false, false, false, false, true, true, false, false}, "</", "</", "</", ""},
	{"<\u017f", [10]bool{true, false, false, false, false, false, false, false, false, false}, "<\u017f", "<\u017f", "<\u017f", ""},
	{"< b", [10]bool{true, false, false, false, false, false, false, false, false, false}, "< b", "<b", "< b", ""},
	{"<1", [10]bool{true, false, false, false, false, false, true, true, false, false}, "<1", "<1", "<1", ""},
	{"<_", [10]bool{true, false, false, false, false, false, true, true, false, false}, "<_", "<_", "<_", ""},
	{"html", [10]bool{true, false, false, false, false, false, false, false, true, false}, "html", "html", "html", ""},
	{"HTML", [10]bool{true, false, false, false, false, false, false, false, true, false}, "HTML", "HTML", "HTML", ""},
	{"htm", [10]bool{true, false, false, false, false, false, false, false, false, false}, "htm", "htm", "htm", ""},
	{"xhtml", [10]bool{true, false, false, false, false, false, false, false, false, false}, "xhtml", "xhtml", "xhtml", ""},
	{"{{a}}", [10]bool{true, false, false, false, false, false, false, false, false, true}, " ", "{{a}}", "{{a}}", ""},
	{"a}}b{{c", [10]bool{true, false, false, false, false, false, false, false, false, true}, " b ", "a}}b{{c", "a}}b{{c", ""},
	{"x}}", [10]bool{true, false, false, false, false, false, false, false, false, true}, " ", "x}}", "x}}", ""},
	{"{{", [10]bool{true, false, false, false, false, false, false, false, false, true}, " ", "{{", "{{", ""},
	{"<% x %>", [10]bool{true, false, false, false, false, false, false, false, false, true}, " ", "<%x%>", "<% x %>", ""},
	{"a%>b<%c", [10]bool{true, false, false, false, false, false, false, false, false, true}, " b ", "a%>b<%c", "a%>b<%c", ""},
	{"${x}", [10]bool{true, false, false, false, false, false, false, false, false, true}, " ", "${x}", "${x}", ""},
	{"a${", [10]bool{true, false, false, false, false, false, false, false, false, true}, "a ", "a${", "a${", ""},
	{"&lt;%", [10]bool{true, false, false, false, false, false, false, false, false, true}, "&lt;%", "&lt;%", "&lt;%", ""},
	{"%&gt;", [10]bool{true, false, false, false, false, false, false, false, false, true}, "%&gt;", "%&gt;", "%&gt;", ""},
	{"\r\n\t x", [10]bool{true, false, false, false, false, false, false, false, false, false}, "\r\n\t x", "x", "x", "\r\n\t "},
	{"\f x", [10]bool{true, false, false, false, false, false, false, false, false, false}, "\f x", "x", "x", ""},
	{" \u00a0x\u2028y\u3000", [10]bool{true, false, false, false, false, false, false, false, false, false}, " \u00a0x\u2028y\u3000", "xy", "x\u2028y", " "},
	{"\u180e\u205f\u2029z", [10]bool{true, false, false, false, false, false, false, false, false, false}, "\u180e\u205f\u2029z", "z", "\u180e\u205f\u2029z", ""},
}

var regexpProbeNames = [10]string{
	"IS_ALLOWED_URI", "IS_SCRIPT_OR_DATA", "DATA_ATTR", "ARIA_ATTR", "ATTR_VALUE_BREAKOUT",
	"FALLBACK_TAG_CLOSE", "ELEMENT_MARKUP_PROBE", "COMMENT_MARKUP_PROBE", "DOCTYPE_NAME", "TMPL_MARKER_SERIALIZED",
}

func TestRegexpTranslation(t *testing.T) {
	compiled := [10]*regexp.Regexp{
		defaultAllowedURI, isScriptOrData, dataAttr, ariaAttr, attrValueBreakout,
		fallbackTagClose, elementMarkupProbe, commentMarkupProbe, doctypeName, tmplMarkerSerialized,
	}
	for _, p := range regexpProbes {
		for i, re := range compiled {
			if got := re.MatchString(p.input); got != p.matches[i] {
				t.Errorf("%s on %q: got %v, JavaScript %v", regexpProbeNames[i], p.input, got, p.matches[i])
			}
		}
		if got := stripTemplateExpressions(p.input); got != p.strip {
			t.Errorf("template strip of %q: got %q, JavaScript %q", p.input, got, p.strip)
		}
		if got := compactURI(p.input); got != p.compact {
			t.Errorf("ATTR_WHITESPACE compaction of %q: got %q, JavaScript %q", p.input, got, p.compact)
		}
		if got := jsTrim(p.input); got != p.trim {
			t.Errorf("trim of %q: got %q, JavaScript %q", p.input, got, p.trim)
		}
		if got := leadingWhitespace.FindString(p.input); got != p.leading {
			t.Errorf("leading whitespace of %q: got %q, JavaScript %q", p.input, got, p.leading)
		}
	}
}
