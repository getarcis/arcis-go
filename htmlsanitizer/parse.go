package htmlsanitizer

import (
	"strconv"
	"strings"

	"golang.org/x/net/html"
)

// DOMPurify's output depends on the tree that parse5 builds for jsdom. The
// x/net/html tree is the same for almost all input; this file covers the
// known differences.
//
// Repaired:
//   - The x/net/html tokenizer keeps duplicate attributes, where parse5 keeps
//     the first, and keeps raw NUL in tag and attribute names and values,
//     where parse5 substitutes U+FFFD.
//   - An end tag such as </mtext> or </desc> that reaches the HTML rules can
//     close a MathML or SVG element of that name in x/net/html. The HTML
//     standard (and parse5) only match HTML elements there and ignore the
//     tag. Such end tags are located by probing the parser and removed from
//     the input before the final parse, which is what ignoring them means.
//   - x/net/html reads <![CDATA[ as a CDATA section whenever the current node
//     is a MathML or SVG element. parse5 excludes the integration points
//     (SVG foreignObject, desc and title, MathML mi, mo, mn, ms and mtext,
//     and annotation-xml with an HTML encoding) and reads a bogus comment
//     there instead. Such sections are located with the same probe and
//     rewritten so x/net/html also reads a bogus comment with the same data.
//   - jsdom overwrites attribute values when <html> or <body> repeats, where
//     the standard and x/net/html keep the first value. This only shows in
//     whole-document output and is emulated there.
//
// Known remaining differences, all in malformed markup and all removing more
// than DOMPurify (pinned in TestRemainingParserDifferences): <hr> inside
// <select> (x/net/html drops it), template content after table-structure
// tags, the leading newline of <pre> and <listing> when other tags come
// first, and whitespace around <frameset> (whole-document output only).

// parseDocument parses dirty the way jsdom's DOMParser does for text/html: a
// full document with scripting disabled. It returns nil when x/net/html
// rejects the input (nesting deeper than 512 open elements) or when the
// probing below cannot settle the tree; the caller fails closed.
func parseDocument(dirty string, wholeDocument bool) *html.Node {
	doc := parseHTML(dirty)
	if doc == nil {
		return nil
	}
	if mayMiscloseForeignElement(doc, dirty) || mayMisreadCDATA(doc, dirty) {
		fixed, ok := settleParserDifferences(dirty)
		if !ok {
			return nil
		}
		if fixed != dirty {
			dirty = fixed
			if doc = parseHTML(dirty); doc == nil {
				return nil
			}
		}
	}
	if wholeDocument {
		adoptRepeatedTagAttributes(doc, dirty)
	}
	repairTree(doc)
	return doc
}

func parseHTML(markup string) *html.Node {
	doc, err := html.ParseWithOptions(strings.NewReader(markup), html.ParseOptionEnableScripting(false))
	if err != nil {
		return nil
	}
	return doc
}

// ─── Attribute repair ────────────────────────────────────────────────────

// repairTree drops duplicate attributes (keeping the first) and replaces NUL
// in element names and attributes, as parse5's tokenizer does. It also
// removes the marker from bogus comments made out of CDATA sections.
func repairTree(n *html.Node) {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		switch c.Type {
		case html.ElementNode:
			c.Data = replaceNUL(c.Data)
			c.Attr = dedupeAttributes(c.Attr)
		case html.CommentNode:
			c.Data = strings.TrimPrefix(c.Data, cdataMarker)
		}
		repairTree(c)
	}
}

func replaceNUL(s string) string {
	if strings.IndexByte(s, 0) < 0 {
		return s
	}
	return strings.ReplaceAll(s, "\x00", "\uFFFD")
}

func dedupeAttributes(attrs []html.Attribute) []html.Attribute {
	if len(attrs) == 0 {
		return attrs
	}
	out := attrs[:0]
	for _, a := range attrs {
		a.Key = replaceNUL(a.Key)
		a.Val = replaceNUL(a.Val)
		if findAttribute(out, a.Namespace, a.Key) < 0 {
			out = append(out, a)
		}
	}
	return out
}

// ─── Foreign end tags and CDATA sections ─────────────────────────────────

// misclosableNames are the foreign elements an end tag in HTML content can
// wrongly close in x/net/html: the MathML and SVG integration points, the
// only foreign elements that HTML elements are inserted under. (SVG
// foreignObject keeps its capital O, so no lowercase end tag matches it.)
var misclosableNames = []string{"annotation-xml", "mtext", "desc", "title", "mi", "mo", "mn", "ms"}

const maxProbes = 16

// probeMarker labels the comment inserted to locate the parser's current
// node, and cdataMarker turns a CDATA section into a bogus comment. A
// noncharacter keeps both apart from real content.
const (
	probeMarker = "\uFFFEarcis-probe"
	cdataMarker = "\uFFFEarcis-cdata"
	cdataStart  = "<![CDATA["
)

func isTextOrHTMLIntegrationPoint(n *html.Node) bool {
	switch n.Namespace {
	case "math":
		switch n.Data {
		case "mi", "mo", "mn", "ms", "mtext", "annotation-xml":
			return true
		}
	case "svg":
		return n.Data == "desc" || n.Data == "title"
	}
	return false
}

// mayMiscloseForeignElement is a cheap necessary condition for the
// x/net/html mistake: it closes an integration point while a non-special
// HTML element is open inside it, so that HTML element ends up as the
// integration point's last child, and the input holds the end tag.
func mayMiscloseForeignElement(n *html.Node, dirty string) bool {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type != html.ElementNode {
			continue
		}
		if isTextOrHTMLIntegrationPoint(c) {
			last := c.LastChild
			if last != nil && last.Type == html.ElementNode && last.Namespace == "" &&
				!xnetSpecialElements.has(last.Data) && indexEndTag(dirty, 0, c.Data) >= 0 {
				return true
			}
		}
		if mayMiscloseForeignElement(c, dirty) {
			return true
		}
	}
	return false
}

// mayMisreadCDATA is the necessary condition for the CDATA difference: the
// input has a CDATA section and the tree an integration point.
func mayMisreadCDATA(n *html.Node, dirty string) bool {
	return strings.Contains(dirty, cdataStart) && containsElement(n, isParse5IntegrationPoint)
}

func containsElement(n *html.Node, match func(*html.Node) bool) bool {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode && (match(c) || containsElement(c, match)) {
			return true
		}
	}
	return false
}

// isParse5IntegrationPoint is parse5's test for where CDATA sections are not
// recognized: HTML integration points and MathML text integration points.
// For annotation-xml the first encoding attribute decides.
func isParse5IntegrationPoint(n *html.Node) bool {
	switch n.Namespace {
	case "svg":
		return n.Data == "foreignObject" || n.Data == "desc" || n.Data == "title"
	case "math":
		switch n.Data {
		case "mi", "mo", "mn", "ms", "mtext":
			return true
		case "annotation-xml":
			for _, a := range n.Attr {
				if a.Namespace == "" && a.Key == "encoding" {
					v := strings.ToLower(a.Val)
					return v == "text/html" || v == "application/xhtml+xml"
				}
			}
		}
	}
	return false
}

type endTagVerdict int

const (
	endTagHandled   endTagVerdict = iota // x/net/html agrees with the standard
	endTagMisclosed                      // x/net/html closes a foreign element the standard leaves open
	endTagUnknown                        // the probe cannot tell
)

// settleParserDifferences walks the misclosing end tags and the CDATA
// sections in document order, since each fix changes the parser state for
// what follows. It removes each end tag that x/net/html would wrongly use to
// close a foreign element (removing a tag is exactly what the standard's
// "ignore the token" does), and marks each CDATA section that parse5 reads as
// a bogus comment so that x/net/html reads one too. It reports false when the
// input cannot be settled within the probe budget.
func settleParserDifferences(dirty string) (string, bool) {
	if strings.Contains(dirty, probeMarker) || strings.Contains(dirty, cdataMarker) {
		return "", false
	}
	probes := 0
	for pos := 0; ; {
		endTag, name := nextMisclosableEndTag(dirty, pos)
		cdata := strings.Index(dirty[pos:], cdataStart)
		if cdata >= 0 {
			cdata += pos
		}
		if endTag < 0 && cdata < 0 {
			return dirty, true
		}
		if probes++; probes > maxProbes {
			return "", false
		}

		if cdata >= 0 && (endTag < 0 || cdata < endTag) {
			probe, ok := probeAt(dirty, cdata)
			if !ok {
				return "", false
			}
			// x/net/html reads CDATA under any foreign current node; parse5
			// reads a bogus comment where that node is an integration point.
			if probe != nil && probe.Parent.Type == html.ElementNode && isParse5IntegrationPoint(probe.Parent) {
				dirty = dirty[:cdata+2] + cdataMarker + dirty[cdata+2:]
				pos = cdata + len(cdataMarker) + len(cdataStart)
				continue
			}
			pos = cdata + len(cdataStart)
			continue
		}

		probe, ok := probeAt(dirty, endTag)
		if !ok {
			return "", false
		}
		switch classifyProbedEndTag(probe, name) {
		case endTagUnknown:
			return "", false
		case endTagMisclosed:
			if n := endTagLength(dirty[endTag:]); n > 0 {
				dirty = dirty[:endTag] + dirty[endTag+n:]
				pos = endTag
				continue
			}
		}
		pos = endTag + 2
	}
}

// probeAt parses dirty with a comment inserted at offset i, where it lands on
// the parser's current node. It returns nil when no comment is created,
// meaning the offset is not in markup (it is inside text, an attribute or a
// comment), and false when the parse fails.
func probeAt(dirty string, i int) (*html.Node, bool) {
	doc := parseHTML(dirty[:i] + "<!--" + probeMarker + "-->" + dirty[i:])
	if doc == nil {
		return nil, false
	}
	return findComment(doc, probeMarker), true
}

// classifyProbedEndTag decides how an end tag named name is handled at the
// probe's position.
func classifyProbedEndTag(probe *html.Node, name string) endTagVerdict {
	if probe == nil {
		return endTagHandled
	}
	current := probe.Parent
	switch {
	case current.Type == html.DocumentNode:
		// Before <html> nothing is open; after </html> the comment goes to
		// the document and the open elements are not visible.
		for s := probe.NextSibling; s != nil; s = s.NextSibling {
			if s.Type == html.ElementNode {
				return endTagHandled
			}
		}
		return endTagUnknown
	case current.Namespace == "" && current.Data == "html":
		// After </body> comments go to the html element, again hiding the
		// open elements.
		for s := probe.PrevSibling; s != nil; s = s.PrevSibling {
			if s.Type == html.ElementNode && s.Namespace == "" && (s.Data == "body" || s.Data == "frameset") {
				return endTagUnknown
			}
		}
		return endTagHandled
	}
	return classifyEndTag(current, name)
}

// classifyEndTag compares how x/net/html and the standard treat an end tag
// named name when current is the current node. The ancestors of the current
// node stand in for the stack of open elements; where they differ (foster
// parenting) the walk meets a special table element and both stop.
func classifyEndTag(current *html.Node, name string) endTagVerdict {
	// In foreign content both close the nearest foreign element of that
	// name, ignoring case, before falling back to the HTML rules.
	for n := current; n != nil && n.Type == html.ElementNode && n.Namespace != ""; n = n.Parent {
		if strings.EqualFold(n.Data, name) {
			return endTagHandled
		}
	}
	// HTML rules ("any other end tag"): the standard only matches HTML
	// elements; x/net/html matches any namespace.
	for n := current; n != nil && n.Type == html.ElementNode; n = n.Parent {
		if n.Data == name {
			if n.Namespace == "" {
				return endTagHandled
			}
			if isTextOrHTMLIntegrationPoint(n) {
				return endTagMisclosed
			}
			return endTagUnknown
		}
		if isXNetSpecial(n) {
			return endTagHandled
		}
	}
	return endTagHandled
}

// isXNetSpecial mirrors x/net/html's "special" category, which ends its
// end-tag walk.
func isXNetSpecial(n *html.Node) bool {
	switch n.Namespace {
	case "":
		return xnetSpecialElements.has(n.Data)
	case "svg":
		return n.Data == "foreignObject" || n.Data == "desc" || n.Data == "title"
	}
	return isTextOrHTMLIntegrationPoint(n)
}

func findComment(n *html.Node, data string) *html.Node {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.CommentNode && c.Data == data {
			return c
		}
		if found := findComment(c, data); found != nil {
			return found
		}
	}
	return nil
}

// nextMisclosableEndTag finds the next end tag at or after from whose name is
// one of misclosableNames.
func nextMisclosableEndTag(dirty string, from int) (int, string) {
	best, bestName := -1, ""
	for _, name := range misclosableNames {
		if i := indexEndTag(dirty, from, name); i >= 0 && (best < 0 || i < best) {
			best, bestName = i, name
		}
	}
	return best, bestName
}

// indexEndTag finds "</name" at or after from, matched the way the tokenizer
// reads a tag name: ASCII case-insensitive and terminated by whitespace, "/"
// or ">".
func indexEndTag(dirty string, from int, name string) int {
	for i := from; i < len(dirty); {
		j := strings.Index(dirty[i:], "</")
		if j < 0 {
			return -1
		}
		i += j
		end := i + 2 + len(name)
		if end < len(dirty) && asciiEqualFold(dirty[i+2:end], name) && isTagNameEnd(dirty[end]) {
			return i
		}
		i += 2
	}
	return -1
}

func isTagNameEnd(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\f' || c == '\r' || c == '/' || c == '>'
}

func asciiEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

// endTagLength is the byte length of the end tag token at the start of s,
// or 0 if s does not start with one.
func endTagLength(s string) int {
	z := html.NewTokenizer(strings.NewReader(s))
	if z.Next() != html.EndTagToken {
		return 0
	}
	return len(z.Raw())
}

// ─── Repeated <html> and <body> ──────────────────────────────────────────

// adoptRepeatedTagAttributes gives the html and body elements jsdom's
// attribute values when those tags repeat: each later tag that the parser
// merges overwrites values that are already set. It parses a copy of the
// input in which every <html> and <body> tag has its attribute names tagged
// with the tag's position, so the merged copy shows which tag supplied what.
func adoptRepeatedTagAttributes(doc *html.Node, dirty string) {
	if countStartTags(dirty, "html") < 2 && countStartTags(dirty, "body") < 2 {
		return
	}
	var b strings.Builder
	last, occurrence := 0, 0
	for i := 0; i < len(dirty); i++ {
		name := startTagNameAt(dirty, i)
		if name == "" {
			continue
		}
		z := html.NewTokenizer(strings.NewReader(dirty[i:]))
		if tt := z.Next(); tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		raw := len(z.Raw())
		tok := z.Token()
		b.WriteString(dirty[last:i])
		b.WriteString("<" + name)
		for _, a := range tok.Attr {
			b.WriteString(" " + a.Key + "\uFFFE" + strconv.Itoa(occurrence))
			if a.Val != "" {
				b.WriteByte('=')
				writeUnquoted(&b, a.Val)
			}
		}
		b.WriteByte('>')
		occurrence++
		last = i + raw
		i = last - 1
	}
	b.WriteString(dirty[last:])

	tagged := parseHTML(b.String())
	if tagged == nil {
		return
	}
	dstHTML, srcHTML := firstChildElement(doc), firstChildElement(tagged)
	if dstHTML == nil || srcHTML == nil {
		return
	}
	adoptTaggedAttributes(dstHTML, srcHTML)
	if dst, src := documentBody(dstHTML), documentBody(srcHTML); dst != nil && src != nil && dst.Data == src.Data {
		adoptTaggedAttributes(dst, src)
	}
}

// adoptTaggedAttributes replays src's position-tagged attributes onto dst in
// order, overwriting earlier values as jsdom does.
func adoptTaggedAttributes(dst, src *html.Node) {
	var merged []html.Attribute
	seen := map[string]bool{}
	for _, a := range src.Attr {
		if seen[a.Key] {
			continue // a duplicate within one tag: the first one counts
		}
		seen[a.Key] = true
		key := a.Key
		if cut := strings.LastIndex(key, "\uFFFE"); cut >= 0 {
			key = key[:cut]
		}
		if j := findAttribute(merged, "", key); j >= 0 {
			merged[j].Val = a.Val
		} else {
			merged = append(merged, html.Attribute{Key: key, Val: a.Val})
		}
	}
	dst.Attr = merged
}

// startTagNameAt returns "html" or "body" if dirty has that start tag at i.
func startTagNameAt(dirty string, i int) string {
	if dirty[i] != '<' {
		return ""
	}
	for _, name := range []string{"html", "body"} {
		end := i + 1 + len(name)
		if end < len(dirty) && asciiEqualFold(dirty[i+1:end], name) && isTagNameEnd(dirty[end]) {
			return name
		}
	}
	return ""
}

func countStartTags(dirty, name string) int {
	n := 0
	for i := 0; i < len(dirty); i++ {
		if startTagNameAt(dirty, i) == name {
			n++
		}
	}
	return n
}

// writeUnquoted writes v as an unquoted attribute value: ASCII letters and
// digits and all non-ASCII bytes as they are, every other byte as a numeric
// character reference, so the value cannot end the tag or change the
// surrounding markup.
func writeUnquoted(b *strings.Builder, v string) {
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c >= 0x80 || ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9') {
			b.WriteByte(c)
			continue
		}
		b.WriteString("&#" + strconv.Itoa(int(c)) + ";")
	}
}

// xnetSpecialElements is x/net/html's list of HTML elements in the
// "special" category, which stop its end-tag walk.
var xnetSpecialElements = newSet([]string{
	"address", "applet", "area", "article", "aside", "base", "basefont", "bgsound", "blockquote", "body",
	"br", "button", "caption", "center", "col", "colgroup", "dd", "details", "dir", "div", "dl", "dt",
	"embed", "fieldset", "figcaption", "figure", "footer", "form", "frame", "frameset", "h1", "h2", "h3",
	"h4", "h5", "h6", "head", "header", "hgroup", "hr", "html", "iframe", "img", "input", "keygen", "li",
	"link", "listing", "main", "marquee", "menu", "meta", "nav", "noembed", "noframes", "noscript",
	"object", "ol", "p", "param", "plaintext", "pre", "script", "section", "select", "source", "style",
	"summary", "table", "tbody", "td", "template", "textarea", "tfoot", "th", "thead", "title", "tr",
	"track", "ul", "wbr", "xmp",
})
