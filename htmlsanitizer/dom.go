package htmlsanitizer

import (
	"strings"

	"golang.org/x/net/html"
)

// x/net/html stores a template's content as the template element's
// children, while the DOM keeps it in a separate DocumentFragment. Helpers
// here present the DOM view: an HTML template has no children of its own.

func isTemplate(n *html.Node) bool {
	return n.Type == html.ElementNode && n.Namespace == "" && n.Data == "template"
}

// hasDOMChildren is Node.hasChildNodes().
func hasDOMChildren(n *html.Node) bool {
	return n.FirstChild != nil && !isTemplate(n)
}

// firstElementChild is ParentNode.firstElementChild.
func firstElementChild(n *html.Node) *html.Node {
	if isTemplate(n) {
		return nil
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode {
			return c
		}
	}
	return nil
}

// nodeName is the DOM nodeName lowercased, as DOMPurify compares it.
func nodeName(n *html.Node) string {
	switch n.Type {
	case html.TextNode:
		return "#text"
	case html.CommentNode:
		return "#comment"
	case html.DocumentNode:
		return "#document"
	}
	return strings.ToLower(n.Data)
}

// textContent is Node.textContent for elements and character data.
func textContent(n *html.Node) string {
	if n.Type == html.TextNode || n.Type == html.CommentNode {
		return n.Data
	}
	var b strings.Builder
	var collect func(*html.Node)
	collect = func(p *html.Node) {
		if isTemplate(p) {
			return
		}
		for c := p.FirstChild; c != nil; c = c.NextSibling {
			switch c.Type {
			case html.TextNode:
				b.WriteString(c.Data)
			case html.ElementNode:
				collect(c)
			}
		}
	}
	collect(n)
	return b.String()
}

// firstChildElement returns the document element.
func firstChildElement(doc *html.Node) *html.Node {
	for c := doc.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode {
			return c
		}
	}
	return nil
}

// documentBody is Document.body: the html element's first body or frameset
// child.
func documentBody(docElement *html.Node) *html.Node {
	if docElement.Namespace != "" || docElement.Data != "html" {
		return nil
	}
	for c := docElement.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode && c.Namespace == "" && (c.Data == "body" || c.Data == "frameset") {
			return c
		}
	}
	return nil
}

// findHTMLElement is getElementsByTagName(name)[0] for an HTML-namespace
// name: the first matching element in tree order, outside template content.
func findHTMLElement(n *html.Node, name string) *html.Node {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type != html.ElementNode {
			continue
		}
		if c.Namespace == "" && c.Data == name {
			return c
		}
		if isTemplate(c) {
			continue
		}
		if found := findHTMLElement(c, name); found != nil {
			return found
		}
	}
	return nil
}

func doctypeOf(doc *html.Node) *html.Node {
	for c := doc.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.DoctypeNode {
			return c
		}
	}
	return nil
}

func findAttribute(attrs []html.Attribute, namespace, key string) int {
	for i, a := range attrs {
		if a.Namespace == namespace && a.Key == key {
			return i
		}
	}
	return -1
}

// setAttribute updates the attribute in place or appends it, like
// Element.setAttribute and setAttributeNS.
func setAttribute(n *html.Node, namespace, key, value string) {
	if i := findAttribute(n.Attr, namespace, key); i >= 0 {
		n.Attr[i].Val = value
		return
	}
	n.Attr = append(n.Attr, html.Attribute{Namespace: namespace, Key: key, Val: value})
}

func deleteAttribute(n *html.Node, namespace, key string) {
	if i := findAttribute(n.Attr, namespace, key); i >= 0 {
		n.Attr = append(n.Attr[:i], n.Attr[i+1:]...)
	}
}

// qualifiedName is Attr.name: x/net/html stores the foreign-attribute prefix
// in Namespace ("xlink", "xml" or "xmlns").
func qualifiedName(a html.Attribute) string {
	switch a.Namespace {
	case "":
		return a.Key
	case "xmlns":
		if a.Key == "xmlns" {
			return a.Key
		}
	}
	return a.Namespace + ":" + a.Key
}

// isValidAttributeLocalName is the DOM check jsdom applies in setAttribute.
func isValidAttributeLocalName(name string) bool {
	return name != "" && !strings.ContainsAny(name, "\x00\t\n\f\r /=>")
}

// ─── Node iterator ───────────────────────────────────────────────────────

// iterator reproduces a DOM NodeIterator showing elements, text and
// comments, including its adjustment when the current node is removed.
type iterator struct {
	root      *html.Node
	ref       *html.Node
	started   bool
	visitRoot bool
}

func newIterator(root *html.Node, visitRoot bool) *iterator {
	return &iterator{root: root, ref: root, visitRoot: visitRoot}
}

func (it *iterator) next() *html.Node {
	var n *html.Node
	if !it.started {
		it.started = true
		n = it.root
		if !it.visitRoot {
			n = it.following(n)
		}
	} else {
		n = it.following(it.ref)
	}
	for n != nil && !isShown(n) {
		n = it.following(n)
	}
	if n != nil {
		it.ref = n
	}
	return n
}

func isShown(n *html.Node) bool {
	return n.Type == html.ElementNode || n.Type == html.TextNode || n.Type == html.CommentNode
}

// following returns the next node in tree order within root. A template's
// children are only entered when the template is the root, standing in for
// its content fragment.
func (it *iterator) following(n *html.Node) *html.Node {
	if n.FirstChild != nil && (n == it.root || !isTemplate(n)) {
		return n.FirstChild
	}
	for ; n != nil && n != it.root; n = n.Parent {
		if n.NextSibling != nil {
			return n.NextSibling
		}
	}
	return nil
}

// beforeRemove applies the NodeIterator pre-removing steps for n, which is
// always the iterator's current node when DOMPurify removes something.
func (it *iterator) beforeRemove(n *html.Node) {
	if n == it.root || n != it.ref {
		return
	}
	if p := n.PrevSibling; p != nil {
		for !isTemplate(p) && p.LastChild != nil {
			p = p.LastChild
		}
		it.ref = p
		return
	}
	it.ref = n.Parent
}

// ─── Template scrubbing ──────────────────────────────────────────────────

// scrubOwnCharacterData mirrors _scrubOwnCharacterData: normalize the tree,
// then strip template expressions from every text and comment node, without
// entering nested template content.
func scrubOwnCharacterData(root *html.Node) {
	normalizeText(root)
	var scrub func(*html.Node)
	scrub = func(p *html.Node) {
		for c := p.FirstChild; c != nil; c = c.NextSibling {
			switch c.Type {
			case html.TextNode, html.CommentNode:
				c.Data = stripTemplateExpressions(c.Data)
			case html.ElementNode:
				if !isTemplate(c) {
					scrub(c)
				}
			}
		}
	}
	scrub(root)
}

// normalizeText is Node.normalize(): drop empty text nodes and merge
// adjacent ones. As in the DOM, nested template content is not entered; the
// root's own children are processed even when the root is a template that
// stands in for its content fragment.
func normalizeText(root *html.Node) {
	var walk func(*html.Node)
	walk = func(p *html.Node) {
		for c := p.FirstChild; c != nil; {
			next := c.NextSibling
			switch c.Type {
			case html.TextNode:
				if c.Data == "" {
					p.RemoveChild(c)
					break
				}
				for next != nil && next.Type == html.TextNode {
					c.Data += next.Data
					following := next.NextSibling
					p.RemoveChild(next)
					next = following
				}
			case html.ElementNode:
				if !isTemplate(c) {
					walk(c)
				}
			}
			c = next
		}
	}
	walk(root)
}

// ─── Serialization ───────────────────────────────────────────────────────
//
// DOMPurify's output is jsdom's innerHTML/outerHTML, which is parse5's
// serializer with jsdom's tree adapter and scripting disabled. The
// functions below follow parse5 8.1.1 exactly.

var voidElements = newSet([]string{
	"area", "base", "basefont", "bgsound", "br", "col", "embed", "frame", "hr", "img", "input", "keygen",
	"link", "meta", "param", "source", "track", "wbr",
})

// rawTextElements serialize their text children unescaped. noscript joins
// them only when scripting is enabled: jsdom's DOMParser document has it
// disabled, but template content belongs to an inert document that keeps the
// default (enabled), which matters for innerHTML read inside template content.
var rawTextElements = newSet([]string{"style", "script", "xmp", "iframe", "noembed", "noframes", "plaintext"})

// innerHTML serializes n's children (a template's content).
func innerHTML(n *html.Node, scripting bool) string {
	if n.Type == html.ElementNode && n.Namespace == "" && voidElements.has(n.Data) {
		return ""
	}
	var b strings.Builder
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		serializeNode(&b, c, scripting)
	}
	return b.String()
}

// outerHTML serializes n itself, as the final output does (scripting
// disabled).
func outerHTML(n *html.Node) string {
	var b strings.Builder
	serializeNode(&b, n, false)
	return b.String()
}

func serializeNode(b *strings.Builder, n *html.Node, scripting bool) {
	switch n.Type {
	case html.ElementNode:
		b.WriteByte('<')
		b.WriteString(n.Data)
		for _, a := range n.Attr {
			b.WriteByte(' ')
			b.WriteString(qualifiedName(a))
			b.WriteString(`="`)
			escapeInto(b, a.Val, true)
			b.WriteByte('"')
		}
		b.WriteByte('>')
		if n.Namespace == "" && voidElements.has(n.Data) {
			return
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			serializeNode(b, c, scripting)
		}
		b.WriteString("</")
		b.WriteString(n.Data)
		b.WriteByte('>')
	case html.TextNode:
		if p := n.Parent; p != nil && p.Type == html.ElementNode && p.Namespace == "" &&
			(rawTextElements.has(p.Data) || (scripting && p.Data == "noscript")) {
			b.WriteString(n.Data)
			return
		}
		escapeInto(b, n.Data, false)
	case html.CommentNode:
		b.WriteString("<!--")
		b.WriteString(n.Data)
		b.WriteString("-->")
	case html.DoctypeNode:
		b.WriteString("<!DOCTYPE ")
		b.WriteString(n.Data)
		b.WriteByte('>')
	}
}

// escapeInto writes s with the escaping of the HTML serialization
// algorithm: & < > and U+00A0 always, and " inside attribute values.
func escapeInto(b *strings.Builder, s string, attribute bool) {
	last := 0
	for i := 0; i < len(s); i++ {
		var esc string
		switch s[i] {
		case '&':
			esc = "&amp;"
		case '<':
			esc = "&lt;"
		case '>':
			esc = "&gt;"
		case '"':
			if !attribute {
				continue
			}
			esc = "&quot;"
		case 0xC2:
			// U+00A0 is encoded as C2 A0 in UTF-8.
			if i+1 >= len(s) || s[i+1] != 0xA0 {
				continue
			}
			b.WriteString(s[last:i])
			b.WriteString("&nbsp;")
			i++
			last = i + 1
			continue
		default:
			continue
		}
		b.WriteString(s[last:i])
		b.WriteString(esc)
		last = i + 1
	}
	b.WriteString(s[last:])
}
