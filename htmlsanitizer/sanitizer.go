// Package htmlsanitizer cleans untrusted HTML with a WHATWG-compliant parser
// (golang.org/x/net/html). For every input and configuration it produces the
// same string as DOMPurify 3.4 running on jsdom, so markup an application
// accepts from users (comments, rich text, CMS content) can be rendered
// safely.
//
// This is an explicit function for fields that contain HTML. It is never
// applied implicitly to request data.
//
// The element, attribute, namespace and URI rules are ported from DOMPurify
// (https://github.com/cure53/DOMPurify, version 3.4.18), Copyright (c) Cure53
// and other contributors, used under the Apache License, Version 2.0.
package htmlsanitizer

import (
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/html"
)

// Sanitizer is a compiled configuration. It is immutable after New returns
// and safe for concurrent use.
type Sanitizer struct {
	allowedTags    set
	allowedAttr    set
	forbidTags     set
	forbidAttr     set
	forbidContents set
	uriSafeAttrs   set
	dataURITags    set
	allowedURI     *regexp.Regexp

	allowDataAttr         bool
	allowARIAAttr         bool
	allowUnknownProtocols bool
	allowSelfCloseInAttr  bool
	keepContent           bool
	safeForTemplates      bool
	safeForXML            bool
	sanitizeDOM           bool
	sanitizeNamedProps    bool
	wholeDocument         bool
	forceBody             bool
}

// Result is the outcome of SanitizeDetailed.
type Result struct {
	// HTML is the sanitized markup, identical to Sanitize's return value.
	HTML string `json:"html"`
	// Removed lists what was dropped, in document order.
	Removed []Removed `json:"removed"`
}

// Removed describes one dropped node or attribute, like an entry of
// DOMPurify's removed list. Element is set for a removed node (a lowercase
// tag name, "#text" or "#comment"); Attribute and From are set for a removed
// attribute.
type Removed struct {
	Element   string `json:"element,omitempty"`
	Attribute string `json:"attribute,omitempty"`
	From      string `json:"from,omitempty"`
}

// New compiles cfg. It returns an error for list entries that can never
// match an element or attribute name, such as "" or "a b", and for
// WholeDocument with "html" in ForbidTags while KeepContent is on (and html
// is not in ForbidContents): DOMPurify throws on every input with that
// configuration, because it cannot move the html element's children into
// the document.
func New(cfg Config) (*Sanitizer, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	s := compile(cfg)
	if s.wholeDocument && s.forbidTags.has("html") && s.keepContent && !s.forbidContents.has("html") {
		return nil, errors.New("htmlsanitizer: WholeDocument with html in ForbidTags fails on every input in DOMPurify; " +
			"also set KeepContent to false or add html to ForbidContents")
	}
	return s, nil
}

var defaultSanitizer = compile(Config{})

// Sanitize cleans dirty with DOMPurify's default configuration.
func Sanitize(dirty string) string {
	return defaultSanitizer.Sanitize(dirty)
}

// Sanitize cleans dirty and returns safe HTML.
//
// Input is treated as UTF-8; invalid byte sequences become U+FFFD. Input
// the parser cannot handle like a browser sanitizes to "" (fail closed):
// nesting deeper than 512 open elements, and the rare malformed markup
// described in parse.go that needs more than 16 parser probes to settle.
func (s *Sanitizer) Sanitize(dirty string) string {
	return s.run(dirty).html
}

// SanitizeDetailed is Sanitize plus the list of removed nodes and
// attributes. Entries for the html, head and body elements, and for their
// attributes, are left out: they depend on how the input is wrapped in a
// document rather than on its content.
func (s *Sanitizer) SanitizeDetailed(dirty string) Result {
	out := s.run(dirty)
	removed := make([]Removed, 0, len(out.removed))
	for _, r := range out.removed {
		if isDocumentElementName(r.Element) || isDocumentElementName(r.From) {
			continue
		}
		removed = append(removed, r)
	}
	return Result{HTML: out.html, Removed: removed}
}

func isDocumentElementName(name string) bool {
	return name == "html" || name == "head" || name == "body"
}

// outcome is the unfiltered result of one run, kept separate so tests can
// compare against DOMPurify's complete removed list.
type outcome struct {
	html    string
	removed []Removed
}

// run follows DOMPurify.sanitize for string input and string output.
func (s *Sanitizer) run(dirty string) outcome {
	if !utf8.ValidString(dirty) {
		dirty = strings.ToValidUTF8(dirty, "\uFFFD")
	}
	if dirty == "" {
		// DOMPurify parses an empty comment so that empty input still
		// walks an (empty) document.
		dirty = "<!-->"
	}
	if !s.safeForTemplates && !s.wholeDocument && !strings.Contains(dirty, "<") {
		return outcome{html: dirty}
	}

	st := &state{s: s}
	doc, root := st.initDocument(dirty)
	if root == nil {
		return outcome{removed: st.removed}
	}
	if s.forceBody && root.FirstChild != nil {
		// Drop the <remove> element initDocument prepended (in whole-document
		// mode this is the head element, as in DOMPurify).
		st.forceRemove(root.FirstChild, root, nil)
	}

	st.walk(root, true)

	serialize := func() string {
		if s.wholeDocument {
			return outerHTML(root)
		}
		return innerHTML(root, false)
	}
	out := serialize()

	// An expression can form across text nodes once a separating element
	// is removed, so scrub the tree as a whole if the output holds a marker.
	if s.safeForTemplates && tmplMarkerSerialized.MatchString(out) {
		scrubOwnCharacterData(root)
		out = serialize()
	}

	if s.wholeDocument && s.allowedTags.has("!doctype") {
		if dt := doctypeOf(doc); dt != nil && dt.Data != "" && doctypeName.MatchString(dt.Data) {
			out = "<!DOCTYPE " + dt.Data + ">\n" + out
		}
	}
	return outcome{html: out, removed: st.removed}
}

// state is the per-call working state; a Sanitizer itself is never mutated.
type state struct {
	s       *Sanitizer
	removed []Removed
	// templateDepth counts the template contents being walked. Nodes there
	// belong to jsdom's inert template document, whose innerHTML serializes
	// with scripting enabled.
	templateDepth int
}

// initDocument mirrors _initDocument: parse the markup as a full document
// with scripting disabled (jsdom's DOMParser), restore leading whitespace the
// parser drops, and return the node the walk starts from.
func (st *state) initDocument(dirty string) (doc, root *html.Node) {
	leading := ""
	if st.s.forceBody {
		dirty = "<remove></remove>" + dirty
	} else {
		leading = leadingWhitespace.FindString(dirty)
	}

	doc = parseDocument(dirty, st.s.wholeDocument)
	if doc == nil {
		return nil, nil
	}

	docElement := firstChildElement(doc)
	if leading != "" && docElement != nil {
		target := documentBody(docElement)
		if target == nil {
			target = docElement
		}
		target.InsertBefore(&html.Node{Type: html.TextNode, Data: leading}, target.FirstChild)
	}

	name := "body"
	if st.s.wholeDocument {
		name = "html"
	}
	return doc, findHTMLElement(doc, name)
}

// walk visits root's subtree in NodeIterator order and sanitizes each node.
// For template content, root is the template element and is not visited
// itself, matching an iterator over the content DocumentFragment.
func (st *state) walk(root *html.Node, visitRoot bool) {
	it := newIterator(root, visitRoot)
	for n := it.next(); n != nil; n = it.next() {
		st.sanitizeElement(n, root, it)
		st.sanitizeAttributes(n, root)
		if isTemplate(n) {
			// Template content is a separate fragment that the iterator
			// does not enter; DOMPurify walks it even when the template
			// element itself was removed.
			st.templateDepth++
			st.walk(n, false)
			st.templateDepth--
			if st.s.safeForTemplates {
				scrubOwnCharacterData(n)
			}
		}
	}
}

func (st *state) record(r Removed) {
	st.removed = append(st.removed, r)
}

// forceRemove mirrors _forceRemove. The walk root stays attached: DOMPurify
// detaches it from its parent, which changes nothing that is visited or
// serialized afterwards.
func (st *state) forceRemove(n, root *html.Node, it *iterator) {
	st.record(Removed{Element: nodeName(n)})
	if n == root || n.Parent == nil {
		return
	}
	if it != nil {
		it.beforeRemove(n)
	}
	n.Parent.RemoveChild(n)
}

// sanitizeElement mirrors _sanitizeElements. DOMPurify's clobbering probe
// (_isClobbered) is omitted: jsdom does not expose a form's named controls
// as properties, so the probe never fires for parsed markup.
func (st *state) sanitizeElement(n, root *html.Node, it *iterator) {
	s := st.s
	tag := nodeName(n)

	if st.isUnsafeNode(n, tag) {
		st.forceRemove(n, root, it)
		return
	}

	if s.forbidTags.has(tag) || !s.allowedTags.has(tag) {
		st.sanitizeDisallowedNode(n, tag, root, it)
		return
	}

	if n.Type == html.ElementNode && !checkValidNamespace(n) {
		st.forceRemove(n, root, it)
		return
	}

	if (tag == "noscript" || tag == "noembed" || tag == "noframes") && fallbackTagClose.MatchString(innerHTML(n, st.templateDepth > 0)) {
		st.forceRemove(n, root, it)
		return
	}

	if s.safeForTemplates && n.Type == html.TextNode {
		if content := stripTemplateExpressions(n.Data); content != n.Data {
			st.record(Removed{Element: "#text"})
			n.Data = content
		}
	}
}

// isUnsafeNode mirrors _isUnsafeNode: structural checks that condemn a node
// regardless of the allowlists. Order matters.
func (st *state) isUnsafeNode(n *html.Node, tag string) bool {
	if !st.s.safeForXML {
		return false
	}
	switch n.Type {
	case html.ElementNode:
		// Namespace-confusion mXSS: markup-looking text with no element
		// children.
		if hasDOMChildren(n) && firstElementChild(n) == nil &&
			elementMarkupProbe.MatchString(textContent(n)) &&
			elementMarkupProbe.MatchString(innerHTML(n, st.templateDepth > 0)) {
			return true
		}
		// Literal-text elements holding an element or markup-like text.
		if literalTextElements.has(tag) && n.Namespace == "" &&
			(firstElementChild(n) != nil || elementMarkupProbe.MatchString(textContent(n))) {
			return true
		}
	case html.CommentNode:
		return commentMarkupProbe.MatchString(n.Data)
	}
	return false
}

// sanitizeDisallowedNode mirrors _sanitizeDisallowedNode: hoist the content
// unless KEEP_CONTENT is off or the element is in FORBID_CONTENTS, then
// remove the node. CUSTOM_ELEMENT_HANDLING is not supported, so no custom
// element is ever kept.
func (st *state) sanitizeDisallowedNode(n *html.Node, tag string, root *html.Node, it *iterator) {
	s := st.s
	// For the walk root DOMPurify copies the children beside it, outside both
	// the walk and the serialized output, so only other nodes are hoisted.
	// (For a forbidden html root that copy throws in DOMPurify; New rejects
	// that configuration.)
	if s.keepContent && !s.forbidContents.has(tag) && n != root && n.Parent != nil && hasDOMChildren(n) {
		// Move the children up, last first, so their order is kept.
		for c := n.LastChild; c != nil; c = n.LastChild {
			n.RemoveChild(c)
			n.Parent.InsertBefore(c, n.NextSibling)
		}
	}
	st.forceRemove(n, root, it)
}

// checkValidNamespace mirrors _checkValidNamespace for the three namespaces
// an HTML parser can produce.
func checkValidNamespace(n *html.Node) bool {
	tag := nodeName(n)
	parentNS, parentTag := "", "template"
	if p := n.Parent; p != nil && p.Type == html.ElementNode {
		parentNS, parentTag = p.Namespace, nodeName(p)
	}

	switch n.Namespace {
	case "svg":
		switch parentNS {
		case "":
			return tag == "svg"
		case "math":
			return tag == "svg" && (parentTag == "annotation-xml" || mathMLTextPoints.has(parentTag))
		}
		return allSVGTags.has(tag)
	case "math":
		switch parentNS {
		case "":
			return tag == "math"
		case "svg":
			return tag == "math" && htmlIntegrationTags.has(parentTag)
		}
		return allMathMLTags.has(tag)
	case "":
		if parentNS == "svg" && !htmlIntegrationTags.has(parentTag) {
			return false
		}
		if parentNS == "math" && !mathMLTextPoints.has(parentTag) {
			return false
		}
		return !allMathMLTags.has(tag) && (commonSVGAndHTMLTags.has(tag) || !allSVGTags.has(tag))
	}
	return false
}

const namedPropsPrefix = "user-content-"

// sanitizeAttributes mirrors _sanitizeAttributes. Attributes are visited
// last to first, as DOMPurify walks the live attribute list backwards.
func (st *state) sanitizeAttributes(n, root *html.Node) {
	if n.Type != html.ElementNode || (n != root && n.Parent == nil) {
		return
	}
	s := st.s
	lcTag := nodeName(n)
	attrs := append([]html.Attribute(nil), n.Attr...)

	for i := len(attrs) - 1; i >= 0; i-- {
		attr := attrs[i]
		name := qualifiedName(attr)
		lcName := strings.ToLower(name)
		initValue := attr.Val
		value := initValue
		if name != "value" {
			value = jsTrim(initValue)
		}

		recreatedNamedProp := false
		if s.sanitizeNamedProps && (lcName == "id" || lcName == "name") && !strings.HasPrefix(value, namedPropsPrefix) {
			// Remove the attribute and re-create it later with the prefixed
			// value, which moves it to the end of the list.
			st.removeAttribute(n, attr)
			value = namedPropsPrefix + value
			recreatedNamedProp = true
		}

		if st.isUnsafeAttributeValue(name, value) {
			st.removeAttribute(n, attr)
			continue
		}
		if !s.allowSelfCloseInAttr && strings.Contains(value, selfClosingTag) {
			st.removeAttribute(n, attr)
			continue
		}
		if s.safeForTemplates {
			value = stripTemplateExpressions(value)
		}
		if !st.isValidAttribute(lcTag, lcName, value) {
			st.removeAttribute(n, attr)
			continue
		}

		if value != initValue {
			if !isValidAttributeLocalName(name) && attr.Namespace == "" {
				// setAttribute would throw InvalidCharacterError.
				st.removeAttribute(n, attr)
				continue
			}
			setAttribute(n, attr.Namespace, attr.Key, value)
			if recreatedNamedProp {
				st.removed = st.removed[:len(st.removed)-1]
			}
		}
	}
}

// removeAttribute mirrors _removeAttribute for string output: an "is"
// attribute cannot be removed from a created element, so its value is
// voided instead (re-added at the end of the list).
func (st *state) removeAttribute(n *html.Node, attr html.Attribute) {
	name := qualifiedName(attr)
	st.record(Removed{Attribute: name, From: nodeName(n)})
	deleteAttribute(n, attr.Namespace, attr.Key)
	if name == "is" {
		setAttribute(n, "", "is", "")
	}
}

// isUnsafeAttributeValue mirrors _isUnsafeAttributeValue.
func (st *state) isUnsafeAttributeValue(name, value string) bool {
	if st.s.safeForXML && attrValueBreakout.MatchString(value) {
		return true
	}
	return strings.ToLower(name) == "attributename" && strings.Contains(value, "href")
}

// isValidAttribute mirrors _isValidAttribute. lcTag and lcName are
// lowercase.
func (st *state) isValidAttribute(lcTag, lcName, value string) bool {
	s := st.s
	if s.forbidAttr.has(lcName) {
		return false
	}
	// Patch-linkage attributes of declarative partial updates.
	if s.safeForXML && (lcName == "patchsrc" || (lcName == "for" && lcTag != "label" && lcTag != "output")) {
		return false
	}
	if s.sanitizeDOM && (lcName == "id" || lcName == "name") {
		if _, clobbers := clobberSet[value]; clobbers {
			return false
		}
	}

	permitted := s.allowedAttr.has(lcName)
	if s.allowDataAttr && dataAttr.MatchString(lcName) {
		return true
	}
	if s.allowARIAAttr && ariaAttr.MatchString(lcName) {
		return true
	}
	if !permitted {
		return false
	}
	if s.uriSafeAttrs.has(lcName) {
		return true
	}

	compact := compactURI(value)
	if s.allowedURI.MatchString(compact) {
		return true
	}
	if (lcName == "src" || lcName == "xlink:href" || lcName == "href") && lcTag != "script" &&
		strings.HasPrefix(value, "data:") && s.dataURITags.has(lcTag) {
		return true
	}
	if s.allowUnknownProtocols && !isScriptOrData.MatchString(compact) {
		return true
	}
	return value == ""
}
