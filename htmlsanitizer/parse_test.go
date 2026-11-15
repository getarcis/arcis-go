package htmlsanitizer

import (
	"strings"
	"testing"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// TestCDATAAtIntegrationPoints pins the CDATA repair. Expected values come
// from DOMPurify 3.4.18 on jsdom 31.0.1 and must match exactly.
func TestCDATAAtIntegrationPoints(t *testing.T) {
	cases := []struct {
		name   string
		config Config
		input  string
		want   string
	}{
		{"svg desc reads a bogus comment that ends at the first >", Config{},
			`<svg><desc><![CDATA[<img src=x onerror=alert(1)>]]></desc></svg>`, `<svg><desc>]]&gt;</desc></svg>`},
		{"mathml text integration point", Config{},
			`<math><mo><![CDATA[ x ]]></mo></math>`, `<math><mo></mo></math>`},
		{"annotation-xml with an html encoding", Config{},
			`<math><annotation-xml encoding="TEXT/HTML"><![CDATA[a>b]]></annotation-xml></math>`, `<math></math>`},
		{"comment data matches when comments are kept", Config{AddTags: []string{"#comment"}},
			`<svg><title><![CDATA[ t ]]>u</title></svg>`, `<svg><title><!--[CDATA[ t ]]-->u</title></svg>`},
		{"other foreign elements keep the CDATA text", Config{},
			`<svg><g><![CDATA[ x ]]></g></svg>`, `<svg><g> x </g></svg>`},
		{"annotation-xml without an html encoding keeps CDATA", Config{},
			`<math><annotation-xml><![CDATA[ y ]]></annotation-xml></math>`, `<math></math>`},
		{"markup after the bogus comment is parsed", Config{AddTags: []string{"foreignobject", "#comment"}},
			`<svg><foreignObject><![CDATA[<b>]]></foreignObject></svg><p>z</p>`, `<svg><foreignObject>]]&gt;</foreignObject></svg><p>z</p>`},
	}
	for _, c := range cases {
		s, err := New(c.config)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := s.Sanitize(c.input); got != c.want {
			t.Errorf("%s:\n got:  %q\n want: %q", c.name, got, c.want)
		}
	}
}

// TestRemainingParserDifferences pins the known cases where x/net/html builds
// a different tree than parse5 and the Go output differs from DOMPurify. Each
// asserts Go's exact output and that it keeps no element or attribute that
// DOMPurify's output (recorded from DOMPurify 3.4.18 on jsdom 31.0.1) lacks.
func TestRemainingParserDifferences(t *testing.T) {
	cases := []struct {
		name      string
		config    Config
		input     string
		want      string
		dompurify string
	}{
		// parse5 follows the 2023 rule that inserts <hr> in <select> after
		// closing an open option; x/net/html ignores the tag.
		{"hr in select", Config{},
			`<select><option>a<hr>b</option></select>`,
			`<select><option>ab</option></select>`,
			`<select><option>a</option><hr>b</select>`},
		{"hr in select with optgroup", Config{},
			`<select><optgroup label="g"><option>x<hr id="h">y</optgroup></select>`,
			`<select><optgroup label="g"><option>xy</option></optgroup></select>`,
			`<select><optgroup label="g"><option>x</option></optgroup><hr id="h">y</select>`},
		// parse5 drops a newline only when it is the very next token after
		// <pre> or <listing>; x/net/html drops it while the element is still
		// empty, even after an ignored end tag.
		{"pre leading newline", Config{},
			"<pre></b>\nx</pre>", "<pre>x</pre>", "<pre>\nx</pre>"},
		{"listing leading newline", Config{},
			"<listing></i>\ny</listing>", "y", "\ny"},
		// parse5 switches template content to table-body mode for a cell
		// after a caption and creates the tbody and tr; x/net/html stays in
		// caption mode and drops the cell.
		{"template cell after caption", Config{},
			`<p>a</p><template><caption><dd></dd><th>b</th></template>`,
			`<p>a</p><template><caption><dd></dd>b</caption></template>`,
			`<p>a</p><template><caption><dd></dd></caption><tbody><tr><th>b</th></tr></tbody></template>`},
		// After a stray table end tag in template content parse5 reconstructs
		// the formatting elements once more than x/net/html does.
		{"template formatting after table end tag", Config{},
			`<p>a</p><template><tr><b><i></thead>x</b></template>`,
			`<p>a</p><template><tr></tr><b><i>x</i></b></template>`,
			`<p>a</p><template><tr></tr><b><i></i></b><b><i>x</i></b></template>`},
		// parse5 ignores raw-text start tags after <frameset> and tokenizes
		// their content as tags; the x/net/html tokenizer still switches to
		// raw text, so the whitespace inside the tags becomes text.
		{"frameset with ignored xmp", Config{WholeDocument: true},
			`<frameset></frameset><xmp><i a=1></i></xmp>`,
			`<html><head></head> </html>`, `<html><head></head></html>`},
		{"frameset with ignored iframe", Config{WholeDocument: true},
			`<frameset><iframe><b c></b></iframe></frameset>`,
			`<html><head></head> </html>`, `<html><head></head></html>`},
	}
	for _, c := range cases {
		s, err := New(c.config)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := s.Sanitize(c.input)
		if got != c.want {
			t.Errorf("%s: output changed (the difference may be fixed; update the test):\n got:  %q\n want: %q", c.name, got, c.want)
		}
		goMarkup := markupInventory(t, got, c.config.WholeDocument)
		dpMarkup := markupInventory(t, c.dompurify, c.config.WholeDocument)
		for key, n := range goMarkup {
			if n > dpMarkup[key] {
				t.Errorf("%s: Go output has %d of %s, DOMPurify %d", c.name, n, key, dpMarkup[key])
			}
		}
	}
}

// markupInventory counts the elements and attributes (with values) in
// sanitized markup.
func markupInventory(t *testing.T, markup string, wholeDocument bool) map[string]int {
	t.Helper()
	var roots []*html.Node
	if wholeDocument {
		doc, err := html.Parse(strings.NewReader(markup))
		if err != nil {
			t.Fatal(err)
		}
		roots = []*html.Node{doc}
	} else {
		nodes, err := html.ParseFragment(strings.NewReader(markup), &html.Node{Type: html.ElementNode, Data: "body", DataAtom: atom.Body})
		if err != nil {
			t.Fatal(err)
		}
		roots = nodes
	}
	counts := map[string]int{}
	var visit func(*html.Node)
	visit = func(n *html.Node) {
		if n.Type == html.ElementNode {
			element := "<" + n.Namespace + ":" + n.Data + ">"
			counts[element]++
			for _, a := range n.Attr {
				counts[element+" "+qualifiedName(a)+"="+a.Val]++
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			visit(c)
		}
	}
	for _, r := range roots {
		visit(r)
	}
	return counts
}
