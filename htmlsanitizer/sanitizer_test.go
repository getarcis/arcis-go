package htmlsanitizer

import (
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// targetedCases cover jsdom and parser behavior the fixtures barely touch.
// Expected values were produced by DOMPurify 3.4.18 on jsdom 31.0.1; removed
// lists are DOMPurify's complete lists.
var targetedCases = []struct {
	name    string
	config  Config
	input   string
	html    string
	removed []Removed
}{
	{
		name:    "template noscript serializes with scripting on",
		config:  Config{SafeForXML: Bool(false), AddTags: []string{"noscript"}},
		input:   "<p>a</p><template><noscript>&lt;/noscript&gt;</noscript></template><noscript>&lt;/noscript&gt;</noscript>",
		html:    "<p>a</p><template></template><noscript>&lt;/noscript&gt;</noscript>",
		removed: []Removed{{Element: "noscript"}},
	},
	{
		name:    "repeated body and html overwrite attributes",
		config:  Config{WholeDocument: true},
		input:   "<html lang=a><body title=1 id=a><p>x</p><body title=2 class=c><html lang=b dir=x>",
		html:    "<html lang=\"b\" dir=\"x\"><head></head><body title=\"2\" id=\"a\" class=\"c\"><p>x</p></body></html>",
		removed: []Removed{},
	},
	{
		name:    "repeated body inside template is ignored",
		config:  Config{WholeDocument: true},
		input:   "<body title=1><template><body title=2></template>",
		html:    "<html><head></head><body title=\"1\"><template></template></body></html>",
		removed: []Removed{},
	},
	{
		name:    "end tag in HTML content leaves mtext open",
		config:  Config{},
		input:   "<math><mtext><b>x</mtext>y<i>z</i></math>w",
		html:    "<math><mtext><b>xy<i>z</i>w</b></mtext></math>",
		removed: []Removed{},
	},
	{
		name:    "end tag in HTML content leaves svg desc open",
		config:  Config{},
		input:   "<svg><desc><span>x</desc><circle r=\"1\"></circle></svg>after",
		html:    "<svg><desc></desc></svg>",
		removed: []Removed{{Element: "span"}},
	},
	{
		name:    "end tag after the HTML child closed is honored",
		config:  Config{},
		input:   "<svg><desc><b>x</b></desc><circle r=\"1\"></circle></svg>after",
		html:    "<svg><desc></desc><circle r=\"1\"></circle></svg>after",
		removed: []Removed{{Element: "b"}},
	},
	{
		name:    "foreign end tag in foreign content is honored",
		config:  Config{},
		input:   "<svg><title>t</title><desc>d</desc></svg><p>p</p>",
		html:    "<svg><title>t</title><desc>d</desc></svg><p>p</p>",
		removed: []Removed{},
	},
	{
		name:    "html element of the same name is closed",
		config:  Config{},
		input:   "<math><mtext><mi>a</mi></mtext></math><p><desc>x</desc>y</p>",
		html:    "<math><mtext></mtext></math><p>y</p>",
		removed: []Removed{{Element: "mi"}, {Element: "desc"}},
	},
	{
		name:    "misclosing end tag text inside attribute is left alone",
		config:  Config{},
		input:   "<math><mtext><b title=\"</mtext>\">x</mtext>y</math>",
		html:    "<math><mtext><b title=\"&lt;/mtext&gt;\">xy</b></mtext></math>",
		removed: []Removed{},
	},
	{
		name:    "two misclosing end tags",
		config:  Config{},
		input:   "<math><mi><b>1</mi>2</math><svg><title><i>3</title>4</svg>5",
		html:    "<math><mi><b>12<svg><title></title></svg></b></mi></math>",
		removed: []Removed{{Element: "i"}},
	},
	{
		name:    "is attribute is voided and moved last",
		config:  Config{},
		input:   "<p is=\"x\" class=\"a\" id=\"b\">t</p>",
		html:    "<p class=\"a\" id=\"b\" is=\"\">t</p>",
		removed: []Removed{{Attribute: "is", From: "p"}},
	},
	{
		name:    "named props are prefixed and moved last",
		config:  Config{SanitizeNamedProps: true},
		input:   "<p id=\"intro\" name=\"x\" class=\"c\">a</p>",
		html:    "<p class=\"c\" name=\"user-content-x\" id=\"user-content-intro\">a</p>",
		removed: []Removed{},
	},
	{
		name:    "leading whitespace is kept",
		config:  Config{},
		input:   " \n\t<b>x</b>",
		html:    " \n\t<b>x</b>",
		removed: []Removed{},
	},
	{
		name:    "empty input",
		config:  Config{},
		input:   "",
		html:    "",
		removed: []Removed{},
	},
	{
		name:    "force body keeps leading style",
		config:  Config{ForceBody: true},
		input:   "<style>p{}</style><b>x</b>",
		html:    "<style>p{}</style><b>x</b>",
		removed: []Removed{{Element: "remove"}},
	},
	{
		name:    "whole document with doctype allowed",
		config:  Config{WholeDocument: true, AddTags: []string{"!doctype"}},
		input:   "<!doctype html><title>t</title><p>x",
		html:    "<!DOCTYPE html>\n<html><head><title>t</title></head><body><p>x</p></body></html>",
		removed: []Removed{},
	},
	{
		name:    "whole document drops html element when content is not kept",
		config:  Config{WholeDocument: true, ForbidTags: []string{"html"}, KeepContent: Bool(false)},
		input:   "<p>x</p>",
		html:    "<html><head></head><body><p>x</p></body></html>",
		removed: []Removed{{Element: "html"}},
	},
	{
		name:    "template content removed with its template",
		config:  Config{AllowedTags: []string{"b"}},
		input:   "x<template><b onclick=\"x\">a</b><script>1</script></template>",
		html:    "x",
		removed: []Removed{{Element: "body"}, {Element: "template"}, {Attribute: "onclick", From: "b"}, {Element: "script"}},
	},
	{
		name:    "safe for templates scrubs across removed elements",
		config:  Config{SafeForTemplates: true, ForbidTags: []string{"i"}},
		input:   "<p>{<i>x</i>{y}}</p><template>{{z}}</template>",
		html:    "<p>{x </p><template> </template>",
		removed: []Removed{{Element: "i"}, {Element: "#text"}, {Element: "#text"}},
	},
}

func TestTargetedCases(t *testing.T) {
	for _, c := range targetedCases {
		t.Run(c.name, func(t *testing.T) {
			s, err := New(c.config)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			got := s.SanitizeDetailed(c.input)
			if got.HTML != c.html {
				t.Errorf("html\n got:  %q\n want: %q", got.HTML, c.html)
			}
			if want := withoutDocumentEntries(c.removed); !reflect.DeepEqual(got.Removed, want) {
				t.Errorf("removed\n got:  %v\n want: %v", got.Removed, want)
			}
		})
	}
}

// dompurifyNotIdempotent lists fixtures where DOMPurify's own output changes
// when sanitized again, with that second result. Most re-parse a leading
// <title> or <template> into the head, which the body-only output drops.
var dompurifyNotIdempotent = map[string]string{
	"dompurify-040":             "",
	"dompurify-206":             "<form><math><mtext></mtext></math></form>",
	"dompurify-209":             "<form><math><mtext></mtext></math></form>",
	"dompurify-211":             "<math><mtext><h1><a></a></h1><h6><a></a></h6></mtext></math>",
	"dompurify-214":             "<math><mtext><option></option><option></option></mtext></math>",
	"config-safe_for_templates": "<p title=\"\"> </p>",
	"fuzz-044":                  "",
	"fuzz-261":                  "<form></form>",
	"fuzz-331":                  "",
	"fuzz-374":                  "",
}

func TestIdempotence(t *testing.T) {
	for _, c := range loadFixtures(t) {
		s := fixtureSanitizer(t, c)
		once := s.Sanitize(c.Input)
		twice := s.Sanitize(once)
		if want, ok := dompurifyNotIdempotent[c.ID]; ok {
			// Not idempotent in DOMPurify either; the second pass must still
			// match DOMPurify's second pass.
			if twice != want {
				t.Errorf("%s second pass: got %q, DOMPurify %q", c.ID, twice, want)
			}
			continue
		}
		if twice != once {
			t.Errorf("%s not idempotent:\n once:  %q\n twice: %q", c.ID, once, twice)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	invalid := map[string]Config{
		"empty tag":                        {AllowedTags: []string{"b", ""}},
		"tag with space":                   {AddTags: []string{"my tag"}},
		"attribute with tab":               {AddAttr: []string{"data-\tx"}},
		"forbid contents with newline":     {ForbidContents: []string{"a\n"}},
		"empty uri safe attribute":         {AddURISafeAttr: []string{""}},
		"whole document forbidding html":   {WholeDocument: true, ForbidTags: []string{"HTML"}},
		"whole document, html, add forbid": {WholeDocument: true, ForbidTags: []string{"html"}, AddForbidContents: []string{"b"}},
	}
	for name, cfg := range invalid {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: New accepted %+v", name, cfg)
		}
	}

	valid := map[string]Config{
		"zero value":                     {},
		"special names":                  {AddTags: []string{"#comment", "!doctype"}},
		"html forbidden without content": {WholeDocument: true, ForbidTags: []string{"html"}, KeepContent: Bool(false)},
		"html forbidden, contents too":   {WholeDocument: true, ForbidTags: []string{"html"}, ForbidContents: []string{"html"}},
		"html forbidden in fragments":    {ForbidTags: []string{"html"}},
	}
	for name, cfg := range valid {
		if _, err := New(cfg); err != nil {
			t.Errorf("%s: New rejected %+v: %v", name, cfg, err)
		}
	}
}

func TestConfigListSemantics(t *testing.T) {
	cases := []struct {
		name  string
		cfg   Config
		input string
		want  string
	}{
		{"nil list keeps the default", Config{AllowedTags: nil}, "<b>x</b>", "<b>x</b>"},
		{"empty list allows nothing", Config{AllowedTags: []string{}}, "<b>x</b>", "x"},
		{"names are case-insensitive", Config{AddTags: []string{"IFRAME"}}, `<iframe src="https://a.example"></iframe>`, `<iframe src="https://a.example"></iframe>`},
		{"keep content off", Config{KeepContent: Bool(false)}, "<p>a<foo>b</foo></p>", "<p>a</p>"},
		{"profiles override allowed tags", Config{AllowedTags: []string{"b"}, UseProfiles: &Profiles{HTML: true}}, "<b>x</b><i>y</i>", "<b>x</b><i>y</i>"},
	}
	for _, c := range cases {
		s, err := New(c.cfg)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := s.Sanitize(c.input); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestDefaultSanitize(t *testing.T) {
	cases := map[string]string{
		`<img src=x onerror=alert(1)><b>ok</b>`: `<img src="x"><b>ok</b>`,
		"plain text & no markup":                "plain text & no markup",
		"\xff<b>x</b>":                          "\uFFFD<b>x</b>",
		"":                                      "",
	}
	for input, want := range cases {
		if got := Sanitize(input); got != want {
			t.Errorf("Sanitize(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestSanitizeDetailedDropsDocumentEntries(t *testing.T) {
	s, err := New(Config{AllowedTags: []string{"p"}})
	if err != nil {
		t.Fatal(err)
	}
	got := s.SanitizeDetailed(`<body onload="x()"><p onclick="y()">a<b>b</b></p>`)
	want := []Removed{{Attribute: "onclick", From: "p"}, {Element: "b"}}
	if got.HTML != "<p>ab</p>" || !reflect.DeepEqual(got.Removed, want) {
		t.Errorf("got %+v, want html %q removed %v", got, "<p>ab</p>", want)
	}
	wantFull := []Removed{{Element: "body"}, {Attribute: "onload", From: "body"}}
	if full := s.run(`<body onload="x()"><p>a</p>`).removed; !reflect.DeepEqual(full, wantFull) {
		t.Errorf("internal list should keep the body entries: got %v, want %v", full, wantFull)
	}
}

// TestFailClosed covers input the parser cannot handle like a browser. These
// remove strictly more than DOMPurify, which keeps the content.
func TestFailClosed(t *testing.T) {
	deep := strings.Repeat("<div>", 600) + "x" + strings.Repeat("</div>", 600)
	if got := Sanitize(deep); got != "" {
		t.Errorf("nesting beyond x/net/html's limit: got %d bytes, want empty", len(got))
	}

	var many strings.Builder
	many.WriteString("<math><mtext><b>")
	for i := 0; i <= maxProbes; i++ {
		many.WriteString("x</mtext>")
	}
	if got := Sanitize(many.String()); got != "" {
		t.Errorf("more end tags than the probe budget: got %q, want empty", got)
	}

	if got := Sanitize("<math><mtext><b><!--" + probeMarker + "-->x</mtext>y"); got != "" {
		t.Errorf("input holding the probe marker: got %q, want empty", got)
	}

	if got := Sanitize("<svg><desc><!" + cdataMarker + "[CDATA[x]]><![CDATA[y]]></desc></svg>"); got != "" {
		t.Errorf("input holding the CDATA marker: got %q, want empty", got)
	}

	var sections strings.Builder
	sections.WriteString("<svg><desc>")
	for i := 0; i <= maxProbes; i++ {
		sections.WriteString("<![CDATA[x]]>")
	}
	if got := Sanitize(sections.String()); got != "" {
		t.Errorf("more CDATA sections than the probe budget: got %q, want empty", got)
	}
}

func TestConcurrentUse(t *testing.T) {
	cases := loadFixtures(t)
	sanitizers := make([]*Sanitizer, len(cases))
	for i, c := range cases {
		sanitizers[i] = fixtureSanitizer(t, c)
	}
	shared := defaultSanitizer

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(offset int) {
			defer wg.Done()
			for k := range cases {
				i := (k + offset*83) % len(cases)
				c := cases[i]
				if got := sanitizers[i].Sanitize(c.Input); got != c.Expected {
					errs <- fmt.Errorf("%s: got %q under concurrent use", c.ID, got)
					return
				}
				shared.SanitizeDetailed(c.Input)
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func BenchmarkFixtures(b *testing.B) {
	cases := loadFixtures(b)
	sanitizers := make([]*Sanitizer, len(cases))
	for i, c := range cases {
		sanitizers[i] = fixtureSanitizer(b, c)
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		for i, c := range cases {
			sanitizers[i].Sanitize(c.Input)
		}
	}
}
