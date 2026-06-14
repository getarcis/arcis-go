package gin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestBlock_XMLBodyXXE proves the gin adapter scans XML / text-xml request
// bodies for XXE. Before the shared pipeline.ScanRequestForThreats extraction
// gin only scanned JSON + form bodies, so an XXE payload sent with an XML
// content type slipped through. chi/net-http already scanned XML; this closes
// the drift.
func TestBlock_XMLBodyXXE(t *testing.T) {
	const xxe = `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`
	for _, ct := range []string{"application/xml", "text/xml"} {
		t.Run(ct, func(t *testing.T) {
			r := blockApp()
			req := httptest.NewRequest(http.MethodPost, "/echo", strings.NewReader(xxe))
			req.Header.Set("Content-Type", ct)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != http.StatusForbidden {
				t.Fatalf("expected 403 for XXE in %s body, got %d (body=%s)", ct, w.Code, w.Body.String())
			}
			var resp map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("invalid json: %v", err)
			}
			if resp["vector"] != "xxe" {
				t.Errorf("expected vector %q, got %v", "xxe", resp["vector"])
			}
		})
	}
}

// TestBlock_XMLBodyCleanPasses guards the false-positive rate: a benign XML
// document with no DOCTYPE / ENTITY must pass through untouched.
func TestBlock_XMLBodyCleanPasses(t *testing.T) {
	const clean = `<?xml version="1.0"?><note><to>Bob</to><from>Alice</from><body>hello</body></note>`
	r := blockApp()
	req := httptest.NewRequest(http.MethodPost, "/echo", strings.NewReader(clean))
	req.Header.Set("Content-Type", "application/xml")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for clean XML, got %d (body=%s)", w.Code, w.Body.String())
	}
}
