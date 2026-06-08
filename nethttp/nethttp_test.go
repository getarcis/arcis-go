package nethttp_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	archttp "github.com/getarcis/arcis-go/nethttp"
)

func helloHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

// realBrowserUA is what every test request sets as User-Agent so the
// v1.7 default bot-detection step (which denies Go-http-client as SCRAPER)
// doesn't block tests that aren't exercising bot behavior.
const realBrowserUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// realGet performs an http.Get with browser-shaped headers so default
// bot detection doesn't deny the request as a Go-http-client SCRAPER.
func realGet(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", realBrowserUA)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Language", "en-US")
	req.Header.Set("Accept-Encoding", "gzip")
	return http.DefaultClient.Do(req)
}

// realPost performs an http.Post with browser-shaped headers (see realGet).
func realPost(url, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", realBrowserUA)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Language", "en-US")
	req.Header.Set("Accept-Encoding", "gzip")
	return http.DefaultClient.Do(req)
}

func TestMiddleware_AllowsCleanRequest(t *testing.T) {
	h := archttp.Middleware()(helloHandler())
	srv := httptest.NewServer(h)
	defer srv.Close()
	defer archttp.Cleanup()

	res, err := realGet(srv.URL + "/")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200", res.StatusCode)
	}
	if got := res.Header.Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("X-Frame-Options: got %q want DENY", got)
	}
	if res.Header.Get("Server") != "" {
		t.Fatalf("Server header should be stripped, got %q", res.Header.Get("Server"))
	}
}

func TestMiddlewareWithConfig_BlockMode_RejectsXSS(t *testing.T) {
	cfg := archttp.DefaultConfig()
	cfg.Block = true
	h := archttp.MiddlewareWithConfig(cfg)(helloHandler())
	srv := httptest.NewServer(h)
	defer srv.Close()
	defer archttp.Cleanup()

	body := strings.NewReader(`{"q":"<script>alert(1)</script>"}`)
	req, _ := http.NewRequest("POST", srv.URL+"/", body)
	req.Header.Set("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("status: got %d want 403", res.StatusCode)
	}
	var payload struct {
		Error string `json:"error"`
	}
	raw, _ := io.ReadAll(res.Body)
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("body decode: %v", err)
	}
	if payload.Error == "" {
		t.Fatalf("expected error string in body, got %s", string(raw))
	}
}

func TestMiddlewareWithConfig_BlockMode_AllowsCleanBody(t *testing.T) {
	cfg := archttp.DefaultConfig()
	cfg.Block = true
	h := archttp.MiddlewareWithConfig(cfg)(helloHandler())
	srv := httptest.NewServer(h)
	defer srv.Close()
	defer archttp.Cleanup()

	body := strings.NewReader(`{"name":"Gagan"}`)
	res, err := realPost(srv.URL+"/", "application/json", body)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200", res.StatusCode)
	}
}

func TestRateLimit_StandaloneRejectsAfterCap(t *testing.T) {
	limit := archttp.RateLimit(2, time.Minute)
	h := limit(helloHandler())
	srv := httptest.NewServer(h)
	defer srv.Close()
	defer archttp.Cleanup()

	for i := 0; i < 2; i++ {
		res, err := realGet(srv.URL + "/")
		if err != nil {
			t.Fatalf("get %d: %v", i, err)
		}
		_ = res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("call %d: got %d want 200", i, res.StatusCode)
		}
	}

	res, err := realGet(srv.URL + "/")
	if err != nil {
		t.Fatalf("third get: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("third call: got %d want 429", res.StatusCode)
	}
	if res.Header.Get("Retry-After") == "" {
		t.Fatalf("expected Retry-After header on 429")
	}
}

func TestRateLimit_SkipsHealthcheck(t *testing.T) {
	skip := func(r *http.Request) bool {
		return r.URL.Path == "/healthz"
	}
	limit := archttp.RateLimitWithSkip(1, time.Minute, skip)
	h := limit(helloHandler())
	srv := httptest.NewServer(h)
	defer srv.Close()
	defer archttp.Cleanup()

	for i := 0; i < 5; i++ {
		res, err := realGet(srv.URL + "/healthz")
		if err != nil {
			t.Fatalf("healthz %d: %v", i, err)
		}
		_ = res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("healthz call %d should be exempt: got %d", i, res.StatusCode)
		}
	}

	// First non-exempt call should pass.
	res, _ := realGet(srv.URL + "/api")
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("first /api call: got %d want 200", res.StatusCode)
	}
	// Second non-exempt call hits the limit of 1.
	res, _ = realGet(srv.URL + "/api")
	_ = res.Body.Close()
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second /api call: got %d want 429", res.StatusCode)
	}
}

func TestMiddlewareWithConfig_HeadersOnlyMode(t *testing.T) {
	cfg := Config{
		Headers:        true,
		FrameOptions:   "SAMEORIGIN",
		ReferrerPolicy: "no-referrer",
		HSTSMaxAge:     63072000,
		HSTSSubdomains: true,
		CSP:            "default-src 'none'",
	}
	h := archttp.MiddlewareWithConfig(cfg)(helloHandler())
	srv := httptest.NewServer(h)
	defer srv.Close()
	defer archttp.Cleanup()

	res, err := realGet(srv.URL + "/")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer res.Body.Close()

	if got := res.Header.Get("X-Frame-Options"); got != "SAMEORIGIN" {
		t.Fatalf("X-Frame-Options: got %q want SAMEORIGIN", got)
	}
	if got := res.Header.Get("Referrer-Policy"); got != "no-referrer" {
		t.Fatalf("Referrer-Policy: got %q want no-referrer", got)
	}
	if got := res.Header.Get("Content-Security-Policy"); got != "default-src 'none'" {
		t.Fatalf("CSP: got %q", got)
	}
	hsts := res.Header.Get("Strict-Transport-Security")
	if !strings.Contains(hsts, "max-age=63072000") || !strings.Contains(hsts, "includeSubDomains") {
		t.Fatalf("HSTS: got %q", hsts)
	}
}

func TestGetSanitizer_ReturnsInstance(t *testing.T) {
	cfg := archttp.DefaultConfig()
	var got bool
	h := archttp.MiddlewareWithConfig(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := archttp.GetSanitizer(r)
		if s != nil {
			got = true
		}
		w.WriteHeader(http.StatusOK)
	}))
	srv := httptest.NewServer(h)
	defer srv.Close()
	defer archttp.Cleanup()

	res, err := realGet(srv.URL + "/")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	_ = res.Body.Close()

	if !got {
		t.Fatalf("expected GetSanitizer to return a non-nil Sanitizer when middleware is in the chain")
	}
}

// Type alias so the test file can spell `Config` without re-importing.
type Config = archttp.Config
