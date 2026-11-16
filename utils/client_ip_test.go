package utils

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
)

type clientIPVectors struct {
	DefaultTrustedProxies []string `json:"default_trusted_proxies"`
	Resolution            []struct {
		ID               string    `json:"id"`
		TrustedProxies   *[]string `json:"trusted_proxies"`
		Peer             string    `json:"peer"`
		XForwardedFor    *string   `json:"x_forwarded_for"`
		ExpectedClientIP string    `json:"expected_client_ip"`
		ExpectedKey      string    `json:"expected_key"`
	} `json:"resolution"`
	Keys []struct {
		IP          string          `json:"ip"`
		IPv6Subnet  json.RawMessage `json:"ipv6_subnet"`
		ExpectedKey string          `json:"expected_key"`
	} `json:"keys"`
}

func loadClientIPVectors(t *testing.T) clientIPVectors {
	t.Helper()
	raw, err := os.ReadFile("../spec/client-ip-vectors.json")
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	var v clientIPVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decode fixtures: %v", err)
	}
	if len(v.Resolution) == 0 || len(v.Keys) == 0 {
		t.Fatal("client IP fixtures are empty")
	}
	return v
}

func TestClientIPVectors_DefaultTrustSetMatchesSpec(t *testing.T) {
	v := loadClientIPVectors(t)
	if strings.Join(v.DefaultTrustedProxies, ",") != strings.Join(defaultTrustedProxies, ",") {
		t.Fatalf("default trust set %v, fixtures say %v", defaultTrustedProxies, v.DefaultTrustedProxies)
	}
}

func TestClientIPVectors_Resolution(t *testing.T) {
	v := loadClientIPVectors(t)
	for _, tc := range v.Resolution {
		var proxies []string
		if tc.TrustedProxies != nil {
			proxies = *tc.TrustedProxies
			if proxies == nil {
				proxies = []string{}
			}
		}
		resolver, err := NewClientIPResolver(proxies)
		if err != nil {
			t.Fatalf("%s: %v", tc.ID, err)
		}
		var xff []string
		if tc.XForwardedFor != nil {
			xff = []string{*tc.XForwardedFor}
		}
		got := resolver.Resolve(tc.Peer, xff...)
		if got != tc.ExpectedClientIP {
			t.Errorf("%s: client IP %q, want %q", tc.ID, got, tc.ExpectedClientIP)
		}
		if key := RateLimitKey(got); key != tc.ExpectedKey {
			t.Errorf("%s: key %q, want %q", tc.ID, key, tc.ExpectedKey)
		}

		// The same case through an *http.Request, with the peer as RemoteAddr.
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = tc.Peer
		if strings.Contains(tc.Peer, ":") {
			req.RemoteAddr = "[" + tc.Peer + "]:443"
		} else {
			req.RemoteAddr = tc.Peer + ":443"
		}
		if tc.XForwardedFor != nil {
			req.Header.Set("X-Forwarded-For", *tc.XForwardedFor)
		}
		if got := resolver.ClientIP(req); got != tc.ExpectedClientIP {
			t.Errorf("%s: ClientIP(req) %q, want %q", tc.ID, got, tc.ExpectedClientIP)
		}
	}
}

func TestClientIPVectors_Keys(t *testing.T) {
	v := loadClientIPVectors(t)
	for _, tc := range v.Keys {
		subnet := 0 // false: the full address
		if string(tc.IPv6Subnet) != "false" {
			if err := json.Unmarshal(tc.IPv6Subnet, &subnet); err != nil {
				t.Fatalf("ipv6_subnet %s: %v", tc.IPv6Subnet, err)
			}
		}
		if got := IPKey(tc.IP, subnet); got != tc.ExpectedKey {
			t.Errorf("IPKey(%q, %s) = %q, want %q", tc.IP, tc.IPv6Subnet, got, tc.ExpectedKey)
		}
	}
}

func TestClientIPResolver_MultipleHeaderLinesJoinInOrder(t *testing.T) {
	// Two X-Forwarded-For lines behave like one comma-joined header.
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.2:443"
	req.Header.Add("X-Forwarded-For", "198.51.100.7")
	req.Header.Add("X-Forwarded-For", "10.0.0.3")
	if got := GetClientIP(req); got != "198.51.100.7" {
		t.Fatalf("got %q, want 198.51.100.7", got)
	}
}

func TestClientIPResolver_UnparseablePeerIsUnknown(t *testing.T) {
	got := MustClientIPResolver(nil).Resolve("@", "198.51.100.7")
	if got != "" {
		t.Fatalf("got %q, want empty", got)
	}
	if key := RateLimitKey(got); key != UnknownClientKey {
		t.Fatalf("key %q, want %q", key, UnknownClientKey)
	}
}

func TestClientIPResolver_SingleIPEntriesAndMappedRanges(t *testing.T) {
	r := MustClientIPResolver([]string{"203.0.113.9", "::ffff:198.51.100.0/120"})
	if got := r.Resolve("203.0.113.9:80", "192.0.2.1"); got != "192.0.2.1" {
		t.Errorf("single IP entry not trusted: got %q", got)
	}
	// An IPv4 peer matches an IPv4-mapped IPv6 range, as in proxy-addr.
	if got := r.Resolve("198.51.100.20:80", "192.0.2.1"); got != "192.0.2.1" {
		t.Errorf("mapped range not trusted: got %q", got)
	}
}

func TestNewClientIPResolver_RejectsInvalidEntries(t *testing.T) {
	for _, bad := range []string{"not-an-ip", "10.0.0.0/33", "1.2.3"} {
		if _, err := NewClientIPResolver([]string{bad}); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
	defer func() {
		r := recover()
		if r == nil || !strings.Contains(r.(string), "invalid TrustedProxies") {
			t.Fatalf("MustClientIPResolver should panic with a clear message, got %v", r)
		}
	}()
	MustClientIPResolver([]string{"nope"})
}

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	})
	return &buf
}

func TestClientIPResolver_WarnsOnceForUntrustedForwardedHeaders(t *testing.T) {
	buf := captureLog(t)
	warnUntrustedForwarded = sync.Once{}

	r := MustClientIPResolver(nil)
	for i := 0; i < 3; i++ {
		if got := r.Resolve("203.0.113.5:1000", "198.51.100.7"); got != "203.0.113.5" {
			t.Fatalf("public peer must win, got %q", got)
		}
	}
	if n := strings.Count(buf.String(), "untrusted peer"); n != 1 {
		t.Fatalf("expected one warning, got %d: %q", n, buf.String())
	}
}

func TestNewClientIPResolver_WarnsOnceForTrustAll(t *testing.T) {
	buf := captureLog(t)
	warnTrustAll = sync.Once{}

	MustClientIPResolver([]string{"0.0.0.0/0"})
	MustClientIPResolver([]string{"::/0"})
	if n := strings.Count(buf.String(), "every peer is trusted"); n != 1 {
		t.Fatalf("expected one warning, got %d: %q", n, buf.String())
	}
}
