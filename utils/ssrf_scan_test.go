package utils

import "testing"

// The body scan flags only SSRF-relevant schemes, not typos or custom app
// schemes that no server-side fetch would act on.
func TestScanForSSRF_SchemeGate(t *testing.T) {
	allowed := []string{
		"lhttps://www.instagram.com/p/x", // typo scheme, not an SSRF vector
		"myapp://deeplink/page",          // custom app scheme
		"https://www.instagram.com/p/x",  // public https
	}
	for _, u := range allowed {
		if ScanForSSRF(map[string]interface{}{"q": u}, nil).Detected {
			t.Errorf("should not flag %q", u)
		}
	}

	blocked := []string{
		"file:///etc/passwd",
		"http://10.0.0.1/admin",
		"gopher://internal:6379/_INFO",
	}
	for _, u := range blocked {
		if !ScanForSSRF(map[string]interface{}{"u": u}, nil).Detected {
			t.Errorf("should flag %q", u)
		}
	}
}
