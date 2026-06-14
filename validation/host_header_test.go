package validation

import "testing"

var hostAllow = []string{"app.example.com", "*.tenant.example.com"}

func TestValidateHost_Allows(t *testing.T) {
	for _, host := range []string{
		"app.example.com",
		"app.example.com:443",       // port stripped
		"APP.EXAMPLE.COM",           // case-insensitive
		"a.tenant.example.com",      // one-level wildcard
		"b.tenant.example.com:8080",
	} {
		if !ValidateHost(host, hostAllow).Safe {
			t.Errorf("expected %q to be allowed", host)
		}
	}
}

func TestValidateHost_Rejects(t *testing.T) {
	for _, host := range []string{
		"attacker.com",
		"evil.example.com",             // not under the wildcard
		"a.b.tenant.example.com",       // two levels — wildcard is single-level
		"tenant.example.com",           // wildcard requires a label
		"app.example.com.attacker.com", // suffix-spoof
	} {
		if ValidateHost(host, hostAllow).Safe {
			t.Errorf("expected %q to be rejected", host)
		}
	}
}

func TestValidateHost_DefaultDeny(t *testing.T) {
	r := ValidateHost("app.example.com", nil)
	if r.Safe {
		t.Error("empty allowlist must default-deny")
	}
}

func TestValidateHost_MissingHost(t *testing.T) {
	if ValidateHost("", hostAllow).Safe {
		t.Error("empty host must be rejected")
	}
}

func TestIsHostAllowed(t *testing.T) {
	if !IsHostAllowed("app.example.com", hostAllow) {
		t.Error("app.example.com should be allowed")
	}
	if IsHostAllowed("evil.com", hostAllow) {
		t.Error("evil.com should be rejected")
	}
}
