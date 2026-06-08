package middleware

import "testing"

func TestExtractUsername(t *testing.T) {
	cases := []struct {
		name  string
		raw   string
		field string
		want  string
	}{
		{"default field", `{"username":"alice"}`, "", "alice"},
		{"custom field", `{"email":"a@b.com"}`, "email", "a@b.com"},
		{"missing field", `{"other":"x"}`, "username", ""},
		{"empty value", `{"username":""}`, "username", ""},
		{"non-string value", `{"username":42}`, "username", ""},
		{"empty body", ``, "username", ""},
		{"not an object", `["a","b"]`, "username", ""},
		{"invalid json", `{bad`, "username", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ExtractUsername([]byte(tc.raw), tc.field); got != tc.want {
				t.Fatalf("ExtractUsername(%q, %q) = %q, want %q", tc.raw, tc.field, got, tc.want)
			}
		})
	}
}

func TestResolveProtect_NilWindowAllows(t *testing.T) {
	d := ResolveProtect(ProtectOptions{}, ProtectVectorLogin, "1.2.3.4", "/login", "POST", "alice")
	if d.Block {
		t.Fatal("nil window must never block")
	}
	if d.StatusCode != 429 {
		t.Fatalf("default status = %d, want 429", d.StatusCode)
	}
	if d.Message == "" {
		t.Fatal("default message must not be empty")
	}
}

func TestResolveProtect_EmptyIPAllows(t *testing.T) {
	win := NewCorrelationWindow(NewCorrelationWindowOptions())
	d := ResolveProtect(ProtectOptions{Window: win}, ProtectVectorLogin, "", "/login", "POST", "alice")
	if d.Block {
		t.Fatal("empty IP must never block")
	}
}

func TestResolveProtect_TripsCredentialStuffing(t *testing.T) {
	win := NewCorrelationWindow(NewCorrelationWindowOptions())
	opts := ProtectOptions{Window: win}
	var last ProtectDecision
	for i := 0; i < 10; i++ {
		last = ResolveProtect(opts, ProtectVectorLogin, "9.9.9.9", "/login", "POST",
			"user"+string(rune('0'+i)))
	}
	if !last.Block || !last.CredentialStuffing {
		t.Fatalf("expected credential-stuffing block, got %+v", last)
	}
}

func TestResolveProtect_CustomStatusAndMessage(t *testing.T) {
	d := ResolveProtect(ProtectOptions{StatusCode: 418, Message: "no"}, ProtectVectorApi, "1.1.1.1", "/api", "GET", "")
	if d.StatusCode != 418 || d.Message != "no" {
		t.Fatalf("custom status/message not honored: %+v", d)
	}
}
