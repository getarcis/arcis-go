package sanitizers

import "regexp"

// Email-header injection prevention (sdk-vectors.md tier 1 #24).
//
// Detect SMTP-header injection at the request boundary. The narrow
// shape (`\r\n` adjacent to an SMTP header keyword like Bcc / Cc / To /
// From / Subject / Reply-To / Return-Path / Content-Type / X-Mailer)
// is attack-specific enough to safely fire from ScanThreats without
// false-positives on legitimate multi-line user content.
//
// Generic header_injection (any CRLF in any string) deliberately stays
// out of ScanThreats — CRLF in a request body is only attack-shaped
// when reflected into a response header. Use DetectHeaderInjection at
// the response-write call site for that.
//
// Mirrors arcis-python/arcis/sanitizers — same regex shape.

// emailHeaderInjectionPattern matches CR/LF/CRLF immediately followed
// by a known SMTP header keyword and a colon. Case-insensitive on the
// keyword.
var emailHeaderInjectionPattern = regexp.MustCompile(
	`(?i)(\r\n|\r|\n)\s*(bcc|cc|to|from|subject|reply-to|return-path|content-type|x-mailer)\s*:`,
)

// DetectEmailHeaderInjection returns true when the input contains a
// CRLF followed by an SMTP header keyword, indicating an attempt to
// inject a new header into an outgoing email.
//
//	DetectEmailHeaderInjection("victim@example.com\r\nBcc: attacker@evil.com")  // true
//	DetectEmailHeaderInjection("multi-line\ntext content")                       // false
//	DetectEmailHeaderInjection("Subject of conversation")                        // false (no CRLF prefix)
func DetectEmailHeaderInjection(input string) bool {
	if input == "" {
		return false
	}
	return emailHeaderInjectionPattern.MatchString(input)
}

// headerInjectionStrictPattern matches a newline (CRLF or bare CR/LF)
// followed by ANY header-name token and a colon (\r\nSet-Cookie:,
// \r\nHost:). This is the response-splitting / header-smuggling signal.
// Unlike a bare-newline check it does not flag multi-line bodies
// (markdown, code), so it is safe at the request boundary. Mirrors the
// Node detectHeaderInjectionStrict + Python email-header-bare-newline.
var headerInjectionStrictPattern = regexp.MustCompile(
	`(?:\r\n|\r|\n)\s*[a-zA-Z][a-zA-Z0-9-]{0,40}\s*:`,
)

// DetectHeaderInjectionStrict returns true on a CRLF-then-header-name-then-
// colon shape (response splitting / header smuggling), never on a bare
// newline. Wired into ScanThreats; the broad DetectHeaderInjection stays
// for response-header sanitization.
func DetectHeaderInjectionStrict(input string) bool {
	if input == "" {
		return false
	}
	return headerInjectionStrictPattern.MatchString(input)
}
