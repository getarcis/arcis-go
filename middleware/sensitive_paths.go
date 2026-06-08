package middleware

// v1.7 W2 wire-up. Blocks well-known scanner probe paths.
//
// Three buckets, almost never legitimate on a typical app:
//   1. Dotfile / VCS leaks   /.env, /.git/*, /.svn/*, /.aws/, ...
//   2. PHP/Wordpress probes  /wp-admin, /wp-login.php, /phpmyadmin, ...
//   3. Diagnostic endpoints  /server-status, /phpinfo.php, /info.php, ...
//
// Apps with legitimate overlapping routes (actual WordPress site, custom
// /admin panel) opt out via Config.Bot=false or Config.ScannerPaths=false.

import (
	"regexp"
)

// SensitivePathPatterns is the default scanner probe path list. Each
// pattern is matched against r.URL.Path; first hit denies the request.
var SensitivePathPatterns = []*regexp.Regexp{
	// Dotfile / VCS leaks
	regexp.MustCompile(`(?i)^/\.env(\.|/|$)`),
	regexp.MustCompile(`(?i)^/\.git(/|$)`),
	regexp.MustCompile(`(?i)^/\.svn(/|$)`),
	regexp.MustCompile(`(?i)^/\.hg(/|$)`),
	regexp.MustCompile(`(?i)^/\.bzr(/|$)`),
	regexp.MustCompile(`(?i)^/\.aws(/|$)`),
	regexp.MustCompile(`(?i)^/\.ssh(/|$)`),
	regexp.MustCompile(`(?i)^/\.htaccess$`),
	regexp.MustCompile(`(?i)^/\.htpasswd$`),
	regexp.MustCompile(`(?i)^/\.npmrc$`),
	regexp.MustCompile(`(?i)^/\.dockerenv$`),

	// WordPress + PHP probes
	regexp.MustCompile(`(?i)^/wp-admin(/|$)`),
	regexp.MustCompile(`(?i)^/wp-login\.php$`),
	regexp.MustCompile(`(?i)^/wp-config\.php$`),
	regexp.MustCompile(`(?i)^/wordpress/wp-(admin|login)`),
	regexp.MustCompile(`(?i)^/xmlrpc\.php$`),

	// Generic admin / DB-admin probes
	regexp.MustCompile(`(?i)^/admin/?$`),
	regexp.MustCompile(`(?i)^/administrator/?$`),
	regexp.MustCompile(`(?i)^/admin\.php$`),
	regexp.MustCompile(`(?i)^/phpmyadmin(/|$)`),
	regexp.MustCompile(`(?i)^/pma(/|$)`),
	regexp.MustCompile(`(?i)^/myadmin(/|$)`),
	regexp.MustCompile(`(?i)^/dbadmin(/|$)`),
	regexp.MustCompile(`(?i)^/adminer\.php$`),

	// Diagnostic / info-leak endpoints
	regexp.MustCompile(`(?i)^/phpinfo\.php$`),
	regexp.MustCompile(`(?i)^/info\.php$`),
	regexp.MustCompile(`(?i)^/test\.php$`),
	regexp.MustCompile(`(?i)^/shell\.php$`),
	regexp.MustCompile(`(?i)^/server-status$`),
	regexp.MustCompile(`(?i)^/server-info$`),

	// Backup / dump leaks
	regexp.MustCompile(`(?i)^/backup(\.|/)`),
	regexp.MustCompile(`(?i)^/dump\.sql$`),
	regexp.MustCompile(`(?i)^/database\.sql$`),
}

// DetectSensitivePath tests a URL path against patterns. Returns the
// first matching pattern's source string for logging/telemetry, or
// "" if no match. When patterns is nil, the package-level
// SensitivePathPatterns is used.
func DetectSensitivePath(path string, patterns []*regexp.Regexp) string {
	pats := patterns
	if pats == nil {
		pats = SensitivePathPatterns
	}
	for _, re := range pats {
		if re.MatchString(path) {
			return re.String()
		}
	}
	return ""
}
