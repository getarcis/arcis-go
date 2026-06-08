package gin

// v1.7 W1 bot UA wire-up integration tests for the gin adapter.
//
// MiddlewareWithConfig by default classifies the request User-Agent and
// denies the AUTOMATED + SECURITY_SCANNER categories with 403. Opt-out via
// Config.Bot = false. SCRAPER (curl, wget, python-requests, monitoring) is
// NOT denied by default because it also covers legitimate non-browser
// clients; block it explicitly with BotDeny = {AUTOMATED, SCRAPER}.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	arcis "github.com/getarcis/arcis-go"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// realBrowserHeaders attaches the headers a real browser always sends so
// behavioral-signal detection in DetectBot falls all the way through to
// the HUMAN classification.
func realBrowserHeaders(r *http.Request) {
	r.Header.Set("Accept", "text/html,application/xhtml+xml")
	r.Header.Set("Accept-Language", "en-US,en;q=0.9")
	r.Header.Set("Accept-Encoding", "gzip, deflate, br")
}

// newRouter builds a gin engine with MiddlewareWithConfig + a single
// /echo handler returning 200. rate-limit is disabled so these tests
// never collide with a 429.
func newRouter(cfg Config) *gin.Engine {
	cfg.RateLimit = false
	r := gin.New()
	r.Use(MiddlewareWithConfig(cfg))
	r.GET("/echo", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return r
}

func do(r *gin.Engine, ua string, withBrowserHeaders bool) int {
	req := httptest.NewRequest("GET", "/echo", nil)
	req.Header.Set("User-Agent", ua)
	if withBrowserHeaders {
		realBrowserHeaders(req)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code
}

func TestBotWireup_DefaultDeniesAutomated(t *testing.T) {
	r := newRouter(DefaultConfig())
	bots := []string{
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Unknown; Linux x86_64) AppleWebKit/534.34 (KHTML, like Gecko) PhantomJS/2.1.1 Safari/534.34",
		"Mozilla/5.0 (compatible; Selenium/4.16.0)",
	}
	for _, ua := range bots {
		if got := do(r, ua, false); got != http.StatusForbidden {
			t.Errorf("UA %q: expected 403, got %d", ua, got)
		}
	}
}

func TestBotWireup_DefaultDeniesSecurityScanners(t *testing.T) {
	r := newRouter(DefaultConfig())
	scanners := []string{
		"sqlmap/1.7.2#stable (https://sqlmap.org)",
		"Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000001)",
		"Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
		"masscan/1.3.2",
		"Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
	}
	for _, ua := range scanners {
		if got := do(r, ua, false); got != http.StatusForbidden {
			t.Errorf("UA %q: expected 403, got %d", ua, got)
		}
	}
}

func TestBotWireup_DefaultAllowsRealClients(t *testing.T) {
	r := newRouter(DefaultConfig())
	// Browsers + search engines (full header set).
	browsers := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
	}
	for _, ua := range browsers {
		if got := do(r, ua, true); got != http.StatusOK {
			t.Errorf("browser UA %q: expected 200, got %d", ua, got)
		}
	}
	// Non-browser SCRAPER clients (curl, wget, python-requests) are not
	// default-denied. Bare UA, mirrors a curl health check.
	clients := []string{"curl/7.68.0", "python-requests/2.28.0", "Wget/1.21.3"}
	for _, ua := range clients {
		if got := do(r, ua, false); got != http.StatusOK {
			t.Errorf("non-browser client UA %q: expected 200, got %d", ua, got)
		}
	}
}

func TestBotWireup_OptOut(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Bot = false
	r := newRouter(cfg)
	if got := do(r, "curl/7.68.0", false); got != http.StatusOK {
		t.Errorf("Bot=false should allow curl, got %d", got)
	}
	if got := do(r, "sqlmap/1.7", false); got != http.StatusOK {
		t.Errorf("Bot=false should allow sqlmap, got %d", got)
	}
}

func TestBotWireup_OptInScraperDeny(t *testing.T) {
	cfg := DefaultConfig()
	cfg.BotDeny = []arcis.BotCategory{arcis.BotCategoryAutomated, arcis.BotCategoryScraper}
	r := newRouter(cfg)
	// With SCRAPER explicitly denied, curl is blocked.
	if got := do(r, "curl/7.68.0", false); got != http.StatusForbidden {
		t.Errorf("deny {AUTOMATED, SCRAPER} should block curl, got %d", got)
	}
}

func TestBotWireup_CorpusRegression(t *testing.T) {
	cases := []struct {
		ua   string
		want arcis.BotCategory
	}{
		// Offensive scanners -> SECURITY_SCANNER
		{"sqlmap/1.7", arcis.BotCategorySecurityScanner},
		{"Nikto/2.5", arcis.BotCategorySecurityScanner},
		{"Nuclei/2.9", arcis.BotCategorySecurityScanner},
		{"masscan/1.3", arcis.BotCategorySecurityScanner},
		// Generic non-browser clients stay SCRAPER
		{"curl/7.68.0", arcis.BotCategoryScraper},
		{"python-requests/2.28", arcis.BotCategoryScraper},
	}
	for _, c := range cases {
		req, _ := http.NewRequest("GET", "/", nil)
		req.Header.Set("User-Agent", c.ua)
		req.Header.Set("Accept", "text/html")
		req.Header.Set("Accept-Language", "en-US")
		req.Header.Set("Accept-Encoding", "gzip")
		got := arcis.DetectBot(req)
		if got.Category != c.want {
			t.Errorf("UA %q: expected category %q, got %q", c.ua, c.want, got.Category)
		}
	}
}
