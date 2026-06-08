package gin

// v1.7 W2 scanner-paths wire-up integration tests for the gin adapter.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

const browserUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

func newRouterScanner(cfg Config) *gin.Engine {
	cfg.RateLimit = false
	r := gin.New()
	r.Use(MiddlewareWithConfig(cfg))
	// Catch-all that returns 200 for anything that survives the middleware.
	r.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	r.GET("/echo", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return r
}

func doPath(r *gin.Engine, path string) int {
	req := httptest.NewRequest("GET", path, nil)
	// Real browser headers so bot UA doesn't intercept.
	req.Header.Set("User-Agent", browserUA)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Language", "en-US")
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code
}

func TestScannerPaths_DefaultDeniesBenchPaths(t *testing.T) {
	r := newRouterScanner(DefaultConfig())
	for _, p := range []string{"/admin", "/wp-admin", "/.env"} {
		if got := doPath(r, p); got != http.StatusForbidden {
			t.Errorf("path %q: expected 403, got %d", p, got)
		}
	}
}

func TestScannerPaths_DefaultDeniesBroaderProbes(t *testing.T) {
	r := newRouterScanner(DefaultConfig())
	probes := []string{
		"/.env.local", "/.git/config", "/.git/HEAD", "/.svn/entries",
		"/.aws/credentials", "/wp-login.php", "/wp-config.php", "/xmlrpc.php",
		"/phpmyadmin/index.php", "/pma/", "/adminer.php", "/phpinfo.php",
		"/server-status", "/administrator",
	}
	for _, p := range probes {
		if got := doPath(r, p); got != http.StatusForbidden {
			t.Errorf("probe %q: expected 403, got %d", p, got)
		}
	}
}

func TestScannerPaths_LegitPathsAllowed(t *testing.T) {
	r := newRouterScanner(DefaultConfig())
	legit := []string{
		"/", "/admin/dashboard", "/admin/users/42", "/api/v1/users",
		"/healthcheck", "/env-vars", "/environment", "/gitlab/projects",
		"/static/image.png", "/login",
	}
	for _, p := range legit {
		if got := doPath(r, p); got != http.StatusOK {
			t.Errorf("legit %q: expected 200, got %d", p, got)
		}
	}
}

func TestScannerPaths_OptOut(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ScannerPaths = false
	r := newRouterScanner(cfg)
	if got := doPath(r, "/.env"); got != http.StatusOK {
		t.Errorf("ScannerPaths=false should allow /.env, got %d", got)
	}
}
