package conformance_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	arcis "github.com/getarcis/arcis-go"
	arcischi "github.com/getarcis/arcis-go/chi"
	arcisecho "github.com/getarcis/arcis-go/echo"
	arcisfiber "github.com/getarcis/arcis-go/fiber"
	arcisgin "github.com/getarcis/arcis-go/gin"
	archttp "github.com/getarcis/arcis-go/nethttp"
	"github.com/gin-gonic/gin"
	gochi "github.com/go-chi/chi/v5"
	"github.com/gofiber/fiber/v2"
	"github.com/labstack/echo/v4"
)

// Real-server regressions for client IP resolution (spec/API_SPEC.md "Client
// IP resolution"). Every server listens on 127.0.0.1, so the peer is loopback:
//   - TrustedProxies empty: loopback is not a proxy, so it plays a public
//     client and rotating X-Forwarded-For must stay in one bucket.
//   - TrustedProxies nil: the default set trusts loopback as a proxy, so
//     distinct forwarded clients get distinct buckets.

type limitedServer struct {
	name  string
	start func(t *testing.T, trustedProxies []string, max int) string
}

func okHandler(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }

func startHTTPServer(t *testing.T, h http.Handler) string {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv.URL
}

func ginServer(t *testing.T, mw gin.HandlerFunc) string {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/", mw, func(c *gin.Context) { c.Status(http.StatusOK) })
	return startHTTPServer(t, r)
}

func echoServer(t *testing.T, mw echo.MiddlewareFunc) string {
	e := echo.New()
	e.GET("/", func(c echo.Context) error { return c.NoContent(http.StatusOK) }, mw)
	return startHTTPServer(t, e)
}

func chiServer(t *testing.T, mw func(http.Handler) http.Handler) string {
	r := gochi.NewRouter()
	r.Use(mw)
	r.Get("/", okHandler)
	return startHTTPServer(t, r)
}

func fiberServer(t *testing.T, mw fiber.Handler) string {
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Get("/", mw, func(c *fiber.Ctx) error { return c.SendStatus(http.StatusOK) })
	return startFiberRealServer(t, app)
}

func bruteForce(t *testing.T, trustedProxies []string, max int) *arcis.BruteForce {
	b := arcis.NewBruteForce(arcis.BruteForceConfig{FastPoints: max, TrustedProxies: trustedProxies})
	t.Cleanup(b.Close)
	return b
}

var limitedServers = []limitedServer{
	{"net/http root Handler", func(t *testing.T, tp []string, max int) string {
		a := arcis.NewWithConfig(arcis.Config{RateLimit: true, RateLimitMax: max, RateLimitWindow: time.Minute, TrustedProxies: tp})
		t.Cleanup(a.Close)
		return startHTTPServer(t, a.Handler(http.HandlerFunc(okHandler)))
	}},
	{"nethttp MiddlewareWithConfig", func(t *testing.T, tp []string, max int) string {
		cfg := archttp.DefaultConfig()
		cfg.RateLimitMax, cfg.TrustedProxies = max, tp
		t.Cleanup(archttp.Cleanup)
		return startHTTPServer(t, archttp.MiddlewareWithConfig(cfg)(http.HandlerFunc(okHandler)))
	}},
	{"nethttp RateLimit", func(t *testing.T, tp []string, max int) string {
		t.Cleanup(archttp.Cleanup)
		return startHTTPServer(t, archttp.RateLimit(max, time.Minute, archttp.WithTrustedProxies(tp))(http.HandlerFunc(okHandler)))
	}},
	{"nethttp BruteForce", func(t *testing.T, tp []string, max int) string {
		return startHTTPServer(t, bruteForce(t, tp, max).Handler(http.HandlerFunc(okHandler)))
	}},
	{"chi MiddlewareWithConfig", func(t *testing.T, tp []string, max int) string {
		cfg := arcischi.DefaultConfig()
		cfg.RateLimitMax, cfg.TrustedProxies = max, tp
		t.Cleanup(arcischi.Cleanup)
		return chiServer(t, arcischi.MiddlewareWithConfig(cfg))
	}},
	{"chi RateLimitWithSkip", func(t *testing.T, tp []string, max int) string {
		t.Cleanup(arcischi.Cleanup)
		return chiServer(t, arcischi.RateLimitWithSkip(max, time.Minute, nil, arcischi.WithTrustedProxies(tp)))
	}},
	{"gin MiddlewareWithConfig", func(t *testing.T, tp []string, max int) string {
		cfg := arcisgin.DefaultConfig()
		cfg.RateLimitMax, cfg.TrustedProxies = max, tp
		t.Cleanup(arcisgin.Cleanup)
		return ginServer(t, arcisgin.MiddlewareWithConfig(cfg))
	}},
	{"gin RateLimit", func(t *testing.T, tp []string, max int) string {
		t.Cleanup(arcisgin.Cleanup)
		return ginServer(t, arcisgin.RateLimit(max, time.Minute, arcisgin.WithTrustedProxies(tp)))
	}},
	{"gin BruteForce", func(t *testing.T, tp []string, max int) string {
		return ginServer(t, arcisgin.BruteForce(bruteForce(t, tp, max)))
	}},
	{"echo MiddlewareWithConfig", func(t *testing.T, tp []string, max int) string {
		cfg := arcisecho.DefaultConfig()
		cfg.RateLimitMax, cfg.TrustedProxies = max, tp
		t.Cleanup(arcisecho.Cleanup)
		return echoServer(t, arcisecho.MiddlewareWithConfig(cfg))
	}},
	{"echo RateLimit", func(t *testing.T, tp []string, max int) string {
		t.Cleanup(arcisecho.Cleanup)
		return echoServer(t, arcisecho.RateLimit(max, time.Minute, arcisecho.WithTrustedProxies(tp)))
	}},
	{"echo BruteForce", func(t *testing.T, tp []string, max int) string {
		return echoServer(t, arcisecho.BruteForce(bruteForce(t, tp, max)))
	}},
	{"fiber MiddlewareWithConfig", func(t *testing.T, tp []string, max int) string {
		cfg := arcisfiber.DefaultConfig()
		cfg.RateLimitMax, cfg.TrustedProxies = max, tp
		t.Cleanup(arcisfiber.Cleanup)
		return fiberServer(t, arcisfiber.MiddlewareWithConfig(cfg))
	}},
	{"fiber RateLimit", func(t *testing.T, tp []string, max int) string {
		t.Cleanup(arcisfiber.Cleanup)
		return fiberServer(t, arcisfiber.RateLimit(max, time.Minute, arcisfiber.WithTrustedProxies(tp)))
	}},
	{"fiber BruteForce", func(t *testing.T, tp []string, max int) string {
		return fiberServer(t, arcisfiber.BruteForce(bruteForce(t, tp, max)))
	}},
}

func statusWithXFF(t *testing.T, serverURL, xff string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, serverURL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("User-Agent", browserUA)
	req.Header.Set("X-Forwarded-For", xff)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	res.Body.Close()
	return res.StatusCode
}

func TestRealServer_PublicPeerRotatingXFFStaysInOneBucket(t *testing.T) {
	const max = 3
	spoofed := []string{"203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4", "2001:db8:aa00::1"}
	for _, server := range limitedServers {
		t.Run(server.name, func(t *testing.T) {
			url := server.start(t, []string{}, max)
			for i, xff := range spoofed {
				got := statusWithXFF(t, url, xff)
				if i < max && got != http.StatusOK {
					t.Fatalf("request %d: status %d, want 200", i+1, got)
				}
				if i >= max && got != http.StatusTooManyRequests {
					t.Fatalf("request %d with rotated XFF %s: status %d, want 429", i+1, xff, got)
				}
			}
		})
	}
}

func TestRealServer_TrustedProxyDistinctClientsGetDistinctBuckets(t *testing.T) {
	steps := []struct {
		xff  string
		want int
	}{
		{"203.0.113.1", http.StatusOK},
		{"203.0.113.2", http.StatusOK},
		{"198.51.100.200, 203.0.113.1", http.StatusTooManyRequests}, // spoofed left entry ignored
		{"2001:db8:1234:5601::1", http.StatusOK},
		{"2001:db8:1234:56ff::2", http.StatusTooManyRequests}, // same /56
		{"2001:db8:1234:5700::1", http.StatusOK},
	}
	for _, server := range limitedServers {
		t.Run(server.name, func(t *testing.T) {
			url := server.start(t, nil, 1)
			for i, step := range steps {
				if got := statusWithXFF(t, url, step.xff); got != step.want {
					t.Fatalf("step %d (XFF %q): status %d, want %d", i+1, step.xff, got, step.want)
				}
			}
		})
	}
}
