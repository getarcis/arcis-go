package conformance_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

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

// Every adapter server exposes the same routes:
//
//	POST /plain      sets X-Powered-By, answers "ok"
//	POST /route-set  sets the given headers itself, answers "ok"
//	POST /nonce      answers with arcis.CSPNonce for the request
const routePoweredBy = "application-framework"

type headerServerOptions struct {
	profile   arcis.HeaderProfile
	baseline  arcis.BaselineHeaderOptions
	routeSets map[string]string
}

var headerAdapters = []struct {
	name  string
	start func(*testing.T, headerServerOptions) string
}{
	{"gin", startGinHeaderServer},
	{"echo", startEchoHeaderServer},
	{"chi", startChiHeaderServer},
	{"nethttp", startNetHTTPHeaderServer},
	{"fiber", startFiberHeaderServer},
}

func startGinHeaderServer(t *testing.T, o headerServerOptions) string {
	gin.SetMode(gin.TestMode)
	cfg := arcisgin.DefaultConfig()
	cfg.HeaderProfile = o.profile
	cfg.BaselineHeaders = o.baseline
	router := gin.New()
	router.Use(arcisgin.MiddlewareWithConfig(cfg))
	router.POST("/plain", func(c *gin.Context) {
		c.Header("X-Powered-By", routePoweredBy)
		c.String(http.StatusOK, "ok")
	})
	router.POST("/route-set", func(c *gin.Context) {
		for name, value := range o.routeSets {
			c.Header(name, value)
		}
		c.String(http.StatusOK, "ok")
	})
	router.POST("/nonce", func(c *gin.Context) {
		c.String(http.StatusOK, arcis.CSPNonce(c.Request.Context()))
	})
	t.Cleanup(arcisgin.Cleanup)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	return server.URL
}

func startEchoHeaderServer(t *testing.T, o headerServerOptions) string {
	cfg := arcisecho.DefaultConfig()
	cfg.HeaderProfile = o.profile
	cfg.BaselineHeaders = o.baseline
	app := echo.New()
	app.Use(arcisecho.MiddlewareWithConfig(cfg))
	app.POST("/plain", func(c echo.Context) error {
		c.Response().Header().Set("X-Powered-By", routePoweredBy)
		return c.String(http.StatusOK, "ok")
	})
	app.POST("/route-set", func(c echo.Context) error {
		for name, value := range o.routeSets {
			c.Response().Header().Set(name, value)
		}
		return c.String(http.StatusOK, "ok")
	})
	app.POST("/nonce", func(c echo.Context) error {
		return c.String(http.StatusOK, arcis.CSPNonce(c.Request().Context()))
	})
	t.Cleanup(arcisecho.Cleanup)
	server := httptest.NewServer(app)
	t.Cleanup(server.Close)
	return server.URL
}

func stdlibHeaderRoutes(o headerServerOptions) (plain, routeSet, nonce http.HandlerFunc) {
	plain = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", routePoweredBy)
		_, _ = io.WriteString(w, "ok")
	}
	routeSet = func(w http.ResponseWriter, r *http.Request) {
		for name, value := range o.routeSets {
			w.Header().Set(name, value)
		}
		_, _ = io.WriteString(w, "ok")
	}
	nonce = func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, arcis.CSPNonce(r.Context()))
	}
	return plain, routeSet, nonce
}

func startChiHeaderServer(t *testing.T, o headerServerOptions) string {
	cfg := arcischi.DefaultConfig()
	cfg.HeaderProfile = o.profile
	cfg.BaselineHeaders = o.baseline
	plain, routeSet, nonce := stdlibHeaderRoutes(o)
	router := gochi.NewRouter()
	router.Use(arcischi.MiddlewareWithConfig(cfg))
	router.Post("/plain", plain)
	router.Post("/route-set", routeSet)
	router.Post("/nonce", nonce)
	t.Cleanup(arcischi.Cleanup)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	return server.URL
}

func startNetHTTPHeaderServer(t *testing.T, o headerServerOptions) string {
	cfg := archttp.DefaultConfig()
	cfg.HeaderProfile = o.profile
	cfg.BaselineHeaders = o.baseline
	plain, routeSet, nonce := stdlibHeaderRoutes(o)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /plain", plain)
	mux.HandleFunc("POST /route-set", routeSet)
	mux.HandleFunc("POST /nonce", nonce)
	t.Cleanup(archttp.Cleanup)
	server := httptest.NewServer(archttp.MiddlewareWithConfig(cfg)(mux))
	t.Cleanup(server.Close)
	return server.URL
}

func startFiberHeaderServer(t *testing.T, o headerServerOptions) string {
	cfg := arcisfiber.DefaultConfig()
	cfg.HeaderProfile = o.profile
	cfg.BaselineHeaders = o.baseline
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(arcisfiber.MiddlewareWithConfig(cfg))
	app.Post("/plain", func(c *fiber.Ctx) error {
		c.Set("X-Powered-By", routePoweredBy)
		return c.SendString("ok")
	})
	app.Post("/route-set", func(c *fiber.Ctx) error {
		for name, value := range o.routeSets {
			c.Set(name, value)
		}
		return c.SendString("ok")
	})
	app.Post("/nonce", func(c *fiber.Ctx) error {
		return c.SendString(arcis.CSPNonce(c.UserContext()))
	})
	t.Cleanup(arcisfiber.Cleanup)
	return startFiberRealServer(t, app)
}

type baselineWireFixture struct {
	Cases []struct {
		Name            string            `json:"name"`
		ExpectedHeaders map[string]string `json:"expected_headers"`
		ExpectedAbsent  []string          `json:"expected_absent"`
	} `json:"cases"`
	Nonce struct {
		ScriptSrcPattern string `json:"script_src_pattern"`
	} `json:"nonce"`
	RouteHeaderWins struct {
		RouteSets       map[string]string `json:"route_sets"`
		ExpectedHeaders map[string]string `json:"expected_headers"`
	} `json:"route_header_wins"`
}

func loadBaselineWireFixture(t *testing.T) baselineWireFixture {
	t.Helper()
	raw, err := os.ReadFile("../spec/TEST_VECTORS.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		SecurityHeaders struct {
			Baseline baselineWireFixture `json:"baseline"`
		} `json:"security_headers"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	fixture := vectors.SecurityHeaders.Baseline
	if len(fixture.Cases) == 0 || fixture.Cases[0].Name != "defaults" || len(fixture.RouteHeaderWins.RouteSets) == 0 || fixture.Nonce.ScriptSrcPattern == "" {
		t.Fatal("security_headers.baseline fixture is incomplete")
	}
	return fixture
}

func assertExactHeader(t *testing.T, headers http.Header, name, want string) {
	t.Helper()
	if got := headers.Values(name); len(got) != 1 || got[0] != want {
		t.Errorf("%s = %q, want %q", name, got, want)
	}
}

func TestBaselineHeadersRealServers(t *testing.T) {
	fixture := loadBaselineWireFixture(t)
	defaults := fixture.Cases[0]
	for _, adapter := range headerAdapters {
		t.Run(adapter.name, func(t *testing.T) {
			url := adapter.start(t, headerServerOptions{
				profile:   arcis.HeaderProfileBaseline,
				routeSets: fixture.RouteHeaderWins.RouteSets,
			})

			response, body := sendRequest(t, url+"/plain", `{"name":"Alice"}`, browserUA)
			if response.StatusCode != http.StatusOK || body != "ok" {
				t.Fatalf("defaults: %d %q", response.StatusCode, body)
			}
			for name, want := range defaults.ExpectedHeaders {
				assertExactHeader(t, response.Header, name, want)
			}
			for _, name := range append(defaults.ExpectedAbsent, "X-Powered-By") {
				if got := response.Header.Values(name); len(got) != 0 {
					t.Errorf("%s should be absent, got %q", name, got)
				}
			}

			response, body = sendRequest(t, url+"/route-set", `{"name":"Alice"}`, browserUA)
			if response.StatusCode != http.StatusOK || body != "ok" {
				t.Fatalf("route-set: %d %q", response.StatusCode, body)
			}
			for name, want := range fixture.RouteHeaderWins.ExpectedHeaders {
				assertExactHeader(t, response.Header, name, want)
			}
		})
	}
}

func TestBaselineNonceRealServers(t *testing.T) {
	pattern := regexp.MustCompile(loadBaselineWireFixture(t).Nonce.ScriptSrcPattern)
	for _, adapter := range headerAdapters {
		t.Run(adapter.name, func(t *testing.T) {
			url := adapter.start(t, headerServerOptions{
				profile: arcis.HeaderProfileBaseline,
				baseline: arcis.BaselineHeaderOptions{
					ContentSecurityPolicy: arcis.CSPOptions{Nonce: true},
					Disable:               []string{"X-Powered-By"},
				},
			})

			seen := map[string]bool{}
			for i := 0; i < 2; i++ {
				response, body := sendRequest(t, url+"/nonce", `{"name":"Alice"}`, browserUA)
				if response.StatusCode != http.StatusOK {
					t.Fatalf("status = %d", response.StatusCode)
				}
				var scriptSrc string
				for _, directive := range strings.Split(response.Header.Get("Content-Security-Policy"), ";") {
					if strings.HasPrefix(directive, "script-src ") {
						scriptSrc = directive
					}
				}
				match := pattern.FindStringSubmatch(scriptSrc)
				if match == nil {
					t.Fatalf("script-src %q does not match %s", scriptSrc, pattern)
				}
				if body != match[1] {
					t.Errorf("handler saw nonce %q, header has %q", body, match[1])
				}
				if seen[match[1]] {
					t.Errorf("nonce %q reused across requests", match[1])
				}
				seen[match[1]] = true
			}

			// Disabling X-Powered-By leaves the application's header alone.
			response, _ := sendRequest(t, url+"/plain", `{"name":"Alice"}`, browserUA)
			assertExactHeader(t, response.Header, "X-Powered-By", routePoweredBy)
		})
	}
}

func TestAdaptersPanicOnInvalidBaselineConfig(t *testing.T) {
	invalid := arcis.BaselineHeaderOptions{XFrameOptions: "allow-from"}
	for name, build := range map[string]func(){
		"gin": func() {
			cfg := arcisgin.DefaultConfig()
			cfg.HeaderProfile, cfg.BaselineHeaders = arcis.HeaderProfileBaseline, invalid
			arcisgin.MiddlewareWithConfig(cfg)
		},
		"echo": func() {
			cfg := arcisecho.DefaultConfig()
			cfg.HeaderProfile, cfg.BaselineHeaders = arcis.HeaderProfileBaseline, invalid
			arcisecho.MiddlewareWithConfig(cfg)
		},
		"chi": func() {
			cfg := arcischi.DefaultConfig()
			cfg.HeaderProfile, cfg.BaselineHeaders = arcis.HeaderProfileBaseline, invalid
			arcischi.MiddlewareWithConfig(cfg)
		},
		"nethttp": func() {
			cfg := archttp.DefaultConfig()
			cfg.HeaderProfile, cfg.BaselineHeaders = arcis.HeaderProfileBaseline, invalid
			archttp.MiddlewareWithConfig(cfg)
		},
		"fiber": func() {
			cfg := arcisfiber.DefaultConfig()
			cfg.HeaderProfile, cfg.BaselineHeaders = arcis.HeaderProfileBaseline, invalid
			arcisfiber.MiddlewareWithConfig(cfg)
		},
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				message, _ := recover().(string)
				if !strings.Contains(message, "invalid security header configuration") || !strings.Contains(message, "invalid action") {
					t.Errorf("panic = %q, want a clear header configuration message", message)
				}
			}()
			build()
		})
	}
}

// The legacy profile of every adapter's DefaultConfig must send the same
// security headers as arcis.New(). The adapters used to omit the
// cross-origin isolation, Origin-Agent-Cluster and DNS prefetch headers.
func TestLegacyHeadersMatchRootDefaultsRealServers(t *testing.T) {
	root := arcis.New()
	t.Cleanup(root.Close)
	server := httptest.NewServer(root.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})))
	t.Cleanup(server.Close)
	rootResponse, _ := sendRequest(t, server.URL, `{"name":"Alice"}`, browserUA)

	reference := map[string]string{}
	for name := range arcis.NewSecurityHeaders(arcis.DefaultConfig()).GetHeaders() {
		reference[name] = rootResponse.Header.Get(name)
		if reference[name] == "" {
			t.Fatalf("arcis.New() did not send %s", name)
		}
	}
	for _, name := range []string{
		"Cross-Origin-Opener-Policy",
		"Cross-Origin-Resource-Policy",
		"Cross-Origin-Embedder-Policy",
		"Origin-Agent-Cluster",
		"X-DNS-Prefetch-Control",
	} {
		if reference[name] == "" {
			t.Fatalf("reference is missing %s", name)
		}
	}

	for _, adapter := range headerAdapters {
		t.Run(adapter.name, func(t *testing.T) {
			url := adapter.start(t, headerServerOptions{})
			response, body := sendRequest(t, url+"/plain", `{"name":"Alice"}`, browserUA)
			if response.StatusCode != http.StatusOK || body != "ok" {
				t.Fatalf("status %d %q", response.StatusCode, body)
			}
			for name, want := range reference {
				assertExactHeader(t, response.Header, name, want)
			}
		})
	}
}
