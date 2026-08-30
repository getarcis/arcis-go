package conformance_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	arcischi "github.com/getarcis/arcis-go/chi"
	arcisecho "github.com/getarcis/arcis-go/echo"
	arcisfiber "github.com/getarcis/arcis-go/fiber"
	arcisgin "github.com/getarcis/arcis-go/gin"
	archttp "github.com/getarcis/arcis-go/nethttp"
	"github.com/getarcis/arcis-go/telemetry"
	"github.com/gin-gonic/gin"
	gochi "github.com/go-chi/chi/v5"
	"github.com/gofiber/fiber/v2"
	"github.com/labstack/echo/v4"
)

var adapterNames = []string{"gin", "echo", "chi", "nethttp", "fiber"}

const safeInvoiceBody = "{\n  \"vendor\": \"Martignetti\", \"note\": \"Customer's invoice: 12 x 750ml\", \"total\": 125.50\n}\n"
const xssBody = `{"note":"<script>alert(1)</script>"}`

func TestRealServerAttackEnforcementPreservesSafeBody(t *testing.T) {
	for _, adapter := range adapterNames {
		t.Run(adapter, func(t *testing.T) {
			serverURL := startEnforcementServer(t, adapter)
			for _, step := range []struct {
				name, body string
				status     int
			}{
				{"safe_before_attack", safeInvoiceBody, http.StatusOK},
				{"attack", xssBody, http.StatusForbidden},
				{"safe_after_attack", safeInvoiceBody, http.StatusOK},
			} {
				t.Run(step.name, func(t *testing.T) {
					response, body := sendRequest(t, serverURL+"/echo", step.body, browserUA)
					if response.StatusCode != step.status {
						t.Fatalf("status = %d, want %d; body=%s", response.StatusCode, step.status, body)
					}
					if step.status == http.StatusOK {
						if body != step.body || response.Header.Get("X-Application-Reached") != "yes" {
							t.Fatalf("application did not receive unchanged input: %q", body)
						}
					} else {
						var denial struct{ Code, Vector string }
						if err := json.Unmarshal([]byte(body), &denial); err != nil {
							t.Fatal(err)
						}
						if denial.Code != "SECURITY_THREAT" || denial.Vector != "xss" || response.Header.Get("X-Application-Reached") != "" {
							t.Fatalf("attack not rejected before application: %s", body)
						}
					}
					assertSharedSecurityHeaders(t, response.Header)
				})
			}
		})
	}
}

func TestRealServerRateLimitCompletesAllowAndDeny(t *testing.T) {
	for _, adapter := range adapterNames {
		t.Run(adapter, func(t *testing.T) {
			serverURL := startEnforcementServer(t, adapter, enforcementOptions{limit: 2})
			for request := 0; request < 4; request++ {
				response, body := sendRequest(t, serverURL+"/echo", safeInvoiceBody, browserUA)
				want := http.StatusOK
				if request >= 2 {
					want = http.StatusTooManyRequests
				}
				if response.StatusCode != want {
					t.Fatalf("request %d: status = %d, want %d; %s", request+1, response.StatusCode, want, body)
				}
				if want == http.StatusOK && body != safeInvoiceBody {
					t.Errorf("allowed request body changed: %q", body)
				}
				if want == http.StatusTooManyRequests && (response.Header.Get("Retry-After") == "" || response.Header.Get("X-Application-Reached") != "") {
					t.Errorf("rate-limit denial did not short-circuit with Retry-After: %v", response.Header)
				}
				if response.Header.Get("X-RateLimit-Limit") != "2" {
					t.Errorf("incorrect limit header: %v", response.Header)
				}
				assertSharedSecurityHeaders(t, response.Header)
			}
		})
	}
}

func TestRealServerBotAllowDenyAndRecovery(t *testing.T) {
	for _, adapter := range adapterNames {
		t.Run(adapter, func(t *testing.T) {
			serverURL := startEnforcementServer(t, adapter)
			for _, step := range []struct {
				name, userAgent string
				status          int
			}{
				{"browser_before", browserUA, http.StatusOK},
				{"security_scanner", "sqlmap/1.7.2#stable (https://sqlmap.org)", http.StatusForbidden},
				{"browser_after", browserUA, http.StatusOK},
				{"nonbrowser_client", "curl/8.0.1", http.StatusOK},
			} {
				t.Run(step.name, func(t *testing.T) {
					response, body := sendRequest(t, serverURL+"/echo", safeInvoiceBody, step.userAgent)
					if response.StatusCode != step.status {
						t.Fatalf("status = %d, want %d; %s", response.StatusCode, step.status, body)
					}
					if step.status == http.StatusOK && body != safeInvoiceBody {
						t.Errorf("allowed body changed: %q", body)
					}
					if step.status == http.StatusForbidden && response.Header.Get("X-Application-Reached") != "" {
						t.Error("denied scanner reached application")
					}
					assertSharedSecurityHeaders(t, response.Header)
				})
			}
		})
	}
}

type enforcementOptions struct {
	limit     int
	dryRun    bool
	telemetry *telemetry.Client
}

func TestRealServerEnforcingPreservesMalformedAndNonJSON(t *testing.T) {
	for _, adapter := range adapterNames {
		t.Run(adapter, func(t *testing.T) {
			serverURL := startEnforcementServer(t, adapter)
			for _, fixture := range []struct{ name, contentType, body string }{
				{"malformed_json", "application/json", `{not json`},
				{"non_json", "text/plain; charset=utf-8", "Customer's invoice: crème brûlée, 12 x 750ml\n"},
			} {
				t.Run(fixture.name, func(t *testing.T) {
					request, err := http.NewRequest(http.MethodPost, serverURL+"/echo", strings.NewReader(fixture.body))
					if err != nil {
						t.Fatal(err)
					}
					request.Header.Set("Content-Type", fixture.contentType)
					request.Header.Set("User-Agent", browserUA)
					request.Header.Set("Accept", "application/json")
					request.Header.Set("Accept-Language", "en-US")
					client := &http.Client{Timeout: 5 * time.Second}
					response, err := client.Do(request)
					if err != nil {
						t.Fatal(err)
					}
					defer response.Body.Close()
					body, err := io.ReadAll(response.Body)
					if err != nil {
						t.Fatal(err)
					}
					if response.StatusCode != http.StatusOK || string(body) != fixture.body {
						t.Fatalf("body not preserved: %d %q", response.StatusCode, body)
					}
				})
			}
		})
	}
}

func startEnforcementServer(t *testing.T, adapter string, options ...enforcementOptions) string {
	t.Helper()
	opts := enforcementOptions{limit: 100}
	if len(options) > 0 {
		opts = options[0]
	}
	if opts.limit == 0 {
		opts.limit = 100
	}
	var handler http.Handler
	switch adapter {
	case "gin":
		gin.SetMode(gin.TestMode)
		cfg := arcisgin.DefaultConfig()
		cfg.Block = true
		cfg.RateLimitMax = opts.limit
		cfg.DryRun = opts.dryRun
		cfg.Telemetry = opts.telemetry
		router := gin.New()
		router.Use(arcisgin.MiddlewareWithConfig(cfg))
		router.POST("/echo", func(c *gin.Context) {
			raw, err := io.ReadAll(c.Request.Body)
			if err != nil {
				c.Status(http.StatusInternalServerError)
				return
			}
			c.Header("X-Application-Reached", "yes")
			c.Data(http.StatusOK, "application/json", raw)
		})
		t.Cleanup(arcisgin.Cleanup)
		handler = router
	case "echo":
		cfg := arcisecho.DefaultConfig()
		cfg.Block = true
		cfg.RateLimitMax = opts.limit
		cfg.DryRun = opts.dryRun
		cfg.Telemetry = opts.telemetry
		app := echo.New()
		app.Use(arcisecho.MiddlewareWithConfig(cfg))
		app.POST("/echo", func(c echo.Context) error {
			raw, err := io.ReadAll(c.Request().Body)
			if err != nil {
				return err
			}
			c.Response().Header().Set("X-Application-Reached", "yes")
			return c.Blob(http.StatusOK, "application/json", raw)
		})
		t.Cleanup(arcisecho.Cleanup)
		handler = app
	case "chi":
		cfg := arcischi.DefaultConfig()
		cfg.Block = true
		cfg.RateLimitMax = opts.limit
		cfg.DryRun = opts.dryRun
		cfg.Telemetry = opts.telemetry
		router := gochi.NewRouter()
		router.Use(arcischi.MiddlewareWithConfig(cfg))
		router.Post("/echo", echoRawBody)
		t.Cleanup(arcischi.Cleanup)
		handler = router
	case "nethttp":
		cfg := archttp.DefaultConfig()
		cfg.Block = true
		cfg.RateLimitMax = opts.limit
		cfg.DryRun = opts.dryRun
		cfg.Telemetry = opts.telemetry
		mux := http.NewServeMux()
		mux.HandleFunc("POST /echo", echoRawBody)
		handler = archttp.MiddlewareWithConfig(cfg)(mux)
		t.Cleanup(archttp.Cleanup)
	case "fiber":
		cfg := arcisfiber.DefaultConfig()
		cfg.Block = true
		cfg.RateLimitMax = opts.limit
		cfg.DryRun = opts.dryRun
		cfg.Telemetry = opts.telemetry
		app := fiber.New(fiber.Config{DisableStartupMessage: true})
		app.Use(arcisfiber.MiddlewareWithConfig(cfg))
		app.Post("/echo", func(c *fiber.Ctx) error {
			c.Set("X-Application-Reached", "yes")
			c.Set("Content-Type", "application/json")
			return c.Send(append([]byte(nil), c.Body()...))
		})
		t.Cleanup(arcisfiber.Cleanup)
		return startFiberRealServer(t, app)
	default:
		t.Fatalf("unknown adapter %q", adapter)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server.URL
}

func echoRawBody(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("X-Application-Reached", "yes")
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(raw)
}
