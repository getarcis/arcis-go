package conformance_test

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	arcisecho "github.com/getarcis/arcis-go/echo"
	arcisfiber "github.com/getarcis/arcis-go/fiber"
	"github.com/gofiber/fiber/v2"
	"github.com/labstack/echo/v4"
)

type applicationErrorFixture struct {
	Name   string
	Config struct {
		RateLimit bool
		Block     bool
		DryRun    bool
	}
	Request struct {
		Method, Path string
		Body         json.RawMessage
	}
	ErrorStatus       int            `json:"error_status"`
	ApplicationStatus int            `json:"application_status"`
	ExpectedBody      string         `json:"expected_body"`
	ExpectedEvent     map[string]any `json:"expected_event"`
	ExpectedStatus    map[string]int `json:"expected_status_by_adapter"`
}

func applicationErrorFixtures(t *testing.T) []applicationErrorFixture {
	t.Helper()
	var vectors struct {
		Telemetry struct {
			ApplicationErrors struct{ Cases []applicationErrorFixture } `json:"application_errors"`
		}
	}
	raw, err := os.ReadFile("../spec/TEST_VECTORS.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Telemetry.ApplicationErrors.Cases) == 0 {
		t.Fatal("no application-error fixtures loaded")
	}
	return vectors.Telemetry.ApplicationErrors.Cases
}

func TestEchoRealServerOuterApplicationError(t *testing.T) {
	for _, fixture := range applicationErrorFixtures(t) {
		t.Run(fixture.Name, func(t *testing.T) {
			client, received := newWireTelemetryCollector(t)
			cfg := arcisecho.DefaultConfig()
			cfg.RateLimit = fixture.Config.RateLimit
			cfg.Block = fixture.Config.Block
			cfg.DryRun = fixture.Config.DryRun
			cfg.Telemetry = client
			failure := echo.NewHTTPError(fixture.ErrorStatus, "private application detail")
			app := echo.New()
			// Outer middleware must still receive the original error. Resolving
			// it inside Arcis would bypass application behavior.
			app.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
				return func(c echo.Context) error {
					err := next(c)
					if err == failure {
						c.Response().Header().Set("X-Error-Propagated", "yes")
					}
					return err
				}
			})
			app.Use(arcisecho.MiddlewareWithConfig(cfg))
			app.HTTPErrorHandler = func(err error, c echo.Context) {
				if err != failure {
					t.Errorf("application received a different error: %v", err)
				}
				_ = c.String(fixture.ApplicationStatus, fixture.ExpectedBody)
			}
			app.POST(fixture.Request.Path, func(c echo.Context) error { return failure })
			server := httptest.NewServer(app)
			t.Cleanup(server.Close)
			t.Cleanup(arcisecho.Cleanup)
			response, body := sendRequest(t, server.URL+fixture.Request.Path, string(fixture.Request.Body), browserUA)
			if response.StatusCode != fixture.ApplicationStatus || body != fixture.ExpectedBody || response.Header.Get("X-Error-Propagated") != "yes" {
				t.Fatalf("application error handling changed: %d %q %v", response.StatusCode, body, response.Header)
			}
			select {
			case event := <-received:
				if event["status"] != float64(fixture.ExpectedStatus["echo"]) {
					t.Errorf("status = %v, want %d", event["status"], fixture.ExpectedStatus["echo"])
				}
				for field, want := range fixture.ExpectedEvent {
					if event[field] != want {
						t.Errorf("%s = %v, want %v", field, event[field], want)
					}
				}
			case <-time.After(5 * time.Second):
				t.Fatal("no telemetry event received")
			}
		})
	}
}

func TestFiberRealServerOuterApplicationError(t *testing.T) {
	for _, fixture := range applicationErrorFixtures(t) {
		t.Run(fixture.Name, func(t *testing.T) {
			client, received := newWireTelemetryCollector(t)
			cfg := arcisfiber.DefaultConfig()
			cfg.RateLimit = fixture.Config.RateLimit
			cfg.Block = fixture.Config.Block
			cfg.DryRun = fixture.Config.DryRun
			cfg.Telemetry = client
			failure := fiber.NewError(fixture.ErrorStatus, "private application detail")
			app := fiber.New(fiber.Config{
				DisableStartupMessage: true,
				ErrorHandler: func(c *fiber.Ctx, err error) error {
					if err != failure {
						t.Errorf("application received a different error: %v", err)
					}
					return c.Status(fixture.ApplicationStatus).SendString(fixture.ExpectedBody)
				},
			})
			app.Use(func(c *fiber.Ctx) error {
				err := c.Next()
				if err == failure {
					c.Set("X-Error-Propagated", "yes")
				}
				return err
			})
			app.Use(arcisfiber.MiddlewareWithConfig(cfg))
			app.Post(fixture.Request.Path, func(c *fiber.Ctx) error {
				// Fiber has not committed this buffer; the outer handler
				// replaces both its status and body.
				_ = c.Status(202).SendString("provisional response")
				return failure
			})
			t.Cleanup(arcisfiber.Cleanup)
			url := startFiberRealServer(t, app)
			response, body := sendRequest(t, url+fixture.Request.Path, string(fixture.Request.Body), browserUA)
			if response.StatusCode != fixture.ApplicationStatus || body != fixture.ExpectedBody || response.Header.Get("X-Error-Propagated") != "yes" {
				t.Fatalf("application error handling changed: %d %q %v", response.StatusCode, body, response.Header)
			}
			select {
			case event := <-received:
				if event["status"] != float64(fixture.ExpectedStatus["fiber"]) {
					t.Errorf("status = %v, want %d", event["status"], fixture.ExpectedStatus["fiber"])
				}
				for field, want := range fixture.ExpectedEvent {
					if event[field] != want {
						t.Errorf("%s = %v, want %v", field, event[field], want)
					}
				}
			case <-time.After(5 * time.Second):
				t.Fatal("no telemetry event received")
			}
		})
	}
}

func TestRealServerOuterRecoveryPreservesObservedFinding(t *testing.T) {
	for _, adapter := range adapterNames {
		t.Run(adapter, func(t *testing.T) {
			client, received := newWireTelemetryCollector(t)
			url := startEnforcementServer(t, adapter, enforcementOptions{
				telemetry: client, dryRun: true, disableRateLimit: true,
				panicBeforeResponse: true, applicationStatus: 503,
			})
			response, body := sendRequest(t, url+"/echo", xssBody, browserUA)
			if response.StatusCode != 503 || body != "application failure" || response.Header.Get("X-Error-Propagated") != "yes" {
				t.Fatalf("application recovery changed: %d %q %v", response.StatusCode, body, response.Header)
			}
			select {
			case event := <-received:
				for field, want := range map[string]any{"decision": "would_deny", "vector": "xss", "severity": "high", "status": float64(0)} {
					if event[field] != want {
						t.Errorf("%s = %v, want %v", field, event[field], want)
					}
				}
			case <-time.After(5 * time.Second):
				t.Fatal("no telemetry event received")
			}
		})
	}
}

func TestEchoRealServerCommittedResponseKeepsKnownStatusAfterError(t *testing.T) {
	client, received := newWireTelemetryCollector(t)
	cfg := arcisecho.DefaultConfig()
	cfg.RateLimit = false
	cfg.Telemetry = client
	app := echo.New()
	app.Use(arcisecho.MiddlewareWithConfig(cfg))
	app.POST("/echo", func(c echo.Context) error {
		if err := c.String(202, "accepted"); err != nil {
			return err
		}
		return echo.NewHTTPError(503, "error after response")
	})
	server := httptest.NewServer(app)
	t.Cleanup(server.Close)
	t.Cleanup(arcisecho.Cleanup)
	response, body := sendRequest(t, server.URL+"/echo", safeInvoiceBody, browserUA)
	if response.StatusCode != 202 || body != "accepted" {
		t.Fatalf("committed application response changed: %d %q", response.StatusCode, body)
	}
	select {
	case event := <-received:
		if event["status"] != float64(202) || event["decision"] != "allow" {
			t.Errorf("committed response not preserved in event: %v", event)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no telemetry event received")
	}
}
