package fiber_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"

	arcisfiber "github.com/getarcis/arcis-go/fiber"
	"github.com/getarcis/arcis-go/telemetry"
)

func fiberRecordingServer(t *testing.T) (string, <-chan []byte) {
	t.Helper()
	requests := make(chan []byte, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests <- body
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	return server.URL, requests
}

func decodeFiberEvent(t *testing.T, body []byte) telemetry.Event {
	t.Helper()
	var envelope struct {
		Events []telemetry.Event `json:"events"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("decode telemetry batch: %v (body=%q)", err, body)
	}
	if len(envelope.Events) != 1 {
		t.Fatalf("got %d events, want 1", len(envelope.Events))
	}
	return envelope.Events[0]
}

func receiveFiberTelemetry(t *testing.T, requests <-chan []byte) []byte {
	t.Helper()
	select {
	case body := <-requests:
		return body
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for telemetry POST")
		return nil
	}
}

func TestFiberTelemetry_DryRunGraphQLPreservesBodyAndEmitsWouldDeny(t *testing.T) {
	url, requests := fiberRecordingServer(t)
	tc, err := telemetry.NewClient(telemetry.Options{
		Endpoint:      url,
		BatchSize:     1,
		FlushInterval: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	cfg := arcisfiber.DefaultConfig()
	cfg.RateLimit = false
	cfg.Bot = false
	cfg.Block = false
	cfg.DryRun = true
	cfg.Telemetry = tc

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(arcisfiber.MiddlewareWithConfig(cfg))
	app.Post("/graphql", func(c *fiber.Ctx) error {
		return c.Type("json").Send(c.Body())
	})
	t.Cleanup(arcisfiber.Cleanup)

	body := `{"query":"{__schema{types{name}}}"}`
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(body))
	req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	req.Header.Set(fiber.HeaderUserAgent, "Mozilla/5.0")
	res, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("response code = %d, want 200", res.StatusCode)
	}
	responseBody, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read handler response: %v", err)
	}
	if string(responseBody) != body {
		t.Fatalf("handler body = %q, want original %q", responseBody, body)
	}

	if err := tc.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	event := decodeFiberEvent(t, receiveFiberTelemetry(t, requests))
	if event.Decision != telemetry.DecisionWouldDeny {
		t.Errorf("Decision = %q, want would_deny", event.Decision)
	}
	if event.Vector != "graphql" {
		t.Errorf("Vector = %q, want graphql", event.Vector)
	}
	if event.Status != http.StatusOK {
		t.Errorf("Status = %d, want 200", event.Status)
	}
}

func TestFiberTelemetry_DryRunRequestDetectorsReachHandlerAndEmitWouldDeny(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		scannerPaths bool
		headerName   string
		headerValue  string
		vector       string
		rule         string
	}{
		{
			name:         "scanner path",
			path:         "/.env",
			scannerPaths: true,
			vector:       "scanner-path",
			rule:         "scanner-path/probe",
		},
		{
			name:         "forwarded loopback spoof",
			path:         "/normal",
			scannerPaths: false,
			headerName:   "X-Forwarded-For",
			headerValue:  "127.0.0.1",
			vector:       "header",
			rule:         "header/forwarded-loopback-spoof",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			url, requests := fiberRecordingServer(t)
			tc, err := telemetry.NewClient(telemetry.Options{
				Endpoint:      url,
				BatchSize:     1,
				FlushInterval: 10 * time.Second,
			})
			if err != nil {
				t.Fatal(err)
			}

			cfg := arcisfiber.DefaultConfig()
			cfg.RateLimit = false
			cfg.Bot = false
			cfg.Block = false
			cfg.ScannerPaths = testCase.scannerPaths
			cfg.DryRun = true
			cfg.Telemetry = tc

			app := fiber.New(fiber.Config{DisableStartupMessage: true})
			app.Use(arcisfiber.MiddlewareWithConfig(cfg))
			app.Get(testCase.path, func(c *fiber.Ctx) error {
				return c.SendString("application-reached")
			})
			t.Cleanup(arcisfiber.Cleanup)

			req := httptest.NewRequest(http.MethodGet, testCase.path, nil)
			req.Header.Set(fiber.HeaderUserAgent, "Mozilla/5.0")
			if testCase.headerName != "" {
				req.Header.Set(testCase.headerName, testCase.headerValue)
			}
			res, err := app.Test(req, -1)
			if err != nil {
				t.Fatalf("app.Test: %v", err)
			}
			responseBody, readErr := io.ReadAll(res.Body)
			_ = res.Body.Close()
			if readErr != nil {
				t.Fatalf("read handler response: %v", readErr)
			}

			if err := tc.Close(context.Background()); err != nil {
				t.Fatalf("Close: %v", err)
			}
			event := decodeFiberEvent(t, receiveFiberTelemetry(t, requests))

			if res.StatusCode != http.StatusOK {
				t.Errorf("response code = %d, want 200", res.StatusCode)
			}
			if string(responseBody) != "application-reached" {
				t.Errorf("handler body = %q, want application-reached", responseBody)
			}
			if event.Decision != telemetry.DecisionWouldDeny {
				t.Errorf("Decision = %q, want would_deny", event.Decision)
			}
			if event.Vector != testCase.vector {
				t.Errorf("Vector = %q, want %s", event.Vector, testCase.vector)
			}
			if event.Rule != testCase.rule {
				t.Errorf("Rule = %q, want %s", event.Rule, testCase.rule)
			}
			if event.Status != http.StatusOK {
				t.Errorf("Status = %d, want 200", event.Status)
			}
		})
	}
}
