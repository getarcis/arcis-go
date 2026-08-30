package nethttp_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	archttp "github.com/getarcis/arcis-go/nethttp"
	"github.com/getarcis/arcis-go/telemetry"
)

func TestMiddlewareWithConfig_DryRunScannerPathReachesHandlerAndEmitsWouldDeny(t *testing.T) {
	telemetryRequests := make(chan []byte, 1)
	telemetryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		telemetryRequests <- body
		w.WriteHeader(http.StatusOK)
	}))
	defer telemetryServer.Close()

	tc, err := telemetry.NewClient(telemetry.Options{
		Endpoint:      telemetryServer.URL,
		BatchSize:     1,
		FlushInterval: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	cfg := archttp.DefaultConfig()
	cfg.RateLimit = false
	cfg.Bot = false
	cfg.Block = false
	cfg.DryRun = true
	cfg.Telemetry = tc

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("application-reached"))
	})
	server := httptest.NewServer(archttp.MiddlewareWithConfig(cfg)(handler))
	defer server.Close()
	defer archttp.Cleanup()

	request, err := http.NewRequest(http.MethodGet, server.URL+"/.env", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("User-Agent", realBrowserUA)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	responseBody, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}

	if err := tc.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var telemetryBody []byte
	select {
	case telemetryBody = <-telemetryRequests:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for telemetry POST")
	}
	var envelope struct {
		Events []telemetry.Event `json:"events"`
	}
	if err := json.Unmarshal(telemetryBody, &envelope); err != nil {
		t.Fatalf("decode telemetry batch: %v (body=%q)", err, telemetryBody)
	}
	if len(envelope.Events) != 1 {
		t.Fatalf("got %d events, want 1", len(envelope.Events))
	}
	event := envelope.Events[0]

	if response.StatusCode != http.StatusOK {
		t.Errorf("response code = %d, want 200", response.StatusCode)
	}
	if string(responseBody) != "application-reached" {
		t.Errorf("handler body = %q, want application-reached", responseBody)
	}
	if event.Decision != telemetry.DecisionWouldDeny {
		t.Errorf("Decision = %q, want would_deny", event.Decision)
	}
	if event.Vector != "scanner-path" {
		t.Errorf("Vector = %q, want scanner-path", event.Vector)
	}
	if event.Status != http.StatusOK {
		t.Errorf("Status = %d, want 200", event.Status)
	}
}

func TestMiddlewareWithConfig_DryRunForwardedHeaderReachesHandlerAndEmitsWouldDeny(t *testing.T) {
	telemetryRequests := make(chan []byte, 1)
	telemetryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		telemetryRequests <- body
		w.WriteHeader(http.StatusOK)
	}))
	defer telemetryServer.Close()

	tc, err := telemetry.NewClient(telemetry.Options{
		Endpoint:      telemetryServer.URL,
		BatchSize:     1,
		FlushInterval: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	cfg := archttp.DefaultConfig()
	cfg.RateLimit = false
	cfg.Bot = false
	cfg.Block = false
	cfg.ScannerPaths = false
	cfg.DryRun = true
	cfg.Telemetry = tc

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("application-reached"))
	})
	server := httptest.NewServer(archttp.MiddlewareWithConfig(cfg)(handler))
	defer server.Close()
	defer archttp.Cleanup()

	request, err := http.NewRequest(http.MethodGet, server.URL+"/normal", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("User-Agent", realBrowserUA)
	request.Header.Set("X-Forwarded-For", "127.0.0.1")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	responseBody, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}

	if err := tc.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var telemetryBody []byte
	select {
	case telemetryBody = <-telemetryRequests:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for telemetry POST")
	}
	var envelope struct {
		Events []telemetry.Event `json:"events"`
	}
	if err := json.Unmarshal(telemetryBody, &envelope); err != nil {
		t.Fatalf("decode telemetry batch: %v (body=%q)", err, telemetryBody)
	}
	if len(envelope.Events) != 1 {
		t.Fatalf("got %d events, want 1", len(envelope.Events))
	}
	event := envelope.Events[0]

	if response.StatusCode != http.StatusOK {
		t.Errorf("response code = %d, want 200", response.StatusCode)
	}
	if string(responseBody) != "application-reached" {
		t.Errorf("handler body = %q, want application-reached", responseBody)
	}
	if event.Decision != telemetry.DecisionWouldDeny {
		t.Errorf("Decision = %q, want would_deny", event.Decision)
	}
	if event.Vector != "header" {
		t.Errorf("Vector = %q, want header", event.Vector)
	}
	if event.Rule != "header/forwarded-loopback-spoof" {
		t.Errorf("Rule = %q, want header/forwarded-loopback-spoof", event.Rule)
	}
	if event.Status != http.StatusOK {
		t.Errorf("Status = %d, want 200", event.Status)
	}
}
