package conformance_test

import (
	"fmt"
	"net/http"
	"runtime"
	"testing"
	"time"
)

func TestRealServerCleanupDoesNotAccumulateGoroutines(t *testing.T) {
	for _, adapter := range adapterNames {
		t.Run(adapter, func(t *testing.T) {
			cycle := func(t *testing.T) {
				client, received := newTelemetryCollector(t)
				serverURL := startEnforcementServer(t, adapter, enforcementOptions{telemetry: client})
				response, body := sendRequest(t, serverURL+"/echo", safeInvoiceBody, browserUA)
				if response.StatusCode != http.StatusOK || body != safeInvoiceBody {
					t.Fatalf("lifecycle request failed: %d %q", response.StatusCode, body)
				}
				client.Flush()
				awaitTelemetry(t, received, 1)
			}
			// Warm framework-owned pools before measuring repeated application
			// lifecycles. Subtest cleanup closes each listener, limiter, and client.
			t.Run("warmup", cycle)
			baseline := runtime.NumGoroutine()
			for iteration := 0; iteration < 8; iteration++ {
				t.Run(fmt.Sprintf("cycle_%d", iteration+1), cycle)
			}
			// Runtime and framework housekeeping may briefly overlap teardown.
			// A two-goroutine allowance cannot hide one leak per lifecycle.
			settleTimeout := 5 * time.Second
			if adapter == "fiber" {
				// fasthttp v1.51.0's worker-pool cleaner sleeps for ten
				// seconds even after Stop. Allow that framework-owned timer
				// to finish; do not mistake it for an Arcis limiter leak.
				settleTimeout = 15 * time.Second
			}
			deadline := time.Now().Add(settleTimeout)
			for runtime.NumGoroutine() > baseline+2 && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			if remaining := runtime.NumGoroutine(); remaining > baseline+2 {
				stacks := make([]byte, 64*1024)
				n := runtime.Stack(stacks, true)
				t.Errorf("goroutines accumulated across 8 shutdowns: before=%d after=%d (allowance=2)\n%s", baseline, remaining, stacks[:n])
			}
		})
	}
}
