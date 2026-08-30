package conformance_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/getarcis/arcis-go/telemetry"
)

func TestRealServerConcurrentLimiterAndTelemetry(t *testing.T) {
	const requests = 24
	const limit = 8
	for _, adapter := range adapterNames {
		t.Run(adapter, func(t *testing.T) {
			client, received := newTelemetryCollector(t)
			serverURL := startEnforcementServer(t, adapter, enforcementOptions{limit: limit, telemetry: client})
			type result struct {
				response *http.Response
				body     string
				err      error
			}
			results := make(chan result, requests)
			start := make(chan struct{})
			for request := 0; request < requests; request++ {
				go func() {
					<-start
					response, body, err := exchangeRequest(serverURL+"/echo", safeInvoiceBody, browserUA)
					results <- result{response, body, err}
				}()
			}
			close(start)
			allowed, denied := 0, 0
			for request := 0; request < requests; request++ {
				result := <-results
				if result.err != nil {
					t.Errorf("concurrent request failed: %v", result.err)
					continue
				}
				switch result.response.StatusCode {
				case http.StatusOK:
					allowed++
					if result.body != safeInvoiceBody {
						t.Errorf("body changed: %q", result.body)
					}
				case http.StatusTooManyRequests:
					denied++
				default:
					t.Errorf("unexpected concurrent status: %d, %s", result.response.StatusCode, result.body)
				}
			}
			if allowed != limit || denied != requests-limit {
				t.Errorf("allowed/denied = %d/%d, want 8/16", allowed, denied)
			}
			eventAllowed, eventDenied := 0, 0
			for _, event := range awaitTelemetry(t, received, requests) {
				if event.Method != "POST" || event.Path != "/echo" || event.IP == "" {
					t.Errorf("invalid request event: %+v", event)
				}
				switch {
				case event.Decision == telemetry.DecisionAllow && event.Status == http.StatusOK:
					eventAllowed++
				case event.Decision == telemetry.DecisionDeny && event.Status == http.StatusTooManyRequests && event.Vector == "rate-limit":
					eventDenied++
				default:
					t.Errorf("incorrect decision event: %+v", event)
				}
			}
			if eventAllowed != allowed || eventDenied != denied {
				t.Errorf("telemetry disagrees with HTTP outcomes: %d/%d versus %d/%d", eventAllowed, eventDenied, allowed, denied)
			}
		})
	}
}

func TestRealServerDryRunPreservesInputWithFindings(t *testing.T) {
	for _, adapter := range adapterNames {
		t.Run(adapter, func(t *testing.T) {
			for _, scenario := range []struct {
				name, body, userAgent, vector string
				count                         int
			}{
				{"attack", xssBody, browserUA, "xss", 1},
				{"bot", safeInvoiceBody, "sqlmap/1.7.2#stable (https://sqlmap.org)", "bot", 1},
				{"rate_limit", safeInvoiceBody, browserUA, "rate-limit", 2},
			} {
				t.Run(scenario.name, func(t *testing.T) {
					client, received := newTelemetryCollector(t)
					serverURL := startEnforcementServer(t, adapter, enforcementOptions{limit: 1, dryRun: true, telemetry: client})
					for request := 0; request < scenario.count; request++ {
						response, body := sendRequest(t, serverURL+"/echo", scenario.body, scenario.userAgent)
						if response.StatusCode != http.StatusOK || body != scenario.body || response.Header.Get("X-Application-Reached") != "yes" {
							t.Fatalf("dry-run did not preserve application input: %d %q", response.StatusCode, body)
						}
						assertSharedSecurityHeaders(t, response.Header)
					}
					events := awaitTelemetry(t, received, scenario.count)
					last := events[len(events)-1]
					if last.Decision != telemetry.DecisionWouldDeny || last.Status != http.StatusOK || last.Vector != scenario.vector {
						t.Errorf("dry-run finding was not reported: %+v", last)
					}
					if scenario.count == 2 && events[0].Decision != telemetry.DecisionAllow {
						t.Errorf("first rate-limited request should be allowed: %+v", events[0])
					}
				})
			}
		})
	}
}

func newTelemetryCollector(t *testing.T) (*telemetry.Client, <-chan telemetry.Event) {
	t.Helper()
	received := make(chan telemetry.Event, 128)
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var batch struct {
			Events []telemetry.Event `json:"events"`
		}
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		for _, event := range batch.Events {
			select {
			case received <- event:
			default:
				t.Error("telemetry collector overflow")
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(collector.Close)
	client, err := telemetry.NewClient(telemetry.Options{
		Endpoint:      collector.URL,
		BatchSize:     4,
		FlushInterval: 500 * time.Millisecond,
		OnError:       func(err error) { t.Errorf("telemetry delivery failed: %v", err) },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := client.Close(ctx); err != nil {
			t.Errorf("telemetry did not stop: %v", err)
		}
	})
	return client, received
}

func awaitTelemetry(t *testing.T, received <-chan telemetry.Event, count int) []telemetry.Event {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	events := make([]telemetry.Event, 0, count)
	for len(events) < count {
		select {
		case event := <-received:
			events = append(events, event)
		case <-timer.C:
			t.Fatalf("received %d/%d telemetry events before deadline", len(events), count)
		}
	}
	return events
}
