package conformance_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/getarcis/arcis-go/telemetry"
)

func TestRealServerSharedApplicationOutcomes(t *testing.T) {
	var vectors struct {
		Telemetry struct {
			MiddlewareEmission struct {
				Cases []struct {
					Name   string
					Config struct {
						DryRun    bool
						Block     bool
						RateLimit json.RawMessage
					}
					Request struct {
						Method, Path string
						Body         json.RawMessage
					}
					ApplicationStatus int            `json:"application_status"`
					ExpectedUnchanged bool           `json:"expected_request_unchanged"`
					ExpectedEvent     map[string]any `json:"expected_event"`
					ExpectedAbsent    []string       `json:"expected_absent_fields"`
				}
			} `json:"middleware_emission"`
		}
	}
	raw, err := os.ReadFile("../spec/TEST_VECTORS.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	matched := 0
	for _, fixture := range vectors.Telemetry.MiddlewareEmission.Cases {
		if fixture.ApplicationStatus == 0 {
			continue
		}
		matched++
		// Fail rather than silently dropping unsupported fixture configuration.
		if fixture.Request.Method != "POST" || fixture.Request.Path != "/echo" || !fixture.Config.Block || string(fixture.Config.RateLimit) != "false" {
			t.Fatalf("unsupported application-outcome fixture: %s", fixture.Name)
		}
		t.Run(fixture.Name, func(t *testing.T) {
			for _, adapter := range adapterNames {
				t.Run(adapter, func(t *testing.T) {
					client, received := newWireTelemetryCollector(t)
					url := startEnforcementServer(t, adapter, enforcementOptions{
						telemetry: client, dryRun: fixture.Config.DryRun,
						applicationStatus: fixture.ApplicationStatus, disableRateLimit: true,
					})
					response, body := sendRequest(t, url+fixture.Request.Path, string(fixture.Request.Body), browserUA)
					if response.StatusCode != fixture.ApplicationStatus || response.Header.Get("X-Application-Reached") != "yes" {
						t.Fatalf("application outcome changed: %d %q", response.StatusCode, body)
					}
					if fixture.ExpectedUnchanged && body != string(fixture.Request.Body) {
						t.Fatalf("application input changed: %q", body)
					}
					select {
					case event := <-received:
						for field, want := range fixture.ExpectedEvent {
							if event[field] != want {
								t.Errorf("%s = %v, want %v", field, event[field], want)
							}
						}
						for _, field := range fixture.ExpectedAbsent {
							if value, ok := event[field]; ok {
								t.Errorf("unexpected %s = %v", field, value)
							}
						}
					case <-time.After(5 * time.Second):
						t.Fatal("no telemetry event received")
					}
				})
			}
		})
	}
	if matched == 0 {
		t.Fatal("no application-outcome fixtures loaded")
	}
}

// Keep the actual wire map so omission assertions do not reserialize an event
// and accidentally hide fields the SDK sent as empty strings or null.
func newWireTelemetryCollector(t *testing.T, configuration ...telemetry.Options) (*telemetry.Client, <-chan map[string]any) {
	t.Helper()
	received := make(chan map[string]any, 4)
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var batch struct{ Events []map[string]any }
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		for _, event := range batch.Events {
			select {
			case received <- event:
			default:
				t.Error("unexpected extra telemetry event")
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(collector.Close)
	options := telemetry.Options{}
	if len(configuration) > 0 {
		options = configuration[0]
	}
	options.Endpoint = collector.URL
	options.BatchSize = 1
	options.OnError = func(err error) { t.Errorf("telemetry delivery failed: %v", err) }
	client, err := telemetry.NewClient(options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := client.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	return client, received
}
