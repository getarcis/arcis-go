package conformance_test

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestRealServerSharedFindingAttribution(t *testing.T) {
	var vectors struct {
		Telemetry struct {
			FindingAttribution struct {
				Cases []struct {
					Name   string
					Config struct {
						RateLimit        bool
						Block            bool
						ForwardedHeaders struct{ TrustedHosts []string }
					}
					Request struct {
						Method, Path string
						Headers      map[string]string
						Body         json.RawMessage
					}
					ExpectedFinding map[string]any `json:"expected_finding"`
				}
			} `json:"finding_attribution"`
		}
	}
	raw, err := os.ReadFile("../spec/TEST_VECTORS.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Telemetry.FindingAttribution.Cases) == 0 {
		t.Fatal("no finding-attribution fixtures loaded")
	}
	for _, fixture := range vectors.Telemetry.FindingAttribution.Cases {
		if fixture.Request.Method != "POST" || !fixture.Config.Block || fixture.Config.RateLimit {
			t.Fatalf("unsupported finding-attribution configuration: %s", fixture.Name)
		}
		t.Run(fixture.Name, func(t *testing.T) {
			for _, adapter := range adapterNames {
				t.Run(adapter, func(t *testing.T) {
					for _, mode := range []struct {
						name     string
						dryRun   bool
						decision string
						status   int
					}{
						{"enforce", false, "deny", 403},
						{"observe", true, "would_deny", 200},
					} {
						t.Run(mode.name, func(t *testing.T) {
							client, received := newWireTelemetryCollector(t)
							url := startEnforcementServer(t, adapter, enforcementOptions{
								telemetry: client, dryRun: mode.dryRun, disableRateLimit: true,
								applicationPath: fixture.Request.Path, trustedHosts: fixture.Config.ForwardedHeaders.TrustedHosts,
							})
							request, err := http.NewRequest(fixture.Request.Method, url+fixture.Request.Path, strings.NewReader(string(fixture.Request.Body)))
							if err != nil {
								t.Fatal(err)
							}
							request.Header.Set("Content-Type", "application/json")
							request.Header.Set("User-Agent", browserUA)
							for key, value := range fixture.Request.Headers {
								request.Header.Set(key, value)
							}
							httpClient := &http.Client{Timeout: 5 * time.Second}
							response, err := httpClient.Do(request)
							if err != nil {
								t.Fatal(err)
							}
							defer response.Body.Close()
							body, err := io.ReadAll(response.Body)
							if err != nil {
								t.Fatal(err)
							}
							if response.StatusCode != mode.status {
								t.Fatalf("status = %d, want %d; %s", response.StatusCode, mode.status, body)
							}
							if mode.dryRun && string(body) != string(fixture.Request.Body) {
								t.Errorf("observed input changed: %s", body)
							}
							if !mode.dryRun && response.Header.Get("X-Application-Reached") != "" {
								t.Error("blocked request reached application")
							}
							select {
							case event := <-received:
								if event["status"] != float64(mode.status) || event["decision"] != mode.decision {
									t.Errorf("incorrect decision/outcome: %v", event)
								}
								for field, want := range fixture.ExpectedFinding {
									if event[field] != want {
										t.Errorf("%s = %v, want %v", field, event[field], want)
									}
								}
							case <-time.After(5 * time.Second):
								t.Fatal("no telemetry event received")
							}
						})
					}
				})
			}
		})
	}
}
