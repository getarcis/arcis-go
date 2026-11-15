package conformance_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/getarcis/arcis-go/telemetry"
)

func TestManualEventPrivacy(t *testing.T) {
	for _, decision := range []telemetry.Decision{
		telemetry.DecisionAllow, telemetry.DecisionDeny,
		telemetry.DecisionChallenge, telemetry.DecisionWouldDeny,
	} {
		t.Run(string(decision), func(t *testing.T) {
			client, received := newWireTelemetryCollector(t)
			original := telemetry.Event{
				IP: "forwarded-secret-201", Method: "POST", Path: "/reset/path-secret-201",
				Decision: decision, Status: 422, Vector: "xss", Rule: "xss/match", Severity: telemetry.SeverityHigh,
				MatchedPattern: "body-secret-201", Reason: "body-secret-201", UserAgent: "ua-secret-201",
				RouteID: "route-secret-201", PolicyID: "policy-secret-201", SDK: "node",
			}
			client.Send(original)
			if original.Path != "/reset/path-secret-201" || original.MatchedPattern != "body-secret-201" {
				t.Fatal("caller event changed")
			}
			original.Rule = "changed-after-record"
			select {
			case event := <-received:
				if event["ip"] != "0.0.0.0" || event["path"] != "[redacted]" {
					t.Errorf("request identifiers leaked: %v", event)
				}
				if event["rule"] != "xss/match" || event["vector"] != "xss" || event["severity"] != "high" ||
					event["decision"] != string(decision) || event["status"] != float64(422) {
					t.Errorf("metadata changed: %v", event)
				}
				wire, err := json.Marshal(event)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(wire), "secret-201") {
					t.Fatal("secret in payload")
				}
				if event["sdk"] != "go" || event["schemaVersion"] != "1.1" {
					t.Error("missing producer identity")
				}
				for _, field := range []string{"routeId", "policyId"} {
					if _, ok := event[field]; ok {
						t.Errorf("unconfigured label: %s", field)
					}
				}
				for _, field := range []string{"matchedPattern", "reason", "userAgent"} {
					if _, ok := event[field]; ok {
						t.Errorf("private field: %s", field)
					}
				}
			case <-time.After(5 * time.Second):
				t.Fatal("no event")
			}
		})
	}
}

func TestTelemetryRejectsInvalidLabels(t *testing.T) {
	var vectors struct {
		Telemetry struct {
			Privacy struct {
				InvalidLabels []string `json:"invalid_labels"`
			}
		}
	}
	raw, err := os.ReadFile("../spec/TEST_VECTORS.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Telemetry.Privacy.InvalidLabels) == 0 {
		t.Fatal("missing label fixtures")
	}
	for _, label := range vectors.Telemetry.Privacy.InvalidLabels {
		for _, field := range []string{"RouteID", "PolicyID"} {
			t.Run(field+"/"+label, func(t *testing.T) {
				opts := telemetry.Options{Endpoint: "http://127.0.0.1/v1/events"}
				if field == "RouteID" {
					opts.RouteID = label
				} else {
					opts.PolicyID = label
				}
				client, err := telemetry.NewClient(opts)
				if client != nil {
					_ = client.Close(context.Background())
				}
				if err == nil || err.Error() != "telemetry: invalid "+field {
					t.Errorf("expected label error, got %v", err)
				}
			})
		}
	}
}

func TestRealServerTelemetryPrivacy(t *testing.T) {
	var vectors struct {
		Telemetry struct {
			Privacy struct {
				Metadata struct {
					Config   struct{ RouteID, PolicyID string }
					Expected map[string]any
				}
				ExpectedPath string   `json:"expected_path"`
				AbsentFields []string `json:"absent_fields"`
				Cases        []struct {
					Name    string
					Request struct {
						Method, Path string
						Headers      map[string]string
						Body         json.RawMessage
					}
					ForbiddenValues []string       `json:"forbidden_values"`
					ExpectedFinding map[string]any `json:"expected_finding"`
				}
			}
		}
	}
	raw, err := os.ReadFile("../spec/TEST_VECTORS.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Telemetry.Privacy.Cases) == 0 {
		t.Fatal("missing privacy fixtures")
	}
	for _, fixture := range vectors.Telemetry.Privacy.Cases {
		t.Run(fixture.Name, func(t *testing.T) {
			for _, adapter := range adapterNames {
				t.Run(adapter, func(t *testing.T) {
					for _, dryRun := range []bool{false, true} {
						name, decision, status := "enforce", "deny", 403
						if dryRun {
							name, decision, status = "observe", "would_deny", 200
						}
						t.Run(name, func(t *testing.T) {
							metadata := vectors.Telemetry.Privacy.Metadata
							collector, received := newWireTelemetryCollector(t, telemetry.Options{
								RouteID: metadata.Config.RouteID, PolicyID: metadata.Config.PolicyID,
							})
							requestURL, err := url.Parse(fixture.Request.Path)
							if err != nil {
								t.Fatal(err)
							}
							serverURL := startEnforcementServer(t, adapter, enforcementOptions{
								telemetry: collector, dryRun: dryRun, disableRateLimit: true,
								applicationPath: requestURL.Path,
							})
							req, err := http.NewRequest(fixture.Request.Method, serverURL+fixture.Request.Path, strings.NewReader(string(fixture.Request.Body)))
							if err != nil {
								t.Fatal(err)
							}
							req.Header.Set("Content-Type", "application/json")
							for key, value := range fixture.Request.Headers {
								req.Header.Set(key, value)
							}
							resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
							if err != nil {
								t.Fatal(err)
							}
							defer resp.Body.Close()
							body, err := io.ReadAll(resp.Body)
							if err != nil {
								t.Fatal(err)
							}
							if resp.StatusCode != status {
								t.Fatalf("status = %d, want %d: %s", resp.StatusCode, status, body)
							}
							if dryRun && string(body) != string(fixture.Request.Body) {
								t.Fatal("observed input changed")
							}
							select {
							case event := <-received:
								if event["sdk"] != "go" {
									t.Errorf("sdk = %v", event["sdk"])
								}
								for field, want := range metadata.Expected {
									if event[field] != want {
										t.Errorf("%s = %v, want %v", field, event[field], want)
									}
								}
								if event["path"] != vectors.Telemetry.Privacy.ExpectedPath {
									t.Errorf("unredacted path: %v", event["path"])
								}
								if event["decision"] != decision || event["status"] != float64(status) {
									t.Errorf("decision/outcome changed: %v", event)
								}
								for field, want := range fixture.ExpectedFinding {
									if event[field] != want {
										t.Errorf("%s = %v, want %v", field, event[field], want)
									}
								}
								for _, field := range vectors.Telemetry.Privacy.AbsentFields {
									if _, ok := event[field]; ok {
										t.Errorf("private field emitted: %s", field)
									}
								}
								wire, err := json.Marshal(event)
								if err != nil {
									t.Fatal(err)
								}
								for _, secret := range fixture.ForbiddenValues {
									if strings.Contains(string(wire), secret) {
										t.Errorf("request secret emitted: %s", secret)
									}
								}
							case <-time.After(5 * time.Second):
								t.Fatal("no telemetry received")
							}
						})
					}
				})
			}
		})
	}
}
