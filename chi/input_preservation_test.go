package chi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"testing"

	chirouter "github.com/go-chi/chi/v5"
)

type dryRunInputFixture struct {
	Name    string `json:"name"`
	Request struct {
		PathParam string            `json:"path_param"`
		Query     map[string]string `json:"query"`
		Headers   map[string]string `json:"headers"`
		Cookies   map[string]string `json:"cookies"`
		BodyRaw   string            `json:"body_raw"`
	} `json:"request"`
	ExpectedRequestUnchanged bool `json:"expected_request_unchanged"`
}

func loadDryRunInputFixtures(t *testing.T) []dryRunInputFixture {
	t.Helper()
	raw, err := os.ReadFile("../spec/TEST_VECTORS.json")
	if err != nil {
		t.Fatalf("read shared vectors: %v", err)
	}
	var vectors struct {
		DryRunInputPreservation struct {
			Cases []dryRunInputFixture `json:"cases"`
		} `json:"dry_run_input_preservation"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("decode shared vectors: %v", err)
	}
	if len(vectors.DryRunInputPreservation.Cases) == 0 {
		t.Fatal("shared dry-run input fixtures are empty")
	}
	return vectors.DryRunInputPreservation.Cases
}

func TestChiDryRunPreservesSharedInputFixtures(t *testing.T) {
	for _, fixture := range loadDryRunInputFixtures(t) {
		t.Run(fixture.Name, func(t *testing.T) {
			if !fixture.ExpectedRequestUnchanged {
				t.Fatal("fixture must require unchanged input")
			}

			cfg := DefaultConfig()
			cfg.RateLimit = false
			cfg.Bot = false
			cfg.Block = true
			cfg.DryRun = true

			type observedRequest struct {
				RawBody       []byte
				ParsedBody    any
				Query         url.Values
				PathParam     string
				FixtureHeader string
				Cookie        string
			}
			var observed observedRequest

			router := chirouter.NewRouter()
			router.Use(MiddlewareWithConfig(cfg))
			router.Post("/preserve/{fixtureID}", func(w http.ResponseWriter, r *http.Request) {
				observed.RawBody, _ = io.ReadAll(r.Body)
				_ = json.Unmarshal(observed.RawBody, &observed.ParsedBody)
				observed.Query = r.URL.Query()
				observed.PathParam = chirouter.URLParam(r, "fixtureID")
				observed.FixtureHeader = r.Header.Get("X-Arcis-Fixture")
				if cookie, err := r.Cookie("arcis_note"); err == nil {
					observed.Cookie = cookie.Value
				}
				w.WriteHeader(http.StatusNoContent)
			})
			t.Cleanup(Cleanup)

			query := url.Values{}
			for key, value := range fixture.Request.Query {
				query.Set(key, value)
			}
			target := "/preserve/" + url.PathEscape(fixture.Request.PathParam) + "?" + query.Encode()
			req := httptest.NewRequest(http.MethodPost, target, bytes.NewBufferString(fixture.Request.BodyRaw))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("User-Agent", "Mozilla/5.0")
			req.Header.Set("X-Arcis-Fixture", fixture.Request.Headers["x-arcis-fixture"])
			req.AddCookie(&http.Cookie{Name: "arcis_note", Value: fixture.Request.Cookies["arcis_note"]})
			response := httptest.NewRecorder()
			router.ServeHTTP(response, req)

			if response.Code != http.StatusNoContent {
				t.Fatalf("response code = %d, want 204", response.Code)
			}
			if !bytes.Equal(observed.RawBody, []byte(fixture.Request.BodyRaw)) {
				t.Errorf("raw body = %q, want exact %q", observed.RawBody, fixture.Request.BodyRaw)
			}
			var expectedParsed any
			if err := json.Unmarshal([]byte(fixture.Request.BodyRaw), &expectedParsed); err != nil {
				t.Fatalf("fixture body is invalid JSON: %v", err)
			}
			if !reflect.DeepEqual(observed.ParsedBody, expectedParsed) {
				t.Errorf("parsed body = %#v, want %#v", observed.ParsedBody, expectedParsed)
			}
			for key, value := range fixture.Request.Query {
				if observed.Query.Get(key) != value {
					t.Errorf("query %s = %q, want %q", key, observed.Query.Get(key), value)
				}
			}
			if observed.PathParam != fixture.Request.PathParam {
				t.Errorf("path param = %q, want %q", observed.PathParam, fixture.Request.PathParam)
			}
			if observed.FixtureHeader != fixture.Request.Headers["x-arcis-fixture"] {
				t.Errorf("fixture header = %q, want %q", observed.FixtureHeader, fixture.Request.Headers["x-arcis-fixture"])
			}
			if observed.Cookie != fixture.Request.Cookies["arcis_note"] {
				t.Errorf("cookie = %q, want %q", observed.Cookie, fixture.Request.Cookies["arcis_note"])
			}
		})
	}
}
