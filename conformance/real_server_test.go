package conformance_test

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	arcischi "github.com/getarcis/arcis-go/chi"
	arcisecho "github.com/getarcis/arcis-go/echo"
	arcisfiber "github.com/getarcis/arcis-go/fiber"
	arcisgin "github.com/getarcis/arcis-go/gin"
	archttp "github.com/getarcis/arcis-go/nethttp"
	"github.com/gin-gonic/gin"
	gochi "github.com/go-chi/chi/v5"
	"github.com/gofiber/fiber/v2"
	"github.com/labstack/echo/v4"
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

type observedRequest struct {
	BodyRaw   string            `json:"body_raw"`
	Body      any               `json:"body"`
	PathParam string            `json:"path_param"`
	Query     map[string]string `json:"query"`
	Headers   map[string]string `json:"headers"`
	Cookies   map[string]string `json:"cookies"`
}

func loadDryRunInputFixtures(t *testing.T) []dryRunInputFixture {
	t.Helper()

	raw, err := os.ReadFile("../spec/TEST_VECTORS.json")
	if err != nil {
		t.Fatalf("read shared fixtures: %v", err)
	}

	var vectors struct {
		DryRunInputPreservation struct {
			Cases []dryRunInputFixture `json:"cases"`
		} `json:"dry_run_input_preservation"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("decode shared fixtures: %v", err)
	}
	if len(vectors.DryRunInputPreservation.Cases) == 0 {
		t.Fatal("shared dry-run input fixtures are empty")
	}
	return vectors.DryRunInputPreservation.Cases
}

func TestGinRealServerPreservesSharedDryRunInputFixtures(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := arcisgin.DefaultConfig()
	cfg.Block = true
	cfg.DryRun = true

	router := gin.New()
	router.Use(arcisgin.MiddlewareWithConfig(cfg))
	router.POST("/preserve/*fixtureID", func(c *gin.Context) {
		raw, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		var parsed any
		if err := json.Unmarshal(raw, &parsed); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		query := make(map[string]string, len(c.Request.URL.Query()))
		for key := range c.Request.URL.Query() {
			query[key] = c.Query(key)
		}
		headers := map[string]string{
			"x-arcis-fixture": c.GetHeader("x-arcis-fixture"),
		}
		cookies := map[string]string{}
		if cookie, err := c.Cookie("arcis_note"); err == nil {
			cookies["arcis_note"] = cookie
		}

		c.JSON(http.StatusOK, observedRequest{
			BodyRaw:   string(raw),
			Body:      parsed,
			PathParam: strings.TrimPrefix(c.Param("fixtureID"), "/"),
			Query:     query,
			Headers:   headers,
			Cookies:   cookies,
		})
	})
	router.POST("/raw", func(c *gin.Context) {
		raw, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.Data(http.StatusOK, c.GetHeader("Content-Type"), raw)
	})

	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	t.Cleanup(arcisgin.Cleanup)
	assertSharedDryRunFixtures(t, server.URL)
	assertMalformedAndNonJSONBodiesPreserved(t, server.URL)
}

func TestEchoRealServerPreservesSharedDryRunInputFixtures(t *testing.T) {
	cfg := arcisecho.DefaultConfig()
	cfg.Block = true
	cfg.DryRun = true

	app := echo.New()
	app.Use(arcisecho.MiddlewareWithConfig(cfg))
	app.POST("/preserve/*", func(c echo.Context) error {
		raw, err := io.ReadAll(c.Request().Body)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}

		var parsed any
		if err := json.Unmarshal(raw, &parsed); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}

		query := make(map[string]string, len(c.QueryParams()))
		for key := range c.QueryParams() {
			query[key] = c.QueryParam(key)
		}
		headers := map[string]string{
			"x-arcis-fixture": c.Request().Header.Get("x-arcis-fixture"),
		}
		cookies := map[string]string{}
		if cookie, err := c.Cookie("arcis_note"); err == nil {
			cookies["arcis_note"] = cookie.Value
		}

		return c.JSON(http.StatusOK, observedRequest{
			BodyRaw:   string(raw),
			Body:      parsed,
			PathParam: c.Param("*"),
			Query:     query,
			Headers:   headers,
			Cookies:   cookies,
		})
	})
	app.POST("/raw", func(c echo.Context) error {
		raw, err := io.ReadAll(c.Request().Body)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return c.Blob(http.StatusOK, c.Request().Header.Get("Content-Type"), raw)
	})

	server := httptest.NewServer(app)
	t.Cleanup(server.Close)
	t.Cleanup(arcisecho.Cleanup)
	assertSharedDryRunFixtures(t, server.URL)
	assertMalformedAndNonJSONBodiesPreserved(t, server.URL)
}

func TestChiRealServerPreservesSharedDryRunInputFixtures(t *testing.T) {
	cfg := arcischi.DefaultConfig()
	cfg.Block = true
	cfg.DryRun = true

	router := gochi.NewRouter()
	router.Use(arcischi.MiddlewareWithConfig(cfg))
	router.Post("/preserve/*", func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var parsed any
		if err := json.Unmarshal(raw, &parsed); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		query := make(map[string]string, len(r.URL.Query()))
		for key := range r.URL.Query() {
			query[key] = r.URL.Query().Get(key)
		}
		headers := map[string]string{
			"x-arcis-fixture": r.Header.Get("x-arcis-fixture"),
		}
		cookies := map[string]string{}
		if cookie, err := r.Cookie("arcis_note"); err == nil {
			cookies["arcis_note"] = cookie.Value
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(observedRequest{
			BodyRaw:   string(raw),
			Body:      parsed,
			PathParam: gochi.URLParam(r, "*"),
			Query:     query,
			Headers:   headers,
			Cookies:   cookies,
		})
	})
	router.Post("/raw", func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(raw)
	})

	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	t.Cleanup(arcischi.Cleanup)
	assertSharedDryRunFixtures(t, server.URL)
	assertMalformedAndNonJSONBodiesPreserved(t, server.URL)
}

func TestNetHTTPRealServerPreservesSharedDryRunInputFixtures(t *testing.T) {
	cfg := archttp.DefaultConfig()
	cfg.Block = true
	cfg.DryRun = true

	mux := http.NewServeMux()
	mux.HandleFunc("POST /preserve/{fixtureID}", func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var parsed any
		if err := json.Unmarshal(raw, &parsed); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		query := make(map[string]string, len(r.URL.Query()))
		for key := range r.URL.Query() {
			query[key] = r.URL.Query().Get(key)
		}
		headers := map[string]string{
			"x-arcis-fixture": r.Header.Get("x-arcis-fixture"),
		}
		cookies := map[string]string{}
		if cookie, err := r.Cookie("arcis_note"); err == nil {
			cookies["arcis_note"] = cookie.Value
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(observedRequest{
			BodyRaw:   string(raw),
			Body:      parsed,
			PathParam: r.PathValue("fixtureID"),
			Query:     query,
			Headers:   headers,
			Cookies:   cookies,
		})
	})
	mux.HandleFunc("POST /raw", func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(raw)
	})

	server := httptest.NewServer(archttp.MiddlewareWithConfig(cfg)(mux))
	t.Cleanup(server.Close)
	t.Cleanup(archttp.Cleanup)
	assertSharedDryRunFixtures(t, server.URL)
	assertMalformedAndNonJSONBodiesPreserved(t, server.URL)
}

func TestFiberRealServerPreservesSharedDryRunInputFixtures(t *testing.T) {
	cfg := arcisfiber.DefaultConfig()
	cfg.Block = true
	cfg.DryRun = true

	controlURL := startFiberRealServer(t, newFiberObservationApp(nil))
	protectedURL := startFiberRealServer(t, newFiberObservationApp(&cfg))
	t.Cleanup(arcisfiber.Cleanup)

	for _, fixture := range loadDryRunInputFixtures(t) {
		t.Run(fixture.Name, func(t *testing.T) {
			control := observeSharedDryRunFixture(t, controlURL, fixture)
			observed := observeSharedDryRunFixture(t, protectedURL, fixture)
			if !reflect.DeepEqual(observed, control) {
				t.Errorf("Arcis changed Fiber application input\n got: %#v\nwant baseline: %#v", observed, control)
			}
			assertObservedMatchesFixture(t, observed, fixture, control.PathParam)
		})
	}
	assertMalformedAndNonJSONBodiesPreserved(t, protectedURL)
}

func newFiberObservationApp(cfg *arcisfiber.Config) *fiber.App {
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	if cfg != nil {
		app.Use(arcisfiber.MiddlewareWithConfig(*cfg))
	}
	app.Post("/preserve/*", func(c *fiber.Ctx) error {
		raw := append([]byte(nil), c.Body()...)

		var parsed any
		if err := json.Unmarshal(raw, &parsed); err != nil {
			return c.Status(http.StatusBadRequest).JSON(map[string]string{"error": err.Error()})
		}

		query := map[string]string{}
		c.Context().QueryArgs().VisitAll(func(key, value []byte) {
			query[string(key)] = string(value)
		})

		return c.Status(http.StatusOK).JSON(observedRequest{
			BodyRaw:   string(raw),
			Body:      parsed,
			PathParam: c.Params("*"),
			Query:     query,
			Headers: map[string]string{
				"x-arcis-fixture": c.Get("x-arcis-fixture"),
			},
			Cookies: map[string]string{
				"arcis_note": c.Cookies("arcis_note"),
			},
		})
	})
	app.Post("/raw", func(c *fiber.Ctx) error {
		raw := append([]byte(nil), c.Body()...)
		c.Set("Content-Type", c.Get("Content-Type"))
		return c.Status(http.StatusOK).Send(raw)
	})
	return app
}

func startFiberRealServer(t *testing.T, app *fiber.App) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	serveResult := make(chan error, 1)
	go func() {
		serveResult <- app.Listener(listener)
	}()
	t.Cleanup(func() {
		if err := app.Shutdown(); err != nil {
			t.Errorf("shutdown Fiber server: %v", err)
		}
		select {
		case err := <-serveResult:
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Errorf("Fiber listener returned: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("Fiber listener did not stop after shutdown")
		}
	})
	return "http://" + listener.Addr().String()
}

func assertSharedDryRunFixtures(t *testing.T, serverURL string) {
	t.Helper()
	for _, fixture := range loadDryRunInputFixtures(t) {
		t.Run(fixture.Name, func(t *testing.T) {
			observed := observeSharedDryRunFixture(t, serverURL, fixture)
			assertObservedMatchesFixture(t, observed, fixture, fixture.Request.PathParam)
		})
	}
}

func observeSharedDryRunFixture(t *testing.T, serverURL string, fixture dryRunInputFixture) observedRequest {
	t.Helper()
	if !fixture.ExpectedRequestUnchanged {
		t.Fatal("fixture must require unchanged request input")
	}

	query := url.Values{}
	for key, value := range fixture.Request.Query {
		query.Set(key, value)
	}
	target := serverURL + "/preserve/" + url.PathEscape(fixture.Request.PathParam) + "?" + query.Encode()
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(fixture.Request.BodyRaw))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for key, value := range fixture.Request.Headers {
		req.Header.Set(key, value)
	}
	for name, value := range fixture.Request.Cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}

	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Do(req)
	if err != nil {
		t.Fatalf("send request: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		responseBody, _ := io.ReadAll(response.Body)
		t.Fatalf("status = %d, want 200; body=%s", response.StatusCode, responseBody)
	}

	var observed observedRequest
	if err := json.NewDecoder(response.Body).Decode(&observed); err != nil {
		t.Fatalf("decode application response: %v", err)
	}
	return observed
}

func assertObservedMatchesFixture(
	t *testing.T,
	observed observedRequest,
	fixture dryRunInputFixture,
	expectedPathParam string,
) {
	t.Helper()
	var expectedBody any
	if err := json.Unmarshal([]byte(fixture.Request.BodyRaw), &expectedBody); err != nil {
		t.Fatalf("fixture body is invalid JSON: %v", err)
	}

	if observed.BodyRaw != fixture.Request.BodyRaw {
		t.Errorf("raw body changed\n got: %q\nwant: %q", observed.BodyRaw, fixture.Request.BodyRaw)
	}
	if !reflect.DeepEqual(observed.Body, expectedBody) {
		t.Errorf("parsed body changed\n got: %#v\nwant: %#v", observed.Body, expectedBody)
	}
	if observed.PathParam != expectedPathParam {
		t.Errorf("path param = %q, want %q", observed.PathParam, expectedPathParam)
	}
	if !reflect.DeepEqual(observed.Query, fixture.Request.Query) {
		t.Errorf("query changed\n got: %#v\nwant: %#v", observed.Query, fixture.Request.Query)
	}
	if !reflect.DeepEqual(observed.Headers, fixture.Request.Headers) {
		t.Errorf("headers changed\n got: %#v\nwant: %#v", observed.Headers, fixture.Request.Headers)
	}
	if !reflect.DeepEqual(observed.Cookies, fixture.Request.Cookies) {
		t.Errorf("cookies changed\n got: %#v\nwant: %#v", observed.Cookies, fixture.Request.Cookies)
	}
}

func assertMalformedAndNonJSONBodiesPreserved(t *testing.T, serverURL string) {
	t.Helper()
	testCases := []struct {
		name        string
		contentType string
		body        string
	}{
		{name: "malformed_json", contentType: "application/json", body: `{not json`},
		{name: "non_json_free_text", contentType: "text/plain; charset=utf-8", body: "Customer's note -- docs/../README.md; crème brûlée"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, serverURL+"/raw", strings.NewReader(testCase.body))
			if err != nil {
				t.Fatalf("create request: %v", err)
			}
			req.Header.Set("Content-Type", testCase.contentType)
			client := &http.Client{Timeout: 5 * time.Second}
			response, err := client.Do(req)
			if err != nil {
				t.Fatalf("send request: %v", err)
			}
			defer response.Body.Close()
			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			if response.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", response.StatusCode, raw)
			}
			if string(raw) != testCase.body {
				t.Errorf("application body changed\n got: %q\nwant: %q", raw, testCase.body)
			}
		})
	}
}
