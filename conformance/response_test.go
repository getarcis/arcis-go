package conformance_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
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

const browserUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

func TestGinRealServerHeadersOnly(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(arcisgin.Headers())
	router.POST("/echo", func(c *gin.Context) {
		c.Header("X-Powered-By", "application-framework")
		c.Header("Server", "application-server")
		_, _ = c.Writer.WriteString("ok")
	})
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	response, body := sendRequest(t, server.URL+"/echo", `<script>literal text</script>`, browserUA)
	if response.StatusCode != http.StatusOK || body != "ok" {
		t.Fatalf("headers-only middleware interfered with application: %d %q", response.StatusCode, body)
	}
	assertSharedSecurityHeaders(t, response.Header)
}

func TestGinRealServerSecurityHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := arcisgin.DefaultConfig()
	cfg.Block = true
	router := gin.New()
	router.Use(arcisgin.MiddlewareWithConfig(cfg))
	router.POST("/echo", func(c *gin.Context) {
		c.Header("X-Powered-By", "application-framework")
		c.Header("Server", "application-server")
		c.String(http.StatusOK, "ok")
	})
	t.Cleanup(arcisgin.Cleanup)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	assertSecurityHeaderResponses(t, server.URL)
}

func TestEchoRealServerSecurityHeaders(t *testing.T) {
	cfg := arcisecho.DefaultConfig()
	cfg.Block = true
	app := echo.New()
	app.Use(arcisecho.MiddlewareWithConfig(cfg))
	app.POST("/echo", func(c echo.Context) error {
		c.Response().Header().Set("X-Powered-By", "application-framework")
		c.Response().Header().Set("Server", "application-server")
		return c.String(http.StatusOK, "ok")
	})
	t.Cleanup(arcisecho.Cleanup)
	server := httptest.NewServer(app)
	t.Cleanup(server.Close)
	assertSecurityHeaderResponses(t, server.URL)
}

func TestEchoRealServerHeadersOnly(t *testing.T) {
	app := echo.New()
	app.Use(arcisecho.Headers())
	app.POST("/echo", func(c echo.Context) error {
		c.Response().Header().Set("X-Powered-By", "application-framework")
		c.Response().Header().Set("Server", "application-server")
		return c.String(http.StatusOK, "ok")
	})
	server := httptest.NewServer(app)
	t.Cleanup(server.Close)
	response, body := sendRequest(t, server.URL+"/echo", `<script>literal text</script>`, browserUA)
	if response.StatusCode != http.StatusOK || body != "ok" {
		t.Fatalf("headers-only middleware interfered with application: %d %q", response.StatusCode, body)
	}
	assertSharedSecurityHeaders(t, response.Header)
}

func TestChiRealServerSecurityHeaders(t *testing.T) {
	cfg := arcischi.DefaultConfig()
	cfg.Block = true
	router := gochi.NewRouter()
	router.Use(arcischi.MiddlewareWithConfig(cfg))
	router.Post("/echo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "application-framework")
		w.Header().Set("Server", "application-server")
		_, _ = io.WriteString(w, "ok")
	})
	t.Cleanup(arcischi.Cleanup)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	assertSecurityHeaderResponses(t, server.URL)
}

func TestChiRealServerHeadersOnly(t *testing.T) {
	router := gochi.NewRouter()
	router.Use(arcischi.Headers())
	router.Post("/echo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "application-framework")
		w.Header().Set("Server", "application-server")
		_, _ = io.WriteString(w, "ok")
	})
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	response, body := sendRequest(t, server.URL+"/echo", `<script>literal text</script>`, browserUA)
	if response.StatusCode != http.StatusOK || body != "ok" {
		t.Fatalf("headers-only middleware interfered with application: %d %q", response.StatusCode, body)
	}
	assertSharedSecurityHeaders(t, response.Header)
}

func TestNetHTTPRealServerSecurityHeaders(t *testing.T) {
	cfg := archttp.DefaultConfig()
	cfg.Block = true
	mux := http.NewServeMux()
	mux.HandleFunc("POST /echo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "application-framework")
		w.Header().Set("Server", "application-server")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	})
	t.Cleanup(archttp.Cleanup)
	server := httptest.NewServer(archttp.MiddlewareWithConfig(cfg)(mux))
	t.Cleanup(server.Close)
	assertSecurityHeaderResponses(t, server.URL)
}

func TestFiberRealServerSecurityHeaders(t *testing.T) {
	cfg := arcisfiber.DefaultConfig()
	cfg.Block = true
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(arcisfiber.MiddlewareWithConfig(cfg))
	app.Post("/echo", func(c *fiber.Ctx) error {
		c.Set("X-Powered-By", "application-framework")
		c.Set("Server", "application-server")
		return c.SendString("ok")
	})
	t.Cleanup(arcisfiber.Cleanup)
	assertSecurityHeaderResponses(t, startFiberRealServer(t, app))
}

func assertSecurityHeaderResponses(t *testing.T, serverURL string) {
	t.Helper()
	for _, testCase := range []struct {
		name   string
		body   string
		status int
	}{
		{"allow", `{"name":"Alice"}`, http.StatusOK},
		{"deny", `{"q":"<script>alert(1)</script>"}`, http.StatusForbidden},
	} {
		t.Run("security_headers/"+testCase.name, func(t *testing.T) {
			response, _ := sendRequest(t, serverURL+"/echo", testCase.body, browserUA)
			if response.StatusCode != testCase.status {
				t.Fatalf("status = %d, want %d", response.StatusCode, testCase.status)
			}
			assertSharedSecurityHeaders(t, response.Header)
		})
	}
}

func sendRequest(t *testing.T, target, body, userAgent string) (*http.Response, string) {
	t.Helper()
	response, raw, err := exchangeRequest(target, body, userAgent)
	if err != nil {
		t.Fatalf("request did not complete: %v", err)
	}
	return response, raw
}

func exchangeRequest(target, body, userAgent string) (*http.Response, string, error) {
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(body))
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "en-US")
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		return response, "", err
	}
	return response, string(raw), nil
}

func assertSharedSecurityHeaders(t *testing.T, headers http.Header) {
	t.Helper()
	raw, err := os.ReadFile("../spec/TEST_VECTORS.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		SecurityHeaders struct {
			Required map[string]string `json:"required_headers_default"`
			Removed  []string          `json:"removed_headers"`
		} `json:"security_headers"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.SecurityHeaders.Required) == 0 || len(vectors.SecurityHeaders.Removed) == 0 {
		t.Fatal("security_headers fixture is empty")
	}
	for name, expected := range vectors.SecurityHeaders.Required {
		got := headers.Get(name)
		switch expected {
		case "must be set":
			if got == "" {
				t.Errorf("%s is missing", name)
			}
		case "must contain 'max-age='":
			if !strings.Contains(got, "max-age=") {
				t.Errorf("%s = %q, missing max-age", name, got)
			}
		default:
			if got != expected {
				t.Errorf("%s = %q, want %q", name, got, expected)
			}
		}
	}
	for _, name := range vectors.SecurityHeaders.Removed {
		if values := headers.Values(name); len(values) != 0 {
			t.Errorf("%s reached the wire: %q", name, values)
		}
	}
	if values := headers.Values("Server"); len(values) != 0 {
		t.Errorf("Server reached the wire: %q", values)
	}
}
