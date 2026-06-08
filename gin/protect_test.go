package gin

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	arcis "github.com/getarcis/arcis-go"
)

func init() { gin.SetMode(gin.TestMode) }

// protectApp builds a Gin router that mounts ProtectLogin on /login with
// the supplied window and echoes the request body back from the handler so
// tests can confirm the body survived the factory's read.
func protectApp(win *arcis.CorrelationWindow) *gin.Engine {
	r := gin.New()
	opts := ProtectOptions{Window: win}
	r.POST("/login", ProtectLogin(opts), func(c *gin.Context) {
		var body map[string]interface{}
		_ = c.ShouldBindJSON(&body)
		c.JSON(http.StatusOK, gin.H{"received": body})
	})
	return r
}

func TestProtectLogin_LegitRequestPasses(t *testing.T) {
	win := arcis.NewCorrelationWindow(arcis.NewCorrelationWindowOptions())
	r := protectApp(win)

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{"username":"alice"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.10:1234"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}
}

func TestProtectLogin_BodyReadableDownstream(t *testing.T) {
	win := arcis.NewCorrelationWindow(arcis.NewCorrelationWindowOptions())
	r := protectApp(win)

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{"username":"bob","extra":"value"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.11:1234"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp struct {
		Received map[string]interface{} `json:"received"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if resp.Received["username"] != "bob" || resp.Received["extra"] != "value" {
		t.Fatalf("downstream handler did not see the body: %#v", resp.Received)
	}
}

func TestProtectLogin_TripsCredentialStuffing(t *testing.T) {
	win := arcis.NewCorrelationWindow(arcis.NewCorrelationWindowOptions())
	r := protectApp(win)

	// Default threshold: 10 distinct usernames at the same route from the
	// same IP trips credential-stuffing. Fire 9 distinct usernames; all
	// should pass.
	for i := 0; i < 9; i++ {
		body := fmt.Sprintf(`{"username":"user%d"}`, i)
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "198.51.100.5:5555"
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d (body=%s)", i, w.Code, w.Body.String())
		}
	}

	// The 10th distinct username crosses the threshold and trips the block.
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{"username":"user9"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100.5:5555"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on credential-stuffing trip, got %d (body=%s)", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if resp["credential_stuffing"] != true {
		t.Errorf("expected credential_stuffing=true, got %v", resp["credential_stuffing"])
	}
}

func TestProtectLogin_HonorsXForwardedFor(t *testing.T) {
	win := arcis.NewCorrelationWindow(arcis.NewCorrelationWindowOptions())
	// gin trusts proxies by default; the protect helper reads the first XFF
	// hop directly so the correlation key is the spoofed-but-recorded
	// client IP. Fire 10 distinct usernames all sharing one XFF first hop
	// but different RemoteAddr; they must aggregate on the XFF IP and trip.
	r := gin.New()
	r.POST("/login", ProtectLogin(ProtectOptions{Window: win}), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ip": protectClientIP(c)})
	})

	var lastCode int
	var lastBody string
	for i := 0; i < 10; i++ {
		body := fmt.Sprintf(`{"username":"cred%d"}`, i)
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", "192.0.2.55, 10.0.0.1")
		req.RemoteAddr = fmt.Sprintf("10.0.0.%d:9000", i+2)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		lastCode = w.Code
		lastBody = w.Body.String()
	}

	if lastCode != http.StatusTooManyRequests {
		t.Fatalf("expected XFF-aggregated requests to trip 429, got %d (body=%s)", lastCode, lastBody)
	}
}

func TestProtectClientIP_FirstHop(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-For", "192.0.2.7, 10.0.0.1")
	r.RemoteAddr = "10.0.0.9:1234"
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = r
	if got := protectClientIP(c); got != "192.0.2.7" {
		t.Fatalf("expected first XFF hop 192.0.2.7, got %q", got)
	}
}

func TestProtectApi_NilWindowPassThrough(t *testing.T) {
	// No window: factory must be a pass-through (never blocks).
	r := gin.New()
	r.POST("/api", ProtectApi(ProtectOptions{}), func(c *gin.Context) {
		body, _ := io.ReadAll(c.Request.Body)
		c.JSON(http.StatusOK, gin.H{"len": len(body)})
	})

	req := httptest.NewRequest(http.MethodPost, "/api", strings.NewReader(`{"username":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected pass-through 200, got %d", w.Code)
	}
}
