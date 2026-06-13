package echo

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	arcis "github.com/getarcis/arcis-go"
)

func TestBruteForce_EchoDeniesAfterExhaustion(t *testing.T) {
	bf := arcis.NewBruteForce(arcis.BruteForceConfig{
		FastPoints: 2, SlowPoints: 100, FastDuration: time.Hour, SlowDuration: time.Hour,
	})
	defer bf.Close()

	e := echo.New()
	e.GET("/login", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]bool{"ok": true})
	}, BruteForce(bf))

	for i := 1; i <= 2; i++ {
		w := httptest.NewRecorder()
		e.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/login", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("attempt %d should pass, got %d", i, w.Code)
		}
	}
	w := httptest.NewRecorder()
	e.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/login", nil))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after the fast budget is exhausted, got %d", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("expected a Retry-After header on the 429")
	}
}

func TestOverload_EchoPassesWhenHealthy(t *testing.T) {
	ol := arcis.NewOverload(arcis.OverloadConfig{MaxLagMs: 500, SampleInterval: time.Hour})
	defer ol.Close()

	e := echo.New()
	e.Use(Overload(ol))
	e.GET("/", func(c echo.Context) error { return c.JSON(http.StatusOK, map[string]bool{"ok": true}) })

	w := httptest.NewRecorder()
	e.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("a healthy server (0 lag) should pass, got %d", w.Code)
	}
}
