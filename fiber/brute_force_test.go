package fiber_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"

	arcis "github.com/getarcis/arcis-go"
	arcisfiber "github.com/getarcis/arcis-go/fiber"
)

func TestBruteForce_FiberDeniesAfterExhaustion(t *testing.T) {
	bf := arcis.NewBruteForce(arcis.BruteForceConfig{
		FastPoints: 2, SlowPoints: 100, FastDuration: time.Hour, SlowDuration: time.Hour,
	})
	defer bf.Close()

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Get("/login", arcisfiber.BruteForce(bf), func(c *fiber.Ctx) error {
		return c.SendString("ok")
	})

	for i := 1; i <= 2; i++ {
		res, err := app.Test(httptest.NewRequest(http.MethodGet, "/login", nil), -1)
		if err != nil {
			t.Fatalf("app.Test: %v", err)
		}
		if res.StatusCode != http.StatusOK {
			t.Fatalf("attempt %d should pass, got %d", i, res.StatusCode)
		}
	}
	res, err := app.Test(httptest.NewRequest(http.MethodGet, "/login", nil), -1)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after the fast budget is exhausted, got %d", res.StatusCode)
	}
	if res.Header.Get("Retry-After") == "" {
		t.Error("expected a Retry-After header on the 429")
	}
}

func TestOverload_FiberPassesWhenHealthy(t *testing.T) {
	ol := arcis.NewOverload(arcis.OverloadConfig{MaxLagMs: 500, SampleInterval: time.Hour})
	defer ol.Close()

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(arcisfiber.Overload(ol))
	app.Get("/", func(c *fiber.Ctx) error { return c.SendString("ok") })

	res, err := app.Test(httptest.NewRequest(http.MethodGet, "/", nil), -1)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("a healthy server (0 lag) should pass, got %d", res.StatusCode)
	}
}
