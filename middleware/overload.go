package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// overload.go — runtime-overload protection, ported from the Node SDK's
// middleware/overload.ts for cross-SDK parity.
//
// Rate limiting caps per-client load; this caps TOTAL server load by sampling
// scheduler latency and shedding new requests with 503 when the runtime is
// saturated. The Node version measures event-loop lag; the Go analog measures
// how late a fixed-interval ticker fires. Under heavy CPU load (or long GC
// pauses) the goroutine running the ticker is scheduled late, so the elapsed
// time exceeds the interval — that excess IS the lag. An exponential moving
// average smooths single-sample spikes so one GC pause does not shed every
// request for a full sample window.

// OverloadConfig configures the overload protector. Zero values fall back to
// the documented defaults; invalid values are clamped to defaults rather than
// panicking at boot.
type OverloadConfig struct {
	MaxLagMs          float64       // smoothed lag (ms) above which requests get 503 (default 500)
	SampleInterval    time.Duration // sampling cadence (default 250ms)
	StatusCode        int           // status when overloaded (default 503)
	Message           string        // response message when overloaded
	RetryAfterSeconds int           // Retry-After header value (default 5)
	Alpha             float64       // EMA factor for the new sample, in (0,1] (default 0.3)
	ExposeLagHeader   bool          // when true, every response gets X-EventLoop-Lag
}

// Overload samples runtime scheduler lag and reports saturation.
type Overload struct {
	cfg      OverloadConfig
	mu       sync.RWMutex
	smoothed float64
	ctx      context.Context
	cancel   context.CancelFunc
}

// NewOverload builds an overload protector, applying defaults/clamps and
// starting the sampler goroutine (stopped via Close).
func NewOverload(cfg OverloadConfig) *Overload {
	if cfg.MaxLagMs <= 0 {
		cfg.MaxLagMs = 500
	}
	if cfg.SampleInterval <= 0 {
		cfg.SampleInterval = 250 * time.Millisecond
	}
	if cfg.StatusCode == 0 {
		cfg.StatusCode = http.StatusServiceUnavailable
	}
	if cfg.Message == "" {
		cfg.Message = "Server overloaded, please retry"
	}
	if cfg.RetryAfterSeconds <= 0 {
		cfg.RetryAfterSeconds = 5
	}
	if cfg.Alpha <= 0 || cfg.Alpha > 1 {
		cfg.Alpha = 0.3
	}

	ctx, cancel := context.WithCancel(context.Background())
	o := &Overload{cfg: cfg, ctx: ctx, cancel: cancel}
	go o.sample()
	return o
}

func (o *Overload) sample() {
	ticker := time.NewTicker(o.cfg.SampleInterval)
	defer ticker.Stop()
	last := time.Now()
	for {
		select {
		case <-o.ctx.Done():
			return
		case now := <-ticker.C:
			elapsed := now.Sub(last)
			measured := elapsed - o.cfg.SampleInterval
			if measured < 0 {
				measured = 0
			}
			measuredMs := float64(measured.Microseconds()) / 1000.0
			o.mu.Lock()
			o.smoothed = emaStep(o.smoothed, measuredMs, o.cfg.Alpha)
			o.mu.Unlock()
			last = now
		}
	}
}

// CurrentLagMs returns the current smoothed scheduler lag in milliseconds.
func (o *Overload) CurrentLagMs() float64 {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.smoothed
}

// Overloaded reports whether smoothed lag currently exceeds the threshold.
func (o *Overload) Overloaded() bool {
	return o.CurrentLagMs() > o.cfg.MaxLagMs
}

// Handler wraps next, shedding requests with the configured status + Retry-After
// while the runtime is overloaded.
func (o *Overload) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o.cfg.ExposeLagHeader {
			w.Header().Set("X-EventLoop-Lag", strconv.Itoa(int(o.CurrentLagMs()+0.5)))
		}
		if o.Overloaded() {
			w.Header().Set("Retry-After", strconv.Itoa(o.cfg.RetryAfterSeconds))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(o.cfg.StatusCode)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error":      o.cfg.Message,
				"retryAfter": o.cfg.RetryAfterSeconds,
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// StatusCode returns the resolved status used when shedding load. Framework
// adapters use it to render the deny response.
func (o *Overload) StatusCode() int { return o.cfg.StatusCode }

// Message returns the resolved overload message.
func (o *Overload) Message() string { return o.cfg.Message }

// RetryAfterSeconds returns the resolved Retry-After value.
func (o *Overload) RetryAfterSeconds() int { return o.cfg.RetryAfterSeconds }

// ExposeLagHeaderEnabled reports whether the X-EventLoop-Lag header is emitted.
func (o *Overload) ExposeLagHeaderEnabled() bool { return o.cfg.ExposeLagHeader }

// Close stops the sampler goroutine.
func (o *Overload) Close() {
	o.cancel()
}

// emaStep computes one exponential-moving-average step:
// smoothed = (1-alpha)*prior + alpha*measured. Kept as a pure function so the
// smoothing math is unit-testable without spinning real timers.
func emaStep(prior, measured, alpha float64) float64 {
	return (1-alpha)*prior + alpha*measured
}
