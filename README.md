# Arcis Go SDK

Security middleware for Go web applications, developed against a shared policy and conformance target with the Node and Python SDKs. The core is stdlib-only. Adapters for Gin, Echo, chi, Fiber, and net/http each import only their own router (chi works with any router that accepts a stdlib `func(http.Handler) http.Handler`; the `nethttp` re-export covers users without a third-party router).

Arcis detects and sanitizes XSS, SQL injection, NoSQL injection, path traversal, command injection, prototype pollution, SSTI, XXE, LDAP injection, XPath injection, and header injection.

```bash
go get github.com/getarcis/arcis-go@latest
```

## Protection

By default (`Block: false`) the middleware exposes a `*Sanitizer` in the request context so handlers can sanitize on demand. With `Block: true`, it scans every request body, query string, and URL path and returns `403` before the handler runs when an attack pattern is detected. The response includes the matched vector:

```json
{
  "error": "Request blocked for security reasons",
  "code": "SECURITY_THREAT",
  "vector": "xss"
}
```

The default request path covers XSS, SQL, NoSQL, path traversal, command injection, SSTI, XXE, LDAP, XPath, header injection, and prototype pollution. On top of that, the default middleware also runs:

- **Bot detection** against an 8-category corpus (695 patterns). Headless browser automation and offensive scanners (sqlmap, nikto, nuclei, nmap, masscan, wpscan, and similar) are blocked by default. Generic non-browser clients such as curl, wget, python-requests, and monitoring agents are classified as scrapers and allowed by default, so health checks and server-to-server traffic keep working.
- **Scanner-path and per-IP correlation** tracking, **GraphQL** abuse limits, **mass-assignment** detection, **SSRF** checks on URL body fields, and **prompt-injection** screening.

Each layer can be disabled through its config option. The request body is read once and restored, so handlers can re-bind it without parser issues.

## Safe dry-run rollout

```go
cfg := arcisgin.DefaultConfig()
cfg.Block = true
cfg.DryRun = true
cfg.Telemetry = tc
r.Use(arcisgin.MiddlewareWithConfig(cfg))
```

`DryRun: true` takes precedence over configured bundle enforcement. Arcis
continues evaluating cached IP reputation, forwarded headers, scanner paths,
bots, rate limits, request-body detectors, and block-mode threat patterns, but
it does not return an Arcis `403` or `429`. Request body bytes, parsed values,
query values, route parameters, headers, and cookies remain unchanged. A
request that would have been rejected is emitted as telemetry decision
`would_deny` with the application's response status. Response security headers
may still be added.

## Adapter capability matrix

`MiddlewareWithConfig` is the full bundled request pipeline. A full bundle
includes request detection, dry-run and blocking decisions, bot and rate
controls, response security headers, telemetry, and request-body restoration.

| Adapter | Full bundle | Shared dry-run fixtures | Real-server smoke suite | Granular helper surface | Limitation or framework behavior |
| --- | --- | --- | --- | --- | --- |
| Gin | Yes | Yes | Yes | Full | Gin-native `gin.HandlerFunc` middleware. |
| Echo | Yes | Yes | Yes | Full | Echo-native `echo.MiddlewareFunc` middleware. |
| Chi | Yes | Yes | Yes | Full | Runtime middleware is stdlib-compatible and does not require Chi. |
| Fiber | Yes | Yes | Yes | Narrower | Exposes bundle, rate, brute-force, overload, protection, and sanitizer lookup helpers. Fiber leaves wildcard route parameters percent-encoded unless the application enables `fiber.Config.UnescapePath`; Arcis preserves the framework value. |
| net/http | Yes | Yes | Yes | Narrower re-export | Exposes bundle, rate, protection, and sanitizer lookup helpers. Import the stdlib-compatible Chi package for granular headers, sanitizer, validation, CSRF, cookie, CORS, and error middleware. |

The real-server suite sends the shared invoice, Unicode catalog, URL, and
free-text fixtures through actual loopback listeners. It also checks attack
enforcement, bot and rate-limit allow/deny paths, unchanged bodies in enforcing
and dry-run modes, headers against shared fixtures, concurrent limiter and
telemetry decisions, and repeated cleanup. Gin, Echo, and Chi have additional
standalone-header coverage; Chi also has streaming, connection-upgrade, and
HTTP/2 response-control checks. See [conformance evidence](CONFORMANCE.md) for
the test map, reproduction commands, and limitations. These smoke tests do not
establish exhaustive protection coverage or feature parity with other tools.

## Quick start (Gin)

```go
import (
    "github.com/gin-gonic/gin"
    arcisgin "github.com/getarcis/arcis-go/gin"
)

func main() {
    r := gin.Default()
    cfg := arcisgin.DefaultConfig()
    cfg.Block = true // 403 on attack payloads (opt-in)
    r.Use(arcisgin.MiddlewareWithConfig(cfg))
    r.GET("/", handler)
    r.Run(":8080")
}
```

## Quick start (chi)

```go
import (
    "net/http"

    "github.com/go-chi/chi/v5"
    arcischi "github.com/getarcis/arcis-go/chi"
)

func main() {
    r := chi.NewRouter()
    cfg := arcischi.DefaultConfig()
    cfg.Block = true
    r.Use(arcischi.MiddlewareWithConfig(cfg))
    r.Get("/", handler)
    http.ListenAndServe(":8080", r)
}
```

The chi adapter is stdlib-only at runtime; `chi/v5` is required only in test builds. Its middleware is the standard `func(next http.Handler) http.Handler`, so it composes with any router that accepts stdlib middleware (gorilla/mux, plain `net/http`, and others).

## Quick start (Fiber)

```go
import (
    "github.com/gofiber/fiber/v2"
    arcisfiber "github.com/getarcis/arcis-go/fiber"
)

func main() {
    app := fiber.New()
    cfg := arcisfiber.DefaultConfig()
    cfg.Block = true
    app.Use(arcisfiber.MiddlewareWithConfig(cfg))
    app.Get("/", handler)
    app.Listen(":8080")
}
```

## Quick start (Echo)

```go
import (
    "github.com/labstack/echo/v4"
    arcisecho "github.com/getarcis/arcis-go/echo"
)

func main() {
    e := echo.New()
    cfg := arcisecho.DefaultConfig()
    cfg.Block = true
    e.Use(arcisecho.MiddlewareWithConfig(cfg))
    e.GET("/", handler)
    e.Start(":8080")
}
```

## Quick start (plain net/http)

For users without a third-party router, the `nethttp` subpackage exposes the same middleware as a `func(http.Handler) http.Handler` decorator, with no router dependency.

```go
import (
    "net/http"
    archttp "github.com/getarcis/arcis-go/nethttp"
)

func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("/", handler)

    cfg := archttp.DefaultConfig()
    cfg.Block = true
    var h http.Handler = mux
    h = archttp.MiddlewareWithConfig(cfg)(h)

    http.ListenAndServe(":8080", h)
}
```

## Composite protection helpers

Every adapter exposes `ProtectLogin`, `ProtectSignup`, and `ProtectApi`. Each composes the relevant checks with a shared per-IP correlation window, extracting the client IP and route from the request automatically. The correlation window (`middleware.CorrelationWindow`) tracks a 60-second rolling per-IP window with scanner-sweep, credential-stuffing, and race-window detection.

## Guards

`arcis.NewGuards` provides a non-HTTP rule engine for queue consumers, agent tool handlers, and background jobs, applying the same Arcis decisions outside the request path.

## Telemetry

Stream allow and deny decisions from any adapter to a self-hosted Arcis dashboard. Stdlib only, opt-in (nil client means zero overhead).

```go
import "github.com/getarcis/arcis-go/telemetry"

tc, _ := telemetry.NewClient(telemetry.Options{
    Endpoint: "https://arcis.example.com/v1/events",
})
defer tc.Close(context.Background())

cfg := arcisgin.DefaultConfig()
cfg.Telemetry = tc
r.Use(arcisgin.MiddlewareWithConfig(cfg))
```

The standalone `RateLimit`, `RateLimitWithStore`, and `RateLimitWithSkip` helpers accept a `WithTelemetry(tc)` option and emit on a `429`:

```go
r.Use(arcisgin.RateLimit(100, time.Minute, arcisgin.WithTelemetry(tc)))
```

The same option shape is available on every adapter (`arcisecho.RateLimit`, `arcischi.RateLimit`, `arcisfiber.RateLimit`, `archttp.RateLimit`).

## Supply chain scanning

The `arcis sca` supply-chain command ships as a single binary via npm and reads lockfiles directly, so it works on any project regardless of which SDK you deploy:

```bash
npm install -g @arcis/cli
arcis sca .   # reads go.sum, package-lock.json, requirements.txt, and more
```

## Reference

- [API specification and shared test vectors](https://github.com/getarcis/arcis/tree/main/spec)
- [Node and Python SDKs](https://github.com/getarcis/arcis)

## License

MIT
