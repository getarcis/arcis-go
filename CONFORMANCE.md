# Go real-server conformance

This is the evidence map for [roadmap issue #45](https://github.com/getarcis/arcis/issues/45).
The tests use real loopback TCP listeners, public middleware entry points, and
application handlers. They do not mock Arcis detectors or limiter state.

## Coverage

| Public behavior | Tests in `conformance/` | Adapters |
| --- | --- | --- |
| Shared exact-input fixtures in dry-run | `real_server_test.go` | Gin, Echo, Chi, net/http, Fiber |
| Safe body unchanged before and after attack rejection | `enforcement_test.go` | All five |
| Rate-limit allow and reject complete | `enforcement_test.go` | All five |
| Browser/client allow, scanner reject, browser recovery | `enforcement_test.go` | All five |
| Malformed JSON and non-JSON preservation | `real_server_test.go`, `enforcement_test.go` | All five, dry-run and enforcing |
| Shared security headers on allow and deny | `response_test.go`, `enforcement_test.go` | All five |
| Standalone headers remove application fingerprint headers on the wire | `response_test.go` | Gin, Echo, Chi |
| Concurrent HTTP and telemetry outcomes agree | `telemetry_test.go` | All five, 24 requests and an 8-request limit |
| Dry-run findings preserve input and emit `would_deny` with application status | `telemetry_test.go` | All five, attack/bot/rate cases |
| Repeated server, limiter, and telemetry cleanup | `lifecycle_test.go` | All five, warmup plus eight cycles |
| Streaming, upgrades, informational responses, HTTP/2 response controls | `streaming_test.go` | Chi bundle and standalone headers |

The shared fixture source is `spec/TEST_VECTORS.json`. Its three
`dry_run_input_preservation` case names appear in test output. Header checks
consume `security_headers.required_headers_default` and `removed_headers`;
they are not a claim of complete Helmet API or default-policy compatibility.

## Runtime corrections covered by regressions

- Security headers are attached before bundled enforcement, so Arcis-generated
  403 and 429 responses receive them too.
- Fingerprint removal occurs before response bytes are committed. Deleting a
  header after an application writes its body is too late for net/http writers.
- Chi's response wrapper preserves flushing, connection upgrades, response
  controller access, the HTTP/2 push interface, and final status codes after
  informational responses. net/http shares Chi's implementation.

## Reproduce

Use the module minimum, Go 1.25, and the current tested line, Go 1.27:

```text
go test ./... -count=1 -timeout=5m
go vet ./...
go test ./... -race -count=1 -timeout=5m
go build ./...
gofmt -l .
go test -v ./conformance -count=1 -timeout=2m
go test -v ./conformance -run TestRealServerCleanupDoesNotAccumulateGoroutines -count=1 -timeout=60s
```

The last command runs lifecycle checks in a fresh test process to reduce
interference from framework background work started by other tests. A clean
formatting check prints no paths. Development verification for #45 uses Docker
Desktop and the official `golang:1.25` / `golang:1.27` images, not a host Go
installation. The same commands run in the containers with this repo mounted
as their working directory.

CI runs both Go lines, race/vet/format checks, and uploads
`arcis-go-conformance-<commit SHA>` with verbose real-server output. Explicit
Bash pipeline failure handling prevents saving the output from masking a test
failure. A local pass is not evidence that GitHub CI ran or that a release was
published; the issue checkpoint records those separately.

## Limits of this evidence

- This is a focused smoke suite, not exhaustive detector coverage, an external
  security audit, or proof that every legitimate request is accepted.
- Fiber's default wildcard route parameters are percent-encoded. Its protected
  application is compared with an identical unprotected Fiber application;
  Arcis does not redefine framework decoding behavior.
- Lifecycle checks compare goroutine counts with a two-goroutine housekeeping
  allowance. Fiber's pinned fasthttp version sleeps for up to ten seconds in
  its worker-pool cleanup loop after shutdown; the test allows fifteen seconds
  for this to settle. This is a bounded accumulation regression check, not
  proof of the absence of every possible leak.
- Network requests have five-second client deadlines. Fiber listener shutdown
  is checked explicitly. The overall test command supplies an additional
  timeout for unexpected cleanup hangs.
- Raw bytes written after an application hijacks a connection are controlled
  by the application, not by HTTP response-header middleware.
- The existing cross-repo data-sync CI job compares fixtures with
  `getarcis/arcis` main. Shared #47 fixture changes must land there before their
  matching Go copy can pass that gate.
