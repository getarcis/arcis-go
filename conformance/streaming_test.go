package conformance_test

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	arcischi "github.com/getarcis/arcis-go/chi"
)

func TestChiRealServerHeadersPreserveConnectionUpgrade(t *testing.T) {
	for _, mode := range []string{"bundle", "headers_only"} {
		t.Run(mode, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hijacker, ok := w.(http.Hijacker)
				if !ok {
					http.Error(w, "upgrade unavailable", http.StatusInternalServerError)
					return
				}
				conn, buffer, err := hijacker.Hijack()
				if err != nil {
					return
				}
				defer conn.Close()
				_, _ = buffer.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: arcis-test\r\n\r\nupgraded\n")
				_ = buffer.Flush()
			})
			middleware := arcischi.Headers()
			if mode == "bundle" {
				middleware = arcischi.Middleware()
				t.Cleanup(arcischi.Cleanup)
			}
			server := httptest.NewServer(middleware(handler))
			t.Cleanup(server.Close)
			conn, err := net.DialTimeout("tcp", server.Listener.Addr().String(), 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			_, err = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: "+browserUA+"\r\nAccept: text/html\r\nAccept-Language: en-US\r\nConnection: Upgrade\r\nUpgrade: arcis-test\r\n\r\n")
			if err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewReader(conn)
			response, err := http.ReadResponse(reader, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusSwitchingProtocols {
				t.Fatalf("upgrade status = %d", response.StatusCode)
			}
			line, err := reader.ReadString('\n')
			if err != nil || line != "upgraded\n" {
				t.Fatalf("upgraded connection = %q, %v", line, err)
			}
		})
	}
}

func TestChiRealServerHeadersPreserveStreaming(t *testing.T) {
	for _, mode := range []string{"bundle", "headers_only"} {
		t.Run(mode, func(t *testing.T) {
			release := make(chan struct{})
			var releaseOnce sync.Once
			finish := func() { releaseOnce.Do(func() { close(release) }) }
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Powered-By", "streaming-app")
				_, _ = io.WriteString(w, "first\n")
				if err := http.NewResponseController(w).Flush(); err != nil {
					_, _ = io.WriteString(w, "flush failed: "+err.Error())
					return
				}
				select {
				case <-release:
					_, _ = io.WriteString(w, "second\n")
				case <-r.Context().Done():
				}
			})
			middleware := arcischi.Headers()
			if mode == "bundle" {
				middleware = arcischi.Middleware()
				t.Cleanup(arcischi.Cleanup)
			}
			server := httptest.NewServer(middleware(handler))
			t.Cleanup(server.Close)
			t.Cleanup(finish)
			client := &http.Client{Timeout: 5 * time.Second}
			response, err := client.Get(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			reader := bufio.NewReader(response.Body)
			first, err := reader.ReadString('\n')
			if err != nil || first != "first\n" {
				t.Fatalf("first chunk before application completion = %q, %v", first, err)
			}
			assertSharedSecurityHeaders(t, response.Header)
			finish()
			rest, err := io.ReadAll(reader)
			if err != nil || string(rest) != "second\n" {
				t.Fatalf("remaining stream = %q, %v", rest, err)
			}
		})
	}
}

func TestChiRealServerHeadersPreserveInformationalResponses(t *testing.T) {
	for _, mode := range []string{"bundle", "headers_only"} {
		t.Run(mode, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusEarlyHints)
				w.Header().Set("X-Powered-By", "application-framework")
				w.WriteHeader(http.StatusCreated)
				_, _ = io.WriteString(w, "created")
			})
			middleware := arcischi.Headers()
			if mode == "bundle" {
				middleware = arcischi.Middleware()
				t.Cleanup(arcischi.Cleanup)
			}
			server := httptest.NewServer(middleware(handler))
			t.Cleanup(server.Close)
			response, body := sendRequest(t, server.URL, "{}", browserUA)
			if response.StatusCode != http.StatusCreated || body != "created" {
				t.Fatalf("final response after 103: %d %q", response.StatusCode, body)
			}
			assertSharedSecurityHeaders(t, response.Header)
		})
	}
}

func TestChiRealServerHeadersPreserveResponseControls(t *testing.T) {
	for _, mode := range []string{"bundle", "headers_only"} {
		t.Run(mode, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				controller := http.NewResponseController(w)
				if err := controller.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
					http.Error(w, err.Error(), 500)
					return
				}
				if err := controller.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
					http.Error(w, err.Error(), 500)
					return
				}
				if _, ok := w.(http.Pusher); !ok {
					http.Error(w, "HTTP/2 push interface hidden", 500)
					return
				}
				_, _ = io.WriteString(w, "ok")
			})
			middleware := arcischi.Headers()
			if mode == "bundle" {
				middleware = arcischi.Middleware()
				t.Cleanup(arcischi.Cleanup)
			}
			server := httptest.NewUnstartedServer(middleware(handler))
			server.EnableHTTP2 = true
			server.StartTLS()
			t.Cleanup(server.Close)
			client := server.Client()
			client.Timeout = 5 * time.Second
			response, err := client.Get(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if response.ProtoMajor != 2 || response.StatusCode != http.StatusOK || string(body) != "ok" {
				t.Fatalf("HTTP/2 response controls unavailable: %s %d %q", response.Proto, response.StatusCode, body)
			}
		})
	}
}
