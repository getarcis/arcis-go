package gin

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// fingerprintWriter strips headers before Gin commits them to the network.
// Embedding preserves Gin's status, size, hijacking, and push interfaces.
type fingerprintWriter struct {
	gin.ResponseWriter
}

func (w *fingerprintWriter) strip() {
	w.Header().Del("Server")
	w.Header().Del("X-Powered-By")
}

func (w *fingerprintWriter) WriteHeader(code int) {
	w.strip()
	w.ResponseWriter.WriteHeader(code)
}

func (w *fingerprintWriter) WriteHeaderNow() {
	w.strip()
	w.ResponseWriter.WriteHeaderNow()
}

func (w *fingerprintWriter) Write(body []byte) (int, error) {
	w.strip()
	return w.ResponseWriter.Write(body)
}

func (w *fingerprintWriter) WriteString(body string) (int, error) {
	w.strip()
	return w.ResponseWriter.WriteString(body)
}

func (w *fingerprintWriter) Flush() {
	w.strip()
	w.ResponseWriter.Flush()
}

func (w *fingerprintWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}
