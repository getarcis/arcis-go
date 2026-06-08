package gin

// v1.7 W3 GraphQL wire-up integration tests for the gin adapter.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func newRouterGraphql(cfg Config) *gin.Engine {
	cfg.RateLimit = false
	r := gin.New()
	r.Use(MiddlewareWithConfig(cfg))
	r.POST("/graphql", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"data": gin.H{}})
	})
	return r
}

func postGraphql(r *gin.Engine, query string) int {
	body, _ := json.Marshal(map[string]string{"query": query})
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", browserUA)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Language", "en-US")
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code
}

func TestGraphqlWireup_DefaultBlocksBenchPayloads(t *testing.T) {
	r := newRouterGraphql(DefaultConfig())
	payloads := map[string]string{
		"alias-bomb":     "{a:user{id} b:user{id} c:user{id} d:user{id} e:user{id} f:user{id} g:user{id} h:user{id} i:user{id} j:user{id} k:user{id} l:user{id}}",
		"fragment-cycle": "fragment A on Query { ...B } fragment B on Query { ...A } { ...A }",
		"deep-query":     "{user{posts{comments{replies{replies{replies{replies{replies{replies{replies{id}}}}}}}}}}}",
		"introspection":  "{__schema{types{name fields{name type{name}}}}}",
	}
	for name, q := range payloads {
		if got := postGraphql(r, q); got != http.StatusForbidden {
			t.Errorf("%s: expected 403, got %d", name, got)
		}
	}
}

func TestGraphqlWireup_AllowsLegitQueries(t *testing.T) {
	r := newRouterGraphql(DefaultConfig())
	queries := []string{
		"{ user { id name email } }",
		"{ user { posts { comments { author { name } } } } }",
		"{ user { __typename id name } }",
		"{ a: user(id: 1) { name } b: user(id: 2) { name } }",
	}
	for _, q := range queries {
		if got := postGraphql(r, q); got != http.StatusOK {
			t.Errorf("query %q: expected 200, got %d", q, got)
		}
	}
}

func TestGraphqlWireup_OptOut(t *testing.T) {
	cfg := DefaultConfig()
	cfg.GraphQL = false
	r := newRouterGraphql(cfg)
	bomb := "{a:u{id} b:u{id} c:u{id} d:u{id} e:u{id} f:u{id} g:u{id} h:u{id} i:u{id} j:u{id} k:u{id} l:u{id}}"
	if got := postGraphql(r, bomb); got != http.StatusOK {
		t.Errorf("GraphQL=false should allow alias bomb, got %d", got)
	}
}

func TestGraphqlWireup_NoQueryFieldPasses(t *testing.T) {
	r := newRouterGraphql(DefaultConfig())
	body, _ := json.Marshal(map[string]string{"other": "field"})
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", browserUA)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Language", "en-US")
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("non-graphql body should pass, got %d", w.Code)
	}
}
