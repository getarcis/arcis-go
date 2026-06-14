package intelligence

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func botStub(entries []map[string]any, hits *int32) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			atomic.AddInt32(hits, 1)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"schema_version": "1", "count": len(entries), "entries": entries,
		})
	}))
}

func TestBotCorpusEnabled(t *testing.T) {
	c1, _ := NewClient(Options{Endpoint: "https://x", CloudDecisions: []string{"bot-corpus"}})
	if !c1.BotCorpusEnabled() {
		t.Fatal("expected BotCorpusEnabled true")
	}
	c2, _ := NewClient(Options{Endpoint: "https://x", CloudDecisions: []string{"ip-rep"}})
	if c2.BotCorpusEnabled() {
		t.Fatal("expected BotCorpusEnabled false when only ip-rep")
	}
}

func TestFetchBotCorpus(t *testing.T) {
	srv := botStub([]map[string]any{
		{"id": "a", "name": "A", "category": "AI_CRAWLER", "patterns": []string{"Abot"}, "forbidden": []string{}},
		{"id": "b", "name": "B", "category": "SECURITY_SCANNER", "patterns": []string{"Bscan"}, "forbidden": []string{}},
	}, nil)
	defer srv.Close()
	c, _ := NewClient(Options{Endpoint: srv.URL, CloudDecisions: []string{"bot-corpus"}})
	defer c.Close()

	entries := c.FetchBotCorpus()
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0].ID != "a" || entries[1].Category != "SECURITY_SCANNER" {
		t.Fatalf("unexpected entries: %+v", entries)
	}
}

func TestFetchBotCorpusFailsOpen(t *testing.T) {
	// Unreachable server -> nil (fail-open).
	srv := botStub(nil, nil)
	url := srv.URL
	srv.Close()
	var errCount int32
	c, _ := NewClient(Options{
		Endpoint: url, CloudDecisions: []string{"bot-corpus"},
		OnError: func(error) { atomic.AddInt32(&errCount, 1) },
	})
	defer c.Close()
	if c.FetchBotCorpus() != nil {
		t.Fatal("expected nil on unreachable service")
	}
	if atomic.LoadInt32(&errCount) != 1 {
		t.Fatalf("expected OnError once, got %d", errCount)
	}
}

func TestFetchBotCorpusFailsOpenOn500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c, _ := NewClient(Options{Endpoint: srv.URL, CloudDecisions: []string{"bot-corpus"}})
	defer c.Close()
	if c.FetchBotCorpus() != nil {
		t.Fatal("expected nil on HTTP 500")
	}
}
