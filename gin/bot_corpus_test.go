package gin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	arcis "github.com/getarcis/arcis-go"
	"github.com/getarcis/arcis-go/intelligence"
)

// botCorpusStub serves the bot-corpus snapshot endpoint with the given entries.
func botCorpusStub(entries []map[string]any) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"schema_version": "1", "count": len(entries), "entries": entries,
		})
	}))
}

func TestGinBotCorpusRefreshDeniesNovelScanner(t *testing.T) {
	defer arcis.ResetBotPatternsForTest()

	const novelUA = "ArcisGinScanner-9999/1.0"
	srv := botCorpusStub([]map[string]any{
		{"id": "arcis-gin-scanner", "name": "ArcisGinScanner", "category": "SECURITY_SCANNER",
			"patterns": []string{"ArcisGinScanner-9999"}, "forbidden": []string{}},
	})
	defer srv.Close()

	client, err := intelligence.NewClient(intelligence.Options{
		Endpoint: srv.URL, CloudDecisions: []string{"bot-corpus"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(MiddlewareWithConfig(Config{
		Bot:          true,
		BotDeny:      []arcis.BotCategory{arcis.BotCategoryAutomated, arcis.BotCategorySecurityScanner},
		Intelligence: client,
	}))
	r.GET("/", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	// The bundle doesn't know this UA; once the startup refresh merges the
	// entry, SECURITY_SCANNER is denied -> 403. Poll for the background merge.
	denied := false
	for i := 0; i < 60; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("User-Agent", novelUA)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code == http.StatusForbidden {
			denied = true
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	if !denied {
		t.Fatal("expected novel scanner UA to be denied once the corpus refresh landed")
	}
}

func TestGinBotCorpusFailsOpen(t *testing.T) {
	defer arcis.ResetBotPatternsForTest()

	client, _ := intelligence.NewClient(intelligence.Options{
		Endpoint: "http://127.0.0.1:1", CloudDecisions: []string{"bot-corpus"}, Timeout: 300 * time.Millisecond,
	})
	defer client.Close()

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(MiddlewareWithConfig(Config{
		Bot:          true,
		BotDeny:      []arcis.BotCategory{arcis.BotCategorySecurityScanner},
		Intelligence: client,
	}))
	r.GET("/", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	// Unreachable corpus service: the bundle is untouched, novel UA stays allowed.
	time.Sleep(50 * time.Millisecond)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", "ArcisGinScanner-9999/1.0")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (fail-open), got %d", w.Code)
	}
}
