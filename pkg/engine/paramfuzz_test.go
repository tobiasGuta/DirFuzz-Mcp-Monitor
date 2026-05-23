package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFuzzParamsIncludesRawWhenSaveRawEnabled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("action") {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("param-hit"))
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("baseline"))
	}))
	defer server.Close()

	engine := NewEngine(1, 100, 0.01)
	engine.Config.SaveRaw = true
	engine.buildAndStoreConfigSnapshot()

	hits, err := engine.FuzzParams(context.Background(), ParamTask{
		URL:    server.URL,
		Method: http.MethodGet,
	}, []string{"action"})
	if err != nil {
		t.Fatalf("FuzzParams returned error: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("expected 1 param hit, got %d", len(hits))
	}
	if hits[0].Request == "" {
		t.Fatal("expected raw request to be captured for param hit")
	}
	if hits[0].Response == "" {
		t.Fatal("expected raw response to be captured for param hit")
	}
	if len(hits[0].RequestBytes) == 0 {
		t.Fatal("expected raw request bytes to be captured for param hit")
	}
	if len(hits[0].ResponseBytes) == 0 {
		t.Fatal("expected raw response bytes to be captured for param hit")
	}
}

func TestShouldQueueParamFuzzSkipsRedirects(t *testing.T) {
	redirectCodes := []int{301, 302, 303, 307, 308}
	for _, statusCode := range redirectCodes {
		if shouldQueueParamFuzz(statusCode, http.MethodGet, 128, 1) {
			t.Fatalf("expected status %d to skip automatic param fuzzing", statusCode)
		}
	}
	if !shouldQueueParamFuzz(200, http.MethodGet, 128, 1) {
		t.Fatal("expected 200 response to queue automatic param fuzzing")
	}
}

func TestFuzzParamsWithoutWordlistReturnsNoHits(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("id") {
			_, _ = w.Write([]byte("param-hit"))
			return
		}
		_, _ = w.Write([]byte("baseline"))
	}))
	defer server.Close()

	engine := NewEngine(1, 100, 0.01)
	engine.buildAndStoreConfigSnapshot()

	hits, err := engine.FuzzParams(context.Background(), ParamTask{
		URL:    server.URL,
		Method: http.MethodGet,
	}, nil)
	if err != nil {
		t.Fatalf("FuzzParams returned error: %v", err)
	}
	if len(hits) != 0 {
		t.Fatalf("expected no param hits without configured wordlist, got %d", len(hits))
	}
}

func TestFuzzParamsUsesConfiguredWordlist(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("id") {
			_, _ = w.Write([]byte("param-hit"))
			return
		}
		_, _ = w.Write([]byte("baseline"))
	}))
	defer server.Close()

	engine := NewEngine(1, 100, 0.01)
	engine.Config.ParamWordlist = []string{"id"}
	engine.buildAndStoreConfigSnapshot()

	hits, err := engine.FuzzParams(context.Background(), ParamTask{
		URL:    server.URL,
		Method: http.MethodGet,
	}, nil)
	if err != nil {
		t.Fatalf("FuzzParams returned error: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("expected 1 param hit with configured wordlist, got %d", len(hits))
	}
	if len(hits[0].Params) != 1 || !strings.EqualFold(hits[0].Params[0], "id") {
		t.Fatalf("expected id param hit, got %+v", hits[0].Params)
	}
}

func TestQueueParamFuzzRequiresConfiguredWordlist(t *testing.T) {
	engine := NewEngine(1, 100, 0.01)
	defer engine.Shutdown()

	res := Result{
		URL:        "http://example.com/api/user",
		Method:     http.MethodGet,
		StatusCode: http.StatusUnauthorized,
	}

	engine.buildAndStoreConfigSnapshot()
	engine.queueParamFuzzFromResult(res, 64, 123)
	if _, ok := engine.paramTaskSeen.Load(strings.ToLower(res.URL)); ok {
		t.Fatal("expected auto param fuzz to stay disabled without configured wordlist")
	}

	engine.Config.ParamWordlist = []string{"id"}
	engine.buildAndStoreConfigSnapshot()
	engine.queueParamFuzzFromResult(res, 64, 123)
	if _, ok := engine.paramTaskSeen.Load(strings.ToLower(res.URL)); !ok {
		t.Fatal("expected auto param fuzz to enable when a param wordlist is configured")
	}
}
