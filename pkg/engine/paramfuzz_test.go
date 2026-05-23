package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
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
