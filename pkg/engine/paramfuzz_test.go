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
	engine.queueParamFuzzFromResult(res, res.URL, 64, 123, "application/json", []byte(`{"error":"missing id parameter"}`))
	if _, ok := engine.paramTaskSeen.Load(paramTaskIdentity(ParamTask{URL: res.URL, Method: res.Method})); ok {
		t.Fatal("expected auto param fuzz to stay disabled without configured wordlist")
	}

	engine.Config.ParamWordlist = []string{"id"}
	engine.buildAndStoreConfigSnapshot()
	engine.queueParamFuzzFromResult(res, res.URL, 64, 123, "application/json", []byte(`{"error":"missing id parameter"}`))
	if _, ok := engine.paramTaskSeen.Load(paramTaskIdentity(ParamTask{URL: res.URL, Method: res.Method})); !ok {
		t.Fatal("expected auto param fuzz to enable when a param wordlist is configured")
	}
}

func TestQueueParamFuzzUsesFinalRedirectURLAsTaskTarget(t *testing.T) {
	engine := NewEngine(1, 100, 0.01)
	defer engine.Shutdown()

	engine.Config.ParamWordlist = []string{"id"}
	engine.buildAndStoreConfigSnapshot()

	res := Result{
		URL:        "http://example.com/api",
		Method:     http.MethodGet,
		StatusCode: http.StatusOK,
	}

	finalURL := "http://example.com/api/"
	engine.queueParamFuzzFromResult(res, finalURL, 64, 123, "application/json", []byte(`{"error":"missing id parameter"}`))

	if _, ok := engine.paramTaskSeen.Load(paramTaskIdentity(ParamTask{URL: finalURL, Method: res.Method})); !ok {
		t.Fatal("expected final redirect URL to be used for param task identity")
	}
	if _, ok := engine.paramTaskSeen.Load(paramTaskIdentity(ParamTask{URL: res.URL, Method: res.Method})); ok {
		t.Fatal("expected original pre-redirect URL not to be used for param task identity")
	}
}

func TestParamTaskIdentityIgnoresQueryValues(t *testing.T) {
	first := ParamTask{URL: "http://example.com/jobs.php?id=15", Method: http.MethodGet}
	second := ParamTask{URL: "http://example.com/jobs.php?id=16", Method: http.MethodGet}

	if got, want := paramTaskIdentity(first), paramTaskIdentity(second); got != want {
		t.Fatalf("expected identical task identity for different query values, got %q vs %q", got, want)
	}
}

func TestEnqueueParamTaskDedupesByQueryKeysNotValues(t *testing.T) {
	engine := NewEngine(1, 100, 0.01)
	defer engine.Shutdown()

	first := ParamTask{URL: "http://example.com/jobs.php?id=15", Method: http.MethodGet}
	second := ParamTask{URL: "http://example.com/jobs.php?id=16", Method: http.MethodGet}

	if !engine.enqueueParamTask(first) {
		t.Fatal("expected first param task to enqueue")
	}
	if engine.enqueueParamTask(second) {
		t.Fatal("expected second param task with same query keys to dedupe")
	}
}

func TestParamHitIdentityDedupesEquivalentProbeURLs(t *testing.T) {
	first := ParamHit{ProbeURL: "http://example.com/jobs.php?id=1", Params: []string{"id"}}
	second := ParamHit{ProbeURL: "http://example.com/jobs.php?id=1", Params: []string{"id"}}

	if got, want := paramHitIdentity(first), paramHitIdentity(second); got != want {
		t.Fatalf("expected identical hit identity for duplicate probe URLs, got %q vs %q", got, want)
	}
}

func TestMarkParamHitSeenSuppressesDuplicateProbeResults(t *testing.T) {
	engine := NewEngine(1, 100, 0.01)
	defer engine.Shutdown()

	hit := ParamHit{ProbeURL: "http://example.com/jobs.php?id=1", Params: []string{"id"}}
	if !engine.markParamHitSeen(hit) {
		t.Fatal("expected first param hit to be marked as new")
	}
	if engine.markParamHitSeen(hit) {
		t.Fatal("expected duplicate param hit to be suppressed")
	}
}

func TestLearnedParamsAreQueuedForKnownPHPTargets(t *testing.T) {
	engine := NewEngine(1, 100, 0.01)
	defer engine.Shutdown()

	task := ParamTask{
		URL:                "http://example.com/info.php",
		Method:             http.MethodGet,
		BaselineStatusCode: http.StatusOK,
		BaselineSize:       2000,
		BaselineHash:       123,
	}
	engine.rememberPHPParamTarget(task)

	added := engine.rememberGlobalParamHints([]string{"id"})
	if len(added) != 1 || !strings.EqualFold(added[0], "id") {
		t.Fatalf("expected id to be learned once, got %v", added)
	}
	engine.queueKnownPHPTargetsForParams(added)

	task.CandidateHints = []string{"id"}
	if _, ok := engine.paramTaskSeen.Load(paramTaskQueueIdentity(task)); !ok {
		t.Fatal("expected learned id parameter to queue a known PHP target")
	}
}

func TestFuzzParamsMergesResponseHintsIntoConfiguredWordlist(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Has("id") {
			_, _ = w.Write([]byte(`{"error":"User not found"}`))
			return
		}
		_, _ = w.Write([]byte(`{"error":"Authentication required. Provide ?id= parameter or log in."}`))
	}))
	defer server.Close()

	engine := NewEngine(1, 100, 0.01)
	engine.Config.ParamWordlist = []string{"unused"}
	engine.buildAndStoreConfigSnapshot()

	hits, err := engine.FuzzParams(context.Background(), ParamTask{
		URL:    server.URL,
		Method: http.MethodGet,
	}, nil)
	if err != nil {
		t.Fatalf("FuzzParams returned error: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("expected 1 param hit from extracted hint, got %d", len(hits))
	}
	if len(hits[0].Params) != 1 || !strings.EqualFold(hits[0].Params[0], "id") {
		t.Fatalf("expected id param hit from response hint, got %+v", hits[0].Params)
	}
}

func TestFuzzParamsUsesNumericProbeValuesForIdentifierParams(t *testing.T) {
	probeURL, _, err := buildParamProbeRequest("http://example.com/api/user", []string{"id", "user_id", "token"}, nil, nil)
	if err != nil {
		t.Fatalf("buildParamProbeRequest returned error: %v", err)
	}
	if !strings.Contains(probeURL, "id=1") {
		t.Fatalf("expected id to use numeric probe value, got %s", probeURL)
	}
	if !strings.Contains(probeURL, "user_id=2") {
		t.Fatalf("expected user_id to use numeric probe value, got %s", probeURL)
	}
	if !strings.Contains(probeURL, "token=c") {
		t.Fatalf("expected non-id param to use generic probe value, got %s", probeURL)
	}
}

func TestBuildParamProbeRequestIncludesConfiguredAndPerCallHeaders(t *testing.T) {
	snap := &configSnapshot{
		Headers: map[string]string{
			"Cookie": "session=abc",
		},
		HeadersTemplate: "Cookie: session=abc\r\n",
	}

	_, rawReq, err := buildParamProbeRequest(
		"http://example.com/api/user",
		[]string{"id"},
		snap,
		map[string]string{"Authorization": "Bearer test-token"},
	)
	if err != nil {
		t.Fatalf("buildParamProbeRequest returned error: %v", err)
	}
	raw := string(rawReq)
	if !strings.Contains(raw, "Cookie: session=abc\r\n") {
		t.Fatalf("expected configured Cookie header in raw request, got:\n%s", raw)
	}
	if !strings.Contains(raw, "Authorization: Bearer test-token\r\n") {
		t.Fatalf("expected per-call Authorization header in raw request, got:\n%s", raw)
	}
}

func TestFuzzParamsSuppressesNotFoundProbeTransitions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Has("id") {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"Authentication required. Provide ?id= parameter or log in."}`))
	}))
	defer server.Close()

	engine := NewEngine(1, 100, 0.01)
	engine.Config.ParamWordlist = []string{"unused"}
	engine.buildAndStoreConfigSnapshot()

	hits, err := engine.FuzzParams(context.Background(), ParamTask{
		URL:    server.URL + "/api/user",
		Method: http.MethodGet,
	}, nil)
	if err != nil {
		t.Fatalf("FuzzParams returned error: %v", err)
	}
	if len(hits) != 0 {
		t.Fatalf("expected 404 probe transition to be suppressed, got %+v", hits)
	}
}

func TestExtractParamHintsFromTextSkipsCommonStopwords(t *testing.T) {
	hints := extractParamHintsFromText(`Authentication required. Provide ?id= parameter or log in.`)
	if !containsStringIgnoreCase(hints, "id") {
		t.Fatalf("expected id hint in %v", hints)
	}
	for _, blocked := range []string{"or", "log", "in", "parameter"} {
		if containsStringIgnoreCase(hints, blocked) {
			t.Fatalf("did not expect stopword %q in %v", blocked, hints)
		}
	}
}

func TestFuzzParamsSuppressesGenericQueryStringChanges(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if len(r.URL.Query()) > 0 {
			_, _ = w.Write([]byte("<html><body>generic query page</body></html>"))
			return
		}
		_, _ = w.Write([]byte("<html><body>baseline page</body></html>"))
	}))
	defer server.Close()

	engine := NewEngine(1, 100, 0.01)
	engine.Config.ParamWordlist = []string{"account", "action", "debug"}
	engine.buildAndStoreConfigSnapshot()

	hits, err := engine.FuzzParams(context.Background(), ParamTask{
		URL:    server.URL + "/register.php",
		Method: http.MethodGet,
	}, nil)
	if err != nil {
		t.Fatalf("FuzzParams returned error: %v", err)
	}
	if len(hits) != 0 {
		t.Fatalf("expected generic query-string changes to be suppressed, got %d hit(s): %+v", len(hits), hits)
	}
}

func TestExtractParamHintsFromHTMLFormsAndLinks(t *testing.T) {
	body := []byte(`<html><body><form action="/search?lang=en"><input name="csrf"><input name="id"></form><a href="/api/user?id=15&view=full">user</a></body></html>`)
	hints := extractParamHints("http://example.com/form", "text/html", body)

	for _, want := range []string{"lang", "csrf", "id", "view"} {
		if !containsStringIgnoreCase(hints, want) {
			t.Fatalf("expected extracted HTML hint %q in %v", want, hints)
		}
	}
}

func containsStringIgnoreCase(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(value, want) {
			return true
		}
	}
	return false
}

func TestExtractParamHintsFromEmptyBodyURL(t *testing.T) {
	hints := extractParamHints("http://example.com/form?token=xyz&api_key=123", "text/html", nil)
	for _, want := range []string{"token", "api_key"} {
		if !containsStringIgnoreCase(hints, want) {
			t.Fatalf("expected extracted URL hint %q in %v when body is empty", want, hints)
		}
	}
}
