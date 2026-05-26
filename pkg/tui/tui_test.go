package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dirfuzz/pkg/engine"
	"dirfuzz/pkg/httpclient"
)

func TestCommandConfigChangesRefreshSnapshot(t *testing.T) {
	eng := engine.NewEngine(1, 1000, 0.01)
	model := NewModel(eng, make(chan engine.Result), make(chan engine.LogEvent))

	runCommand := func(name, args string) {
		t.Helper()
		for _, cmd := range model.commands {
			if cmd.Name == name {
				cmd.Handler(&model, args)
				return
			}
		}
		t.Fatalf("command %q not found", name)
	}

	runCommand("fw", "3")
	runCommand("body", "id={PAYLOAD}")
	runCommand("saveraw", "on")

	snap := eng.RuntimeSnapshot()
	if snap.FilterWords != 3 {
		t.Fatalf("snapshot FilterWords = %d, want 3", snap.FilterWords)
	}
	if snap.RequestBody != "id={PAYLOAD}" {
		t.Fatalf("snapshot RequestBody = %q", snap.RequestBody)
	}
	if !snap.SaveRaw {
		t.Fatal("snapshot SaveRaw was not enabled")
	}
}

func TestClosedResultStreamQuitsTUI(t *testing.T) {
	eng := engine.NewEngine(1, 1000, 0.01)
	defer eng.Shutdown()

	resultsCh := make(chan engine.Result)
	close(resultsCh)
	model := NewModel(eng, resultsCh, make(chan engine.LogEvent))

	msg := model.listenForResults()()
	if _, ok := msg.(ResultStreamClosedMsg); !ok {
		t.Fatalf("listenForResults() closed channel message = %T, want ResultStreamClosedMsg", msg)
	}

	updated, _ := model.Update(msg)
	updatedModel := updated.(*Model)
	if !updatedModel.quitting {
		t.Fatal("expected model to enter quitting state when result stream closes")
	}
}

func TestOpenRepeaterSessionAppendsInsteadOfReplacing(t *testing.T) {
	eng := engine.NewEngine(1, 1000, 0.01)
	model := NewModel(eng, make(chan engine.Result), make(chan engine.LogEvent))

	model.openRepeaterSession("https://example.test", "GET /one HTTP/1.1\nHost: example.test\n")
	model.openRepeaterSession("https://example.test", "GET /two HTTP/1.1\nHost: example.test\n")

	if got := len(model.repeaterSessions); got != 2 {
		t.Fatalf("repeaterSessions len = %d, want 2", got)
	}
	if model.activeRepeaterIdx != 1 {
		t.Fatalf("activeRepeaterIdx = %d, want 1", model.activeRepeaterIdx)
	}
	if got := model.repeaterSessions[0].Request; got != "GET /one HTTP/1.1\nHost: example.test\n" {
		t.Fatalf("first session request = %q", got)
	}
	if got := model.repeaterInput.Value(); got != "GET /two HTTP/1.1\nHost: example.test\n" {
		t.Fatalf("active repeater input = %q, want second session request", got)
	}
}

func TestRepeaterResultRoutesToMatchingSession(t *testing.T) {
	eng := engine.NewEngine(1, 1000, 0.01)
	model := NewModel(eng, make(chan engine.Result), make(chan engine.LogEvent))

	model.openRepeaterSession("https://example.test", "GET /one HTTP/1.1\nHost: example.test\n")
	firstID := model.repeaterSessions[0].ID
	model.openRepeaterSession("https://example.test", "GET /two HTTP/1.1\nHost: example.test\n")

	resp := &httpclient.RawResponse{
		StatusCode: 200,
		Raw:        []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"),
	}

	updated, _ := model.Update(RepeaterResultMsg{
		SessionID:   firstID,
		RawResponse: resp,
		Duration:    150 * time.Millisecond,
	})
	updatedModel := updated.(*Model)

	if got := updatedModel.repeaterInput.Value(); got != "GET /two HTTP/1.1\nHost: example.test\n" {
		t.Fatalf("active repeater input after background result = %q, want second session request", got)
	}
	if got := updatedModel.repeaterSessions[0].LastStatus; got != 200 {
		t.Fatalf("first session LastStatus = %d, want 200", got)
	}
	if got := updatedModel.repeaterSessions[0].Response; got == "" {
		t.Fatal("first session response was not stored")
	}
	if got := updatedModel.repeaterSessions[1].Request; got != "GET /two HTTP/1.1\nHost: example.test\n" {
		t.Fatalf("second session request = %q, want unchanged second request", got)
	}
}

func TestLoadPersistedResultsMergesLatestByIdentity(t *testing.T) {
	eng := engine.NewEngine(1, 1000, 0.01)
	model := NewModel(eng, make(chan engine.Result), make(chan engine.LogEvent))
	model.ConfigureHistoryPersistence("results.jsonl", appendHistoryMode)

	model.LoadPersistedResults([]engine.Result{
		{URL: "https://example.test/admin", Method: "GET", Path: "/admin", StatusCode: 200, Size: 10},
		{URL: "https://example.test/admin", Method: "GET", Path: "/admin", StatusCode: 403, Size: 11},
		{URL: "https://example.test/login", Method: "GET", Path: "/login", StatusCode: 200, Size: 12},
	})

	if got := len(model.logLineHits); got != 2 {
		t.Fatalf("len(logLineHits) = %d, want 2", got)
	}
	if model.logLineHits[0] == nil || model.logLineHits[0].StatusCode != 403 {
		t.Fatalf("first merged hit status = %v, want 403", model.logLineHits[0])
	}
	if model.logLineHits[1] == nil || model.logLineHits[1].Path != "/login" {
		t.Fatalf("second merged hit = %v, want /login", model.logLineHits[1])
	}
}

func TestResetAfterRestartPreservingHistoryKeepsHitsAndRepeater(t *testing.T) {
	eng := engine.NewEngine(1, 1000, 0.01)
	model := NewModel(eng, make(chan engine.Result), make(chan engine.LogEvent))
	model.ConfigureHistoryPersistence("results.jsonl", appendHistoryMode)
	model.LoadPersistedResults([]engine.Result{
		{URL: "https://example.test/admin", Method: "GET", Path: "/admin", StatusCode: 200, Size: 10},
	})
	model.openRepeaterSession("https://example.test", "GET /admin HTTP/1.1\nHost: example.test\n")

	model.resetAfterRestartPreservingHistory()

	if got := len(model.logLineHits); got != 1 {
		t.Fatalf("len(logLineHits) after restart reset = %d, want 1", got)
	}
	if got := len(model.repeaterSessions); got != 1 {
		t.Fatalf("len(repeaterSessions) after restart reset = %d, want 1", got)
	}
	if !model.startTime.After(time.Now().Add(-2 * time.Second)) {
		t.Fatal("expected startTime to be refreshed during restart reset")
	}
}

func TestPersistedUIStateRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "results.jsonl")

	eng := engine.NewEngine(1, 1000, 0.01)
	model := NewModel(eng, make(chan engine.Result), make(chan engine.LogEvent))
	model.ConfigureHistoryPersistence(outputPath, appendHistoryMode)
	model.openRepeaterSession("https://example.test", "GET /one HTTP/1.1\nHost: example.test\n")
	model.repeaterSessions[0].Response = "HTTP/1.1 200 OK\n\nok"
	model.repeaterSessions[0].LastStatus = 200
	model.repeaterSessions[0].LastRaw = []byte{0x01, 0x02, 0x03}

	if err := model.FlushPersistedUIState(); err != nil {
		t.Fatalf("FlushPersistedUIState error = %v", err)
	}
	if _, err := os.Stat(outputPath + ".ui.json"); err != nil {
		t.Fatalf("expected sidecar file to exist: %v", err)
	}

	restored := NewModel(eng, make(chan engine.Result), make(chan engine.LogEvent))
	restored.ConfigureHistoryPersistence(outputPath, appendHistoryMode)
	if err := restored.LoadPersistedUIState(); err != nil {
		t.Fatalf("LoadPersistedUIState error = %v", err)
	}

	if got := len(restored.repeaterSessions); got != 1 {
		t.Fatalf("len(restored.repeaterSessions) = %d, want 1", got)
	}
	if got := restored.repeaterSessions[0].Request; got != "GET /one HTTP/1.1\nHost: example.test\n" {
		t.Fatalf("restored request = %q", got)
	}
	if got := string(restored.repeaterSessions[0].LastRaw); got != string([]byte{0x01, 0x02, 0x03}) {
		t.Fatalf("restored LastRaw = %v", restored.repeaterSessions[0].LastRaw)
	}
}

func TestBuildCurlCommandFromRawRequest(t *testing.T) {
	rawReq := "POST /submit?id=1 HTTP/1.1\r\nHost: example.test\r\nUser-Agent: DirFuzz/2.0\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}"

	curlCmd, err := buildCurlCommand(rawReq, "http://example.test/")
	if err != nil {
		t.Fatalf("buildCurlCommand error = %v", err)
	}

	checks := []string{
		"POST",
		"http://example.test:80/submit?id=1",
		"Host: example.test",
		"User-Agent: DirFuzz/2.0",
		"Content-Type: application/json",
		"{\"ok\":true}",
	}
	for _, want := range checks {
		if !strings.Contains(curlCmd, want) {
			t.Fatalf("curl command %q does not contain %q", curlCmd, want)
		}
	}
}

func TestBuildCurlCommandFromBodylessRawRequest(t *testing.T) {
	rawReq := "GET /config HTTP/1.1\nHost: 10.67.164.196\nConnection: keep-alive\nUser-Agent: DirFuzz/2.0\nAccept: */*"

	curlCmd, err := buildCurlCommand(rawReq, "http://10.67.164.196/")
	if err != nil {
		t.Fatalf("buildCurlCommand error = %v", err)
	}
	if !strings.Contains(curlCmd, "GET") {
		t.Fatalf("curl command %q does not contain GET", curlCmd)
	}
	if !strings.Contains(curlCmd, "http://10.67.164.196:80/config") {
		t.Fatalf("curl command %q does not contain expected target", curlCmd)
	}
}

func TestExportRepeaterRequestCreatesFile(t *testing.T) {
	eng := engine.NewEngine(1, 1000, 0.01)
	model := NewModel(eng, make(chan engine.Result), make(chan engine.LogEvent))
	model.openRepeaterSession("https://example.test", "GET /one HTTP/1.1\nHost: example.test\n")

	path, err := model.exportRepeaterRequest("")
	if err != nil {
		t.Fatalf("exportRepeaterRequest error = %v", err)
	}
	defer os.Remove(path)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}
	if got := string(data); got != "GET /one HTTP/1.1\nHost: example.test\n" {
		t.Fatalf("exported request = %q", got)
	}
}
