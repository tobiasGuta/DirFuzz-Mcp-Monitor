package tui

import (
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
