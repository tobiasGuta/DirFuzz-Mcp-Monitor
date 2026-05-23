package tui

import (
	"testing"

	"dirfuzz/pkg/engine"
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
