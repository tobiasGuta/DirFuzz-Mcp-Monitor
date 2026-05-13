package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	lua "github.com/yuin/gopher-lua"
)

// TestPluginMatcher verifies Lua matcher plugin functionality
func TestPluginMatcher(t *testing.T) {
	// Create a test Lua script
	script := `
function match(response)
    return response.status_code == 200 and response.size > 100
end
`
	tmpfile, err := os.CreateTemp("", "test_matcher_*.lua")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(script)); err != nil {
		t.Fatal(err)
	}
	tmpfile.Close()

	// Load plugin
	matcher, err := NewPluginMatcher(tmpfile.Name())
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}
	defer matcher.Close()

	// Test matching
	tests := []struct {
		statusCode int
		size       int
		expected   bool
	}{
		{200, 150, true},  // Should match
		{200, 50, false},  // Size too small
		{404, 150, false}, // Wrong status code
		{500, 50, false},  // Both wrong
	}

	for _, tt := range tests {
		matched, _, _ := matcher.Match(tt.statusCode, tt.size, 0, 0, "test body", "text/html")
		if matched != tt.expected {
			t.Errorf("Match(status=%d, size=%d) = %v, want %v",
				tt.statusCode, tt.size, matched, tt.expected)
		}
	}
}

// TestPluginMutator verifies Lua mutator plugin functionality
func TestPluginMutator(t *testing.T) {
	// Create a test Lua script
	script := `
function mutate(original)
    local variants = {}
    table.insert(variants, original)
    table.insert(variants, original .. ".bak")
    table.insert(variants, string.upper(original))
    return variants
end
`
	tmpfile, err := os.CreateTemp("", "test_mutator_*.lua")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(script)); err != nil {
		t.Fatal(err)
	}
	tmpfile.Close()

	// Load plugin
	mutator, err := NewPluginMutator(tmpfile.Name())
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}
	defer mutator.Close()

	// Test mutation
	original := "admin"
	variants := mutator.Mutate(original, "", 0)

	expected := []string{"admin", "admin.bak", "ADMIN"}
	if len(variants) != len(expected) {
		t.Errorf("Expected %d variants, got %d", len(expected), len(variants))
	}

	for i, want := range expected {
		if i >= len(variants) || variants[i] != want {
			t.Errorf("Variant %d: got %q, want %q", i, variants[i], want)
		}
	}
}

// TestPluginMatcherError verifies error handling
func TestPluginMatcherError(t *testing.T) {
	// Try to load non-existent file
	_, err := NewPluginMatcher("/nonexistent/file.lua")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}

	// Try to load script without match function
	script := `
function wrong_name()
    return true
end
`
	tmpfile, err := os.CreateTemp("", "test_no_match_*.lua")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(script)); err != nil {
		t.Fatal(err)
	}
	tmpfile.Close()

	_, err = NewPluginMatcher(tmpfile.Name())
	if err == nil {
		t.Error("Expected error for missing match function")
	}
}

// TestPluginMutatorError verifies error handling
func TestPluginMutatorError(t *testing.T) {
	// Try to load non-existent file
	_, err := NewPluginMutator("/nonexistent/file.lua")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}

	// Try to load script without mutate function
	script := `
function wrong_name()
    return {}
end
`
	tmpfile, err := os.CreateTemp("", "test_no_mutate_*.lua")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(script)); err != nil {
		t.Fatal(err)
	}
	tmpfile.Close()

	_, err = NewPluginMutator(tmpfile.Name())
	if err == nil {
		t.Error("Expected error for missing mutate function")
	}
}

func TestHTTPLibBlocksPrivateTargetWhenNotAllowed(t *testing.T) {
	L := lua.NewState()
	defer L.Close()
	registerHTTPLib(L, context.Background(), 2*time.Second, "", false, false)

	req := L.NewTable()
	L.SetField(req, "url", lua.LString("http://127.0.0.1:65535/"))
	if err := L.CallByParam(lua.P{Fn: L.GetGlobal("http_send"), NRet: 1, Protect: true}, req); err != nil {
		t.Fatalf("http_send call failed: %v", err)
	}
	defer L.Pop(1)

	result, ok := L.Get(-1).(*lua.LTable)
	if !ok {
		t.Fatalf("expected result table, got %s", L.Get(-1).Type())
	}
	errMsg := L.GetField(result, "error").String()
	if !strings.Contains(errMsg, "SSRF protection:") {
		t.Fatalf("expected SSRF protection error, got %q", errMsg)
	}
}

func TestHTTPLibAllowsPrivateTargetWhenEnabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	L := lua.NewState()
	defer L.Close()
	registerHTTPLib(L, context.Background(), 2*time.Second, "", false, true)

	req := L.NewTable()
	L.SetField(req, "url", lua.LString(srv.URL))
	if err := L.CallByParam(lua.P{Fn: L.GetGlobal("http_send"), NRet: 1, Protect: true}, req); err != nil {
		t.Fatalf("http_send call failed: %v", err)
	}
	defer L.Pop(1)

	result, ok := L.Get(-1).(*lua.LTable)
	if !ok {
		t.Fatalf("expected result table, got %s", L.Get(-1).Type())
	}
	if errField := L.GetField(result, "error"); errField != lua.LNil {
		t.Fatalf("expected no error, got %q", errField.String())
	}
	if code := L.GetField(result, "status_code").String(); code != "200" {
		t.Fatalf("expected status_code=200, got %s", code)
	}
}

func TestPluginMatcherFallsBackWhenPoolIsBusy(t *testing.T) {
	script := `
function match(response)
    return response.status_code == 200
end
`
	tmpfile, err := os.CreateTemp("", "test_matcher_busy_pool_*.lua")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())
	if _, err := tmpfile.Write([]byte(script)); err != nil {
		t.Fatal(err)
	}
	tmpfile.Close()

	matcher, err := NewPluginMatcher(tmpfile.Name())
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}
	defer matcher.Close()

	// Drain all pooled VMs to simulate saturation.
	borrowed := make([]*lua.LState, 0, cap(matcher.pool))
	for i := 0; i < cap(matcher.pool); i++ {
		borrowed = append(borrowed, <-matcher.pool)
	}
	defer func() {
		for _, L := range borrowed {
			matcher.pool <- L
		}
	}()

	done := make(chan bool, 1)
	go func() {
		matched, _, _ := matcher.Match(200, 10, 1, 1, "ok", "text/plain")
		done <- matched
	}()

	select {
	case matched := <-done:
		if !matched {
			t.Fatal("expected fallback matcher execution to return true")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("matcher blocked while VM pool was saturated")
	}
}
