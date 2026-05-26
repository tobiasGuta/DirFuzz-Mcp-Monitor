package main

import (
	"os"
	"path/filepath"
	"testing"

	"dirfuzz/pkg/engine"
)

func TestValidateHistoryModeDefaults(t *testing.T) {
	cfg := cliConfig{HistoryMode: HistoryModeOverwrite}
	if err := validateHistoryMode(cfg); err != nil {
		t.Fatalf("validateHistoryMode(overwrite) error = %v", err)
	}
}

func TestValidateHistoryModeAppendRequiresOutputFile(t *testing.T) {
	cfg := cliConfig{
		HistoryMode:  HistoryModeAppend,
		OutputFormat: engine.DefaultOutputFormat,
	}
	if err := validateHistoryMode(cfg); err == nil {
		t.Fatal("expected append mode without output file to fail")
	}
}

func TestValidateHistoryModeAppendRequiresJSONL(t *testing.T) {
	cfg := cliConfig{
		HistoryMode:  HistoryModeAppend,
		OutputFile:   "results.csv",
		OutputFormat: "csv",
	}
	if err := validateHistoryMode(cfg); err == nil {
		t.Fatal("expected append mode with csv output to fail")
	}
}

func TestLoadPersistedResultsRestoresRawBytes(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "results.jsonl")
	res := engine.Result{
		Path:          "/admin",
		URL:           "https://example.test/admin",
		Method:        "GET",
		StatusCode:    200,
		Request:       "GET /admin HTTP/1.1\r\nHost: example.test\r\n\r\n",
		Response:      "HTTP/1.1 200 OK\r\n\r\nok",
		RequestBytes:  []byte{0x00, 0x01, 0x02},
		ResponseBytes: []byte{0x03, 0x04, 0x05},
	}
	raw, err := res.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON error = %v", err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	results, err := loadPersistedResults(path)
	if err != nil {
		t.Fatalf("loadPersistedResults error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}
	if got := string(results[0].RequestBytes); got != string(res.RequestBytes) {
		t.Fatalf("RequestBytes = %v, want %v", results[0].RequestBytes, res.RequestBytes)
	}
	if got := string(results[0].ResponseBytes); got != string(res.ResponseBytes) {
		t.Fatalf("ResponseBytes = %v, want %v", results[0].ResponseBytes, res.ResponseBytes)
	}
}

func TestValidateExcludePathsRejectsInvalidRegex(t *testing.T) {
	if err := validateExcludePaths([]string{"logout", "("}); err == nil {
		t.Fatal("expected invalid exclude-path regex to fail validation")
	}
}
