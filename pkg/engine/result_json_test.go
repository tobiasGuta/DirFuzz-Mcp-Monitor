package engine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResultJSONRoundTripPreservesRawBytes(t *testing.T) {
	original := Result{
		Path:          "/secret",
		Method:        "GET",
		StatusCode:    200,
		Request:       "GET /secret HTTP/1.1\r\nHost: example.test\r\n\r\n",
		Response:      "HTTP/1.1 200 OK\r\n\r\nok",
		RequestBytes:  []byte{0x01, 0x02, 0x03},
		ResponseBytes: []byte{0x04, 0x05, 0x06},
	}

	raw, err := original.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON error = %v", err)
	}

	var restored Result
	if err := restored.UnmarshalJSON(raw); err != nil {
		t.Fatalf("UnmarshalJSON error = %v", err)
	}

	if string(restored.RequestBytes) != string(original.RequestBytes) {
		t.Fatalf("RequestBytes = %v, want %v", restored.RequestBytes, original.RequestBytes)
	}
	if string(restored.ResponseBytes) != string(original.ResponseBytes) {
		t.Fatalf("ResponseBytes = %v, want %v", restored.ResponseBytes, original.ResponseBytes)
	}
}

func TestLoadPreviousScanAcceptsExtendedResultJSON(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "previous.jsonl")

	res := Result{
		Path:          "/drift",
		StatusCode:    403,
		RequestBytes:  []byte{0x01, 0x02},
		ResponseBytes: []byte{0x03, 0x04},
	}
	raw, err := res.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON error = %v", err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	eng := NewEngine(1, 1000, 0.01)
	if err := eng.LoadPreviousScan(path); err != nil {
		t.Fatalf("LoadPreviousScan error = %v", err)
	}
	if got := eng.PreviousState["/drift"]; got != 403 {
		t.Fatalf("PreviousState[/drift] = %d, want 403", got)
	}
}
