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
		Method:        "GET",
		StatusCode:    403,
		Size:          21,
		Words:         2,
		RequestBytes:  []byte{0x01, 0x02},
		ResponseBytes: []byte("HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nnope drift"),
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
	prev, ok := eng.PreviousState[previousScanKey("GET", "/drift")]
	if !ok {
		t.Fatal("expected previous scan entry for GET /drift")
	}
	if prev.StatusCode != 403 {
		t.Fatalf("PreviousState status = %d, want 403", prev.StatusCode)
	}
	if prev.Size != 21 {
		t.Fatalf("PreviousState size = %d, want 21", prev.Size)
	}
	if prev.Words != 2 {
		t.Fatalf("PreviousState words = %d, want 2", prev.Words)
	}
	if prev.BodyHash == "" {
		t.Fatal("expected previous scan body hash to be populated")
	}
}

func TestApplyEagleDriftFlagsNewEndpoints(t *testing.T) {
	eng := NewEngine(1, 1000, 0.01)
	res := Result{Path: "/new", Method: "GET", StatusCode: 200, Size: 12, Words: 1}

	eng.applyEagleDrift(&res, eagleBodyHash([]byte("fresh")))

	if !res.IsEagleAlert {
		t.Fatal("expected eagle alert for new endpoint")
	}
	if !res.IsEagleNewEndpoint {
		t.Fatal("expected new endpoint eagle flag")
	}
}

func TestApplyEagleDriftFlagsStatusSizeAndContentChanges(t *testing.T) {
	eng := NewEngine(1, 1000, 0.01)
	eng.PreviousState = map[string]previousScanEntry{
		previousScanKey("GET", "/drift"): {
			StatusCode: 401,
			Size:       10,
			Words:      2,
			BodyHash:   eagleBodyHash([]byte("old body")),
		},
	}
	res := Result{Path: "/drift", Method: "GET", StatusCode: 200, Size: 25, Words: 4}

	eng.applyEagleDrift(&res, eagleBodyHash([]byte("new body")))

	if !res.IsEagleAlert {
		t.Fatal("expected eagle alert")
	}
	if !res.StatusDrift || res.OldStatusCode != 401 {
		t.Fatalf("status drift = %v old=%d, want true/401", res.StatusDrift, res.OldStatusCode)
	}
	if !res.SizeDrift || res.OldSize != 10 || res.DriftDeltaBytes != 15 {
		t.Fatalf("size drift old=%d delta=%d, want 10/15", res.OldSize, res.DriftDeltaBytes)
	}
	if !res.ContentDrift || res.OldWords != 2 {
		t.Fatalf("content drift = %v old words=%d, want true/2", res.ContentDrift, res.OldWords)
	}
}

func TestApplyEagleDriftUsesLegacyPathKeyFallback(t *testing.T) {
	eng := NewEngine(1, 1000, 0.01)
	eng.PreviousState = map[string]previousScanEntry{
		"/legacy": {
			StatusCode: 200,
			Size:       8,
			Words:      1,
		},
	}
	res := Result{Path: "/legacy", Method: "GET", StatusCode: 200, Size: 9, Words: 1}

	eng.applyEagleDrift(&res, "")

	if !res.SizeDrift {
		t.Fatal("expected size drift via legacy path fallback")
	}
}
