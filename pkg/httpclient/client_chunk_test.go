package httpclient

import "testing"

func TestDechunkBodyRejectsHugeDeclaredChunkWithoutOOM(t *testing.T) {
	body := []byte("7FFFFFFFFFFFFFFF\r\nabc\r\n0\r\n\r\n")

	got, trailers := dechunkBody(body)
	if trailers != nil {
		t.Fatalf("expected no trailers, got %#v", trailers)
	}
	if len(got) > MaxBodySize {
		t.Fatalf("dechunked body length = %d, want <= %d", len(got), MaxBodySize)
	}
	if len(got) == 0 {
		t.Fatalf("expected some bytes to be returned, got none")
	}
}
