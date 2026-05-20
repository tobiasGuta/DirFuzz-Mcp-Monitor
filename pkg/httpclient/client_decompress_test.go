package httpclient

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"testing"

	"github.com/andybalholm/brotli"
)

func TestDecompressorsCapExpandedOutput(t *testing.T) {
	plain := bytes.Repeat([]byte("A"), MaxBodySize+1024)

	tests := []struct {
		name string
		make func([]byte) ([]byte, error)
	}{
		{
			name: "gzip",
			make: func(src []byte) ([]byte, error) {
				var buf bytes.Buffer
				w := gzip.NewWriter(&buf)
				if _, err := w.Write(src); err != nil {
					return nil, err
				}
				if err := w.Close(); err != nil {
					return nil, err
				}
				return decompressGzip(buf.Bytes())
			},
		},
		{
			name: "zlib-deflate",
			make: func(src []byte) ([]byte, error) {
				var buf bytes.Buffer
				w := zlib.NewWriter(&buf)
				if _, err := w.Write(src); err != nil {
					return nil, err
				}
				if err := w.Close(); err != nil {
					return nil, err
				}
				return decompressDeflate(buf.Bytes())
			},
		},
		{
			name: "raw-deflate",
			make: func(src []byte) ([]byte, error) {
				var buf bytes.Buffer
				w, err := flate.NewWriter(&buf, flate.DefaultCompression)
				if err != nil {
					return nil, err
				}
				if _, err := w.Write(src); err != nil {
					return nil, err
				}
				if err := w.Close(); err != nil {
					return nil, err
				}
				return decompressDeflate(buf.Bytes())
			},
		},
		{
			name: "brotli",
			make: func(src []byte) ([]byte, error) {
				var buf bytes.Buffer
				w := brotli.NewWriter(&buf)
				if _, err := w.Write(src); err != nil {
					return nil, err
				}
				if err := w.Close(); err != nil {
					return nil, err
				}
				return decompressBrotli(buf.Bytes())
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.make(plain)
			if err != nil {
				t.Fatalf("decompression failed: %v", err)
			}
			if len(got) > MaxBodySize {
				t.Fatalf("decompressed length = %d, want <= %d", len(got), MaxBodySize)
			}
			if len(got) != MaxBodySize {
				t.Fatalf("decompressed length = %d, want %d", len(got), MaxBodySize)
			}
			if !bytes.Equal(got[:32], bytes.Repeat([]byte("A"), 32)) {
				t.Fatalf("unexpected decompressed prefix: %q", got[:32])
			}
		})
	}
}

func TestDecompressorsReturnEmptyBodyUnchanged(t *testing.T) {
	tests := []struct {
		name string
		fn   func([]byte) ([]byte, error)
	}{
		{name: "gzip", fn: decompressGzip},
		{name: "deflate", fn: decompressDeflate},
		{name: "brotli", fn: decompressBrotli},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.fn(nil)
			if err != nil {
				t.Fatalf("expected no error for empty body: %v", err)
			}
			if len(got) != 0 {
				t.Fatalf("expected empty output, got %d bytes", len(got))
			}
			if got != nil {
				t.Fatalf("expected nil result for nil input, got %#v", got)
			}
		})
	}
}
