package engine

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
)

func TestClassify403(t *testing.T) {
	tests := []struct {
		name     string
		body     []byte
		headers  string
		expected string
	}{
		{
			name:     "Cloudflare WAF Block",
			body:     []byte("Attention Required! | Cloudflare"),
			headers:  "HTTP/1.1 403 Forbidden\r\nServer: cloudflare\r\n",
			expected: Forbidden403TypeCFWAFBlock,
		},
		{
			name:     "Cloudflare Admin 403",
			body:     []byte("request forbidden by administrative rules"),
			headers:  "HTTP/1.1 403 Forbidden\r\nCF-RAY: 123456789-SJC\r\n",
			expected: Forbidden403TypeCFAdmin403,
		},
		{
			name:     "Nginx 403",
			body:     []byte("<center>nginx</center>"),
			headers:  "HTTP/1.1 403 Forbidden\r\nServer: nginx\r\n",
			expected: Forbidden403TypeNginx403,
		},
		{
			name:     "Generic 403",
			body:     []byte("Forbidden"),
			headers:  "HTTP/1.1 403 Forbidden\r\n",
			expected: Forbidden403TypeGeneric403,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Classify403(tt.body, tt.headers); got != tt.expected {
				t.Errorf("Classify403() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestAutoCalibrate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Wildcard response")
	}))
	defer server.Close()

	eng := NewEngine(1, 100, 0.01)
	eng.Config.Lock()
	eng.Config.AllowPrivateTargets = true
	eng.Config.Unlock()
	if err := eng.SetTarget(server.URL); err != nil {
		t.Fatalf("SetTarget() failed: %v", err)
	}

	if err := eng.AutoCalibrate(); err != nil {
		t.Fatalf("AutoCalibrate() failed: %v", err)
	}

	// This is a simplified check. A more robust test would inspect the filter.
	if len(eng.Config.FilterSizes) == 0 {
		t.Errorf("AutoCalibrate() did not add a filter size")
	}
}

func TestChangeWordlistConcurrency(t *testing.T) {
	// Create a dummy wordlist file
	tmpfile, err := os.CreateTemp("", "wordlist")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())
	if _, err := tmpfile.WriteString("test\n"); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	eng := NewEngine(10, 1000, 0.01)
	eng.SetTarget("http://localhost:12345") // Dummy target

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				_ = eng.ChangeWordlist(tmpfile.Name())
			}
		}()
	}
	wg.Wait()
}
