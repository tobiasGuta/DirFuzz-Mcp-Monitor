package engine

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func TestSanitizeHeaderToken(t *testing.T) {
	got := sanitizeHeaderToken("X-Test\r\nInjected: 1\rValue\n")
	want := "X-TestInjected: 1Value"
	if got != want {
		t.Fatalf("sanitizeHeaderToken() = %q, want %q", got, want)
	}
}

func TestBuildRequestSetsAcceptEncodingIdentity(t *testing.T) {
	raw := string(buildRequest("GET", "/admin", "example.com", "DirFuzz/2.0", "", ""))
	if !strings.Contains(raw, "Accept-Encoding: identity\r\n") {
		t.Fatalf("request missing Accept-Encoding identity header: %q", raw)
	}
}

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

func TestSimhashBodyIsStable(t *testing.T) {
	body := []byte("Page /foo not found")
	if got, want := simhashBody(body), simhashBody(body); got != want {
		t.Fatalf("simhashBody() = %d, want %d", got, want)
	}
}

func TestSimhashSoft404Clustering(t *testing.T) {
	eng := NewEngine(1, 100, 0.01)
	eng.SimhashThreshold = 3
	eng.SimhashClusterLimit = 2

	if eng.isSimhashSoftFour(0x1234567890abcdef) {
		t.Fatal("first cluster member should not be suppressed")
	}
	if !eng.isSimhashSoftFour(0x1234567890abcdee) {
		t.Fatal("second close cluster member should be suppressed at the limit")
	}
	if !eng.isSimhashSoftFour(0x1234567890abcded) {
		t.Fatal("subsequent close cluster member should stay suppressed")
	}
	if eng.isSimhashSoftFour(0xfedcba0987654321) {
		t.Fatal("distant hash should start a fresh cluster")
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

func TestAutoCalibrateUsesNormalizedBodySize(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "missing %s", r.URL.Path)
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

	expectedSize := len("missing /FUZZ")
	if !eng.Config.FilterSizes[expectedSize] {
		t.Fatalf("expected normalized filter size %d to be added; got %+v", expectedSize, eng.Config.FilterSizes)
	}
}

func TestAutoCalibrateUsesPayloadPlaceholderInBaseURL(t *testing.T) {
	var nonSearchCalls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/search" {
			n := atomic.AddInt32(&nonSearchCalls, 1)
			fmt.Fprintf(w, "wrong-route-%d", n)
			return
		}
		q := r.URL.Query().Get("q")
		fmt.Fprintf(w, "missing %s", q)
	}))
	defer server.Close()

	eng := NewEngine(1, 100, 0.01)
	eng.Config.Lock()
	eng.Config.AllowPrivateTargets = true
	eng.Config.Unlock()
	if err := eng.SetTarget(server.URL + "/search?q={PAYLOAD}"); err != nil {
		t.Fatalf("SetTarget() failed: %v", err)
	}

	if err := eng.AutoCalibrate(); err != nil {
		t.Fatalf("AutoCalibrate() failed: %v", err)
	}

	if atomic.LoadInt32(&nonSearchCalls) != 0 {
		t.Fatalf("expected calibration to use /search path only, got %d non-search calls", nonSearchCalls)
	}
	expectedSize := len("missing FUZZ")
	if !eng.Config.FilterSizes[expectedSize] {
		t.Fatalf("expected normalized filter size %d to be added; got %+v", expectedSize, eng.Config.FilterSizes)
	}
}

func TestIsSameSpiderScopeHostIgnoresPort(t *testing.T) {
	absSameHost, err := url.Parse("http://example.com:8080/admin")
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}
	if !isSameSpiderScopeHost("example.com", absSameHost) {
		t.Fatal("expected same hostname to match even when absolute URL includes port")
	}

	absDifferentHost, err := url.Parse("http://other.example.com:8080/admin")
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}
	if isSameSpiderScopeHost("example.com", absDifferentHost) {
		t.Fatal("expected different hostname to be rejected")
	}

	relative, err := url.Parse("/admin")
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}
	if !isSameSpiderScopeHost("example.com", relative) {
		t.Fatal("expected relative link to be accepted")
	}
}

func TestSetRPSUpdatesLimiterBurst(t *testing.T) {
	eng := NewEngine(50, 1000, 0.01)
	limiter := eng.getLimiter("example.com:443")
	if limiter.Burst() != eng.currentBurst {
		t.Fatalf("initial limiter burst = %d, want %d", limiter.Burst(), eng.currentBurst)
	}

	eng.SetRPS(1)

	if eng.currentLimit != rate.Limit(1) {
		t.Fatalf("currentLimit = %v, want %v", eng.currentLimit, rate.Limit(1))
	}
	if eng.currentBurst != MinRateLimitBurst {
		t.Fatalf("currentBurst = %d, want %d", eng.currentBurst, MinRateLimitBurst)
	}
	if limiter.Burst() != MinRateLimitBurst {
		t.Fatalf("existing limiter burst = %d, want %d", limiter.Burst(), MinRateLimitBurst)
	}

	newLimiter := eng.getLimiter("another.example.com:443")
	if newLimiter.Burst() != MinRateLimitBurst {
		t.Fatalf("new limiter burst = %d, want %d", newLimiter.Burst(), MinRateLimitBurst)
	}
}

func TestLoadResumeStateRestoresBloomFilter(t *testing.T) {
	tmpDir := t.TempDir()
	resumePath := filepath.Join(tmpDir, "resume.json")

	eng1 := NewEngine(2, 100, 0.01)
	eng1.ResumeFile = resumePath
	eng1.shardedFilter.TestAndAddString("GET:/admin")
	eng1.shardedFilter.TestAndAddString("GET:/secret")
	eng1.saveResumeState("wordlists/common.txt", 42, true)

	eng2 := NewEngine(2, 100, 0.01)
	eng2.ResumeFile = resumePath
	wordlist, line, err := eng2.LoadResumeState(resumePath)
	if err != nil {
		t.Fatalf("LoadResumeState() failed: %v", err)
	}
	if wordlist != "wordlists/common.txt" || line != 42 {
		t.Fatalf("resume state mismatch: wordlist=%q line=%d", wordlist, line)
	}
	if !eng2.shardedFilter.TestAndAddString("GET:/admin") {
		t.Fatal("expected restored bloom filter to mark GET:/admin as already seen")
	}
	if !eng2.shardedFilter.TestAndAddString("GET:/secret") {
		t.Fatal("expected restored bloom filter to mark GET:/secret as already seen")
	}
	if eng2.shardedFilter.TestAndAddString("GET:/new") {
		t.Fatal("expected unseen key to be accepted after bloom restore")
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

func TestVerbTamperHeaders(t *testing.T) {
	tests := []struct {
		name   string
		method string
		want   map[string]string
	}{
		{
			name:   "GET returns nil",
			method: "GET",
			want:   nil,
		},
		{
			name:   "HEAD returns nil",
			method: "HEAD",
			want:   nil,
		},
		{
			name:   "DELETE returns override headers",
			method: "DELETE",
			want: map[string]string{
				"X-HTTP-Method-Override": "DELETE",
				"X-Forwarded-Method":     "DELETE",
				"X-Method-Override":      "DELETE",
			},
		},
		{
			name:   "PATCH returns override headers",
			method: "PATCH",
			want: map[string]string{
				"X-HTTP-Method-Override": "PATCH",
				"X-Forwarded-Method":     "PATCH",
				"X-Method-Override":      "PATCH",
			},
		},
		{
			name:   "POST returns override headers",
			method: "POST",
			want: map[string]string{
				"X-HTTP-Method-Override": "POST",
				"X-Forwarded-Method":     "POST",
				"X-Method-Override":      "POST",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := verbTamperHeaders(tt.method)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("verbTamperHeaders(%q) = %#v, want %#v", tt.method, got, tt.want)
			}
		})
	}
}

func TestWorkerVerbTamperHonorsManualOverrideHeader(t *testing.T) {
	type observed struct {
		xHTTPMethodOverride string
		xForwardedMethod    string
		xMethodOverride     string
	}

	observedCh := make(chan observed, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observedCh <- observed{
			xHTTPMethodOverride: r.Header.Get("X-HTTP-Method-Override"),
			xForwardedMethod:    r.Header.Get("X-Forwarded-Method"),
			xMethodOverride:     r.Header.Get("X-Method-Override"),
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	eng := NewEngine(1, 100, 0.01)
	eng.Config.Lock()
	eng.Config.AllowPrivateTargets = true
	eng.Config.Unlock()
	if err := eng.SetTarget(server.URL); err != nil {
		t.Fatalf("SetTarget() failed: %v", err)
	}
	eng.UpdateConfig(func(c *Config) {
		c.VerbTamper = true
	})

	eng.Start()
	defer eng.Shutdown()

	runID := atomic.LoadInt64(&eng.RunID)
	eng.Submit(Job{
		Path:   "/tamper",
		Depth:  0,
		Method: "DELETE",
		RunID:  runID,
		ExtraHeaders: map[string]string{
			"X-HTTP-Method-Override": "PUT",
		},
	})
	eng.Wait()

	select {
	case got := <-observedCh:
		if got.xHTTPMethodOverride != "PUT" {
			t.Fatalf("manual override should win: got X-HTTP-Method-Override=%q, want %q", got.xHTTPMethodOverride, "PUT")
		}
		if got.xForwardedMethod != "DELETE" {
			t.Fatalf("expected auto X-Forwarded-Method to remain method value: got %q, want %q", got.xForwardedMethod, "DELETE")
		}
		if got.xMethodOverride != "DELETE" {
			t.Fatalf("expected auto X-Method-Override to remain method value: got %q, want %q", got.xMethodOverride, "DELETE")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for worker request")
	}
}
