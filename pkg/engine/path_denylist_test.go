package engine

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync"
	"sync/atomic"
	"testing"
)

func TestPathExcludedByRegexpsMatchesCanonicalPath(t *testing.T) {
	regexps := []*regexp.Regexp{
		regexp.MustCompile(`(?i)logout`),
		regexp.MustCompile(`delete_account`),
	}

	if !pathExcludedByRegexps("http://example.com/logout?next=%2Fadmin", regexps) {
		t.Fatal("expected full URL logout path to be excluded")
	}
	if !pathExcludedByRegexps("/api/v1/delete_account", regexps) {
		t.Fatal("expected matching request path to be excluded")
	}
	if pathExcludedByRegexps("/profile", regexps) {
		t.Fatal("did not expect unrelated path to be excluded")
	}
}

func TestSubmitSkipsExcludedPaths(t *testing.T) {
	var (
		mu       sync.Mutex
		requests []string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, r.URL.RequestURI())
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	eng := NewEngine(1, 100, 0.01)
	defer eng.Shutdown()
	eng.Config.Lock()
	eng.Config.AllowPrivateTargets = true
	eng.Config.ExcludePathPatterns = []string{`(?i)logout|delete`}
	eng.Config.Unlock()
	eng.RefreshConfigSnapshot()
	if err := eng.SetTarget(server.URL); err != nil {
		t.Fatalf("SetTarget() failed: %v", err)
	}

	eng.Start()
	runID := atomic.LoadInt64(&eng.RunID)
	eng.Submit(Job{Path: "/logout", Method: http.MethodGet, RunID: runID})
	eng.Submit(Job{Path: "/profile", Method: http.MethodGet, RunID: runID})
	eng.Wait()

	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 1 {
		t.Fatalf("expected exactly one request after exclusions, got %d (%v)", len(requests), requests)
	}
	if requests[0] != "/profile" {
		t.Fatalf("expected allowed path to be requested, got %q", requests[0])
	}
}

func TestSubmitHarvestPathSkipsExcludedPaths(t *testing.T) {
	var (
		mu       sync.Mutex
		requests []string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, r.URL.RequestURI())
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	eng := NewEngine(1, 100, 0.01)
	defer eng.Shutdown()
	eng.Config.Lock()
	eng.Config.AllowPrivateTargets = true
	eng.Config.ExcludePathPatterns = []string{`(?i)logout|delete`}
	eng.Config.Unlock()
	eng.RefreshConfigSnapshot()
	if err := eng.SetTarget(server.URL); err != nil {
		t.Fatalf("SetTarget() failed: %v", err)
	}

	eng.Start()
	runID := atomic.LoadInt64(&eng.RunID)
	eng.SubmitHarvestPath("/logout", runID, 0)
	eng.SubmitHarvestPath("/admin", runID, 0)
	eng.Wait()

	if got := atomic.LoadInt64(&eng.HarvestedPaths); got != 1 {
		t.Fatalf("HarvestedPaths = %d, want 1", got)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 1 {
		t.Fatalf("expected exactly one harvested request after exclusions, got %d (%v)", len(requests), requests)
	}
	if requests[0] != "/admin" {
		t.Fatalf("expected allowed harvested path to be requested, got %q", requests[0])
	}
}
