package engine

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestCanonicalPassiveHarvestCandidate(t *testing.T) {
	base, err := http.NewRequest(http.MethodGet, "https://example.com/app/", nil)
	if err != nil {
		t.Fatal(err)
	}
	parsedBase := base.URL

	tests := []struct {
		name     string
		candidate string
		want     string
	}{
		{
			name:      "same-host-absolute",
			candidate: "https://example.com/api/v1/legacy_export",
			want:      "/api/v1/legacy_export",
		},
		{
			name:      "subdomain-absolute",
			candidate: "http://www.example.com/admin",
			want:      "/admin",
		},
		{
			name:      "external-host-rejected",
			candidate: "https://evil.test/steal",
			want:      "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := canonicalPassiveHarvestCandidate(parsedBase, tc.candidate); got != tc.want {
				t.Fatalf("canonicalPassiveHarvestCandidate(%q) = %q, want %q", tc.candidate, got, tc.want)
			}
		})
	}
}

func TestPassiveHarvestingQueuesAndTimesOutSlowSource(t *testing.T) {
	oldWaybackURL := passiveWaybackCDXURL
	oldCommonCrawlCollectionURL := passiveCommonCrawlCollectionURL
	oldCommonCrawlIndexBaseURL := passiveCommonCrawlIndexBaseURL
	oldOTXBaseURL := passiveAlienVaultOTXBaseURL
	defer func() {
		passiveWaybackCDXURL = oldWaybackURL
		passiveCommonCrawlCollectionURL = oldCommonCrawlCollectionURL
		passiveCommonCrawlIndexBaseURL = oldCommonCrawlIndexBaseURL
		passiveAlienVaultOTXBaseURL = oldOTXBaseURL
	}()

	targetHits := make(map[string]int)
	var targetMu sync.Mutex
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetMu.Lock()
		targetHits[r.URL.Path]++
		targetMu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer targetSrv.Close()

	waybackSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[["original"],["` + targetSrv.URL + `/wayback-only"]]`))
	}))
	defer waybackSrv.Close()

	commonCrawlBaseURL := ""
	commonCrawlSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/collinfo.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"cdx-api":"` + commonCrawlBaseURL + `/cc-index"}]`))
		case "/cc-index":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"url":"` + targetSrv.URL + `/api/v1/legacy_export"}
{"url":"` + targetSrv.URL + `/reports/list"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer commonCrawlSrv.Close()
	commonCrawlBaseURL = commonCrawlSrv.URL

	otxSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/indicators/hostname/127.0.0.1/url_list" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"url_list":{"url_list":[{"url":"` + targetSrv.URL + `/oob/otx"}]}}`))
	}))
	defer otxSrv.Close()

	passiveWaybackCDXURL = waybackSrv.URL + "/cdx/search/cdx"
	passiveCommonCrawlCollectionURL = commonCrawlSrv.URL + "/collinfo.json"
	passiveCommonCrawlIndexBaseURL = commonCrawlSrv.URL
	passiveAlienVaultOTXBaseURL = otxSrv.URL + "/api/v1"

	wordlistPath := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(wordlistPath, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	eng := NewEngine(2, DefaultBloomFilterSize, DefaultBloomFilterFP)
	defer eng.Shutdown()
	eng.UpdateConfig(func(c *Config) {
		c.AllowPrivateTargets = true
		c.Timeout = 200 * time.Millisecond
		c.HarvestPassive = true
		c.HarvestOTXKey = "test-key"
	})
	if err := eng.SetTarget(targetSrv.URL); err != nil {
		t.Fatalf("SetTarget() error = %v", err)
	}

	start := time.Now()
	eng.Start()
	eng.KickoffScanner(wordlistPath, 0)
	eng.Wait()
	eng.Shutdown()

	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("passive harvesting took too long: %s", elapsed)
	}

	targetMu.Lock()
	defer targetMu.Unlock()

	if got := targetHits["/api/v1/legacy_export"]; got == 0 {
		t.Fatalf("expected common crawl path to be queued, hits=%v", targetHits)
	}
	if got := targetHits["/reports/list"]; got == 0 {
		t.Fatalf("expected common crawl secondary path to be queued, hits=%v", targetHits)
	}
	if got := targetHits["/oob/otx"]; got == 0 {
		t.Fatalf("expected OTX path to be queued, hits=%v", targetHits)
	}
	if got := targetHits["/wayback-only"]; got != 0 {
		t.Fatalf("expected slow wayback source to time out before queueing results, hits=%v", targetHits)
	}
}
