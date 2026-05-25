package engine

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	defaultPassiveHarvestSourceTimeout  = 6 * time.Second
	defaultPassiveHarvestOverallTimeout = 18 * time.Second
	passiveHarvestResultLimit           = 1000
)

var (
	passiveWaybackCDXURL             = "https://web.archive.org/cdx/search/cdx"
	passiveCommonCrawlCollectionURL  = "https://index.commoncrawl.org/collinfo.json"
	passiveCommonCrawlIndexBaseURL   = "https://index.commoncrawl.org"
	passiveAlienVaultOTXBaseURL      = "https://otx.alienvault.com/api/v1"
)

func (e *Engine) shouldRunPassiveHarvest() bool {
	if e == nil || e.Config == nil {
		return false
	}
	e.Config.RLock()
	enabled := e.Config.HarvestPassive || e.Config.Harvest
	e.Config.RUnlock()
	return enabled
}

// StartPassiveHarvesting queries passive URL sources and queues the discovered
// paths into the live scan. The work is bounded by short per-source timeouts so
// a slow source cannot stall the scan lifecycle indefinitely.
func (e *Engine) StartPassiveHarvesting(ctx context.Context, runID int64, target string) {
	defer e.scannerWg.Done()

	if !e.shouldRunPassiveHarvest() {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}

	base := strings.TrimSpace(target)
	if base == "" {
		base = e.BaseURL()
	}
	if base == "" {
		return
	}

	parsedBase, err := url.Parse(base)
	if err != nil {
		e.emitLogEvent(LogLevelWarning, LogCategoryDiscovery, EventHarvestParseError, "passive harvest base URL could not be parsed", map[string]interface{}{
			"target": base,
			"error":  err.Error(),
		})
		return
	}

	e.Config.RLock()
	otxKey := strings.TrimSpace(e.Config.HarvestOTXKey)
	sourceTimeout := defaultPassiveHarvestSourceTimeout
	if e.Config.Timeout > 0 && e.Config.Timeout < sourceTimeout {
		sourceTimeout = e.Config.Timeout
	}
	e.Config.RUnlock()
	if sourceTimeout <= 0 {
		sourceTimeout = defaultPassiveHarvestSourceTimeout
	}
	overallTimeout := defaultPassiveHarvestOverallTimeout
	if sourceTimeout*3 > overallTimeout {
		overallTimeout = sourceTimeout * 3
	}
	if overallTimeout < sourceTimeout {
		overallTimeout = sourceTimeout
	}

	overallCtx, cancel := context.WithTimeout(ctx, overallTimeout)
	defer cancel()

	client := &http.Client{Timeout: sourceTimeout}

	type passiveSource struct {
		name string
		run  func(context.Context) ([]string, error)
	}

	sources := []passiveSource{
		{
			name: "wayback",
			run: func(ctx context.Context) ([]string, error) {
				return fetchWaybackPassivePaths(ctx, client, parsedBase)
			},
		},
		{
			name: "commoncrawl",
			run: func(ctx context.Context) ([]string, error) {
				return fetchCommonCrawlPassivePaths(ctx, client, parsedBase)
			},
		},
	}
	if otxKey != "" {
		sources = append(sources, passiveSource{
			name: "alienvault-otx",
			run: func(ctx context.Context) ([]string, error) {
				return fetchAlienVaultOTXPassivePaths(ctx, client, parsedBase, otxKey)
			},
		})
	} else {
		e.emitLogEvent(LogLevelInfo, LogCategoryDiscovery, EventHarvestParseError, "alienvault otx passive harvest skipped; no API key configured", map[string]interface{}{
			"source": "alienvault-otx",
		})
	}

	var wg sync.WaitGroup
	for _, source := range sources {
		source := source
		wg.Add(1)
		go func() {
			defer wg.Done()

			sourceCtx, cancel := context.WithTimeout(overallCtx, sourceTimeout)
			defer cancel()

			paths, err := source.run(sourceCtx)
			if err != nil {
				if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
					e.emitLogEvent(LogLevelWarning, LogCategoryDiscovery, EventHarvestParseError, "passive harvest source timed out", map[string]interface{}{
						"source": source.name,
						"error":  err.Error(),
					})
					return
				}
				e.emitLogEvent(LogLevelWarning, LogCategoryDiscovery, EventHarvestParseError, "passive harvest source failed", map[string]interface{}{
					"source": source.name,
					"error":  err.Error(),
				})
				return
			}

			e.ingestPassiveHarvestPaths(parsedBase, runID, source.name, paths)
		}()
	}

	wg.Wait()
}

func (e *Engine) ingestPassiveHarvestPaths(base *url.URL, runID int64, source string, paths []string) {
	if e == nil || base == nil {
		return
	}

	seen := make(map[string]struct{}, len(paths))
	for _, candidate := range paths {
		normalized := canonicalPassiveHarvestCandidate(base, candidate)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}

		e.emitLogEvent(LogLevelInfo, LogCategoryDiscovery, EventHarvestDiscovery, fmt.Sprintf("discovered passive endpoint %s", normalized), map[string]interface{}{
			"path":   normalized,
			"source": source,
		})
		e.SubmitHarvestPath(normalized, runID, 0)
	}
}

func fetchWaybackPassivePaths(ctx context.Context, client *http.Client, base *url.URL) ([]string, error) {
	host := passiveHarvestScopeHost(base)
	if host == "" {
		return nil, errors.New("missing target hostname")
	}

	endpoint, err := url.Parse(passiveWaybackCDXURL)
	if err != nil {
		return nil, err
	}
	q := endpoint.Query()
	q.Set("url", host+"/*")
	q.Set("matchType", "prefix")
	q.Set("output", "json")
	q.Set("fl", "original")
	q.Set("collapse", "urlkey")
	q.Set("limit", strconv.Itoa(passiveHarvestResultLimit))
	endpoint.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("wayback returned HTTP %d", resp.StatusCode)
	}

	dec := json.NewDecoder(resp.Body)
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '[' {
		return nil, errors.New("unexpected wayback response format")
	}

	var headers []string
	if !dec.More() {
		return nil, nil
	}
	if err := dec.Decode(&headers); err != nil {
		return nil, err
	}
	idx := indexOfCaseInsensitive(headers, "original")
	if idx < 0 {
		idx = 0
	}

	paths := make([]string, 0, 64)
	for dec.More() {
		var row []string
		if err := dec.Decode(&row); err != nil {
			return nil, err
		}
		if idx < len(row) {
			paths = append(paths, row[idx])
		}
	}
	return paths, nil
}

func fetchCommonCrawlPassivePaths(ctx context.Context, client *http.Client, base *url.URL) ([]string, error) {
	host := passiveHarvestScopeHost(base)
	if host == "" {
		return nil, errors.New("missing target hostname")
	}

	collectionURL, err := url.Parse(passiveCommonCrawlCollectionURL)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, collectionURL.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("commoncrawl collection list returned HTTP %d", resp.StatusCode)
	}

	var collections []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&collections); err != nil {
		return nil, err
	}
	if len(collections) == 0 {
		return nil, errors.New("commoncrawl collection list is empty")
	}

	indexURL := stringFromMap(collections[0], "cdx-api", "cdxApi", "cdx_api")
	if indexURL == "" {
		name := stringFromMap(collections[0], "name", "id")
		if name == "" {
			return nil, errors.New("commoncrawl collection entry missing index url")
		}
		indexURL = strings.TrimRight(passiveCommonCrawlIndexBaseURL, "/") + "/" + name + "-index"
	}

	indexEndpoint, err := url.Parse(indexURL)
	if err != nil {
		return nil, err
	}
	q := indexEndpoint.Query()
	q.Set("url", host+"/*")
	q.Set("output", "json")
	q.Set("fl", "url")
	q.Set("collapse", "urlkey")
	q.Set("pageSize", strconv.Itoa(passiveHarvestResultLimit))
	indexEndpoint.RawQuery = q.Encode()

	req, err = http.NewRequestWithContext(ctx, http.MethodGet, indexEndpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err = client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("commoncrawl index returned HTTP %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	paths := make([]string, 0, 64)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var row map[string]any
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}
		if candidate := stringFromMap(row, "url", "original", "target", "path"); candidate != "" {
			paths = append(paths, candidate)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return paths, nil
}

func fetchAlienVaultOTXPassivePaths(ctx context.Context, client *http.Client, base *url.URL, apiKey string) ([]string, error) {
	if strings.TrimSpace(apiKey) == "" {
		return nil, errors.New("missing OTX API key")
	}
	host := passiveHarvestScopeHost(base)
	if host == "" {
		return nil, errors.New("missing target hostname")
	}

	otxEndpoint := strings.TrimRight(passiveAlienVaultOTXBaseURL, "/") + "/indicators/hostname/" + url.PathEscape(host) + "/url_list"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, otxEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-OTX-API-KEY", apiKey)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("otx returned HTTP %d", resp.StatusCode)
	}

	var payload struct {
		URLList struct {
			URLList []struct {
				URL string `json:"url"`
			} `json:"url_list"`
		} `json:"url_list"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}

	paths := make([]string, 0, len(payload.URLList.URLList))
	for _, item := range payload.URLList.URLList {
		if item.URL != "" {
			paths = append(paths, item.URL)
		}
	}
	return paths, nil
}

func canonicalPassiveHarvestCandidate(base *url.URL, candidate string) string {
	candidate = strings.TrimSpace(strings.Trim(candidate, "\"'`"))
	if candidate == "" {
		return ""
	}

	if resolved, ok := resolveHarvestRef(base, candidate); ok {
		candidate = resolved
	}

	candidate = strings.ReplaceAll(candidate, "\r", "")
	candidate = strings.ReplaceAll(candidate, "\n", "")
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return ""
	}
	if strings.HasPrefix(candidate, "javascript:") || strings.HasPrefix(candidate, "data:") {
		return ""
	}
	if strings.Contains(candidate, "://") {
		parsed, err := url.Parse(candidate)
		if err == nil {
			if base != nil && !samePassiveOrigin(base, parsed) {
				return ""
			}
			candidate = parsed.Path
			if parsed.RawQuery != "" {
				candidate += "?" + parsed.RawQuery
			}
		}
	}
	if normalizedQuery := normalizeHarvestQuery(candidate); normalizedQuery != "" {
		candidate = normalizedQuery
	}
	if strings.Contains(candidate, "/") && !strings.HasPrefix(candidate, "/") {
		candidate = "/" + candidate
	}
	if candidate == "/" {
		return ""
	}
	if strings.ContainsFunc(candidate, unicode.IsSpace) {
		return ""
	}
	return candidate
}

func samePassiveOrigin(base, other *url.URL) bool {
	if base == nil || other == nil {
		return false
	}
	baseHost := strings.ToLower(strings.TrimSpace(base.Hostname()))
	otherHost := strings.ToLower(strings.TrimSpace(other.Hostname()))
	if baseHost == "" || otherHost == "" {
		return false
	}
	if baseHost == otherHost {
		return true
	}
	if strings.HasSuffix(otherHost, "."+baseHost) || strings.HasSuffix(baseHost, "."+otherHost) {
		return true
	}
	return false
}

func passiveHarvestScopeHost(base *url.URL) string {
	if base == nil {
		return ""
	}
	host := strings.TrimSpace(base.Hostname())
	if host != "" {
		return host
	}
	return strings.TrimSpace(base.Host)
}

func indexOfCaseInsensitive(values []string, want string) int {
	want = strings.TrimSpace(strings.ToLower(want))
	for i, value := range values {
		if strings.TrimSpace(strings.ToLower(value)) == want {
			return i
		}
	}
	return -1
}

func stringFromMap(m map[string]any, keys ...string) string {
	for _, key := range keys {
		if val, ok := m[key]; ok {
			switch typed := val.(type) {
			case string:
				if strings.TrimSpace(typed) != "" {
					return typed
				}
			case fmt.Stringer:
				if s := strings.TrimSpace(typed.String()); s != "" {
					return s
				}
			}
		}
	}
	return ""
}
