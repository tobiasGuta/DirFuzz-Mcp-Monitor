package engine

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
)

const sourceMapHarvestBodyLimit = 10 * 1024 * 1024

var sourceMapRouteRe = regexp.MustCompile(`(?i)(?:/api/[A-Za-z0-9._~!$&'()*+,;=:@%/?-]+|/v[0-9]+/[A-Za-z0-9._~!$&'()*+,;=:@%/?-]+|/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+(?:/[A-Za-z0-9._~!$&'()*+,;=:@%/?-]+)*)`)

type sourceMapDocument struct {
	Sources        []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent"`
}

// ExtractSourceMapURL returns the source map URL advertised by response
// headers or, if absent, the trailing //# sourceMappingURL=... directive.
func ExtractSourceMapURL(headers map[string]string, body []byte) string {
	for key, val := range headers {
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "sourcemap", "x-sourcemap":
			if cleaned := cleanSourceMapURL(val); cleaned != "" {
				return cleaned
			}
		}
	}

	if len(body) == 0 {
		return ""
	}

	tail := body
	if len(tail) > 8192 {
		tail = tail[len(tail)-8192:]
	}
	lowerTail := strings.ToLower(string(tail))
	idx := strings.LastIndex(lowerTail, "sourcemappingurl=")
	if idx < 0 {
		return ""
	}

	value := string(tail[idx+len("sourceMappingURL="):])
	if lineEnd := strings.IndexAny(value, "\r\n"); lineEnd >= 0 {
		value = value[:lineEnd]
	}
	if commentEnd := strings.Index(value, "*/"); commentEnd >= 0 {
		value = value[:commentEnd]
	}
	return cleanSourceMapURL(value)
}

// ParseSourceMap fetches and parses a source map, then feeds any harvested
// routes back into the engine queue.
func ParseSourceMap(ctx context.Context, jsURL, mapURL string, engine *Engine, snap *configSnapshot) error {
	if engine == nil {
		return fmt.Errorf("source map parse requires engine")
	}
	return parseSourceMapWithDepth(ctx, jsURL, mapURL, engine, snap, 1, atomic.LoadInt64(&engine.RunID))
}

func parseSourceMapWithDepth(ctx context.Context, jsURL, mapURL string, engine *Engine, snap *configSnapshot, harvestDepth int, runID int64) error {
	if engine == nil {
		return fmt.Errorf("source map parse requires engine")
	}
	if snap == nil {
		snap = engine.configSnap.Load()
		if snap == nil {
			return fmt.Errorf("source map parse requires config snapshot")
		}
	}
	if ctx == nil {
		ctx = context.Background()
	}

	resolvedURL, mapBody, err := loadSourceMapBytes(ctx, engine, snap, jsURL, mapURL)
	if err != nil {
		return err
	}

	var doc sourceMapDocument
	dec := json.NewDecoder(bytes.NewReader(mapBody))
	if err := dec.Decode(&doc); err != nil {
		return fmt.Errorf("parse source map %s: %w", resolvedURL, err)
	}

	seen := make(map[string]struct{})
	for _, source := range doc.Sources {
		if path := normalizeSourceMapRoute(source); path != "" {
			seen[path] = struct{}{}
		}
	}
	for _, content := range doc.SourcesContent {
		if content == "" {
			continue
		}
		for _, candidate := range extractSourceMapRoutes(content) {
			if path := normalizeSourceMapRoute(candidate); path != "" {
				seen[path] = struct{}{}
			}
		}
	}

	for path := range seen {
		engine.SubmitHarvestPath(path, runID, harvestDepth)
	}

	return nil
}

func loadSourceMapBytes(ctx context.Context, engine *Engine, snap *configSnapshot, jsURL, mapURL string) (string, []byte, error) {
	resolved, err := resolveSourceMapURL(jsURL, mapURL)
	if err != nil {
		return "", nil, err
	}
	if resolved.Scheme == "data" {
		data, err := decodeDataSourceMap(resolved.String())
		if err != nil {
			return "", nil, err
		}
		return resolved.String(), data, nil
	}

	requestTimeout := snap.Timeout
	if requestTimeout <= 0 {
		requestTimeout = DefaultHTTPTimeout
	}

	limiter := engine.getLimiter(resolved.Host)
	if limiter != nil {
		if err := limiter.Wait(ctx); err != nil {
			return "", nil, err
		}
	}

	reqPath := resolved.Path
	if resolved.RawQuery != "" {
		reqPath += "?" + resolved.RawQuery
	}
	if reqPath == "" {
		reqPath = "/"
	}

	rawRequest := buildRequest(http.MethodGet, reqPath, resolved.Host, snap.UserAgent, snap.HeadersTemplate, "")
	resp, err := engine.executeRequestWithRetry(ctx, resolved.String(), rawRequest, requestTimeout, "")
	if err != nil {
		return "", nil, err
	}
	if resp == nil {
		return "", nil, fmt.Errorf("source map request returned nil response for %s", resolved.String())
	}
	if resp.BodyEncoded {
		return "", nil, fmt.Errorf("source map response body is encoded for %s", resolved.String())
	}
	if len(resp.Body) > sourceMapHarvestBodyLimit {
		return "", nil, fmt.Errorf("source map body exceeds limit for %s", resolved.String())
	}
	return resolved.String(), append([]byte(nil), resp.Body...), nil
}

func resolveSourceMapURL(jsURL, mapURL string) (*url.URL, error) {
	jsURL = strings.TrimSpace(jsURL)
	mapURL = strings.TrimSpace(mapURL)
	if jsURL == "" {
		return nil, fmt.Errorf("source map parse requires javascript url")
	}
	if mapURL == "" {
		return nil, fmt.Errorf("source map url is empty")
	}

	ref, err := url.Parse(mapURL)
	if err != nil {
		return nil, fmt.Errorf("parse source map url: %w", err)
	}
	if ref.Scheme == "data" {
		return ref, nil
	}

	base, err := url.Parse(jsURL)
	if err != nil {
		return nil, fmt.Errorf("parse javascript url: %w", err)
	}
	return base.ResolveReference(ref), nil
}

func decodeDataSourceMap(raw string) ([]byte, error) {
	comma := strings.Index(raw, ",")
	if comma < 0 {
		return nil, fmt.Errorf("invalid data source map url")
	}
	meta := raw[:comma]
	payload := raw[comma+1:]
	if strings.Contains(meta, ";base64") {
		return base64.StdEncoding.DecodeString(payload)
	}
	unescaped, err := url.QueryUnescape(payload)
	if err != nil {
		return nil, err
	}
	return []byte(unescaped), nil
}

func cleanSourceMapURL(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.Trim(raw, `"'`)
	raw = strings.TrimSuffix(raw, "*/")
	raw = strings.TrimSpace(raw)
	if idx := strings.IndexAny(raw, " \t"); idx >= 0 {
		raw = raw[:idx]
	}
	return raw
}

func extractSourceMapRoutes(content string) []string {
	if strings.TrimSpace(content) == "" {
		return nil
	}
	matches := sourceMapRouteRe.FindAllString(content, -1)
	if len(matches) == 0 {
		return nil
	}
	return matches
}

func normalizeSourceMapRoute(candidate string) string {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return ""
	}
	candidate = strings.Trim(candidate, "\"'` \t\r\n,;)]}")
	if candidate == "" {
		return ""
	}
	if strings.HasPrefix(candidate, "http://") || strings.HasPrefix(candidate, "https://") {
		parsed, err := url.Parse(candidate)
		if err != nil {
			return ""
		}
		path := parsed.Path
		if parsed.RawQuery != "" {
			path += "?" + parsed.RawQuery
		}
		if path == "" {
			path = "/"
		}
		return path
	}
	if !strings.HasPrefix(candidate, "/") {
		candidate = "/" + candidate
	}
	return candidate
}

func (e *Engine) shouldHarvestSourceMap(reqPath, contentType string) bool {
	reqPath = strings.ToLower(strings.TrimSpace(reqPath))
	contentType = strings.ToLower(strings.TrimSpace(contentType))
	return strings.HasSuffix(reqPath, ".js") || strings.Contains(contentType, "javascript")
}

func (e *Engine) scheduleSourceMapHarvest(ctx context.Context, jsURL, mapURL string, snap *configSnapshot, runID int64, harvestDepth int) {
	if e == nil || snap == nil || !snap.HarvestSourceMaps {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return
	default:
	}
	if e.sourceMapSem == nil {
		return
	}
	select {
	case e.sourceMapSem <- struct{}{}:
		e.activeJobs.Add(1)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					// Keep shutdown accounting balanced even if parsing panics.
				}
				<-e.sourceMapSem
				e.activeJobs.Done()
			}()
			if err := parseSourceMapWithDepth(ctx, jsURL, mapURL, e, snap, harvestDepth, runID); err != nil {
				e.emitLogEvent(LogLevelWarning, LogCategoryDiscovery, EventHarvestParseError, fmt.Sprintf("source map harvest failed for %s: %v", jsURL, err), map[string]interface{}{
					"javascript_url": jsURL,
					"source_map_url": mapURL,
					"error":          err.Error(),
				})
			}
		}()
	default:
		// Drop excess source-map work rather than letting the engine spawn an
		// unbounded number of network-bound goroutines.
	}
}
