package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"dirfuzz/pkg/httpclient"

	"go.yaml.in/yaml/v3"
	"golang.org/x/net/html"
)

const harvestBodyLimit = 2 * 1024 * 1024

var (
	harvestJSRe       = regexp.MustCompile(`(?i)(?:["'\x60]\s*(/[A-Za-z0-9_/\-.?&=%]{3,})|fetch\(\s*["']([^"']+)["']|axios\.\w+\(\s*["']([^"']+)["']|apiBase\s*=\s*["']([^"']+)["']|\b\d+:"([a-z0-9_/\-.]{3,})")`)
	harvestPathRe     = regexp.MustCompile(`/(?:[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~:-]+)*)/?(?:\?[A-Za-z0-9._~!$&'()*+,;=:@%/?-]*)?`)
	camelBoundaryRe   = regexp.MustCompile(`([a-z0-9])([A-Z])`)
	acronymBoundaryRe = regexp.MustCompile(`([A-Z]+)([A-Z][a-z])`)
)

type harvestOptions struct {
	js                 bool
	api                bool
	response           bool
	responseMaxDepth   int
	responseMaxFetches int
}

type openAPISpec struct {
	Paths   map[string]any `json:"paths" yaml:"paths"`
	Servers []struct {
		URL string `json:"url"`
	} `json:"servers"`
}

type graphqlIntrospection struct {
	Data struct {
		Schema struct {
			Types []struct {
				Name   string `json:"name"`
				Fields []struct {
					Name string `json:"name"`
				} `json:"fields"`
			} `json:"types"`
		} `json:"__schema"`
	} `json:"data"`
}

// HarvestEndpoints fetches and parses discovery surfaces from the target and
// returns a deduplicated list of discovered paths and keywords.
func HarvestEndpoints(ctx context.Context, baseURL string, client *http.Client) []string {
	return harvestEndpointsWithOptions(nil, ctx, baseURL, client, harvestOptions{js: true, api: true, response: true})
}

// HarvestEndpoints builds the harvesting client from the engine config and
// returns discovered endpoints according to the configured mode flags.
func (e *Engine) HarvestEndpoints(ctx context.Context) ([]string, error) {
	if e == nil {
		return nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	e.Config.RLock()
	enabled := e.Config.Harvest || e.Config.HarvestJS || e.Config.HarvestAPI || e.Config.HarvestResponse
	harvestAll := e.Config.Harvest
	jsMode := e.Config.HarvestJS
	apiMode := e.Config.HarvestAPI
	responseMode := e.Config.HarvestResponse
	timeout := e.Config.Timeout
	if timeout <= 0 {
		timeout = DefaultHTTPTimeout
	}
	insecure := e.Config.Insecure
	h2Mode := e.Config.H2Mode
	allowPrivate := e.Config.AllowPrivateTargets
	e.Config.RUnlock()

	if !enabled {
		return nil, nil
	}

	baseURL := e.BaseURL()
	if baseURL == "" {
		return nil, fmt.Errorf("harvest requires a target URL")
	}

	client, err := newHarvestClient(baseURL, timeout, insecure, h2Mode, allowPrivate)
	if err != nil {
		return nil, err
	}

	opts := harvestOptions{
		js:                 harvestAll || jsMode,
		api:                harvestAll || apiMode,
		response:           harvestAll || responseMode,
		responseMaxDepth:   e.Config.HarvestResponseDepth,
		responseMaxFetches: e.Config.HarvestResponseFetch,
	}
	if opts.responseMaxDepth <= 0 {
		opts.responseMaxDepth = DefaultHarvestResponseDepth
	}
	if opts.responseMaxFetches <= 0 {
		opts.responseMaxFetches = DefaultHarvestResponseFetch
	}
	if harvestAll && !jsMode && !apiMode && !responseMode {
		opts.js = true
		opts.api = true
		opts.response = true
	}
	return harvestEndpointsWithOptions(e, ctx, baseURL, client, opts), nil
}

func newHarvestClient(baseURL string, timeout time.Duration, insecure bool, h2Mode bool, allowPrivateTargets bool) (*http.Client, error) {
	if h2Mode {
		return httpclient.NewH2ClientWithPrivatePolicy(baseURL, timeout, insecure, DefaultH2MaxHeaderListSize, allowPrivateTargets)
	}

	tr := httpclient.NewTransport(timeout, insecure, allowPrivateTargets)
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

func harvestEndpointsWithOptions(e *Engine, ctx context.Context, baseURL string, client *http.Client, opts harvestOptions) []string {
	if client == nil || baseURL == "" {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}
	resourceBase := *base
	if resourceBase.Path != "" && !strings.HasSuffix(resourceBase.Path, "/") {
		resourceBase.Path += "/"
	}

	discovered := make(map[string]struct{})
	queuedResponseTargets := make(map[string]struct{})
	type responseHarvestTarget struct {
		url   string
		depth int
	}
	var responseQueue []responseHarvestTarget
	add := func(candidate string) string {
		normalized := canonicalHarvestCandidate(base, candidate)
		if normalized == "" {
			return ""
		}
		if _, exists := discovered[normalized]; !exists && e != nil {
			e.emitLogEvent(LogLevelInfo, LogCategoryDiscovery, EventHarvestDiscovery, fmt.Sprintf("discovered endpoint %s", normalized), map[string]interface{}{
				"path": normalized,
			})
		}
		discovered[normalized] = struct{}{}
		return normalized
	}
	enqueueResponseTarget := func(normalized string, depth int) {
		if !opts.response || depth <= 0 || depth > opts.responseMaxDepth {
			return
		}
		if targetURL := harvestResponseTargetURL(&resourceBase, normalized); targetURL != "" {
			if _, seen := queuedResponseTargets[targetURL]; !seen {
				queuedResponseTargets[targetURL] = struct{}{}
				responseQueue = append(responseQueue, responseHarvestTarget{url: targetURL, depth: depth})
			}
		}
	}

	if opts.js || opts.response {
		if rootBody, rootResp, err := fetchHarvestBody(ctx, client, baseURL, nil); err == nil {
			if opts.response {
				contentType := ""
				if rootResp != nil {
					contentType = rootResp.Header.Get("Content-Type")
				}
				for _, candidate := range responseHarvestCandidatesForTarget(baseURL, rootBody, contentType) {
					if normalized := add(candidate); normalized != "" {
						enqueueResponseTarget(normalized, 1)
					}
				}
			}
			if opts.js {
				scriptURLs := collectScriptSrcs(e, rootBody, &resourceBase)
				for _, scriptURL := range scriptURLs {
					if scriptBody, _, err := fetchHarvestBody(ctx, client, scriptURL, nil); err == nil {
						for _, candidate := range extractJSHarvestCandidates(scriptBody) {
							add(candidate)
						}
					}
				}
				if e != nil {
					e.emitLogEvent(LogLevelSuccess, LogCategoryDiscovery, EventHarvestJSAnalysisComplete, fmt.Sprintf("JS analysis completed with %d script URL(s)", len(scriptURLs)), map[string]interface{}{
						"script_urls": len(scriptURLs),
					})
				}
			}
		}
	}

	if opts.response {
		processed := 0
		for len(responseQueue) > 0 && processed < opts.responseMaxFetches {
			target := responseQueue[0]
			responseQueue = responseQueue[1:]
			if target.depth > opts.responseMaxDepth {
				continue
			}

			body, resp, err := fetchHarvestBody(ctx, client, target.url, nil)
			processed++
			if err != nil || resp == nil || !shouldProcessHarvestResponseStatus(resp.StatusCode) {
				continue
			}

			contentType := resp.Header.Get("Content-Type")
			candidates := responseHarvestCandidatesForTarget(target.url, body, contentType)
			for _, candidate := range candidates {
				if normalized := add(candidate); normalized != "" && target.depth < opts.responseMaxDepth {
					enqueueResponseTarget(normalized, target.depth+1)
				}
			}
		}
	}

	if opts.api {
		for _, path := range openAPIHarvestPaths(&resourceBase) {
			body, resp, err := fetchHarvestBody(ctx, client, path, nil)
			if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
				continue
			}
			for _, candidate := range extractOpenAPIHarvestCandidates(e, body) {
				add(candidate)
			}
		}

		for _, path := range graphqlHarvestPaths(&resourceBase) {
			reqBody := []byte(`{"query":"{ __schema { types { name fields { name } } } }"}`)
			body, resp, err := fetchHarvestBody(ctx, client, path, bytes.NewReader(reqBody))
			if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
				continue
			}
			for _, candidate := range extractGraphQLHarvestCandidates(e, body) {
				add(candidate)
			}
		}
	}

	out := make([]string, 0, len(discovered))
	for candidate := range discovered {
		out = append(out, candidate)
	}
	sort.Strings(out)
	return out
}

func (e *Engine) queueResponseHarvestFromResult(job Job, requestURL string, finalRedirectURL string, contentType string, body []byte) {
	if e == nil || len(body) == 0 {
		return
	}

	snap := e.configSnap.Load()
	if snap == nil || !snap.HarvestResponse {
		return
	}

	maxDepth := snap.HarvestResponseDepth
	if maxDepth <= 0 {
		maxDepth = DefaultHarvestResponseDepth
	}
	if job.HarvestDepth >= maxDepth {
		return
	}

	baseURL := strings.TrimSpace(finalRedirectURL)
	if baseURL == "" {
		baseURL = strings.TrimSpace(requestURL)
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return
	}

	for _, candidate := range responseHarvestCandidatesForTarget(baseURL, body, contentType) {
		normalized := canonicalHarvestCandidate(base, candidate)
		if normalized == "" {
			continue
		}
		e.SubmitHarvestPath(normalized, job.RunID, job.HarvestDepth+1)
	}
}

func fetchHarvestBody(ctx context.Context, client *http.Client, target string, body io.Reader) ([]byte, *http.Response, error) {
	method := http.MethodGet
	if body != nil {
		method = http.MethodPost
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "DirFuzz-Harvest/1.0")
	req.Header.Set("Accept", "*/*")
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, harvestBodyLimit)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, resp, err
	}
	return data, resp, nil
}

func collectScriptSrcs(e *Engine, rootBody []byte, base *url.URL) []string {
	doc, err := html.Parse(bytes.NewReader(rootBody))
	if err != nil {
		if e != nil {
			e.emitLogEvent(LogLevelError, LogCategoryDiscovery, EventHarvestParseError, fmt.Sprintf("failed to parse HTML discovery body: %v", err), map[string]interface{}{
				"error": err.Error(),
			})
		}
		return nil
	}

	var out []string
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n == nil {
			return
		}
		if n.Type == html.ElementNode && strings.EqualFold(n.Data, "script") {
			for _, attr := range n.Attr {
				if strings.EqualFold(attr.Key, "src") {
					if resolved := resolveHarvestURL(base, attr.Val); resolved != "" {
						out = append(out, resolved)
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return out
}

func extractJSHarvestCandidates(body []byte) []string {
	matches := harvestJSRe.FindAllStringSubmatch(string(body), -1)
	if len(matches) == 0 {
		return nil
	}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		for i := 1; i < len(m); i++ {
			if m[i] != "" {
				out = append(out, m[i])
				break
			}
		}
	}
	return out
}

func extractOpenAPIHarvestCandidates(e *Engine, body []byte) []string {
	var spec openAPISpec
	if err := json.Unmarshal(body, &spec); err != nil {
		if err := yaml.Unmarshal(body, &spec); err != nil {
			if e != nil {
				e.emitLogEvent(LogLevelError, LogCategoryDiscovery, EventHarvestParseError, fmt.Sprintf("failed to parse OpenAPI discovery body: %v", err), map[string]interface{}{
					"error": err.Error(),
				})
			}
			return nil
		}
	}

	var out []string
	for path := range spec.Paths {
		out = append(out, path)
	}
	for _, server := range spec.Servers {
		if server.URL == "" {
			continue
		}
		if u, err := url.Parse(server.URL); err == nil {
			if u.Path != "" {
				out = append(out, u.Path)
			}
		}
	}
	return out
}

func extractGraphQLHarvestCandidates(e *Engine, body []byte) []string {
	var spec graphqlIntrospection
	if err := json.Unmarshal(body, &spec); err != nil {
		if e != nil {
			e.emitLogEvent(LogLevelError, LogCategoryDiscovery, EventHarvestParseError, fmt.Sprintf("failed to parse GraphQL discovery body: %v", err), map[string]interface{}{
				"error": err.Error(),
			})
		}
		return nil
	}

	var out []string
	for _, typ := range spec.Data.Schema.Types {
		if typ.Name != "" {
			out = append(out, keywordVariants(typ.Name)...)
		}
		for _, field := range typ.Fields {
			if field.Name != "" {
				out = append(out, keywordVariants(field.Name)...)
			}
		}
	}
	return out
}

func extractResponseHarvestCandidates(body []byte, contentType string) []string {
	if len(body) == 0 {
		return nil
	}

	if looksLikeJSONContent(contentType, body) {
		if candidates := extractJSONHarvestCandidates(body); len(candidates) > 0 {
			return dedupeHarvestVariants(candidates)
		}
	}

	matches := harvestPathRe.FindAllString(string(body), -1)
	if len(matches) == 0 {
		return nil
	}
	return dedupeHarvestVariants(matches)
}

func responseHarvestCandidatesForTarget(targetURL string, body []byte, contentType string) []string {
	candidates := extractResponseHarvestCandidates(body, contentType)
	hints := extractResponseParamHints(targetURL, contentType, body)
	if len(hints) == 0 {
		return candidates
	}
	if hinted := buildHarvestCandidateWithParams(targetURL, hints); hinted != "" {
		candidates = append(candidates, hinted)
	}
	return dedupeHarvestVariants(candidates)
}

func shouldProcessHarvestResponseStatus(statusCode int) bool {
	if statusCode >= 200 && statusCode < 300 {
		return true
	}
	switch statusCode {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusBadRequest:
		return true
	default:
		return false
	}
}

func extractResponseParamHints(targetURL string, contentType string, body []byte) []string {
	if len(body) == 0 || !shouldHarvestResponseParamHints(targetURL, contentType, body) {
		return nil
	}
	return uniqueStrings(extractParamHintsFromText(string(body)))
}

func shouldHarvestResponseParamHints(targetURL string, contentType string, body []byte) bool {
	if isStaticHarvestAsset(targetURL) {
		return false
	}
	if looksLikeJSONContent(contentType, body) {
		return true
	}

	mediaType, _, err := mime.ParseMediaType(strings.TrimSpace(contentType))
	if err != nil {
		mediaType = strings.ToLower(strings.TrimSpace(contentType))
	}
	mediaType = strings.ToLower(mediaType)
	return mediaType == "text/plain"
}

func isStaticHarvestAsset(targetURL string) bool {
	parsed, err := url.Parse(strings.TrimSpace(targetURL))
	if err != nil {
		return false
	}
	lowerPath := strings.ToLower(parsed.EscapedPath())
	for _, ext := range []string{".js", ".css", ".gif", ".png", ".jpg", ".jpeg", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map"} {
		if strings.HasSuffix(lowerPath, ext) {
			return true
		}
	}
	return false
}

func looksLikeJSONContent(contentType string, body []byte) bool {
	contentType = strings.ToLower(strings.TrimSpace(contentType))
	if strings.Contains(contentType, "json") {
		return true
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return false
	}
	return trimmed[0] == '{' || trimmed[0] == '['
}

func extractJSONHarvestCandidates(body []byte) []string {
	var payload any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil
	}

	var out []string
	var walk func(any)
	walk = func(value any) {
		switch typed := value.(type) {
		case map[string]any:
			for _, child := range typed {
				walk(child)
			}
		case []any:
			for _, child := range typed {
				walk(child)
			}
		case string:
			for _, candidate := range harvestPathRe.FindAllString(typed, -1) {
				out = append(out, candidate)
			}
		}
	}
	walk(payload)
	return out
}

func harvestResponseTargetURL(base *url.URL, candidate string) string {
	if base == nil || candidate == "" || !strings.HasPrefix(candidate, "/") {
		return ""
	}
	if !looksLikeResponseEndpoint(candidate) {
		return ""
	}
	return resolveHarvestURL(base, candidate)
}

func looksLikeResponseEndpoint(candidate string) bool {
	lower := strings.ToLower(candidate)
	return strings.Contains(lower, "/api/") ||
		strings.HasPrefix(lower, "/api") ||
		strings.Contains(lower, "/v1/") ||
		strings.Contains(lower, "/v2/") ||
		strings.Contains(lower, "/v3/") ||
		strings.Contains(lower, "/rest/") ||
		strings.Contains(lower, "/graphql")
}

func openAPIHarvestPaths(base *url.URL) []string {
	paths := []string{
		"openapi.json",
		"openapi.yaml",
		"swagger.json",
		"swagger/v1/swagger.json",
		"api-docs",
		"v1/api-docs",
		".well-known/openapi",
	}
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		out = append(out, resolveHarvestURL(base, p))
	}
	return out
}

func graphqlHarvestPaths(base *url.URL) []string {
	paths := []string{"graphql", "api/graphql", "v1/graphql"}
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		out = append(out, resolveHarvestURL(base, p))
	}
	return out
}

func resolveHarvestURL(base *url.URL, ref string) string {
	if base == nil {
		return ref
	}
	ref = strings.TrimSpace(strings.Trim(ref, "\"'`"))
	if ref == "" {
		return ""
	}

	parsed, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	if parsed.Scheme != "" {
		if !sameHarvestOrigin(base, parsed) {
			return ""
		}
		return parsed.String()
	}

	resolved := base.ResolveReference(parsed)
	if !sameHarvestOrigin(base, resolved) {
		return ""
	}
	if resolved.String() == "" {
		return ref
	}
	return resolved.String()
}

func resolveHarvestRef(base *url.URL, ref string) (string, bool) {
	ref = strings.TrimSpace(strings.Trim(ref, "\"'`"))
	if ref == "" {
		return "", false
	}
	if strings.HasPrefix(strings.ToLower(ref), "javascript:") || strings.HasPrefix(strings.ToLower(ref), "data:") {
		return "", false
	}

	parsed, err := url.Parse(ref)
	if err != nil {
		return "", false
	}

	if parsed.Scheme != "" {
		if base != nil && !sameHarvestOrigin(base, parsed) {
			return "", false
		}
		ref = parsed.Path
		if parsed.RawQuery != "" {
			ref += "?" + parsed.RawQuery
		}
	} else if strings.HasPrefix(ref, "//") {
		if base == nil {
			return "", false
		}
		parsed = base.ResolveReference(parsed)
		if !sameHarvestOrigin(base, parsed) {
			return "", false
		}
		ref = parsed.Path
		if parsed.RawQuery != "" {
			ref += "?" + parsed.RawQuery
		}
	}

	if base != nil && !strings.HasPrefix(ref, "/") && strings.Contains(ref, "/") {
		ref = "/" + ref
	}
	return strings.TrimSpace(ref), true
}

func sameHarvestOrigin(base, other *url.URL) bool {
	if base == nil || other == nil {
		return false
	}
	return strings.EqualFold(base.Scheme, other.Scheme) && strings.EqualFold(base.Host, other.Host)
}

func canonicalHarvestCandidate(base *url.URL, candidate string) string {
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
		if parsed, err := url.Parse(candidate); err == nil {
			if base != nil && !sameHarvestOrigin(base, parsed) {
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

func buildHarvestCandidateWithParams(targetURL string, hints []string) string {
	parsed, err := url.Parse(strings.TrimSpace(targetURL))
	if err != nil {
		return ""
	}

	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}

	query := parsed.Query()
	for _, hint := range hints {
		hint = strings.TrimSpace(hint)
		if hint == "" {
			continue
		}
		query.Set(hint, "")
	}
	encoded := query.Encode()
	if encoded == "" {
		return path
	}
	return path + "?" + encoded
}

func normalizeHarvestQuery(candidate string) string {
	parts := strings.SplitN(candidate, "?", 2)
	if len(parts) != 2 {
		return ""
	}

	parsed, err := url.Parse(candidate)
	if err != nil {
		return ""
	}

	query := parsed.Query()
	if len(query) == 0 {
		return strings.TrimSuffix(candidate, "?")
	}
	for key := range query {
		query.Set(key, "")
	}

	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	return path + "?" + query.Encode()
}

func keywordVariants(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	snake := toSnakeCase(raw)
	kebab := strings.ReplaceAll(snake, "_", "-")
	vars := []string{raw}
	if snake != raw {
		vars = append(vars, snake)
	}
	if kebab != raw && kebab != snake {
		vars = append(vars, kebab)
	}
	return dedupeHarvestVariants(vars)
}

func toSnakeCase(s string) string {
	if s == "" {
		return s
	}
	s = acronymBoundaryRe.ReplaceAllString(s, "${1}_${2}")
	s = camelBoundaryRe.ReplaceAllString(s, "${1}_${2}")
	s = strings.ReplaceAll(s, "-", "_")
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.ReplaceAll(s, "__", "_")
	return strings.ToLower(strings.Trim(s, "_"))
}

func dedupeHarvestVariants(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
