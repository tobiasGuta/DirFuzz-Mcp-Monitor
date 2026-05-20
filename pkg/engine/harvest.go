package engine

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
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
	camelBoundaryRe   = regexp.MustCompile(`([a-z0-9])([A-Z])`)
	acronymBoundaryRe = regexp.MustCompile(`([A-Z]+)([A-Z][a-z])`)
)

type harvestOptions struct {
	js  bool
	api bool
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
	return harvestEndpointsWithOptions(nil, ctx, baseURL, client, harvestOptions{js: true, api: true})
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
	enabled := e.Config.Harvest || e.Config.HarvestJS || e.Config.HarvestAPI
	jsOnly := e.Config.HarvestJS
	apiOnly := e.Config.HarvestAPI
	timeout := e.Config.Timeout
	if timeout <= 0 {
		timeout = DefaultHTTPTimeout
	}
	insecure := e.Config.Insecure
	h2Mode := e.Config.H2Mode
	e.Config.RUnlock()

	if !enabled {
		return nil, nil
	}

	baseURL := e.BaseURL()
	if baseURL == "" {
		return nil, fmt.Errorf("harvest requires a target URL")
	}

	client, err := newHarvestClient(baseURL, timeout, insecure, h2Mode)
	if err != nil {
		return nil, err
	}

	opts := harvestOptions{
		js:  !apiOnly,
		api: !jsOnly,
	}
	// Explicit sub-mode flags narrow the default full harvest. If both are set
	// we keep both paths enabled.
	if jsOnly {
		opts.js = true
		opts.api = false
	}
	if apiOnly {
		opts.api = true
		opts.js = false
	}
	if e.Config.Harvest && !jsOnly && !apiOnly {
		opts.js = true
		opts.api = true
	}
	return harvestEndpointsWithOptions(e, ctx, baseURL, client, opts), nil
}

func newHarvestClient(baseURL string, timeout time.Duration, insecure bool, h2Mode bool) (*http.Client, error) {
	if h2Mode {
		return httpclient.NewH2Client(baseURL, timeout, insecure, DefaultH2MaxHeaderListSize)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
	}
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
	add := func(candidate string) {
		if normalized := canonicalHarvestCandidate(base, candidate); normalized != "" {
			if _, exists := discovered[normalized]; !exists && e != nil {
				e.emitLogEvent(LogLevelInfo, LogCategoryDiscovery, EventHarvestDiscovery, fmt.Sprintf("discovered endpoint %s", normalized), map[string]interface{}{
					"path": normalized,
				})
			}
			discovered[normalized] = struct{}{}
		}
	}

	if opts.js {
		if rootBody, _, err := fetchHarvestBody(ctx, client, baseURL, nil); err == nil {
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
