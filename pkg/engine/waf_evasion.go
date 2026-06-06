package engine

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

const evasionRankingFloor = 5

// EvasionScoreboard tracks how each bypass technique performs across the scan.
type EvasionScoreboard struct {
	mu       sync.RWMutex
	attempts map[string]int
	hits     map[string]int
}

// EvasionScoreboardRow is a rendered scoreboard entry.
type EvasionScoreboardRow struct {
	Technique string
	Attempts  int
	Bypasses  int
	Rate      float64
}

func NewEvasionScoreboard() *EvasionScoreboard {
	return &EvasionScoreboard{
		attempts: make(map[string]int),
		hits:     make(map[string]int),
	}
}

func (s *EvasionScoreboard) Record(technique string, bypassed bool) {
	if s == nil || technique == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts[technique]++
	if bypassed {
		s.hits[technique]++
	}
}

func (s *EvasionScoreboard) Snapshot() map[string]EvasionScoreboardRow {
	out := make(map[string]EvasionScoreboardRow)
	if s == nil {
		return out
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for technique, attempts := range s.attempts {
		row := EvasionScoreboardRow{
			Technique: technique,
			Attempts:  attempts,
			Bypasses:  s.hits[technique],
		}
		if attempts > 0 {
			row.Rate = float64(row.Bypasses) / float64(attempts)
		}
		out[technique] = row
	}
	for technique, bypasses := range s.hits {
		if _, ok := out[technique]; ok {
			continue
		}
		out[technique] = EvasionScoreboardRow{
			Technique: technique,
			Bypasses:  bypasses,
			Rate:      0,
		}
	}
	return out
}

func (s *EvasionScoreboard) Summary() []EvasionScoreboardRow {
	rows := s.Snapshot()
	if len(rows) == 0 {
		return nil
	}
	out := make([]EvasionScoreboardRow, 0, len(rows))
	for _, row := range rows {
		out = append(out, row)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Rate != out[j].Rate {
			return out[i].Rate > out[j].Rate
		}
		if out[i].Attempts != out[j].Attempts {
			return out[i].Attempts > out[j].Attempts
		}
		return out[i].Technique < out[j].Technique
	})
	return out
}

// TopTechniques returns up to n techniques sorted by highest bypass rate.
func (s *EvasionScoreboard) TopTechniques(n int) []EvasionScoreboardRow {
	if s == nil || n <= 0 {
		return nil
	}
	rows := s.Summary()
	if len(rows) == 0 {
		return nil
	}
	if n > len(rows) {
		n = len(rows)
	}
	out := make([]EvasionScoreboardRow, n)
	copy(out, rows[:n])
	return out
}

func (s *EvasionScoreboard) RankedTechniques(vendor string) []EvasionTechnique {
	base := EvasionStrategiesFor(vendor)
	if len(base) == 0 || s == nil {
		return base
	}

	rows := s.Snapshot()
	totalAttempts := 0
	for _, row := range rows {
		totalAttempts += row.Attempts
	}
	if totalAttempts < evasionRankingFloor {
		return base
	}

	type scoredTechnique struct {
		tech  EvasionTechnique
		rate  float64
		score EvasionScoreboardRow
		idx   int
	}

	scored := make([]scoredTechnique, 0, len(base))
	for i, tech := range base {
		row, ok := rows[tech.Name]
		if !ok || row.Attempts == 0 {
			scored = append(scored, scoredTechnique{tech: tech, rate: -1, idx: i})
			continue
		}
		scored = append(scored, scoredTechnique{tech: tech, rate: row.Rate, score: row, idx: i})
	}

	sort.SliceStable(scored, func(i, j int) bool {
		li, lj := scored[i], scored[j]
		if li.rate < 0 && lj.rate < 0 {
			return li.idx < lj.idx
		}
		if li.rate < 0 {
			return false
		}
		if lj.rate < 0 {
			return true
		}
		if li.rate != lj.rate {
			return li.rate > lj.rate
		}
		if li.score.Attempts != lj.score.Attempts {
			return li.score.Attempts > lj.score.Attempts
		}
		return li.idx < lj.idx
	})

	out := make([]EvasionTechnique, 0, len(scored))
	for _, item := range scored {
		out = append(out, item.tech)
	}
	return out
}

func (e *Engine) evasionTechniqueSeen(path, technique string) bool {
	if e == nil || path == "" || technique == "" {
		return false
	}
	v, ok := e.evasionAttempted.Load(path)
	if !ok {
		return false
	}
	seen, _ := v.([]string)
	for _, name := range seen {
		if name == technique {
			return true
		}
	}
	return false
}

func (e *Engine) markEvasionTechnique(path, technique string) {
	if e == nil || path == "" || technique == "" {
		return
	}
	v, _ := e.evasionAttempted.Load(path)
	seen, _ := v.([]string)
	if e.evasionTechniqueSeen(path, technique) {
		return
	}
	updated := append(append([]string(nil), seen...), technique)
	e.evasionAttempted.Store(path, updated)
}

func (e *Engine) EvasionSummaryRows() []EvasionScoreboardRow {
	if e == nil || e.EvasionScoreboard == nil {
		return nil
	}
	return e.EvasionScoreboard.Summary()
}

func (e *Engine) setWAFState(detected bool, vendor string) {
	if e == nil {
		return
	}
	e.wafStateMu.Lock()
	e.wafDetected = detected
	e.wafVendorGuess = strings.TrimSpace(vendor)
	e.wafStateMu.Unlock()
}

func (e *Engine) wafState() (bool, string) {
	if e == nil {
		return false, ""
	}
	e.wafStateMu.RLock()
	defer e.wafStateMu.RUnlock()
	return e.wafDetected, e.wafVendorGuess
}

type WAFProbeAttempt struct {
	Technique   string   `json:"technique"`
	Path        string   `json:"path"`
	StatusCode  int      `json:"status_code"`
	SizeBytes   int      `json:"size_bytes"`
	ContentType string   `json:"content_type,omitempty"`
	Bypassed    bool     `json:"bypassed"`
	Labels      []string `json:"labels,omitempty"`
}

type WAFProbeReport struct {
	Target             string                 `json:"target"`
	Path               string                 `json:"path"`
	Method             string                 `json:"method"`
	Vendor             string                 `json:"vendor"`
	Detected           bool                   `json:"detected"`
	Confidence         string                 `json:"confidence,omitempty"`
	Evidence           []string               `json:"evidence,omitempty"`
	BaselineStatusCode int                    `json:"baseline_status_code"`
	BaselineSizeBytes  int                    `json:"baseline_size_bytes"`
	Attempts           []WAFProbeAttempt      `json:"attempts"`
	Scoreboard         []EvasionScoreboardRow `json:"scoreboard,omitempty"`
}

func (e *Engine) ProbeWAF(ctx context.Context, targetURL, rawPath, method string, headers map[string]string, timeout time.Duration, proxyAddr string) (WAFProbeReport, error) {
	report := WAFProbeReport{
		Target: targetURL,
		Path:   rawPath,
		Method: method,
	}
	if method == "" {
		method = "GET"
		report.Method = method
	}
	if e == nil {
		return report, fmt.Errorf("engine is nil")
	}
	if targetURL == "" {
		return report, fmt.Errorf("targetURL is required")
	}

	if strings.HasPrefix(rawPath, "http://") || strings.HasPrefix(rawPath, "https://") {
		targetURL = rawPath
	}
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return report, err
	}
	reqPath := rawPath
	if strings.HasPrefix(reqPath, "http://") || strings.HasPrefix(reqPath, "https://") {
		parsedPath, err := url.Parse(reqPath)
		if err != nil {
			return report, err
		}
		if parsedPath.Path != "" {
			reqPath = parsedPath.Path
		}
		if parsedPath.RawQuery != "" {
			reqPath += "?" + parsedPath.RawQuery
		}
	}
	if reqPath == "" {
		reqPath = "/"
	}
	if !strings.HasPrefix(reqPath, "/") {
		reqPath = "/" + reqPath
	}

	snap := e.configSnap.Load()
	ua := "DirFuzz/2.0"
	headersTemplate := ""
	if snap != nil {
		if snap.UserAgent != "" {
			ua = snap.UserAgent
		}
		headersTemplate = snap.HeadersTemplate
	}
	if timeout <= 0 {
		timeout = DefaultHTTPTimeout
	}

	baseHeaders := cloneHeadersMap(headers)
	basePath := reqPath
	rawRequest := buildRequest(method, basePath, parsed.Host, ua, headersTemplate, "")
	resp, err := e.executeRequestWithRetry(ctx, parsed.String(), rawRequest, timeout, proxyAddr)
	if err != nil {
		return report, err
	}

	report.BaselineStatusCode = resp.StatusCode
	report.BaselineSizeBytes = len(resp.Body)
	waf := FingerprintWAF(resp.Body, resp.Headers, resp.StatusCode, int64(resp.Duration/time.Millisecond))
	report.Vendor = waf.Vendor
	report.Detected = waf.Detected
	report.Confidence = waf.Confidence
	report.Evidence = append([]string(nil), waf.Evidence...)
	e.setWAFState(waf.Detected, waf.Vendor)

	techniques := EvasionStrategiesFor(report.Vendor)
	if len(techniques) == 0 {
		techniques = EvasionStrategiesFor("")
	}

	for _, tech := range techniques {
		modPath, modHeaders := tech.ModifyRequest(reqPath, baseHeaders, method)
		if modPath == "" {
			modPath = reqPath
		}
		if modHeaders == nil {
			modHeaders = cloneHeadersMap(baseHeaders)
		}
		rawReq := buildRequest(method, modPath, parsed.Host, ua, renderHeaderBlock(modHeaders), "")
		attemptResp, attemptErr := e.executeRequestWithRetry(ctx, parsed.String(), rawReq, timeout, proxyAddr)
		attempt := WAFProbeAttempt{
			Technique: tech.Name,
			Path:      modPath,
		}
		if attemptErr != nil || attemptResp == nil {
			attempt.Labels = []string{"error"}
			report.Attempts = append(report.Attempts, attempt)
			continue
		}
		attempt.StatusCode = attemptResp.StatusCode
		attempt.SizeBytes = len(attemptResp.Body)
		attempt.ContentType = responseContentType(attemptResp)
		attempt.Bypassed = attemptResp.StatusCode != report.BaselineStatusCode && attemptResp.StatusCode != 403
		if e.EvasionScoreboard != nil {
			e.EvasionScoreboard.Record(tech.Name, attempt.Bypassed)
		}
		report.Attempts = append(report.Attempts, attempt)
	}
	report.Scoreboard = e.EvasionSummaryRows()
	return report, nil
}

// WAFResult holds the result of WAF fingerprinting.
type WAFResult struct {
	Detected   bool
	Vendor     string
	Confidence string
	Evidence   []string
}

// FingerprintWAF detects WAF presence and vendor from response characteristics.
func FingerprintWAF(body []byte, headers string, statusCode int, durationMs int64) WAFResult {
	headersLower := strings.ToLower(headers)
	bodyStr := strings.ToLower(string(body))

	var evidence []string
	vendor := ""
	confidence := "low"

	// Cloudflare
	if strings.Contains(headersLower, "cf-ray:") ||
		strings.Contains(headersLower, "server: cloudflare") ||
		strings.Contains(bodyStr, "cf-error-details") ||
		strings.Contains(headersLower, "__cf_bm") {
		vendor = "cloudflare"
		confidence = "high"
		evidence = append(evidence, "cf-ray header or cloudflare body markers")
	}

	// Akamai
	if vendor == "" && (strings.Contains(headersLower, "x-check-cacheable:") ||
		strings.Contains(headersLower, "x-akamai-transformed:") ||
		strings.Contains(headersLower, "server: akamaighost") ||
		(strings.Contains(bodyStr, "reference #") && strings.Contains(bodyStr, "akamai"))) {
		vendor = "akamai"
		confidence = "high"
		evidence = append(evidence, "akamai header signatures")
	}

	// AWS WAF
	if vendor == "" && statusCode == 403 &&
		(strings.Contains(headersLower, "x-amzn-requestid:") ||
			strings.Contains(bodyStr, "request blocked") ||
			strings.Contains(bodyStr, "aws-waf")) {
		vendor = "aws_waf"
		confidence = "medium"
		evidence = append(evidence, "x-amzn-requestid with 403 or aws-waf body")
	}

	// Imperva / Incapsula
	if vendor == "" && (strings.Contains(headersLower, "x-iinfo:") ||
		strings.Contains(headersLower, "x-cdn: incapsula") ||
		strings.Contains(headersLower, "visid_incap_") ||
		strings.Contains(bodyStr, "incapsula incident id")) {
		vendor = "imperva"
		confidence = "high"
		evidence = append(evidence, "incapsula/imperva headers or body")
	}

	// F5 BIG-IP
	if vendor == "" && (strings.Contains(headersLower, "x-cnection:") ||
		strings.Contains(headersLower, "server: bigip") ||
		(strings.Contains(bodyStr, "the requested url was rejected") &&
			strings.Contains(bodyStr, "support id"))) {
		vendor = "f5_bigip"
		confidence = "high"
		evidence = append(evidence, "f5 bigip signatures")
	}

	// Sucuri
	if vendor == "" && (strings.Contains(headersLower, "x-sucuri-id:") ||
		strings.Contains(headersLower, "server: sucuri/cloudproxy") ||
		strings.Contains(bodyStr, "sucuri website firewall")) {
		vendor = "sucuri"
		confidence = "high"
		evidence = append(evidence, "sucuri header or body marker")
	}

	// Barracuda
	if vendor == "" && (strings.Contains(bodyStr, "barracuda web application firewall") ||
		strings.Contains(headersLower, "server: barracuda")) {
		vendor = "barracuda"
		confidence = "high"
		evidence = append(evidence, "barracuda waf body or header")
	}

	// ModSecurity
	if vendor == "" && (strings.Contains(headersLower, "mod_security") ||
		strings.Contains(headersLower, "modsecurity") ||
		strings.Contains(bodyStr, "modsecurity action") ||
		strings.Contains(bodyStr, "mod_security")) {
		vendor = "modsecurity"
		confidence = "high"
		evidence = append(evidence, "modsecurity header or body")
	}

	// Generic Nginx 403 (no other markers)
	if vendor == "" && strings.Contains(bodyStr, "<center>nginx</center>") {
		vendor = "nginx"
		confidence = "medium"
		evidence = append(evidence, "nginx default 403 body")
	}

	if vendor == "" {
		return WAFResult{Detected: false, Vendor: "unknown"}
	}

	return WAFResult{
		Detected:   true,
		Vendor:     vendor,
		Confidence: confidence,
		Evidence:   evidence,
	}
}

func (e *Engine) logWAFBypassAttempt(vendor, technique, path string, attempt int) {
	if e == nil {
		return
	}
	e.emitLogEvent(LogLevelInfo, LogCategoryNetwork, EventWAFBypassAttempt, fmt.Sprintf("trying %s on %s", technique, vendor), map[string]interface{}{
		"vendor":    vendor,
		"technique": technique,
		"path":      path,
		"attempt":   attempt,
	})
}

func (e *Engine) logWAFBypassOutcome(vendor, technique, path string, bypassed bool, statusCode int) {
	if e == nil {
		return
	}
	level := LogLevelWarning
	if bypassed {
		level = LogLevelSuccess
	}
	message := fmt.Sprintf("%s on %s %s", technique, vendor, map[bool]string{true: "succeeded", false: "failed"}[bypassed])
	e.emitLogEvent(level, LogCategoryNetwork, EventWAFBypassOutcome, message, map[string]interface{}{
		"vendor":      vendor,
		"technique":   technique,
		"path":        path,
		"bypassed":    bypassed,
		"status_code": statusCode,
	})
}

// EvasionTechnique is a single WAF bypass strategy.
type EvasionTechnique struct {
	Name          string
	ModifyRequest func(rawPath string, headers map[string]string, method string) (string, map[string]string)
}

func cloneHeadersMap(h map[string]string) map[string]string {
	n := make(map[string]string, len(h))
	for k, v := range h {
		n[k] = v
	}
	return n
}

// EvasionStrategiesFor returns evasion techniques for the given WAF vendor.
func EvasionStrategiesFor(vendor string) []EvasionTechnique {
	switch vendor {
	case "modsecurity":
		return []EvasionTechnique{
			{
				Name: "double-slash",
				ModifyRequest: func(p string, h map[string]string, method string) (string, map[string]string) {
					nh := cloneHeadersMap(h)
					if method != "GET" && method != "HEAD" {
						nh["Transfer-Encoding"] = "chunked"
					}
					return "//" + strings.TrimPrefix(p, "/"), nh
				},
			},
			{
				Name: "null-byte",
				ModifyRequest: func(p string, h map[string]string, method string) (string, map[string]string) {
					return p + "%00", cloneHeadersMap(h)
				},
			},
			{
				Name: "chunked-encoding",
				ModifyRequest: func(p string, h map[string]string, method string) (string, map[string]string) {
					nh := cloneHeadersMap(h)
					if method != "GET" && method != "HEAD" {
						nh["Transfer-Encoding"] = "chunked"
					}
					return p, nh
				},
			},
		}
	case "akamai":
		return []EvasionTechnique{
			{
				Name: "case-variation",
				ModifyRequest: func(p string, h map[string]string, method string) (string, map[string]string) {
					var sb strings.Builder
					for i, c := range p {
						if i%2 == 0 {
							sb.WriteRune(c)
						} else {
							sb.WriteString(strings.ToUpper(string(c)))
						}
					}
					return sb.String(), cloneHeadersMap(h)
				},
			},
			{
				Name: "cache-buster",
				ModifyRequest: func(p string, h map[string]string, method string) (string, map[string]string) {
					return fmt.Sprintf("%s?cb=%d", p, rand.Int64()), cloneHeadersMap(h)
				},
			},
		}
	case "imperva":
		return []EvasionTechnique{
			{
				Name: "xff-localhost",
				ModifyRequest: func(p string, h map[string]string, method string) (string, map[string]string) {
					nh := cloneHeadersMap(h)
					nh["X-Forwarded-For"] = "127.0.0.1"
					nh["X-Remote-IP"] = "127.0.0.1"
					nh["X-Originating-IP"] = "127.0.0.1"
					return p, nh
				},
			},
		}
	case "cloudflare":
		return []EvasionTechnique{
			{
				Name: "cf-connecting-ip",
				ModifyRequest: func(p string, h map[string]string, method string) (string, map[string]string) {
					nh := cloneHeadersMap(h)
					nh["CF-Connecting-IP"] = "127.0.0.1"
					nh["X-Forwarded-For"] = "127.0.0.1"
					return p, nh
				},
			},
			{
				Name: "path-dotslash",
				ModifyRequest: func(p string, h map[string]string, method string) (string, map[string]string) {
					mutated := mutatePathOnly(p, func(path string) string {
						return "/%2e" + path
					})
					return mutated, cloneHeadersMap(h)
				},
			},
		}
	default:
		return []EvasionTechnique{
			{
				Name: "x-original-url",
				ModifyRequest: func(p string, h map[string]string, method string) (string, map[string]string) {
					nh := cloneHeadersMap(h)
					nh["X-Original-URL"] = p
					return "/", nh
				},
			},
			{
				Name: "x-rewrite-url",
				ModifyRequest: func(p string, h map[string]string, method string) (string, map[string]string) {
					nh := cloneHeadersMap(h)
					nh["X-Rewrite-URL"] = p
					return "/", nh
				},
			},
			{
				Name: "x-custom-ip-127",
				ModifyRequest: func(p string, h map[string]string, method string) (string, map[string]string) {
					nh := cloneHeadersMap(h)
					nh["X-Custom-IP-Authorization"] = "127.0.0.1"
					return p, nh
				},
			},
			{
				Name: "trailing-slash",
				ModifyRequest: func(p string, h map[string]string, method string) (string, map[string]string) {
					mutated := mutatePathOnly(p, func(path string) string {
						return strings.TrimRight(path, "/") + "/"
					})
					return mutated, cloneHeadersMap(h)
				},
			},
			{
				Name: "dot-slash",
				ModifyRequest: func(p string, h map[string]string, method string) (string, map[string]string) {
					mutated := mutatePathOnly(p, func(path string) string {
						return path + "/./"
					})
					return mutated, cloneHeadersMap(h)
				},
			},
			{
				Name: "url-encoded-slash",
				ModifyRequest: func(p string, h map[string]string, method string) (string, map[string]string) {
					mutated := mutatePathOnly(p, func(path string) string {
						return strings.Replace(path, "/", "%2f", 1)
					})
					return mutated, cloneHeadersMap(h)
				},
			},
			{
				Name: "double-slash-prefix",
				ModifyRequest: func(p string, h map[string]string, method string) (string, map[string]string) {
					mutated := mutatePathOnly(p, func(path string) string {
						return "//" + strings.TrimPrefix(path, "/")
					})
					return mutated, cloneHeadersMap(h)
				},
			},
			{
				Name: "x-forwarded-for-127",
				ModifyRequest: func(p string, h map[string]string, method string) (string, map[string]string) {
					nh := cloneHeadersMap(h)
					nh["X-Forwarded-For"] = "127.0.0.1"
					return p, nh
				},
			},
			{
				Name: "head-method",
				ModifyRequest: func(p string, h map[string]string, method string) (string, map[string]string) {
					return p, cloneHeadersMap(h)
				},
			},
			{
				Name: "trailing-dot-slash",
				ModifyRequest: func(p string, h map[string]string, method string) (string, map[string]string) {
					mutated := mutatePathOnly(p, func(path string) string {
						return path + "/./"
					})
					return mutated, cloneHeadersMap(h)
				},
			},
			{
				Name: "unicode-first-char",
				ModifyRequest: func(p string, h map[string]string, method string) (string, map[string]string) {
					mutated := mutatePathOnly(p, func(path string) string {
						if len(path) > 1 {
							return fmt.Sprintf("/%s%s", "%C0%AF", path[1:])
						}
						return path
					})
					return mutated, cloneHeadersMap(h)
				},
			},
		}
	}
}

// H2EvasionStrategies returns HTTP/2-specific evasion hooks.
// The current client API exposes HTTP/2 streams but not raw frame injection,
// so these techniques are lightweight request variants that keep the hooks in
// place for future frame-level expansion.
func H2EvasionStrategies() []EvasionTechnique {
	return []EvasionTechnique{
		{
			Name: "h2-header-case",
			ModifyRequest: func(p string, h map[string]string, method string) (string, map[string]string) {
				if strings.Contains(p, "?") {
					return p + "&h2case=1", cloneHeadersMap(h)
				}
				return p + "?h2case=1", cloneHeadersMap(h)
			},
		},
		{
			Name: "h2-priority-frame",
			ModifyRequest: func(p string, h map[string]string, method string) (string, map[string]string) {
				if strings.Contains(p, "?") {
					return p + "&h2prio=1", cloneHeadersMap(h)
				}
				return p + "?h2prio=1", cloneHeadersMap(h)
			},
		},
	}
}

func FormatEvasionSummaryRows(rows []EvasionScoreboardRow) string {
	if len(rows) == 0 {
		return "WAF Bypass Summary\nNo bypass attempts recorded."
	}
	var sb strings.Builder
	sb.WriteString("WAF Bypass Summary\n")
	sb.WriteString("Technique | Attempts | Bypasses | Rate%\n")
	sb.WriteString("--- | ---: | ---: | ---:\n")
	for _, row := range rows {
		fmt.Fprintf(&sb, "%s | %d | %d | %.1f%%\n",
			row.Technique, row.Attempts, row.Bypasses, row.Rate*100)
	}
	return sb.String()
}

// Bypass403Techniques returns path mutations and header sets that are
// known to bypass application-level 403 controls independently of WAF vendor.
func Bypass403Techniques(rawPath string, headers map[string]string) []EvasionTechnique {
	cloneHeaders := func(h map[string]string) map[string]string {
		n := make(map[string]string, len(h))
		for k, v := range h {
			n[k] = v
		}
		return n
	}

	return []EvasionTechnique{
		{
			Name: "x-original-url",
			ModifyRequest: func(p string, h map[string]string, _ string) (string, map[string]string) {
				nh := cloneHeaders(h)
				nh["X-Original-URL"] = p
				return "/", nh
			},
		},
		{
			Name: "x-rewrite-url",
			ModifyRequest: func(p string, h map[string]string, _ string) (string, map[string]string) {
				nh := cloneHeaders(h)
				nh["X-Rewrite-URL"] = p
				return "/", nh
			},
		},
		{
			Name: "x-custom-ip-127",
			ModifyRequest: func(p string, h map[string]string, _ string) (string, map[string]string) {
				nh := cloneHeaders(h)
				nh["X-Custom-IP-Authorization"] = "127.0.0.1"
				return p, nh
			},
		},
		{
			Name: "trailing-slash",
			ModifyRequest: func(p string, h map[string]string, _ string) (string, map[string]string) {
				mutated := mutatePathOnly(p, func(path string) string {
					return strings.TrimRight(path, "/") + "/"
				})
				return mutated, cloneHeaders(h)
			},
		},
		{
			Name: "dot-slash",
			ModifyRequest: func(p string, h map[string]string, _ string) (string, map[string]string) {
				mutated := mutatePathOnly(p, func(path string) string {
					return path + "/./"
				})
				return mutated, cloneHeaders(h)
			},
		},
		{
			Name: "url-encoded-slash",
			ModifyRequest: func(p string, h map[string]string, _ string) (string, map[string]string) {
				mutated := mutatePathOnly(p, func(path string) string {
					return strings.Replace(path, "/", "%2f", 1)
				})
				return mutated, cloneHeaders(h)
			},
		},
		{
			Name: "double-slash-prefix",
			ModifyRequest: func(p string, h map[string]string, _ string) (string, map[string]string) {
				mutated := mutatePathOnly(p, func(path string) string {
					return "//" + strings.TrimPrefix(path, "/")
				})
				return mutated, cloneHeaders(h)
			},
		},
		{
			Name: "x-forwarded-for-127",
			ModifyRequest: func(p string, h map[string]string, _ string) (string, map[string]string) {
				nh := cloneHeaders(h)
				nh["X-Forwarded-For"] = "127.0.0.1"
				return p, nh
			},
		},
	}
}

func mutatePathOnly(p string, mutate func(string) string) string {
	idx := strings.Index(p, "?")
	if idx < 0 {
		return mutate(p)
	}
	path := p[:idx]
	query := p[idx:]
	return mutate(path) + query
}
