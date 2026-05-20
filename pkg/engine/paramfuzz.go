package engine

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// ParamTask describes a hidden-parameter fuzzing target.
type ParamTask struct {
	URL                 string
	Method              string
	BaselineHash        uint64
	BaselineStatusCode  int
	BaselineSize        int
	BaselineContentType string
}

type paramBaseline struct {
	statusCode int
	size       int
	hash       uint64
}

// ParamHit captures a hidden-parameter discovery result.
type ParamHit struct {
	Params      []string          `json:"params"`
	ProbeURL    string            `json:"probe_url"`
	StatusCode  int               `json:"status_code"`
	Size        int               `json:"size"`
	Words       int               `json:"words"`
	Lines       int               `json:"lines"`
	ContentType string            `json:"content_type,omitempty"`
	Duration    time.Duration     `json:"duration,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
}

type ParamProbeFinding struct {
	Params      []string          `json:"params"`
	ProbeURL    string            `json:"probe_url"`
	StatusCode  int               `json:"status_code"`
	SizeBytes   int               `json:"size_bytes"`
	Words       int               `json:"words"`
	Lines       int               `json:"lines"`
	ContentType string            `json:"content_type,omitempty"`
	DurationMS  int64             `json:"duration_ms"`
	Headers     map[string]string `json:"headers,omitempty"`
}

type ParamProbeReport struct {
	Target             string              `json:"target"`
	Path               string              `json:"path"`
	Method             string              `json:"method"`
	BaselineStatusCode int                 `json:"baseline_status_code"`
	BaselineSizeBytes  int                 `json:"baseline_size_bytes"`
	BaselineHash       uint64              `json:"baseline_hash"`
	Findings           []ParamProbeFinding `json:"findings"`
}

const paramChunkSize = 50

var defaultParamWordlist = []string{
	"action",
	"admin",
	"api",
	"auth",
	"auth_token",
	"callback",
	"cmd",
	"continue",
	"controller",
	"count",
	"csrf",
	"data",
	"debug",
	"destination",
	"download",
	"edit",
	"email",
	"endpoint",
	"exec",
	"export",
	"file",
	"filter",
	"format",
	"group",
	"hash",
	"height",
	"host",
	"id",
	"include",
	"index",
	"input",
	"item",
	"lang",
	"language",
	"layout",
	"limit",
	"locale",
	"login",
	"logout",
	"method",
	"mode",
	"module",
	"name",
	"next",
	"nonce",
	"object",
	"offset",
	"open",
	"op",
	"order",
	"output",
	"page",
	"page_num",
	"page_number",
	"password",
	"path",
	"preview",
	"print",
	"p",
	"query",
	"q",
	"range",
	"redirect",
	"redirect_to",
	"ref",
	"referrer",
	"response",
	"return",
	"route",
	"search",
	"select",
	"section",
	"show",
	"sort",
	"source",
	"state",
	"status",
	"start",
	"step",
	"style",
	"submit",
	"target",
	"template",
	"template_id",
	"test",
	"theme",
	"time",
	"token",
	"type",
	"uid",
	"url",
	"user",
	"username",
	"value",
	"view",
	"width",
	"xml",
	"yaml",
	"x",
	"y",
}

var paramProbeValues = []string{"a", "b", "c", "d", "e"}

func (e *Engine) startParamFuzzWorkers(workerCount int) {
	if e == nil || e.paramTaskChan == nil || workerCount <= 0 {
		return
	}
	for i := 0; i < workerCount; i++ {
		e.paramFuzzWg.Add(1)
		go func() {
			defer e.paramFuzzWg.Done()
			e.paramFuzzWorker()
		}()
	}
}

func (e *Engine) paramFuzzWorker() {
	for task := range e.paramTaskChan {
		e.runParamTask(task)
	}
}

func (e *Engine) queueParamFuzzFromResult(res Result, bodySize int, bodyHash uint64) {
	if e == nil || res.URL == "" || res.IsAutoFilter {
		return
	}
	if !shouldQueueParamFuzz(res.StatusCode, res.Method, bodySize, bodyHash) {
		return
	}

	task := ParamTask{
		URL:                res.URL,
		Method:             res.Method,
		BaselineHash:       bodyHash,
		BaselineStatusCode: res.StatusCode,
		BaselineSize:       bodySize,
	}
	if task.Method == "" {
		task.Method = "GET"
	}
	e.enqueueParamTask(task)
}

func shouldQueueParamFuzz(statusCode int, method string, bodySize int, bodyHash uint64) bool {
	_ = bodyHash
	if strings.EqualFold(method, "HEAD") {
		return false
	}
	if bodySize <= 0 {
		return false
	}
	switch statusCode {
	case 200, 201, 202, 203, 204, 206, 301, 302, 303, 307, 308, 401, 403:
		return true
	default:
		return false
	}
}

func (e *Engine) enqueueParamTask(task ParamTask) bool {
	if e == nil || e.paramTaskChan == nil || task.URL == "" {
		return false
	}

	key := strings.ToLower(task.URL)
	if _, loaded := e.paramTaskSeen.LoadOrStore(key, struct{}{}); loaded {
		return false
	}

	select {
	case e.paramTaskChan <- task:
		return true
	default:
		e.paramTaskSeen.Delete(key)
		return false
	}
}

func (e *Engine) runParamTask(task ParamTask) {
	if e == nil || task.URL == "" {
		return
	}

	ctx := context.Background()
	if sc := e.scannerCtx.Load(); sc != nil && sc.ctx != nil {
		ctx = sc.ctx
	}

	hits, err := e.FuzzParams(ctx, task, nil)
	if err != nil || len(hits) == 0 {
		return
	}

	if len(hits) == 0 {
		return
	}

	for _, hit := range hits {
		if len(hit.Params) == 0 {
			continue
		}
		msg := fmt.Sprintf("hidden parameters discovered: %s", strings.Join(hit.Params, ","))
		res := Result{
			Path:             hit.ProbeURL,
			Method:           "GET",
			StatusCode:       hit.StatusCode,
			Size:             hit.Size,
			Words:            hit.Words,
			Lines:            hit.Lines,
			ContentType:      hit.ContentType,
			Duration:         hit.Duration,
			URL:              hit.ProbeURL,
			Headers:          map[string]string{"Msg": msg},
			Labels:           []string{"PARAM-FUZZ"},
			DiscoveredParams: append([]string(nil), hit.Params...),
		}
		if len(hit.Params) == 1 {
			res.Confidence = "single-param"
		} else {
			res.Confidence = fmt.Sprintf("%d params", len(hit.Params))
		}
		if len(hit.Headers) > 0 {
			res.Headers = hit.Headers
			res.Headers["Msg"] = msg
		}
		e.handleResultNonBlocking(res)
	}
}

// FuzzParams runs hidden-parameter discovery against task.URL using either a
// caller-provided wordlist or the built-in defaults.
func (e *Engine) FuzzParams(ctx context.Context, task ParamTask, customWordlist []string) ([]ParamHit, error) {
	if e == nil {
		return nil, fmt.Errorf("engine is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if task.URL == "" {
		return nil, fmt.Errorf("task.URL is required")
	}
	if task.Method == "" {
		task.Method = "GET"
	}

	snap := e.configSnap.Load()
	if snap == nil {
		e.buildAndStoreConfigSnapshot()
		snap = e.configSnap.Load()
	}

	candidates := uniqueStrings(customWordlist)
	if len(candidates) == 0 {
		candidates = uniqueStrings(defaultParamWordlist)
	}
	if len(candidates) == 0 {
		return nil, nil
	}

	baseline := paramBaseline{
		statusCode: task.BaselineStatusCode,
		size:       task.BaselineSize,
		hash:       task.BaselineHash,
	}
	if baseline.statusCode == 0 && baseline.size == 0 && baseline.hash == 0 {
		parsed, err := url.Parse(task.URL)
		if err != nil {
			return nil, fmt.Errorf("invalid param fuzz target URL: %w", err)
		}
		reqPath := parsed.EscapedPath()
		if reqPath == "" {
			reqPath = "/"
		}
		if parsed.RawQuery != "" {
			reqPath += "?" + parsed.RawQuery
		}
		ua := "DirFuzz/2.0"
		headersTemplate := ""
		timeout := DefaultHTTPTimeout
		proxyOut := ""
		if snap != nil {
			if snap.UserAgent != "" {
				ua = snap.UserAgent
			}
			headersTemplate = snap.HeadersTemplate
			if snap.Timeout > 0 {
				timeout = snap.Timeout
			}
			proxyOut = snap.ProxyOut
		}
		rawReq := buildRequest(task.Method, reqPath, parsed.Host, ua, headersTemplate, "")
		resp, err := e.executeRequestWithRetry(ctx, parsed.String(), rawReq, timeout, proxyOut)
		if err != nil || resp == nil {
			return nil, err
		}
		bodySize, _, _, _, bodyHash := computeResponseMetrics(resp, task.Method)
		baseline = paramBaseline{
			statusCode: resp.StatusCode,
			size:       bodySize,
			hash:       bodyHash,
		}
		task.BaselineStatusCode = resp.StatusCode
		task.BaselineSize = bodySize
		task.BaselineHash = bodyHash
	}

	return e.discoverParamHits(ctx, task, candidates, baseline, snap), nil
}

func (e *Engine) discoverParamHits(
	ctx context.Context,
	task ParamTask,
	candidates []string,
	baseline paramBaseline,
	snap *configSnapshot,
) []ParamHit {
	if len(candidates) == 0 {
		return nil
	}
	if len(candidates) > paramChunkSize {
		var hits []ParamHit
		for start := 0; start < len(candidates); start += paramChunkSize {
			end := start + paramChunkSize
			if end > len(candidates) {
				end = len(candidates)
			}
			hits = append(hits, e.discoverParamHits(ctx, task, candidates[start:end], baseline, snap)...)
		}
		return hits
	}

	hit, matched, err := e.probeParamSubset(ctx, task, candidates, baseline, snap)
	if err != nil || !matched {
		return nil
	}

	if len(candidates) == 1 {
		hit.Params = append([]string(nil), candidates...)
		return []ParamHit{hit}
	}

	mid := len(candidates) / 2
	left := e.discoverParamHits(ctx, task, candidates[:mid], baseline, snap)
	right := e.discoverParamHits(ctx, task, candidates[mid:], baseline, snap)
	return append(left, right...)
}

func (e *Engine) probeParamSubset(
	ctx context.Context,
	task ParamTask,
	params []string,
	baseline paramBaseline,
	snap *configSnapshot,
) (ParamHit, bool, error) {
	if len(params) == 0 {
		return ParamHit{}, false, nil
	}

	probeURL, rawReq, err := buildParamProbeRequest(task.URL, params, snap)
	if err != nil {
		return ParamHit{}, false, err
	}

	timeout := DefaultHTTPTimeout
	proxyOut := ""
	if snap != nil {
		if snap.Timeout > 0 {
			timeout = snap.Timeout
		}
		proxyOut = snap.ProxyOut
	}

	resp, err := e.executeRequestWithRetry(ctx, probeURL, rawReq, timeout, proxyOut)
	if err != nil || resp == nil {
		return ParamHit{}, false, err
	}

	bodySize, wordCount, lineCount, contentType, bodyHash := computeResponseMetrics(resp, "GET")
	if !responseDiffersFromBaseline(baseline, resp.StatusCode, bodySize, bodyHash) {
		return ParamHit{}, false, nil
	}

	return ParamHit{
		Params:      append([]string(nil), params...),
		ProbeURL:    probeURL,
		StatusCode:  resp.StatusCode,
		Size:        bodySize,
		Words:       wordCount,
		Lines:       lineCount,
		ContentType: contentType,
		Duration:    resp.Duration,
		Headers:     captureParamHeaders(resp.Headers),
	}, true, nil
}

func buildParamProbeRequest(taskURL string, params []string, snap *configSnapshot) (string, []byte, error) {
	u, err := url.Parse(taskURL)
	if err != nil {
		return "", nil, fmt.Errorf("invalid param fuzz target URL: %w", err)
	}

	query := u.Query()
	for i, param := range params {
		if param == "" {
			continue
		}
		query.Set(param, paramProbeValues[i%len(paramProbeValues)])
	}
	u.RawQuery = query.Encode()

	reqPath := u.EscapedPath()
	if reqPath == "" {
		reqPath = "/"
	}
	if u.RawQuery != "" {
		reqPath += "?" + u.RawQuery
	}

	ua := "DirFuzz/2.0"
	headersTemplate := ""
	if snap != nil {
		if snap.UserAgent != "" {
			ua = snap.UserAgent
		}
		headersTemplate = snap.HeadersTemplate
	}

	return u.String(), buildRequest("GET", reqPath, u.Host, ua, headersTemplate, ""), nil
}

func responseDiffersFromBaseline(baseline paramBaseline, statusCode, size int, bodyHash uint64) bool {
	if statusCode != baseline.statusCode {
		return true
	}
	if baseline.size != size {
		return true
	}
	if bodyHash != baseline.hash {
		return true
	}
	return false
}

func captureParamHeaders(rawHeaders string) map[string]string {
	if rawHeaders == "" {
		return nil
	}
	headers := make(map[string]string)
	for _, line := range strings.Split(strings.ReplaceAll(rawHeaders, "\r\n", "\n"), "\n") {
		idx := strings.Index(line, ":")
		if idx == -1 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:idx]))
		val := strings.TrimSpace(line[idx+1:])
		switch key {
		case "server":
			headers["Server"] = val
		case "x-powered-by":
			headers["X-Powered-By"] = val
		case "cf-ray":
			headers["Cf-Ray"] = val
		case "content-type":
			headers["Content-Type"] = val
		}
	}
	if len(headers) == 0 {
		return nil
	}
	return headers
}

func (e *Engine) ProbeHiddenParams(ctx context.Context, targetURL, rawPath, method string, headers map[string]string) (ParamProbeReport, error) {
	report := ParamProbeReport{Target: targetURL, Path: rawPath, Method: method}
	if e == nil {
		return report, fmt.Errorf("engine is nil")
	}
	if targetURL == "" {
		return report, fmt.Errorf("targetURL is required")
	}
	if method == "" {
		method = "GET"
		report.Method = method
	}

	taskURL := targetURL
	if rawPath != "" {
		if strings.HasPrefix(rawPath, "http://") || strings.HasPrefix(rawPath, "https://") {
			taskURL = rawPath
		} else {
			taskURL = strings.TrimRight(targetURL, "/") + "/" + strings.TrimLeft(rawPath, "/")
		}
	}
	snap := e.configSnap.Load()
	if snap == nil {
		e.buildAndStoreConfigSnapshot()
		snap = e.configSnap.Load()
	}

	parsed, err := url.Parse(taskURL)
	if err != nil {
		return report, err
	}
	if strings.HasPrefix(rawPath, "http://") || strings.HasPrefix(rawPath, "https://") {
		if parsed.Path != "" {
			report.Path = parsed.Path
		}
		if parsed.RawQuery != "" {
			report.Path += "?" + parsed.RawQuery
		}
	}
	ua := "DirFuzz/2.0"
	headersTemplate := ""
	timeout := DefaultHTTPTimeout
	proxyOut := ""
	if snap != nil {
		if snap.UserAgent != "" {
			ua = snap.UserAgent
		}
		headersTemplate = snap.HeadersTemplate
		if snap.Timeout > 0 {
			timeout = snap.Timeout
		}
		proxyOut = snap.ProxyOut
	}
	if len(headers) > 0 {
		headersTemplate += renderHeaderBlock(headers)
	}

	reqPath := parsed.EscapedPath()
	if reqPath == "" {
		reqPath = "/"
	}
	if parsed.RawQuery != "" {
		reqPath += "?" + parsed.RawQuery
	}

	rawReq := buildRequest(method, reqPath, parsed.Host, ua, headersTemplate, "")
	resp, err := e.executeRequestWithRetry(ctx, parsed.String(), rawReq, timeout, proxyOut)
	if err != nil || resp == nil {
		return report, err
	}
	bodySize, _, _, _, bodyHash := computeResponseMetrics(resp, method)
	report.BaselineStatusCode = resp.StatusCode
	report.BaselineSizeBytes = bodySize
	report.BaselineHash = bodyHash

	task := ParamTask{
		URL:                parsed.String(),
		Method:             method,
		BaselineHash:       bodyHash,
		BaselineStatusCode: resp.StatusCode,
		BaselineSize:       bodySize,
	}
	baseline := paramBaseline{
		statusCode: resp.StatusCode,
		size:       bodySize,
		hash:       bodyHash,
	}
	candidates := uniqueStrings(defaultParamWordlist)
	hits := e.discoverParamHits(ctx, task, candidates, baseline, snap)
	for _, hit := range hits {
		report.Findings = append(report.Findings, ParamProbeFinding{
			Params:      append([]string(nil), hit.Params...),
			ProbeURL:    hit.ProbeURL,
			StatusCode:  hit.StatusCode,
			SizeBytes:   hit.Size,
			Words:       hit.Words,
			Lines:       hit.Lines,
			ContentType: hit.ContentType,
			DurationMS:  hit.Duration.Milliseconds(),
			Headers:     hit.Headers,
		})
	}
	return report, nil
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
