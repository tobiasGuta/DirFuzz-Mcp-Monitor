package engine

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/html"
)

// ParamTask describes a hidden-parameter fuzzing target.
type ParamTask struct {
	URL                 string
	Method              string
	BaselineHash        uint64
	BaselineStatusCode  int
	BaselineSize        int
	BaselineContentType string
	CandidateHints      []string
}

type paramBaseline struct {
	statusCode int
	size       int
	hash       uint64
}

type paramResponseFingerprint struct {
	statusCode int
	size       int
	hash       uint64
}

// ParamHit captures a hidden-parameter discovery result.
type ParamHit struct {
	Params        []string          `json:"params"`
	ProbeURL      string            `json:"probe_url"`
	StatusCode    int               `json:"status_code"`
	Size          int               `json:"size"`
	Words         int               `json:"words"`
	Lines         int               `json:"lines"`
	ContentType   string            `json:"content_type,omitempty"`
	Duration      time.Duration     `json:"duration,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	Request       string            `json:"request,omitempty"`
	Response      string            `json:"response,omitempty"`
	RequestBytes  []byte            `json:"-"`
	ResponseBytes []byte            `json:"-"`
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

var paramProbeValues = []string{"a", "b", "c", "d", "e"}
var numericParamProbeValues = []string{"1", "2", "3", "4", "5"}
var paramControlNames = []string{
	"__dirfuzz_control",
	"__dirfuzz_probe",
}

var (
	paramHintPatternRes = []*regexp.Regexp{
		regexp.MustCompile(`(?i)[?&]([a-zA-Z][a-zA-Z0-9_.-]{0,63})=`),
		regexp.MustCompile(`(?i)\b([a-zA-Z][a-zA-Z0-9_.-]{0,63})\s+parameter\b`),
		regexp.MustCompile(`(?i)\bparameter\s+([a-zA-Z][a-zA-Z0-9_.-]{0,63})\b`),
		regexp.MustCompile(`(?i)\bprovide\s+[?&]?([a-zA-Z][a-zA-Z0-9_.-]{0,63})=?\s+parameter\b`),
		regexp.MustCompile(`(?i)\bmissing\s+(?:required\s+)?parameter\s+[\"'` + "`" + `]?([a-zA-Z][a-zA-Z0-9_.-]{0,63})[\"'` + "`" + `]?\b`),
	}
	paramHintStopwords = map[string]struct{}{
		"a": {}, "an": {}, "and": {}, "auth": {}, "authentication": {}, "in": {}, "is": {},
		"log": {}, "login": {}, "missing": {}, "or": {}, "parameter": {}, "please": {},
		"provide": {}, "required": {}, "the": {}, "to": {}, "valid": {}, "value": {},
	}
)

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
		func() {
			defer e.paramTasksWg.Done()
			e.runParamTask(task)
		}()
	}
}

func (e *Engine) queueParamFuzzFromResult(res Result, effectiveURL string, bodySize int, bodyHash uint64, contentType string, body []byte) {
	if e == nil || res.URL == "" || res.IsAutoFilter {
		return
	}
	if strings.TrimSpace(effectiveURL) == "" {
		effectiveURL = res.URL
	}
	snap := e.configSnap.Load()
	hints := extractParamHints(effectiveURL, contentType, body)
	if isPHPParamTarget(effectiveURL) {
		hints = append(hints, e.globalParamHints()...)
	}
	if len(paramCandidates(nil, snap, hints)) == 0 {
		return
	}
	if !shouldQueueParamFuzz(res.StatusCode, res.Method, bodySize, bodyHash) {
		return
	}

	task := ParamTask{
		URL:                 effectiveURL,
		Method:              res.Method,
		BaselineHash:        bodyHash,
		BaselineStatusCode:  res.StatusCode,
		BaselineSize:        bodySize,
		BaselineContentType: contentType,
		CandidateHints:      hints,
	}
	if task.Method == "" {
		task.Method = "GET"
	}
	e.rememberPHPParamTarget(task)
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
	case 200, 201, 202, 203, 204, 206, 401, 403:
		return true
	default:
		return false
	}
}

func (e *Engine) enqueueParamTask(task ParamTask) bool {
	if e == nil || e.paramTaskChan == nil || task.URL == "" {
		return false
	}

	key := paramTaskQueueIdentity(task)
	if key == "" {
		key = strings.ToLower(strings.TrimSpace(task.URL))
	}
	if _, loaded := e.paramTaskSeen.LoadOrStore(key, struct{}{}); loaded {
		return false
	}
	baseKey := paramTaskIdentity(task)
	if baseKey != "" && baseKey != key {
		e.paramTaskSeen.Store(baseKey, struct{}{})
	}

	e.paramTasksWg.Add(1)
	select {
	case e.paramTaskChan <- task:
		return true
	default:
		e.paramTasksWg.Done()
		e.paramTaskSeen.Delete(key)
		if baseKey != "" && baseKey != key {
			e.paramTaskSeen.Delete(baseKey)
		}
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
		newParams := e.rememberGlobalParamHints(hit.Params)
		if len(newParams) > 0 {
			e.queueKnownPHPTargetsForParams(newParams)
		}
		if !e.markParamHitSeen(hit) {
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
		if hit.Request != "" || len(hit.RequestBytes) > 0 {
			res.Request = hit.Request
			res.RequestBytes = append([]byte(nil), hit.RequestBytes...)
		}
		if hit.Response != "" || len(hit.ResponseBytes) > 0 {
			res.Response = hit.Response
			res.ResponseBytes = append([]byte(nil), hit.ResponseBytes...)
		}
		e.handleResultNonBlocking(res)
	}
}

func (e *Engine) markParamHitSeen(hit ParamHit) bool {
	if e == nil {
		return false
	}
	key := paramHitIdentity(hit)
	if key == "" {
		return true
	}
	_, loaded := e.paramHitSeen.LoadOrStore(key, struct{}{})
	return !loaded
}

func (e *Engine) rememberGlobalParamHints(params []string) []string {
	if e == nil {
		return nil
	}
	var added []string
	for _, param := range uniqueStrings(params) {
		if !isLikelyParamHint(param) {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(param))
		if _, loaded := e.paramHintsSeen.LoadOrStore(key, param); loaded {
			continue
		}
		added = append(added, param)
	}
	return added
}

func (e *Engine) globalParamHints() []string {
	if e == nil {
		return nil
	}
	var hints []string
	e.paramHintsSeen.Range(func(_, value any) bool {
		if hint, ok := value.(string); ok && hint != "" {
			hints = append(hints, hint)
		}
		return true
	})
	return uniqueStrings(hints)
}

func (e *Engine) rememberPHPParamTarget(task ParamTask) {
	if e == nil || task.URL == "" || !isPHPParamTarget(task.URL) {
		return
	}
	key := phpParamTargetIdentity(task.URL, task.Method)
	if key == "" {
		return
	}
	e.phpParamTargets.Store(key, task)
}

func (e *Engine) queueKnownPHPTargetsForParams(params []string) {
	if e == nil || len(params) == 0 {
		return
	}
	params = uniqueStrings(params)
	e.phpParamTargets.Range(func(_, value any) bool {
		task, ok := value.(ParamTask)
		if !ok || task.URL == "" {
			return true
		}
		task.CandidateHints = uniqueStrings(append(task.CandidateHints, params...))
		e.enqueueParamTask(task)
		return true
	})
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
		bodySize, _, _, contentType, bodyHash := computeResponseMetrics(resp, task.Method)
		baseline = paramBaseline{
			statusCode: resp.StatusCode,
			size:       bodySize,
			hash:       bodyHash,
		}
		task.BaselineStatusCode = resp.StatusCode
		task.BaselineSize = bodySize
		task.BaselineHash = bodyHash
		task.BaselineContentType = contentType
		if len(task.CandidateHints) == 0 {
			task.CandidateHints = extractParamHints(task.URL, contentType, resp.Body)
		}
	}

	candidates := paramCandidates(customWordlist, snap, task.CandidateHints)
	if len(candidates) == 0 {
		return nil, nil
	}

	controls := e.paramNoiseControls(ctx, task, candidates, snap)
	return e.discoverParamHits(ctx, task, candidates, baseline, controls, snap), nil
}

func (e *Engine) discoverParamHits(
	ctx context.Context,
	task ParamTask,
	candidates []string,
	baseline paramBaseline,
	controls []paramResponseFingerprint,
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
			hits = append(hits, e.discoverParamHits(ctx, task, candidates[start:end], baseline, controls, snap)...)
		}
		return hits
	}

	hit, matched, err := e.probeParamSubset(ctx, task, candidates, baseline, controls, snap)
	if err != nil || !matched {
		return nil
	}

	if len(candidates) == 1 {
		hit.Params = append([]string(nil), candidates...)
		return []ParamHit{hit}
	}

	mid := len(candidates) / 2
	left := e.discoverParamHits(ctx, task, candidates[:mid], baseline, controls, snap)
	right := e.discoverParamHits(ctx, task, candidates[mid:], baseline, controls, snap)
	return append(left, right...)
}

func (e *Engine) probeParamSubset(
	ctx context.Context,
	task ParamTask,
	params []string,
	baseline paramBaseline,
	controls []paramResponseFingerprint,
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
	if !isUsefulParamProbeTransition(baseline, resp.StatusCode) {
		return ParamHit{}, false, nil
	}
	if responseMatchesParamControls(controls, resp.StatusCode, bodySize, bodyHash) {
		return ParamHit{}, false, nil
	}

	hit := ParamHit{
		Params:      append([]string(nil), params...),
		ProbeURL:    probeURL,
		StatusCode:  resp.StatusCode,
		Size:        bodySize,
		Words:       wordCount,
		Lines:       lineCount,
		ContentType: contentType,
		Duration:    resp.Duration,
		Headers:     captureParamHeaders(resp.Headers),
	}
	if snap != nil && snap.SaveRaw {
		hit.Request = string(rawReq)
		hit.Response = string(resp.Raw)
		hit.RequestBytes = append([]byte(nil), rawReq...)
		hit.ResponseBytes = append([]byte(nil), resp.Raw...)
	}
	return hit, true, nil
}

func (e *Engine) paramNoiseControls(
	ctx context.Context,
	task ParamTask,
	candidates []string,
	snap *configSnapshot,
) []paramResponseFingerprint {
	if e == nil || task.URL == "" {
		return nil
	}

	controlParams := chooseParamControlNames(task.URL, candidates)
	if len(controlParams) == 0 {
		return nil
	}

	timeout := DefaultHTTPTimeout
	proxyOut := ""
	if snap != nil {
		if snap.Timeout > 0 {
			timeout = snap.Timeout
		}
		proxyOut = snap.ProxyOut
	}

	controls := make([]paramResponseFingerprint, 0, len(controlParams))
	for _, controlParam := range controlParams {
		probeURL, rawReq, err := buildParamProbeRequest(task.URL, []string{controlParam}, snap)
		if err != nil {
			continue
		}
		resp, err := e.executeRequestWithRetry(ctx, probeURL, rawReq, timeout, proxyOut)
		if err != nil || resp == nil {
			continue
		}
		bodySize, _, _, _, bodyHash := computeResponseMetrics(resp, "GET")
		controls = append(controls, paramResponseFingerprint{
			statusCode: resp.StatusCode,
			size:       bodySize,
			hash:       bodyHash,
		})
	}
	return controls
}

func chooseParamControlNames(taskURL string, candidates []string) []string {
	used := make(map[string]struct{}, len(candidates)+4)
	for _, candidate := range candidates {
		candidate = strings.ToLower(strings.TrimSpace(candidate))
		if candidate != "" {
			used[candidate] = struct{}{}
		}
	}
	if parsed, err := url.Parse(taskURL); err == nil {
		for key := range parsed.Query() {
			key = strings.ToLower(strings.TrimSpace(key))
			if key != "" {
				used[key] = struct{}{}
			}
		}
	}

	controls := make([]string, 0, len(paramControlNames))
	for _, name := range paramControlNames {
		key := strings.ToLower(name)
		if _, exists := used[key]; exists {
			continue
		}
		controls = append(controls, name)
	}
	return controls
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
		query.Set(param, paramProbeValue(param, i))
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

func isUsefulParamProbeTransition(baseline paramBaseline, statusCode int) bool {
	if statusCode == http.StatusNotFound {
		return false
	}
	return true
}

func paramProbeValue(param string, index int) string {
	if looksIdentifierParam(param) {
		return numericParamProbeValues[index%len(numericParamProbeValues)]
	}
	return paramProbeValues[index%len(paramProbeValues)]
}

func looksIdentifierParam(param string) bool {
	param = strings.ToLower(strings.TrimSpace(param))
	if param == "" {
		return false
	}
	return param == "id" ||
		strings.HasSuffix(param, "_id") ||
		strings.HasSuffix(param, "-id") ||
		strings.HasSuffix(param, ".id") ||
		strings.HasSuffix(param, "id")
}

func responseMatchesParamControls(controls []paramResponseFingerprint, statusCode, size int, bodyHash uint64) bool {
	for _, control := range controls {
		if control.statusCode == statusCode && control.size == size && control.hash == bodyHash {
			return true
		}
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
	bodySize, _, _, contentType, bodyHash := computeResponseMetrics(resp, method)
	report.BaselineStatusCode = resp.StatusCode
	report.BaselineSizeBytes = bodySize
	report.BaselineHash = bodyHash

	task := ParamTask{
		URL:                 parsed.String(),
		Method:              method,
		BaselineHash:        bodyHash,
		BaselineStatusCode:  resp.StatusCode,
		BaselineSize:        bodySize,
		BaselineContentType: contentType,
	}
	baseline := paramBaseline{
		statusCode: resp.StatusCode,
		size:       bodySize,
		hash:       bodyHash,
	}
	if len(task.CandidateHints) == 0 {
		task.CandidateHints = extractParamHints(task.URL, task.BaselineContentType, resp.Body)
	}
	candidates := paramCandidates(nil, snap, task.CandidateHints)
	if len(candidates) == 0 {
		return report, nil
	}
	controls := e.paramNoiseControls(ctx, task, candidates, snap)
	hits := e.discoverParamHits(ctx, task, candidates, baseline, controls, snap)
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

func paramCandidates(customWordlist []string, snap *configSnapshot, hints []string) []string {
	baseCandidates := uniqueStrings(customWordlist)
	if len(baseCandidates) == 0 && snap != nil {
		baseCandidates = uniqueStrings(snap.ParamWordlist)
	}
	if len(baseCandidates) == 0 {
		return nil
	}
	return uniqueStrings(append(baseCandidates, hints...))
}

func paramTaskIdentity(task ParamTask) string {
	rawURL := strings.TrimSpace(task.URL)
	if rawURL == "" {
		return ""
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(task.Method)) + "|" + strings.ToLower(rawURL)
	}

	queryKeys := make([]string, 0, len(parsed.Query()))
	for key := range parsed.Query() {
		key = strings.ToLower(strings.TrimSpace(key))
		if key != "" {
			queryKeys = append(queryKeys, key)
		}
	}
	sort.Strings(queryKeys)
	canonicalPath := parsed.EscapedPath()
	if canonicalPath == "" {
		canonicalPath = "/"
	}

	return strings.ToLower(strings.TrimSpace(task.Method)) + "|" +
		strings.ToLower(parsed.Scheme) + "|" +
		strings.ToLower(parsed.Host) + "|" +
		strings.ToLower(canonicalPath) + "|" +
		strings.Join(queryKeys, ",")
}

func paramTaskQueueIdentity(task ParamTask) string {
	base := paramTaskIdentity(task)
	if base == "" {
		return ""
	}
	hintKeys := make([]string, 0, len(task.CandidateHints))
	for _, hint := range task.CandidateHints {
		hint = strings.ToLower(strings.TrimSpace(hint))
		if hint != "" {
			hintKeys = append(hintKeys, hint)
		}
	}
	sort.Strings(hintKeys)
	return base + "|" + strings.Join(uniqueStrings(hintKeys), ",")
}

func phpParamTargetIdentity(rawURL string, method string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return strings.ToLower(strings.TrimSpace(method)) + "|" + strings.ToLower(strings.TrimSpace(rawURL))
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	return strings.ToLower(strings.TrimSpace(method)) + "|" +
		strings.ToLower(parsed.Scheme) + "|" +
		strings.ToLower(parsed.Host) + "|" +
		strings.ToLower(path)
}

func isPHPParamTarget(rawURL string) bool {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return false
	}
	return strings.HasSuffix(strings.ToLower(parsed.EscapedPath()), ".php")
}

func paramHitIdentity(hit ParamHit) string {
	rawURL := strings.TrimSpace(hit.ProbeURL)
	if rawURL == "" {
		return ""
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "get|" + strings.ToLower(rawURL) + "|" + strings.ToLower(strings.Join(uniqueStrings(hit.Params), ","))
	}

	query := parsed.Query()
	parsed.RawQuery = query.Encode()
	parsed.Fragment = ""

	return "get|" +
		strings.ToLower(parsed.Scheme) + "|" +
		strings.ToLower(parsed.Host) + "|" +
		parsed.EscapedPath() + "|" +
		parsed.RawQuery + "|" +
		strings.ToLower(strings.Join(uniqueStrings(hit.Params), ","))
}

func extractParamHints(targetURL string, contentType string, body []byte) []string {
	if len(body) == 0 {
		return nil
	}

	var hints []string
	hints = append(hints, extractParamHintsFromURL(targetURL)...)
	hints = append(hints, extractParamHintsFromText(string(body))...)
	hints = append(hints, extractParamHintsFromHTML(body)...)
	return uniqueStrings(hints)
}

func extractParamHintsFromURL(targetURL string) []string {
	parsed, err := url.Parse(strings.TrimSpace(targetURL))
	if err != nil {
		return nil
	}
	query := parsed.Query()
	if len(query) == 0 {
		return nil
	}
	hints := make([]string, 0, len(query))
	for key := range query {
		if isLikelyParamHint(key) {
			hints = append(hints, key)
		}
	}
	return hints
}

func extractParamHintsFromText(text string) []string {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	var hints []string
	for _, pattern := range paramHintPatternRes {
		matches := pattern.FindAllStringSubmatch(text, -1)
		for _, match := range matches {
			if len(match) > 1 && isLikelyParamHint(match[1]) {
				hints = append(hints, match[1])
			}
		}
	}
	return hints
}

func extractParamHintsFromHTML(body []byte) []string {
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return nil
	}

	var hints []string
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node == nil {
			return
		}
		if node.Type == html.ElementNode {
			switch strings.ToLower(node.Data) {
			case "input", "select", "textarea", "button":
				if name := htmlAttr(node, "name"); isLikelyParamHint(name) {
					hints = append(hints, name)
				}
			case "form", "a", "link":
				hints = append(hints, extractParamHintsFromURL(htmlAttr(node, "action"))...)
				hints = append(hints, extractParamHintsFromURL(htmlAttr(node, "href"))...)
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)
	return hints
}

func htmlAttr(node *html.Node, key string) string {
	for _, attr := range node.Attr {
		if strings.EqualFold(attr.Key, key) {
			return strings.TrimSpace(attr.Val)
		}
	}
	return ""
}

func isLikelyParamHint(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return false
	}
	if _, blocked := paramHintStopwords[value]; blocked {
		return false
	}
	return true
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
