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

type paramHit struct {
	params      []string
	probeURL    string
	statusCode  int
	size        int
	words       int
	lines       int
	contentType string
	duration    time.Duration
	headers     map[string]string
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

	snap := e.configSnap.Load()
	if snap == nil {
		e.buildAndStoreConfigSnapshot()
		snap = e.configSnap.Load()
	}

	candidates := uniqueStrings(defaultParamWordlist)
	if len(candidates) == 0 {
		return
	}

	baseline := paramBaseline{
		statusCode: task.BaselineStatusCode,
		size:       task.BaselineSize,
		hash:       task.BaselineHash,
	}

	ctx := context.Background()
	if sc := e.scannerCtx.Load(); sc != nil && sc.ctx != nil {
		ctx = sc.ctx
	}

	hits := e.discoverParamHits(ctx, task, candidates, baseline, snap)
	if len(hits) == 0 {
		return
	}

	for _, hit := range hits {
		if len(hit.params) == 0 {
			continue
		}
		msg := fmt.Sprintf("hidden parameters discovered: %s", strings.Join(hit.params, ","))
		res := Result{
			Path:             hit.probeURL,
			Method:           "GET",
			StatusCode:       hit.statusCode,
			Size:             hit.size,
			Words:            hit.words,
			Lines:            hit.lines,
			ContentType:      hit.contentType,
			Duration:         hit.duration,
			URL:              hit.probeURL,
			Headers:          map[string]string{"Msg": msg},
			Labels:           []string{"PARAM-FUZZ"},
			DiscoveredParams: append([]string(nil), hit.params...),
		}
		if len(hit.params) == 1 {
			res.Confidence = "single-param"
		} else {
			res.Confidence = fmt.Sprintf("%d params", len(hit.params))
		}
		if len(hit.headers) > 0 {
			res.Headers = hit.headers
			res.Headers["Msg"] = msg
		}
		e.handleResultNonBlocking(res)
	}
}

func (e *Engine) discoverParamHits(
	ctx context.Context,
	task ParamTask,
	candidates []string,
	baseline paramBaseline,
	snap *configSnapshot,
) []paramHit {
	if len(candidates) == 0 {
		return nil
	}
	if len(candidates) > paramChunkSize {
		var hits []paramHit
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
		hit.params = append([]string(nil), candidates...)
		return []paramHit{hit}
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
) (paramHit, bool, error) {
	if len(params) == 0 {
		return paramHit{}, false, nil
	}

	probeURL, rawReq, err := buildParamProbeRequest(task.URL, params, snap)
	if err != nil {
		return paramHit{}, false, err
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
		return paramHit{}, false, err
	}

	bodySize, wordCount, lineCount, contentType, bodyHash := computeResponseMetrics(resp, "GET")
	if !responseDiffersFromBaseline(baseline, resp.StatusCode, bodySize, bodyHash) {
		return paramHit{}, false, nil
	}

	return paramHit{
		params:      append([]string(nil), params...),
		probeURL:    probeURL,
		statusCode:  resp.StatusCode,
		size:        bodySize,
		words:       wordCount,
		lines:       lineCount,
		contentType: contentType,
		duration:    resp.Duration,
		headers:     captureParamHeaders(resp.Headers),
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
