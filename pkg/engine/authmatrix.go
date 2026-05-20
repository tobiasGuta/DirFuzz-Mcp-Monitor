package engine

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"dirfuzz/pkg/httpclient"
)

type authMatrixRole struct {
	role    string
	level   int
	headers []string
}

type authMatrixRoleResponse struct {
	role       string
	level      int
	rawRequest []byte
	resp       *httpclient.RawResponse
	err        error
}

// AuthMatrixFinding captures an authorization mismatch discovered during
// replay across roles.
type AuthMatrixFinding struct {
	Labels     []string `json:"labels,omitempty"`
	Confidence string   `json:"confidence,omitempty"`
	Summary    string   `json:"summary,omitempty"`
	Role       string   `json:"role,omitempty"`
}

type AuthReplayResponse struct {
	Role        string `json:"role"`
	Level       int    `json:"level"`
	StatusCode  int    `json:"status_code"`
	SizeBytes   int    `json:"size_bytes"`
	ContentType string `json:"content_type,omitempty"`
	DurationMS  int64  `json:"duration_ms"`
	Error       string `json:"error,omitempty"`
}

type AuthPathReport struct {
	Path         string               `json:"path"`
	Method       string               `json:"method"`
	SelectedRole string               `json:"selected_role,omitempty"`
	Finding      *AuthMatrixFinding   `json:"finding,omitempty"`
	Responses    []AuthReplayResponse `json:"responses"`
}

type AuthMatrixReport struct {
	Target string           `json:"target"`
	Paths  []AuthPathReport `json:"paths"`
}

func (e *Engine) executeAuthMatrixRequests(
	ctx context.Context,
	targetURL, reqPath, reqHost, ua string,
	baseHeaders map[string]string,
	timeout time.Duration,
	proxyAddr string,
	authMatrix map[string][]string,
) (*httpclient.RawResponse, []byte, string, *AuthMatrixFinding, error) {
	roles := normalizeAuthRoles(authMatrix)
	if len(roles) == 0 {
		return nil, nil, "", nil, nil
	}

	if ctx == nil {
		ctx = context.Background()
	}

	parsedTarget, err := url.Parse(targetURL)
	if err != nil {
		return nil, nil, "", nil, fmt.Errorf("invalid auth-matrix target URL: %w", err)
	}

	if reqPath == "" {
		reqPath = "/"
	}
	method := "GET"

	results := make([]authMatrixRoleResponse, len(roles))
	var wg sync.WaitGroup
	for i, role := range roles {
		wg.Add(1)
		go func(i int, role authMatrixRole) {
			defer wg.Done()
			roleHeaders := mergeAuthHeaders(baseHeaders, role.headers)
			headersStr := renderHeaderBlock(roleHeaders)
			rawReq := buildRequest(method, reqPath, reqHost, ua, headersStr, "")
			resp, err := e.executeRequestWithRetry(ctx, parsedTarget.String(), rawReq, timeout, proxyAddr)
			results[i] = authMatrixRoleResponse{
				role:       role.role,
				level:      role.level,
				rawRequest: rawReq,
				resp:       resp,
				err:        err,
			}
		}(i, role)
	}
	wg.Wait()

	successes := make([]authMatrixRoleResponse, 0, len(results))
	for _, res := range results {
		if res.err == nil && res.resp != nil {
			successes = append(successes, res)
		}
	}
	if len(successes) == 0 {
		if len(results) > 0 && results[0].err != nil {
			return nil, nil, "", nil, results[0].err
		}
		return nil, nil, "", nil, fmt.Errorf("auth matrix requests failed for %s", targetURL)
	}

	selected, finding := evaluateAuthMatrixResponses(reqPath, successes)
	return selected.resp, selected.rawRequest, method, finding, nil
}

func normalizeAuthRoles(authMatrix map[string][]string) []authMatrixRole {
	if len(authMatrix) == 0 {
		return nil
	}
	roles := make([]authMatrixRole, 0, len(authMatrix))
	for role, headers := range authMatrix {
		role = strings.TrimSpace(role)
		if role == "" {
			continue
		}
		roleHeaders := make([]string, 0, len(headers))
		for _, hdr := range headers {
			hdr = strings.TrimSpace(hdr)
			if hdr != "" {
				roleHeaders = append(roleHeaders, hdr)
			}
		}
		if len(roleHeaders) == 0 {
			continue
		}
		roles = append(roles, authMatrixRole{
			role:    role,
			level:   authRoleLevel(role),
			headers: roleHeaders,
		})
	}
	sort.SliceStable(roles, func(i, j int) bool {
		if roles[i].level != roles[j].level {
			return roles[i].level < roles[j].level
		}
		return strings.ToLower(roles[i].role) < strings.ToLower(roles[j].role)
	})
	return roles
}

func mergeAuthHeaders(base map[string]string, extra []string) map[string]string {
	out := make(map[string]string, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for _, hdr := range extra {
		if idx := strings.Index(hdr, ":"); idx != -1 {
			key := strings.TrimSpace(hdr[:idx])
			val := strings.TrimSpace(hdr[idx+1:])
			if key != "" {
				out[key] = val
			}
		}
	}
	return out
}

func renderHeaderBlock(headers map[string]string) string {
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
		b.WriteString(fmt.Sprintf("%s: %s\r\n", k, headers[k]))
	}
	return b.String()
}

func evaluateAuthMatrixResponses(path string, responses []authMatrixRoleResponse) (authMatrixRoleResponse, *AuthMatrixFinding) {
	sort.SliceStable(responses, func(i, j int) bool {
		if responses[i].level != responses[j].level {
			return responses[i].level < responses[j].level
		}
		return strings.ToLower(responses[i].role) < strings.ToLower(responses[j].role)
	})
	selected := responses[0]

	publicRole := pickAuthRoleResponse(responses, 0)
	userRole := pickAuthRoleResponse(responses, 1)
	adminRole := pickAuthRoleResponse(responses, 2)

	if publicRole != nil && userRole != nil && sameAuthResponse(publicRole.resp, userRole.resp) {
		selected = *publicRole
		return selected, nil
	}

	if userRole == nil || adminRole == nil {
		return selected, nil
	}

	summary := authMatrixSummary(publicRole, userRole, adminRole)
	pathLower := strings.ToLower(path)
	adminishPath := isAdminishPath(pathLower)

	if userRole.resp != nil && adminRole.resp != nil {
		if userRole.resp.StatusCode == 403 && adminRole.resp.StatusCode == 200 {
			selected = *adminRole
			return selected, &AuthMatrixFinding{
				Labels:     []string{"AUTH-MATRIX", "BAC", "PRIVILEGE-ESCALATION"},
				Confidence: fmt.Sprintf("%s=403;%s=200", userRole.role, adminRole.role),
				Summary:    summary,
				Role:       adminRole.role,
			}
		}
		if adminishPath && sameAuthResponse(userRole.resp, adminRole.resp) {
			selected = *adminRole
			return selected, &AuthMatrixFinding{
				Labels:     []string{"AUTH-MATRIX", "IDOR", "BAC"},
				Confidence: fmt.Sprintf("simhash-match:%s=%s", userRole.role, adminRole.role),
				Summary:    summary,
				Role:       adminRole.role,
			}
		}
	}

	return selected, nil
}

func pickAuthRoleResponse(responses []authMatrixRoleResponse, targetLevel int) *authMatrixRoleResponse {
	for i := range responses {
		if responses[i].level == targetLevel {
			return &responses[i]
		}
	}
	if targetLevel == 1 && len(responses) >= 2 {
		return &responses[1]
	}
	if targetLevel == 2 && len(responses) > 0 {
		return &responses[len(responses)-1]
	}
	if targetLevel == 0 && len(responses) > 0 {
		return &responses[0]
	}
	return nil
}

func authRoleLevel(role string) int {
	lower := strings.ToLower(strings.TrimSpace(role))
	switch {
	case strings.Contains(lower, "unauth") || strings.Contains(lower, "anon") || strings.Contains(lower, "guest") || strings.Contains(lower, "public"):
		return 0
	case strings.Contains(lower, "admin") || strings.Contains(lower, "root") || strings.Contains(lower, "superuser") || strings.Contains(lower, "priv"):
		return 2
	default:
		return 1
	}
}

func sameAuthResponse(a, b *httpclient.RawResponse) bool {
	if a == nil || b == nil {
		return false
	}
	return a.StatusCode == b.StatusCode && len(a.Body) == len(b.Body) && simhashBody(a.Body) == simhashBody(b.Body)
}

func authMatrixSummary(publicRole, userRole, adminRole *authMatrixRoleResponse) string {
	parts := make([]string, 0, 3)
	if publicRole != nil && publicRole.resp != nil {
		parts = append(parts, fmt.Sprintf("%s=%d/%d", publicRole.role, publicRole.resp.StatusCode, len(publicRole.resp.Body)))
	}
	if userRole != nil && userRole.resp != nil {
		parts = append(parts, fmt.Sprintf("%s=%d/%d", userRole.role, userRole.resp.StatusCode, len(userRole.resp.Body)))
	}
	if adminRole != nil && adminRole.resp != nil {
		parts = append(parts, fmt.Sprintf("%s=%d/%d", adminRole.role, adminRole.resp.StatusCode, len(adminRole.resp.Body)))
	}
	return strings.Join(parts, " | ")
}

func isAdminishPath(path string) bool {
	path = strings.ToLower(path)
	keywords := []string{"/admin", "/administrator", "/manage", "/management", "/panel", "/dashboard", "/internal", "/control", "/staff", "/settings"}
	for _, kw := range keywords {
		if strings.Contains(path, kw) {
			return true
		}
	}
	return false
}

func responseContentType(resp *httpclient.RawResponse) string {
	if resp == nil {
		return ""
	}
	if resp.HeaderMap != nil {
		if v := strings.TrimSpace(resp.HeaderMap["Content-Type"]); v != "" {
			return v
		}
	}
	headers := strings.ReplaceAll(strings.ReplaceAll(resp.Headers, "\r\n", "\n"), "\r", "\n")
	for _, line := range strings.Split(headers, "\n") {
		if idx := strings.Index(line, ":"); idx != -1 && strings.EqualFold(strings.TrimSpace(line[:idx]), "Content-Type") {
			return strings.TrimSpace(line[idx+1:])
		}
	}
	return ""
}

func (e *Engine) testAuthMatrixReport(ctx context.Context, targetURL string, paths []string, authMatrix map[string][]string, baseHeaders map[string]string, timeout time.Duration, proxyAddr string) (AuthMatrixReport, error) {
	report := AuthMatrixReport{Target: targetURL}
	if e == nil {
		return report, fmt.Errorf("engine is nil")
	}
	if targetURL == "" {
		return report, fmt.Errorf("targetURL is required")
	}
	roles := normalizeAuthRoles(authMatrix)
	if len(roles) == 0 {
		return report, fmt.Errorf("auth_matrix is empty")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout <= 0 {
		timeout = DefaultHTTPTimeout
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
	if len(baseHeaders) > 0 {
		headersTemplate += renderHeaderBlock(baseHeaders)
	}

	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		parsedTargetURL := targetURL
		if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
			parsedTargetURL = path
		}
		parsedTarget, err := url.Parse(parsedTargetURL)
		if err != nil {
			return report, err
		}
		reqPath := path
		if strings.HasPrefix(reqPath, "http://") || strings.HasPrefix(reqPath, "https://") {
			reqPath = parsedTarget.Path
			if reqPath == "" {
				reqPath = "/"
			}
			if parsedTarget.RawQuery != "" {
				reqPath += "?" + parsedTarget.RawQuery
			}
		} else {
			if !strings.HasPrefix(reqPath, "/") {
				reqPath = "/" + reqPath
			}
			if parsedTarget.Path != "" && parsedTarget.Path != "/" {
				reqPath = strings.TrimRight(parsedTarget.Path, "/") + reqPath
			}
		}

		responses := make([]authMatrixRoleResponse, len(roles))
		var wg sync.WaitGroup
		for i, role := range roles {
			wg.Add(1)
			go func(i int, role authMatrixRole) {
				defer wg.Done()
				roleHeaders := mergeAuthHeaders(baseHeaders, role.headers)
				rawReq := buildRequest("GET", reqPath, parsedTarget.Host, ua, headersTemplate+renderHeaderBlock(roleHeaders), "")
				resp, err := e.executeRequestWithRetry(ctx, parsedTarget.String(), rawReq, timeout, proxyAddr)
				responses[i] = authMatrixRoleResponse{
					role:       role.role,
					level:      role.level,
					rawRequest: rawReq,
					resp:       resp,
					err:        err,
				}
			}(i, role)
		}
		wg.Wait()

		selected, finding := evaluateAuthMatrixResponses(reqPath, responses)
		pathReport := AuthPathReport{
			Path:         reqPath,
			Method:       "GET",
			SelectedRole: selected.role,
			Responses:    make([]AuthReplayResponse, 0, len(responses)),
		}
		for _, res := range responses {
			item := AuthReplayResponse{
				Role:  res.role,
				Level: res.level,
			}
			if res.err != nil {
				item.Error = res.err.Error()
			} else if res.resp != nil {
				item.StatusCode = res.resp.StatusCode
				item.SizeBytes = len(res.resp.Body)
				item.ContentType = responseContentType(res.resp)
				item.DurationMS = res.resp.Duration.Milliseconds()
			}
			pathReport.Responses = append(pathReport.Responses, item)
		}
		if finding != nil {
			pathReport.Finding = finding
		}
		report.Paths = append(report.Paths, pathReport)
	}
	return report, nil
}

// TestAuthMatrix replays the provided paths under each auth role and returns
// only the discovered findings. The engine must already have a configured
// target via SetTarget so relative paths can be resolved consistently.
func (e *Engine) TestAuthMatrix(ctx context.Context, paths []string, roles map[string][]string) ([]AuthMatrixFinding, error) {
	if e == nil {
		return nil, fmt.Errorf("engine is nil")
	}
	baseURL := e.BaseURL()
	if baseURL == "" {
		return nil, fmt.Errorf("engine target is not configured")
	}
	report, err := e.testAuthMatrixReport(ctx, baseURL, paths, roles, nil, 0, "")
	if err != nil {
		return nil, err
	}
	findings := make([]AuthMatrixFinding, 0, len(report.Paths))
	for _, pathReport := range report.Paths {
		if pathReport.Finding != nil {
			findings = append(findings, *pathReport.Finding)
		}
	}
	return findings, nil
}
