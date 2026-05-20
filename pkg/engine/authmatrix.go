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

type authMatrixFinding struct {
	labels     []string
	confidence string
	summary    string
	role       string
}

func (e *Engine) executeAuthMatrixRequests(
	ctx context.Context,
	targetURL, reqPath, reqHost, ua string,
	baseHeaders map[string]string,
	timeout time.Duration,
	proxyAddr string,
	authMatrix map[string][]string,
) (*httpclient.RawResponse, []byte, string, *authMatrixFinding, error) {
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

func evaluateAuthMatrixResponses(path string, responses []authMatrixRoleResponse) (authMatrixRoleResponse, *authMatrixFinding) {
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
			return selected, &authMatrixFinding{
				labels:     []string{"AUTH-MATRIX", "BAC", "PRIVILEGE-ESCALATION"},
				confidence: fmt.Sprintf("%s=403;%s=200", userRole.role, adminRole.role),
				summary:    summary,
				role:       adminRole.role,
			}
		}
		if adminishPath && sameAuthResponse(userRole.resp, adminRole.resp) {
			selected = *adminRole
			return selected, &authMatrixFinding{
				labels:     []string{"AUTH-MATRIX", "IDOR", "BAC"},
				confidence: fmt.Sprintf("simhash-match:%s=%s", userRole.role, adminRole.role),
				summary:    summary,
				role:       adminRole.role,
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
