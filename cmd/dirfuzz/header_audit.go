package main

import (
	"fmt"
	"strings"

	"dirfuzz/pkg/engine"
)

// securityHeaderChecks defines the security headers to audit and basic checks.
var securityHeaderChecks = []struct {
	Header string
	Check  func(val string) string
}{
	{
		Header: "Strict-Transport-Security",
		Check: func(val string) string {
			if val == "" {
				return "missing - no HSTS policy"
			}
			if !strings.Contains(strings.ToLower(val), "max-age") {
				return "present but missing max-age directive"
			}
			return ""
		},
	},
	{
		Header: "Content-Security-Policy",
		Check: func(val string) string {
			if val == "" {
				return "missing - no CSP defined"
			}
			if strings.Contains(val, "unsafe-inline") {
				return "contains unsafe-inline"
			}
			if strings.Contains(val, "unsafe-eval") {
				return "contains unsafe-eval"
			}
			return ""
		},
	},
	{
		Header: "X-Frame-Options",
		Check: func(val string) string {
			if val == "" {
				return "missing - clickjacking protection absent"
			}
			upper := strings.ToUpper(val)
			if upper != "DENY" && upper != "SAMEORIGIN" {
				return fmt.Sprintf("unexpected value: %q", val)
			}
			return ""
		},
	},
	{
		Header: "X-Content-Type-Options",
		Check: func(val string) string {
			if val == "" {
				return "missing - MIME sniffing not prevented"
			}
			if strings.ToLower(val) != "nosniff" {
				return fmt.Sprintf("expected nosniff, got: %q", val)
			}
			return ""
		},
	},
	{
		Header: "Referrer-Policy",
		Check: func(val string) string {
			if val == "" {
				return "missing - browser default referrer policy applies"
			}
			return ""
		},
	},
	{
		Header: "Permissions-Policy",
		Check: func(val string) string {
			if val == "" {
				return "missing - no feature policy defined"
			}
			return ""
		},
	},
	{
		Header: "Access-Control-Allow-Origin",
		Check: func(val string) string {
			if val == "*" {
				return "wildcard (*) - any origin may read the response"
			}
			return ""
		},
	},
}

// HeaderAuditFinding records a missing or misconfigured header finding.
type HeaderAuditFinding struct {
	URL     string
	Status  int
	Header  string
	Finding string
}

// RunHeaderAudit returns findings for missing/misconfigured security headers.
func RunHeaderAudit(results []engine.Result) []HeaderAuditFinding {
	var findings []HeaderAuditFinding
	for _, r := range results {
		// Skip non-2xx responses to reduce noise.
		if r.StatusCode < 200 || r.StatusCode >= 300 {
			continue
		}
		for _, check := range securityHeaderChecks {
			val := r.Headers[check.Header]
			if finding := check.Check(val); finding != "" {
				findings = append(findings, HeaderAuditFinding{
					URL:     r.URL,
					Status:  r.StatusCode,
					Header:  check.Header,
					Finding: finding,
				})
			}
		}
	}
	return findings
}

// PrintHeaderAuditSummary writes a human-readable summary to stdout.
func PrintHeaderAuditSummary(findings []HeaderAuditFinding) {
	if len(findings) == 0 {
		fmt.Println("[header-audit] All audited security headers look acceptable.")
		return
	}
	fmt.Printf("[header-audit] %d finding(s):\n", len(findings))
	for _, f := range findings {
		fmt.Printf("  [%d] %s - %s: %s\n", f.Status, f.URL, f.Header, f.Finding)
	}
}

// RenderHeaderAuditMarkdown returns a Markdown report section.
func RenderHeaderAuditMarkdown(findings []HeaderAuditFinding) string {
	var sb strings.Builder
	sb.WriteString("## Security Header Audit\n\n")
	if len(findings) == 0 {
		sb.WriteString("No security header issues found.\n")
		return sb.String()
	}
	sb.WriteString("| Status | URL | Header | Finding |\n")
	sb.WriteString("| --- | --- | --- | --- |\n")
	for _, f := range findings {
		sb.WriteString(fmt.Sprintf("| %d | %s | %s | %s |\n", f.Status, f.URL, f.Header, f.Finding))
	}
	return sb.String()
}
