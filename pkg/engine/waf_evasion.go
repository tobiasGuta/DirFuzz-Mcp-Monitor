package engine

import (
	"fmt"
	"math/rand/v2"
	"strings"
)

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

// EvasionTechnique is a single WAF bypass strategy.
type EvasionTechnique struct {
	Name          string
	ModifyRequest func(rawPath string, headers map[string]string) (string, map[string]string)
}

// EvasionStrategiesFor returns evasion techniques for the given WAF vendor.
func EvasionStrategiesFor(vendor string) []EvasionTechnique {
	cloneHeaders := func(h map[string]string) map[string]string {
		n := make(map[string]string, len(h))
		for k, v := range h {
			n[k] = v
		}
		return n
	}

	switch vendor {
	case "modsecurity":
		return []EvasionTechnique{
			{
				Name: "double-slash",
				ModifyRequest: func(p string, h map[string]string) (string, map[string]string) {
					nh := cloneHeaders(h)
					nh["Transfer-Encoding"] = "chunked"
					return "//" + strings.TrimPrefix(p, "/"), nh
				},
			},
			{
				Name: "null-byte",
				ModifyRequest: func(p string, h map[string]string) (string, map[string]string) {
					return p + "%00", cloneHeaders(h)
				},
			},
			{
				Name: "chunked-encoding",
				ModifyRequest: func(p string, h map[string]string) (string, map[string]string) {
					nh := cloneHeaders(h)
					nh["Transfer-Encoding"] = "chunked"
					return p, nh
				},
			},
		}
	case "akamai":
		return []EvasionTechnique{
			{
				Name: "case-variation",
				ModifyRequest: func(p string, h map[string]string) (string, map[string]string) {
					var sb strings.Builder
					for i, c := range p {
						if i%2 == 0 {
							sb.WriteRune(c)
						} else {
							sb.WriteString(strings.ToUpper(string(c)))
						}
					}
					return sb.String(), cloneHeaders(h)
				},
			},
			{
				Name: "cache-buster",
				ModifyRequest: func(p string, h map[string]string) (string, map[string]string) {
					return fmt.Sprintf("%s?cb=%d", p, rand.Int64()), cloneHeaders(h)
				},
			},
		}
	case "imperva":
		return []EvasionTechnique{
			{
				Name: "xff-localhost",
				ModifyRequest: func(p string, h map[string]string) (string, map[string]string) {
					nh := cloneHeaders(h)
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
				ModifyRequest: func(p string, h map[string]string) (string, map[string]string) {
					nh := cloneHeaders(h)
					nh["CF-Connecting-IP"] = "127.0.0.1"
					nh["X-Forwarded-For"] = "127.0.0.1"
					return p, nh
				},
			},
			{
				Name: "path-dotslash",
				ModifyRequest: func(p string, h map[string]string) (string, map[string]string) {
					return "/%2e" + p, cloneHeaders(h)
				},
			},
		}
	default:
		return []EvasionTechnique{
			{
				Name: "head-method",
				ModifyRequest: func(p string, h map[string]string) (string, map[string]string) {
					return p, cloneHeaders(h)
				},
			},
			{
				Name: "trailing-dot-slash",
				ModifyRequest: func(p string, h map[string]string) (string, map[string]string) {
					return p + "/./", cloneHeaders(h)
				},
			},
			{
				Name: "unicode-first-char",
				ModifyRequest: func(p string, h map[string]string) (string, map[string]string) {
					if len(p) > 1 {
						return fmt.Sprintf("/%s%s", "%C0%AF", p[1:]), cloneHeaders(h)
					}
					return p, cloneHeaders(h)
				},
			},
		}
	}
}
