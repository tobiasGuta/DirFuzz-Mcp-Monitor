// Package scope loads H1-Scope-Watcher JSON files from a directory and
// validates whether a target URL is bounty-eligible before a scan starts.
//
// JSON structure expected in each file:
//
//	[
//	  {"asset_type": "URL",      "asset_identifier": "api.example.com", "eligible_for_bounty": true},
//	  {"asset_type": "WILDCARD", "asset_identifier": "*.example.com",   "eligible_for_bounty": true}
//	]
package scope

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Asset is one entry from an H1-Scope-Watcher scope file.
type Asset struct {
	AssetType         string `json:"asset_type"`
	AssetIdentifier   string `json:"asset_identifier"`
	EligibleForBounty bool   `json:"eligible_for_bounty"`
}

// LoadDir reads every *.json file inside dir, parses each one as []Asset, and
// returns the combined slice plus a warning list for any skipped files.
// Returns an error only if dir itself cannot be listed.
func LoadDir(dir string) ([]Asset, []string, error) {
	pattern := filepath.Join(dir, "*.json")
	paths, err := filepath.Glob(pattern)
	if err != nil {
		return nil, nil, fmt.Errorf("scope: listing %q: %w", dir, err)
	}

	var all []Asset
	warnings := make([]string, 0, len(paths))
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("scope: skipping %s (read error): %v", p, err))
			continue
		}
		var batch []Asset
		if err := json.Unmarshal(data, &batch); err != nil {
			warnings = append(warnings, fmt.Sprintf("scope: skipping %s (parse error): %v", p, err))
			continue
		}
		all = append(all, batch...)
	}
	return all, warnings, nil
}

// IsAllowed returns true when target is covered by at least one bounty-eligible
// asset in assets. The check is case-insensitive on hostnames.
//
// Matching rules:
//   - "URL"      asset: target host must equal the asset identifier host.
//   - "WILDCARD" asset: target host must be a strict subdomain of the wildcard
//     base (e.g. "dev.tile.com" matches "*.tile.com", but "tile.com" does not).
//   - "CIDR"     asset: target IP must fall within the CIDR block.
//   - "SOURCE_CODE" and "EXECUTABLE" are explicit passthrough types for scope
//     files but are never treated as HTTP-fuzzable assets.
//
// Any asset whose eligible_for_bounty is false is silently skipped.
func IsAllowed(target string, assets []Asset) (bool, string) {
	if len(assets) == 0 {
		return false, "no scope files loaded"
	}
	targetHost, targetPort := extractTargetEndpoint(target)
	targetIP := net.ParseIP(targetHost)
	if targetHost == "" && targetIP == nil {
		return false, fmt.Sprintf("target %q is not a valid http(s) URL or hostname", target)
	}

	for _, a := range assets {
		if !a.EligibleForBounty {
			continue
		}
		switch strings.ToUpper(strings.TrimSpace(a.AssetType)) {
		case "URL":
			if matchURL(targetHost, targetPort, a.AssetIdentifier) {
				return true, fmt.Sprintf("matched URL %s", normalizeAssetIdentifier(a.AssetIdentifier))
			}
		case "WILDCARD":
			if matchWildcard(targetHost, targetPort, a.AssetIdentifier) {
				return true, fmt.Sprintf("matched wildcard %s", normalizeAssetIdentifier(a.AssetIdentifier))
			}
		case "CIDR":
			if matchCIDR(targetIP, a.AssetIdentifier) {
				return true, fmt.Sprintf("matched CIDR %s", strings.TrimSpace(a.AssetIdentifier))
			}
		case "SOURCE_CODE", "EXECUTABLE":
			continue
		default:
			continue
		}
	}
	if targetHost != "" {
		return false, fmt.Sprintf("target host %q matched no in-scope asset", targetHost)
	}
	return false, "target matched no in-scope asset"
}

// ── internal helpers ──────────────────────────────────────────────────────────

// extractTargetEndpoint returns the lowercase hostname and the effective port
// for a raw URL string or bare hostname. If a port is omitted, the helper uses
// the default port for http/https when possible.
func extractTargetEndpoint(raw string) (string, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}
	if scheme, ok := schemePrefix(raw); ok {
		if scheme != "http" && scheme != "https" {
			return "", ""
		}
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", ""
	}
	if scheme := strings.ToLower(u.Scheme); scheme != "http" && scheme != "https" {
		return "", ""
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" {
		port = defaultPortForScheme(strings.ToLower(u.Scheme))
	}
	return host, port
}

// extractAssetEndpoint returns the lowercase hostname and explicit port, if
// present, from a scope asset identifier.
func extractAssetEndpoint(identifier string) (string, string) {
	clean := strings.ToLower(strings.TrimSpace(identifier))
	if clean == "" {
		return "", ""
	}
	if strings.Contains(clean, "://") {
		u, err := url.Parse(clean)
		if err != nil {
			return "", ""
		}
		scheme := strings.ToLower(u.Scheme)
		if scheme != "http" && scheme != "https" {
			return "", ""
		}
		host := strings.ToLower(u.Hostname())
		port := u.Port()
		return host, port
	}
	if idx := strings.IndexAny(clean, "/?#"); idx != -1 {
		clean = clean[:idx]
	}
	if strings.HasPrefix(clean, "[") {
		if end := strings.IndexByte(clean, ']'); end != -1 {
			host := clean[1:end]
			remainder := clean[end+1:]
			if strings.HasPrefix(remainder, ":") && isNumeric(remainder[1:]) {
				return host, remainder[1:]
			}
			return host, ""
		}
		return "", ""
	}
	if idx := strings.LastIndexByte(clean, ':'); idx != -1 {
		host := clean[:idx]
		port := clean[idx+1:]
		if host != "" && isNumeric(port) && !strings.Contains(host, ":") {
			return host, port
		}
	}
	return clean, ""
}

func normalizeAssetIdentifier(identifier string) string {
	idHost, idPort := extractAssetEndpoint(identifier)
	if idHost == "" {
		return strings.TrimSpace(identifier)
	}
	if idPort == "" {
		return idHost
	}
	return net.JoinHostPort(idHost, idPort)
}

func defaultPortForScheme(scheme string) string {
	switch scheme {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}

func matchURL(targetHost, targetPort, identifier string) bool {
	idHost, idPort := extractAssetEndpoint(identifier)
	if idHost == "" || targetHost == "" || targetHost != idHost {
		return false
	}
	return portMatches(targetPort, idPort)
}

func matchWildcard(targetHost, targetPort, identifier string) bool {
	idHost, idPort := extractAssetEndpoint(identifier)
	if targetHost == "" || !strings.HasPrefix(idHost, "*.") {
		return false
	}
	baseDomain := idHost[2:]
	if baseDomain == "" {
		return false
	}
	suffix := "." + baseDomain
	if !strings.HasSuffix(targetHost, suffix) {
		return false
	}
	if !portMatches(targetPort, idPort) {
		return false
	}
	return len(targetHost) > len(baseDomain)
}

func matchCIDR(targetIP net.IP, identifier string) bool {
	if targetIP == nil {
		return false
	}
	_, network, err := net.ParseCIDR(strings.TrimSpace(identifier))
	if err != nil {
		return false
	}
	return network.Contains(targetIP)
}

func portMatches(targetPort, assetPort string) bool {
	if assetPort == "" {
		return true
	}
	return targetPort != "" && targetPort == assetPort
}

func schemePrefix(raw string) (string, bool) {
	idx := strings.IndexByte(raw, ':')
	if idx <= 0 {
		return "", false
	}
	prefix := raw[:idx]
	if !isSchemeName(prefix) {
		return "", false
	}
	if idx+1 >= len(raw) {
		return prefix, true
	}
	next := raw[idx+1]
	if next >= '0' && next <= '9' {
		return "", false
	}
	if next == '[' {
		return "", false
	}
	return prefix, true
}

func isSchemeName(s string) bool {
	if s == "" || !isAlpha(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if isAlpha(c) || isNumericByte(c) || c == '+' || c == '-' || c == '.' {
			continue
		}
		return false
	}
	return true
}

func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isNumericByte(c byte) bool {
	return c >= '0' && c <= '9'
}

// isNumeric returns true when s consists entirely of ASCII digits.
func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
