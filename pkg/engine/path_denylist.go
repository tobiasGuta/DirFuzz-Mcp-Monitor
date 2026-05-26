package engine

import (
	"net/url"
	"regexp"
	"strings"
)

func canonicalExcludedPath(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}

	path := parsed.EscapedPath()
	if path == "" {
		path = parsed.Path
	}
	if path == "" {
		path = raw
	}
	if parsed.RawQuery != "" {
		path += "?" + parsed.RawQuery
	}
	return path
}

func pathExcludedByRegexps(raw string, regexps []*regexp.Regexp) bool {
	if len(regexps) == 0 {
		return false
	}

	candidate := canonicalExcludedPath(raw)
	for _, re := range regexps {
		if re == nil {
			continue
		}
		if re.MatchString(candidate) {
			return true
		}
	}
	return false
}

func (e *Engine) shouldExcludePath(raw string) bool {
	if e == nil {
		return false
	}
	snap := e.configSnap.Load()
	if snap == nil {
		e.buildAndStoreConfigSnapshot()
		snap = e.configSnap.Load()
	}
	if snap == nil {
		return false
	}
	return pathExcludedByRegexps(raw, snap.ExcludePathRegexps)
}
