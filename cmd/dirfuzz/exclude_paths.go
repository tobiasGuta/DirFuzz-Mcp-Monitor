package main

import (
	"fmt"
	"regexp"
	"strings"
)

func normalizeExcludePaths(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		out = append(out, value)
	}
	return out
}

func validateExcludePaths(values []string) error {
	for _, value := range normalizeExcludePaths(values) {
		if _, err := regexp.Compile(value); err != nil {
			return fmt.Errorf("invalid --exclude-path %q: %w", value, err)
		}
	}
	return nil
}
