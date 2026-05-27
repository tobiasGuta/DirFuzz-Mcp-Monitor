package tui

import (
	"strings"
	"testing"
)

func TestBuildSplitDiffCollapsesUnchangedSections(t *testing.T) {
	left, right := buildSplitDiff(
		[]byte("HTTP/1.1 200 OK\r\nHeader: one\r\n\r\nsame line\r\nold value\r\ntrailer\r\n"),
		[]byte("HTTP/1.1 200 OK\r\nHeader: one\r\n\r\nsame line\r\nnew value\r\ntrailer\r\n"),
		true,
	)

	if !strings.Contains(left, "old value") {
		t.Fatalf("left diff missing deleted line: %q", left)
	}
	if !strings.Contains(right, "new value") {
		t.Fatalf("right diff missing inserted line: %q", right)
	}
	if !strings.Contains(left, "unchanged lines") {
		t.Fatalf("left diff should collapse unchanged content: %q", left)
	}
	if !strings.Contains(right, "unchanged lines") {
		t.Fatalf("right diff should collapse unchanged content: %q", right)
	}
	if strings.Contains(left, "same line") || strings.Contains(right, "same line") {
		t.Fatalf("diff should hide unchanged body lines, got left=%q right=%q", left, right)
	}
}

func TestBuildSplitDiffReportsIdenticalResponses(t *testing.T) {
	left, right := buildSplitDiff(
		[]byte("HTTP/1.1 200 OK\r\n\r\nsame"),
		[]byte("HTTP/1.1 200 OK\r\n\r\nsame"),
		true,
	)

	if !strings.Contains(left, "Responses are identical.") {
		t.Fatalf("left diff missing identical message: %q", left)
	}
	if !strings.Contains(right, "Responses are identical.") {
		t.Fatalf("right diff missing identical message: %q", right)
	}
}

func TestBuildSplitDiffFullModeKeepsContext(t *testing.T) {
	left, right := buildSplitDiff(
		[]byte("HTTP/1.1 200 OK\r\nHeader: one\r\n\r\nsame line\r\nold value\r\ntrailer\r\n"),
		[]byte("HTTP/1.1 200 OK\r\nHeader: one\r\n\r\nsame line\r\nnew value\r\ntrailer\r\n"),
		false,
	)

	if !strings.Contains(left, "same line") || !strings.Contains(right, "same line") {
		t.Fatalf("full diff should retain unchanged context, got left=%q right=%q", left, right)
	}
	if strings.Contains(left, "unchanged lines") || strings.Contains(right, "unchanged lines") {
		t.Fatalf("full diff should not collapse unchanged blocks, got left=%q right=%q", left, right)
	}
}
