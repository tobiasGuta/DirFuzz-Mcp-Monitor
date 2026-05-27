package tui

import (
	"fmt"
	"strings"
	"time"

	"dirfuzz/pkg/engine"

	"github.com/charmbracelet/lipgloss"
	"github.com/sergi/go-diff/diffmatchpatch"
)

type DiffSample struct {
	Title string
	Bytes []byte
}

var (
	diffEqualStyle   = lipgloss.NewStyle().Foreground(DraculaFg)
	diffDeleteStyle  = lipgloss.NewStyle().Foreground(DraculaRed).Bold(true)
	diffInsertStyle  = lipgloss.NewStyle().Foreground(DraculaGreen).Bold(true)
	diffHeaderStyle  = lipgloss.NewStyle().Foreground(DraculaCyan).Bold(true)
	diffWarningStyle = lipgloss.NewStyle().Foreground(DraculaOrange).Bold(true)
	diffContextStyle = lipgloss.NewStyle().Foreground(DraculaComment).Italic(true)
)

func (m *Model) selectedDiffSample() *DiffSample {
	if m.selectedIndex < 0 || m.selectedIndex >= len(m.logLineHits) {
		return nil
	}

	hit := m.logLineHits[m.selectedIndex]
	if hit == nil || len(hit.ResponseBytes) == 0 {
		return nil
	}

	return diffSampleFromResult(hit)
}

func (m *Model) replayDiffSample() *DiffSample {
	if len(m.repeaterLastRaw) == 0 {
		return nil
	}

	title := "Replay"
	if m.repeaterLastStatus > 0 {
		title = fmt.Sprintf("Replay [%d]", m.repeaterLastStatus)
	}

	return &DiffSample{
		Title: title,
		Bytes: append([]byte(nil), m.repeaterLastRaw...),
	}
}

func diffSampleFromResult(hit *engine.Result) *DiffSample {
	if hit == nil || len(hit.ResponseBytes) == 0 {
		return nil
	}

	title := hit.Path
	if title == "" {
		title = hit.URL
	}
	if title == "" {
		title = "Selected response"
	}
	if hit.StatusCode > 0 {
		title = fmt.Sprintf("%s [%d]", title, hit.StatusCode)
	}

	return &DiffSample{
		Title: title,
		Bytes: append([]byte(nil), hit.ResponseBytes...),
	}
}

func eagleBaselineDiffSample(hit *engine.Result) *DiffSample {
	if hit == nil || len(hit.PreviousResponseBytes) == 0 {
		return nil
	}

	title := hit.Path
	if title == "" {
		title = hit.URL
	}
	if title == "" {
		title = "Baseline response"
	}
	if hit.OldStatusCode > 0 {
		title = fmt.Sprintf("%s [baseline %d]", title, hit.OldStatusCode)
	} else {
		title = fmt.Sprintf("%s [baseline]", title)
	}

	return &DiffSample{
		Title: title,
		Bytes: append([]byte(nil), hit.PreviousResponseBytes...),
	}
}

func (m *Model) saveDiffReferenceFromSelected() bool {
	sample := m.selectedDiffSample()
	if sample == nil {
		m.statusMessage = errorStyle.Render("No raw response available. Use --save-raw and select a hit first.")
		m.statusExpiry = timeNowPlus(3)
		return false
	}

	m.diffReference = sample
	m.statusMessage = statusStyle.Render(fmt.Sprintf("Saved reference: %s", sample.Title))
	m.statusExpiry = timeNowPlus(2)
	return true
}

func (m *Model) saveDiffReferenceFromReplay() bool {
	sample := m.replayDiffSample()
	if sample == nil {
		m.statusMessage = errorStyle.Render("No replay response available yet.")
		m.statusExpiry = timeNowPlus(3)
		return false
	}

	m.diffReference = sample
	m.statusMessage = statusStyle.Render(fmt.Sprintf("Saved replay reference: %s", sample.Title))
	m.statusExpiry = timeNowPlus(2)
	return true
}

func (m *Model) openDiffViewFromSelected() bool {
	cur := m.selectedDiffSample()
	if cur == nil {
		m.statusMessage = errorStyle.Render("No current response available for diff.")
		m.statusExpiry = timeNowPlus(3)
		return false
	}

	ref := m.diffReference
	if ref == nil && m.selectedIndex >= 0 && m.selectedIndex < len(m.logLineHits) {
		ref = eagleBaselineDiffSample(m.logLineHits[m.selectedIndex])
	}
	if ref == nil {
		m.statusMessage = errorStyle.Render("No reference saved yet. Press 'R' on a hit first, or use an Eagle hit with a saved baseline.")
		m.statusExpiry = timeNowPlus(3)
		return false
	}

	m.diffReference = ref
	m.diffCurrent = cur
	m.state = StateDiffView
	m.updateDiffView()
	return true
}

func (m *Model) openDiffViewFromReplay() bool {
	ref := m.diffReference
	cur := m.replayDiffSample()
	if ref == nil {
		m.statusMessage = errorStyle.Render("No reference saved yet. Press 'R' on a hit first.")
		m.statusExpiry = timeNowPlus(3)
		return false
	}
	if cur == nil {
		m.statusMessage = errorStyle.Render("No replay response available for diff.")
		m.statusExpiry = timeNowPlus(3)
		return false
	}

	m.diffCurrent = cur
	m.state = StateDiffView
	m.updateDiffView()
	return true
}

func (m *Model) updateDiffView() {
	if m.diffReference == nil || m.diffCurrent == nil {
		m.diffLeftViewport.SetContent(diffWarningStyle.Render("No diff data available."))
		m.diffRightViewport.SetContent(diffWarningStyle.Render("No diff data available."))
		return
	}

	left, right := buildSplitDiff(m.diffReference.Bytes, m.diffCurrent.Bytes, m.diffCompactOnly)
	m.diffLeftViewport.SetContent(left)
	m.diffRightViewport.SetContent(right)
	m.diffLeftViewport.GotoTop()
	m.diffRightViewport.GotoTop()
}

func (m *Model) toggleDiffMode() string {
	m.diffCompactOnly = !m.diffCompactOnly
	m.updateDiffView()
	if m.diffCompactOnly {
		return "Diff mode: compact changed-only"
	}
	return "Diff mode: full context"
}

func buildSplitDiff(leftRaw, rightRaw []byte, compactOnly bool) (string, string) {
	leftText := normalizeDiffBlob(leftRaw)
	rightText := normalizeDiffBlob(rightRaw)

	dmp := diffmatchpatch.New()
	dmp.DiffTimeout = 0
	leftChars, rightChars, lineArray := dmp.DiffLinesToChars(leftText, rightText)
	diffs := dmp.DiffMain(leftChars, rightChars, false)
	dmp.DiffCleanupSemantic(diffs)
	diffs = dmp.DiffCharsToLines(diffs, lineArray)

	hasChanges := false
	for _, diff := range diffs {
		if diff.Type != diffmatchpatch.DiffEqual {
			hasChanges = true
			break
		}
	}
	if !hasChanges {
		if strings.TrimSpace(leftText) == "" && strings.TrimSpace(rightText) == "" {
			msg := diffContextStyle.Render("No response content to diff.")
			return msg, msg
		}
		msg := diffContextStyle.Render("Responses are identical.")
		return msg + "\n\n" + diffEqualStyle.Render(leftText), msg + "\n\n" + diffEqualStyle.Render(rightText)
	}

	if !compactOnly {
		return renderFullSplitDiff(diffs)
	}

	var leftOut strings.Builder
	var rightOut strings.Builder

	for _, diff := range diffs {
		switch diff.Type {
		case diffmatchpatch.DiffEqual:
			placeholder := collapsedEqualPlaceholder(diff.Text)
			if placeholder == "" {
				continue
			}
			rendered := diffContextStyle.Render(placeholder)
			leftOut.WriteString(rendered)
			rightOut.WriteString(rendered)
		case diffmatchpatch.DiffDelete:
			leftOut.WriteString(diffDeleteStyle.Render(diff.Text))
		case diffmatchpatch.DiffInsert:
			rightOut.WriteString(diffInsertStyle.Render(diff.Text))
		}
	}

	return leftOut.String(), rightOut.String()
}

func renderFullSplitDiff(diffs []diffmatchpatch.Diff) (string, string) {
	var leftOut strings.Builder
	var rightOut strings.Builder

	for _, diff := range diffs {
		switch diff.Type {
		case diffmatchpatch.DiffEqual:
			rendered := diffEqualStyle.Render(diff.Text)
			leftOut.WriteString(rendered)
			rightOut.WriteString(rendered)
		case diffmatchpatch.DiffDelete:
			leftOut.WriteString(diffDeleteStyle.Render(diff.Text))
		case diffmatchpatch.DiffInsert:
			rightOut.WriteString(diffInsertStyle.Render(diff.Text))
		}
	}

	return leftOut.String(), rightOut.String()
}

func collapsedEqualPlaceholder(text string) string {
	lineCount := countDiffLines(text)
	switch {
	case lineCount <= 0:
		return ""
	case lineCount == 1:
		return "... 1 unchanged line ...\n"
	default:
		return fmt.Sprintf("... %d unchanged lines ...\n", lineCount)
	}
}

func countDiffLines(text string) int {
	if text == "" {
		return 0
	}
	count := strings.Count(text, "\n")
	if !strings.HasSuffix(text, "\n") {
		count++
	}
	return count
}

func normalizeDiffBlob(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	s := string(raw)
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return s
}

func timeNowPlus(seconds int) time.Time {
	return time.Now().Add(time.Duration(seconds) * time.Second)
}
