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
	ref := m.diffReference
	cur := m.selectedDiffSample()
	if ref == nil {
		m.statusMessage = errorStyle.Render("No reference saved yet. Press 'R' on a hit first.")
		m.statusExpiry = timeNowPlus(3)
		return false
	}
	if cur == nil {
		m.statusMessage = errorStyle.Render("No current response available for diff.")
		m.statusExpiry = timeNowPlus(3)
		return false
	}

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

	left, right := buildSplitDiff(m.diffReference.Bytes, m.diffCurrent.Bytes)
	m.diffLeftViewport.SetContent(left)
	m.diffRightViewport.SetContent(right)
	m.diffLeftViewport.GotoTop()
	m.diffRightViewport.GotoTop()
}

func buildSplitDiff(leftRaw, rightRaw []byte) (string, string) {
	leftText := normalizeDiffBlob(leftRaw)
	rightText := normalizeDiffBlob(rightRaw)

	dmp := diffmatchpatch.New()
	dmp.DiffTimeout = 0
	diffs := dmp.DiffMain(leftText, rightText, true)
	dmp.DiffCleanupSemantic(diffs)

	var leftOut strings.Builder
	var rightOut strings.Builder

	for _, diff := range diffs {
		switch diff.Type {
		case diffmatchpatch.DiffEqual:
			leftOut.WriteString(diffEqualStyle.Render(diff.Text))
			rightOut.WriteString(diffEqualStyle.Render(diff.Text))
		case diffmatchpatch.DiffDelete:
			leftOut.WriteString(diffDeleteStyle.Render(diff.Text))
		case diffmatchpatch.DiffInsert:
			rightOut.WriteString(diffInsertStyle.Render(diff.Text))
		}
	}

	return leftOut.String(), rightOut.String()
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
