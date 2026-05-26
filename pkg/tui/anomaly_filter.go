package tui

import (
	"strings"

	"dirfuzz/pkg/engine"
)

func hasInterestingLabel(labels []string) bool {
	for _, label := range labels {
		normalized := strings.ToUpper(strings.TrimSpace(label))
		switch {
		case normalized == "AUTH-MATRIX":
			return true
		case normalized == "BAC":
			return true
		case normalized == "IDOR":
			return true
		case normalized == "PRIVILEGE-ESCALATION":
			return true
		case normalized == "TIMING-ORACLE":
			return true
		case strings.HasPrefix(normalized, "BYPASS:"):
			return true
		}
	}
	return false
}

func isAnomalousHit(hit *engine.Result) bool {
	if hit == nil {
		return false
	}
	return hit.MarkedInteresting ||
		hit.IsEagleAlert ||
		hit.ContentDrift ||
		len(hit.DiscoveredParams) > 0 ||
		hasInterestingLabel(hit.Labels)
}

func (m *Model) visibleListIndexes() []int {
	indexes := make([]int, 0, len(m.logs))
	for i := range m.logs {
		if !m.anomalyFilterOnly {
			indexes = append(indexes, i)
			continue
		}
		if i >= len(m.logLineHits) || !isAnomalousHit(m.logLineHits[i]) {
			continue
		}
		indexes = append(indexes, i)
	}
	return indexes
}

func (m *Model) selectedVisiblePos(indexes []int) int {
	for i, idx := range indexes {
		if idx == m.selectedIndex {
			return i
		}
	}
	return -1
}

func (m *Model) normalizeVisibleSelection(indexes []int) int {
	if len(indexes) == 0 {
		m.selectedIndex = 0
		m.listScrollIdx = 0
		m.atBottom = true
		return -1
	}

	pos := m.selectedVisiblePos(indexes)
	if pos >= 0 {
		return pos
	}

	m.selectedIndex = indexes[0]
	m.listScrollIdx = 0
	m.atBottom = len(indexes) == 1
	return 0
}

func (m *Model) syncVisibleScroll(indexes []int, selectedPos int) {
	if len(indexes) == 0 {
		m.listScrollIdx = 0
		m.atBottom = true
		return
	}

	height := m.viewport.Height
	if height <= 0 {
		height = 1
	}

	maxScroll := len(indexes) - height
	if maxScroll < 0 {
		maxScroll = 0
	}
	if m.listScrollIdx > maxScroll {
		m.listScrollIdx = maxScroll
	}
	if m.listScrollIdx < 0 {
		m.listScrollIdx = 0
	}

	if selectedPos < m.listScrollIdx {
		m.listScrollIdx = selectedPos
	}
	if selectedPos >= m.listScrollIdx+height {
		m.listScrollIdx = selectedPos - height + 1
	}
	if m.listScrollIdx > maxScroll {
		m.listScrollIdx = maxScroll
	}
	if m.listScrollIdx < 0 {
		m.listScrollIdx = 0
	}

	m.atBottom = selectedPos == len(indexes)-1
}

func (m *Model) moveListSelection(delta int) {
	indexes := m.visibleListIndexes()
	selectedPos := m.normalizeVisibleSelection(indexes)
	if len(indexes) == 0 || selectedPos < 0 {
		m.renderListView()
		return
	}

	selectedPos += delta
	if selectedPos < 0 {
		selectedPos = 0
	}
	if selectedPos >= len(indexes) {
		selectedPos = len(indexes) - 1
	}
	m.selectedIndex = indexes[selectedPos]
	m.syncVisibleScroll(indexes, selectedPos)
	m.renderListView()
}

func (m *Model) pageListSelection(delta int) {
	indexes := m.visibleListIndexes()
	selectedPos := m.normalizeVisibleSelection(indexes)
	if len(indexes) == 0 || selectedPos < 0 {
		m.renderListView()
		return
	}

	selectedPos += delta
	if selectedPos < 0 {
		selectedPos = 0
	}
	if selectedPos >= len(indexes) {
		selectedPos = len(indexes) - 1
	}
	m.selectedIndex = indexes[selectedPos]
	m.syncVisibleScroll(indexes, selectedPos)
	m.renderListView()
}

func (m *Model) setAnomalyFilterOnly(enabled bool) string {
	if m.anomalyFilterOnly == enabled {
		if enabled {
			return mutedStyle.Render("Anomaly filter already enabled.")
		}
		return mutedStyle.Render("Anomaly filter already disabled.")
	}
	m.anomalyFilterOnly = enabled
	m.listScrollIdx = 0
	m.markUIStateDirty()
	m.renderListView()

	if enabled {
		if len(m.visibleListIndexes()) == 0 {
			return mutedStyle.Render("Anomaly-only view enabled. No anomaly hits yet.")
		}
		return statusStyle.Render("[*] Anomaly-only view enabled")
	}
	return statusStyle.Render("[*] Full results view restored")
}

func (m *Model) toggleAnomalyFilterOnly() string {
	return m.setAnomalyFilterOnly(!m.anomalyFilterOnly)
}
