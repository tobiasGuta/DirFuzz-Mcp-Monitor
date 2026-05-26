package tui

import (
	"fmt"
	"sort"

	"dirfuzz/pkg/engine"
)

func (m *Model) selectedHit() *engine.Result {
	if m.selectedIndex < 0 || m.selectedIndex >= len(m.logLineHits) {
		return nil
	}
	return m.logLineHits[m.selectedIndex]
}

func (m *Model) applyMarkedHit(hit *engine.Result) {
	if hit == nil {
		return
	}
	if m.markedHitKeys == nil {
		hit.MarkedInteresting = false
		return
	}
	hit.MarkedInteresting = m.markedHitKeys[historyIdentityKey(*hit)]
}

func (m *Model) markedHitKeyList() []string {
	if len(m.markedHitKeys) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m.markedHitKeys))
	for key, marked := range m.markedHitKeys {
		if marked {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func (m *Model) applyMarkedStateToVisibleHits() {
	for i := range m.logLineHits {
		if m.logLineHits[i] == nil {
			continue
		}
		m.applyMarkedHit(m.logLineHits[i])
		if i < len(m.logs) {
			m.logs[i] = formatResult(*m.logLineHits[i])
		}
	}
	for i := range m.hits {
		m.applyMarkedHit(&m.hits[i])
	}
	m.logsChanged = true
	m.dashboardDirty = true
}

func (m *Model) setMarkedHitByKey(key string, marked bool) {
	if key == "" {
		return
	}
	if m.markedHitKeys == nil {
		m.markedHitKeys = make(map[string]bool)
	}
	if marked {
		m.markedHitKeys[key] = true
	} else {
		delete(m.markedHitKeys, key)
	}
	m.applyMarkedStateToVisibleHits()
	m.markUIStateDirty()
}

func (m *Model) setSelectedHitMarked(marked bool) string {
	hit := m.selectedHit()
	if hit == nil {
		return errorStyle.Render("No hit selected to mark.")
	}

	key := historyIdentityKey(*hit)
	if hit.MarkedInteresting == marked {
		if marked {
			return mutedStyle.Render(fmt.Sprintf("Already marked interesting: %s", hit.Path))
		}
		return mutedStyle.Render(fmt.Sprintf("Already unmarked: %s", hit.Path))
	}

	m.setMarkedHitByKey(key, marked)
	if m.state == StateList {
		m.renderListView()
	} else if m.state == StateDetail {
		m.updateDetailView()
	}

	if marked {
		return statusStyle.Render(fmt.Sprintf("[*] Marked interesting: %s", hit.Path))
	}
	return statusStyle.Render(fmt.Sprintf("[*] Unmarked: %s", hit.Path))
}

func (m *Model) toggleSelectedHitMarked() string {
	hit := m.selectedHit()
	if hit == nil {
		return errorStyle.Render("No hit selected to mark.")
	}
	return m.setSelectedHitMarked(!hit.MarkedInteresting)
}
