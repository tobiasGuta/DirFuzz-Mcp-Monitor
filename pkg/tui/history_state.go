package tui

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"time"

	"dirfuzz/pkg/engine"
)

const (
	appendHistoryMode          = "append"
	persistedUIStateVersion    = 1
	uiStateAutosaveDebounceDur = time.Second
)

type persistedRepeaterSession struct {
	ID           int                    `json:"id"`
	Label        string                 `json:"label"`
	Target       string                 `json:"target"`
	Request      string                 `json:"request"`
	Response     string                 `json:"response"`
	HasError     bool                   `json:"has_error,omitempty"`
	LastStatus   int                    `json:"last_status,omitempty"`
	LastDuration time.Duration          `json:"last_duration,omitempty"`
	LastRawB64   string                 `json:"last_raw_b64,omitempty"`
	History      []RepeaterHistoryEntry `json:"history,omitempty"`
	HistoryIdx   int                    `json:"history_idx,omitempty"`
}

type persistedUIState struct {
	Version           int                        `json:"version"`
	ActiveRepeaterIdx int                        `json:"active_repeater_idx,omitempty"`
	AnomalyFilterOnly bool                       `json:"anomaly_filter_only,omitempty"`
	MarkedHitKeys     []string                   `json:"marked_hit_keys,omitempty"`
	RepeaterFocusReq  bool                       `json:"repeater_focus_req"`
	RepeaterSessions  []persistedRepeaterSession `json:"repeater_sessions,omitempty"`
}

func (m *Model) ConfigureHistoryPersistence(outputFile, historyMode string) {
	m.historyMode = strings.ToLower(strings.TrimSpace(historyMode))
	if m.historyMode == appendHistoryMode && strings.TrimSpace(outputFile) != "" {
		m.historyUIPath = outputFile + ".ui.json"
	} else {
		m.historyUIPath = ""
	}
}

func (m *Model) historyAppendEnabled() bool {
	return m.historyMode == appendHistoryMode && m.historyUIPath != ""
}

func historyIdentityKey(hit engine.Result) string {
	method := strings.ToUpper(strings.TrimSpace(hit.Method))
	if method == "" {
		method = "GET"
	}

	target := strings.TrimSpace(hit.Path)
	if rawURL := strings.TrimSpace(hit.URL); rawURL != "" {
		if parsed, err := url.Parse(rawURL); err == nil {
			target = parsed.EscapedPath()
			if target == "" {
				target = parsed.Path
			}
			if target == "" {
				target = "/"
			}
			if parsed.RawQuery != "" {
				target += "?" + parsed.RawQuery
			}
		} else {
			target = rawURL
		}
	}
	return method + "|" + target
}

func (m *Model) decrementLogIndexes() {
	for key, idx := range m.logIndexByKey {
		if idx <= 0 {
			delete(m.logIndexByKey, key)
			continue
		}
		m.logIndexByKey[key] = idx - 1
	}
}

func (m *Model) decrementHitIndexes() {
	for key, idx := range m.hitIndexByKey {
		if idx <= 0 {
			delete(m.hitIndexByKey, key)
			continue
		}
		m.hitIndexByKey[key] = idx - 1
	}
}

func (m *Model) trimOldestLogEntry() {
	if len(m.logs) == 0 {
		return
	}
	if len(m.logLineHits) > 0 && m.logLineHits[0] != nil {
		delete(m.logIndexByKey, historyIdentityKey(*m.logLineHits[0]))
	}
	m.logs = m.logs[1:]
	if len(m.logLineHits) > 0 {
		m.logLineHits = m.logLineHits[1:]
	}
	m.decrementLogIndexes()
	if m.selectedIndex > 0 {
		m.selectedIndex--
	}
	if m.listScrollIdx > 0 {
		m.listScrollIdx--
	}
}

func (m *Model) trimOldestHitEntry() {
	if len(m.hits) == 0 {
		return
	}
	delete(m.hitIndexByKey, historyIdentityKey(m.hits[0]))
	m.hits = m.hits[1:]
	m.decrementHitIndexes()
}

func (m *Model) upsertHistoryHit(text string, hit engine.Result) {
	m.applyMarkedHit(&hit)
	text = formatResult(hit)
	key := historyIdentityKey(hit)
	if logIdx, ok := m.logIndexByKey[key]; ok && logIdx >= 0 && logIdx < len(m.logs) {
		hitCopy := hit
		m.logs[logIdx] = text
		m.logLineHits[logIdx] = &hitCopy
		if hitIdx, ok := m.hitIndexByKey[key]; ok && hitIdx >= 0 && hitIdx < len(m.hits) {
			m.hits[hitIdx] = hit
		} else {
			if len(m.hits) >= maxLogEntries {
				m.trimOldestHitEntry()
			}
			m.hits = append(m.hits, hit)
			m.hitIndexByKey[key] = len(m.hits) - 1
		}
		m.logsChanged = true
		m.dashboardDirty = true
		return
	}

	if len(m.logs) >= maxLogEntries {
		m.trimOldestLogEntry()
	}
	if len(m.hits) >= maxLogEntries {
		m.trimOldestHitEntry()
	}

	m.logs = append(m.logs, text)
	hitCopy := hit
	m.logLineHits = append(m.logLineHits, &hitCopy)
	m.hits = append(m.hits, hit)
	m.logIndexByKey[key] = len(m.logs) - 1
	m.hitIndexByKey[key] = len(m.hits) - 1

	if m.atBottom {
		m.selectedIndex = len(m.logs) - 1
		m.listScrollIdx = len(m.logs) - m.viewport.Height
		if m.listScrollIdx < 0 {
			m.listScrollIdx = 0
		}
	}

	m.logsChanged = true
	m.dashboardDirty = true
}

func (m *Model) LoadPersistedResults(results []engine.Result) {
	if !m.historyAppendEnabled() || len(results) == 0 {
		return
	}
	for _, hit := range results {
		m.upsertHistoryHit(formatResult(hit), hit)
	}
	m.renderListView()
}

func (m *Model) markUIStateDirty() {
	if !m.historyAppendEnabled() {
		return
	}
	m.uiStateDirty = true
	m.uiStateDirtyAt = time.Now()
}

func (m *Model) LoadPersistedUIState() error {
	if !m.historyAppendEnabled() {
		return nil
	}

	data, err := os.ReadFile(m.historyUIPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var state persistedUIState
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}
	if state.Version != persistedUIStateVersion {
		return nil
	}

	m.markedHitKeys = make(map[string]bool, len(state.MarkedHitKeys))
	for _, key := range state.MarkedHitKeys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		m.markedHitKeys[key] = true
	}
	m.applyMarkedStateToVisibleHits()
	m.anomalyFilterOnly = state.AnomalyFilterOnly

	m.repeaterSessions = nil
	m.repeaterFocusReq = state.RepeaterFocusReq
	maxID := 0
	for _, saved := range state.RepeaterSessions {
		raw := []byte(nil)
		if saved.LastRawB64 != "" {
			decoded, err := base64.StdEncoding.DecodeString(saved.LastRawB64)
			if err != nil {
				return err
			}
			raw = decoded
		}
		session := RepeaterSession{
			ID:           saved.ID,
			Label:        saved.Label,
			Target:       saved.Target,
			Request:      saved.Request,
			Response:     saved.Response,
			HasError:     saved.HasError,
			LastStatus:   saved.LastStatus,
			LastDuration: saved.LastDuration,
			LastRaw:      raw,
			History:      append([]RepeaterHistoryEntry(nil), saved.History...),
			HistoryIdx:   saved.HistoryIdx,
		}
		if session.ID > maxID {
			maxID = session.ID
		}
		if session.Label == "" {
			session.Label = repeaterSessionLabel(session.Request)
		}
		m.repeaterSessions = append(m.repeaterSessions, session)
	}
	if maxID >= m.nextRepeaterSessionID {
		m.nextRepeaterSessionID = maxID + 1
	}
	if len(m.repeaterSessions) == 0 {
		m.uiStateDirty = false
		return nil
	}

	active := state.ActiveRepeaterIdx
	if active < 0 {
		active = 0
	}
	if active >= len(m.repeaterSessions) {
		active = len(m.repeaterSessions) - 1
	}
	m.loadRepeaterSessionIntoUI(active)
	m.uiStateDirty = false
	return nil
}

func (m *Model) buildPersistedUIState() persistedUIState {
	m.syncActiveRepeaterSessionFromUI()

	state := persistedUIState{
		Version:           persistedUIStateVersion,
		ActiveRepeaterIdx: m.activeRepeaterIdx,
		AnomalyFilterOnly: m.anomalyFilterOnly,
		MarkedHitKeys:     m.markedHitKeyList(),
		RepeaterFocusReq:  m.repeaterFocusReq,
		RepeaterSessions:  make([]persistedRepeaterSession, 0, len(m.repeaterSessions)),
	}
	for _, session := range m.repeaterSessions {
		saved := persistedRepeaterSession{
			ID:           session.ID,
			Label:        session.Label,
			Target:       session.Target,
			Request:      session.Request,
			Response:     session.Response,
			HasError:     session.HasError,
			LastStatus:   session.LastStatus,
			LastDuration: session.LastDuration,
			History:      append([]RepeaterHistoryEntry(nil), session.History...),
			HistoryIdx:   session.HistoryIdx,
		}
		if len(session.LastRaw) > 0 {
			saved.LastRawB64 = base64.StdEncoding.EncodeToString(session.LastRaw)
		}
		state.RepeaterSessions = append(state.RepeaterSessions, saved)
	}
	return state
}

func (m *Model) FlushPersistedUIState() error {
	if !m.historyAppendEnabled() {
		return nil
	}
	if len(m.repeaterSessions) == 0 && len(m.markedHitKeys) == 0 && !m.anomalyFilterOnly {
		if err := os.Remove(m.historyUIPath); err != nil && !os.IsNotExist(err) {
			return err
		}
		m.uiStateDirty = false
		return nil
	}

	payload, err := json.MarshalIndent(m.buildPersistedUIState(), "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(m.historyUIPath, payload, 0o600); err != nil {
		return err
	}
	m.uiStateDirty = false
	return nil
}

func (m *Model) resetAfterRestartPreservingHistory() {
	m.systemLogs.reset()
	m.logViewport.SetContent("")
	m.startTime = time.Now()
	m.rpsHistoryFull = nil
	m.workerUtilizationHistory = nil
	m.errorRateHistory = nil
	m.queueDepthHistory = nil
	m.totalErrors = 0
	m.totalRetries = 0
	m.totalProxyRotations = 0
	m.peakRPS = 0
	m.avgResponseTime = 0
	m.activeWorkers = 0
	m.responseSamples = 0
	m.lastMetricsTick = time.Time{}
	m.lastErrorCount = 0
	m.logPanelScrollOffset = 0
	m.logPanelAutoScroll = true
	m.logPanelDirty = true
	m.dashboardDirty = true
	m.dashboardCacheValid = false
	m.dashboardCache = ""
	m.logPanelCacheValid = false
	m.logPanelCache = ""
	m.logPanelCacheKey = ""
	m.logEventsSinceRender = 0
	m.logSearchTerm = ""
	m.logDetailsExpanded = false
	m.logSelectedIndex = 0
	m.errorPulseOn = false
	m.errorPulseUntil = time.Time{}
	m.logsChanged = true

	if m.state == StateDetail {
		m.updateDetailView()
	} else if m.state == StateList {
		m.renderListView()
	}
}
