package tui

import (
	"bytes"
	"context"
	"dirfuzz/pkg/engine"
	"dirfuzz/pkg/httpclient"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/reflow/wrap"
)

// TUI Colors (Dracula Theme)
var (
	DraculaBg      = lipgloss.Color("#282a36")
	DraculaFg      = lipgloss.Color("#f8f8f2")
	DraculaPurple  = lipgloss.Color("#bd93f9")
	DraculaGreen   = lipgloss.Color("#50fa7b")
	DraculaCyan    = lipgloss.Color("#8be9fd")
	DraculaOrange  = lipgloss.Color("#ffb86c")
	DraculaRed     = lipgloss.Color("#ff5555")
	DraculaPink    = lipgloss.Color("#ff79c6")
	DraculaYellow  = lipgloss.Color("#f1fa8c")
	DraculaComment = lipgloss.Color("#6272a4")
)

// Styles
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(DraculaPurple).
			Background(DraculaBg).
			PaddingLeft(1).
			PaddingRight(1)

	statusStyle = lipgloss.NewStyle().
			Foreground(DraculaGreen)

	errorStyle = lipgloss.NewStyle().
			Foreground(DraculaRed)

	mutedStyle = lipgloss.NewStyle().
			Foreground(DraculaComment)

	highlightStyle = lipgloss.NewStyle().
			Foreground(DraculaCyan)

	orangeStyle = lipgloss.NewStyle().
			Foreground(DraculaOrange)

	pinkStyle = lipgloss.NewStyle().
			Foreground(DraculaPink)

	yellowStyle = lipgloss.NewStyle().
			Foreground(DraculaYellow)

	logStyle = lipgloss.NewStyle().
			Foreground(DraculaFg)

	cmdPromptStyle = lipgloss.NewStyle().
			Foreground(DraculaPurple).
			Bold(true)

	separatorStyle = lipgloss.NewStyle().
			Foreground(DraculaComment)

	autocompleteBoxStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(DraculaCyan).
				Padding(0, 1)

	autocompleteItemStyle = lipgloss.NewStyle().
				Foreground(DraculaFg)

	autocompleteSelectedStyle = lipgloss.NewStyle().
					Foreground(DraculaCyan).
					Bold(true)

	paneStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(DraculaPurple).
			Padding(0, 1)

	paneActiveStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(DraculaCyan).
			Padding(0, 1)

	paneInactiveStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(DraculaComment).
				Padding(0, 1)

	detailPaneHeaderBaseStyle = lipgloss.NewStyle().
					Bold(true).
					Padding(0, 1)

	requestPaneHeaderStyle = lipgloss.NewStyle().
				Bold(true).
				Padding(0, 1).
				Foreground(DraculaBg).
				Background(DraculaCyan)

	responsePaneHeaderStyle = lipgloss.NewStyle().
				Bold(true).
				Padding(0, 1).
				Foreground(DraculaBg).
				Background(DraculaOrange)

	selectedRowStyle = lipgloss.NewStyle().
				Bold(true)

	selectedCursorStyle = lipgloss.NewStyle().
				Foreground(DraculaCyan).
				Bold(true)

	severity2xxStyle     = lipgloss.NewStyle().Foreground(DraculaGreen)
	severity3xxStyle     = lipgloss.NewStyle().Foreground(DraculaCyan)
	severity403Style     = lipgloss.NewStyle().Foreground(DraculaOrange)
	severity4xxStyle     = lipgloss.NewStyle().Foreground(DraculaYellow)
	severity5xxStyle     = lipgloss.NewStyle().Foreground(DraculaRed)
	severityNeutralStyle = lipgloss.NewStyle().Foreground(DraculaComment)

	badgeBaseStyle = lipgloss.NewStyle().
			Bold(true).
			Padding(0, 1)

	status2xxStyle        = lipgloss.NewStyle().Foreground(DraculaGreen)
	status3xxStyle        = lipgloss.NewStyle().Foreground(DraculaCyan)
	status403Style        = lipgloss.NewStyle().Foreground(DraculaOrange)
	status4xxStyle        = lipgloss.NewStyle().Foreground(DraculaYellow)
	status5xxStyle        = lipgloss.NewStyle().Foreground(DraculaRed)
	forbiddenCFWAFStyle   = lipgloss.NewStyle().Foreground(DraculaRed)
	forbiddenCFAdminStyle = lipgloss.NewStyle().Foreground(DraculaOrange)
	forbiddenNginxStyle   = lipgloss.NewStyle().Foreground(DraculaCyan)

	pauseBannerOrangeStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(DraculaYellow).
				Border(lipgloss.RoundedBorder()).
				BorderForeground(DraculaOrange).
				Align(lipgloss.Center)

	pauseBannerYellowStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(DraculaOrange).
				Border(lipgloss.RoundedBorder()).
				BorderForeground(DraculaYellow).
				Align(lipgloss.Center)
)

var ansiEscapePattern = regexp.MustCompile(`\x1b\[[0-9;]*m`)

const maxLogEntries = 10000
const maxCmdLines = 500
const bottomBandHeight = 14

func renderStatusBadge(activeColor lipgloss.Color, icon, label string, count int64) string {
	// Dim the badge if the count is zero to reduce visual noise
	displayColor := activeColor
	if count == 0 {
		displayColor = DraculaComment
	}

	leftBorder := lipgloss.RoundedBorder()
	leftBorder.TopRight = "┬"
	leftBorder.BottomRight = "┴"

	leftStyle := lipgloss.NewStyle().
		Foreground(displayColor).
		Border(leftBorder).
		BorderForeground(displayColor).
		Padding(0, 1)

	rightBorder := lipgloss.RoundedBorder()
	rightBorder.TopLeft = "─"
	rightBorder.BottomLeft = "─"
	rightBorder.Left = ""

	rightStyle := lipgloss.NewStyle().
		Foreground(displayColor).
		Border(rightBorder). // True for all edges so top/bottom draw properly
		BorderForeground(displayColor).
		Padding(0, 1).
		Bold(true)

	left := leftStyle.Render(fmt.Sprintf("%s %s", icon, label))
	right := rightStyle.Render(fmt.Sprintf("%d", count))

	return lipgloss.JoinHorizontal(lipgloss.Center, left, right)
}

func renderSeverityMarker(hit *engine.Result) string {
	if hit == nil {
		return severityNeutralStyle.Render("·")
	}

	symbol := "●"
	switch {
	case hit.StatusCode >= 200 && hit.StatusCode < 300:
		return severity2xxStyle.Render(symbol)
	case hit.StatusCode >= 300 && hit.StatusCode < 400:
		return severity3xxStyle.Render(symbol)
	case hit.StatusCode == 403:
		return severity403Style.Render(symbol)
	case hit.StatusCode >= 400 && hit.StatusCode < 500:
		return severity4xxStyle.Render(symbol)
	case hit.StatusCode >= 500:
		return severity5xxStyle.Render(symbol)
	default:
		return severityNeutralStyle.Render(symbol)
	}
}

func renderTriageMarker(hit *engine.Result) string {
	if hit == nil || !hit.MarkedInteresting {
		return mutedStyle.Render(" ")
	}
	return yellowStyle.Render("★")
}

func severitySymbol(hit *engine.Result) string {
	if hit == nil {
		return "·"
	}
	return "●"
}

func stripANSI(text string) string {
	return ansiEscapePattern.ReplaceAllString(text, "")
}

func renderPaneHeader(style lipgloss.Style, width int, title string) string {
	if width < 1 {
		width = 1
	}
	return style.Width(width).Align(lipgloss.Left).Render(title)
}

func newRepeaterTextarea() textarea.Model {
	ta := newRepeaterTextarea()
	return ta
}

func repeaterSessionLabel(rawReq string) string {
	line := strings.TrimSpace(strings.Split(rawReq, "\n")[0])
	if line == "" {
		return "untitled"
	}
	parts := strings.Fields(line)
	label := line
	if len(parts) >= 2 {
		label = parts[0] + " " + parts[1]
	}
	runes := []rune(label)
	if len(runes) > 28 {
		label = string(runes[:27]) + "…"
	}
	return label
}

func (m *Model) activeRepeaterSession() *RepeaterSession {
	if m.activeRepeaterIdx < 0 || m.activeRepeaterIdx >= len(m.repeaterSessions) {
		return nil
	}
	return &m.repeaterSessions[m.activeRepeaterIdx]
}

func (m *Model) findRepeaterSessionIndex(sessionID int) int {
	for i := range m.repeaterSessions {
		if m.repeaterSessions[i].ID == sessionID {
			return i
		}
	}
	return -1
}

func (m *Model) syncActiveRepeaterSessionFromUI() {
	session := m.activeRepeaterSession()
	if session == nil {
		return
	}
	session.Request = m.repeaterInput.Value()
	session.Label = repeaterSessionLabel(session.Request)
	session.Target = m.repeaterTarget
	session.Sending = m.repeaterSending
	session.LastStatus = m.repeaterLastStatus
	session.LastDuration = m.repeaterLastDuration
	if len(m.repeaterLastRaw) > 0 || len(session.LastRaw) == 0 {
		session.LastRaw = append(session.LastRaw[:0], m.repeaterLastRaw...)
	}
	session.CancelFn = m.repeaterCancelFn
	session.History = append(session.History[:0], m.repeaterHistory...)
	session.HistoryIdx = m.repeaterHistoryIdx
	m.markUIStateDirty()
}

func (m *Model) loadRepeaterSessionIntoUI(idx int) {
	if idx < 0 || idx >= len(m.repeaterSessions) {
		return
	}

	session := &m.repeaterSessions[idx]
	m.activeRepeaterIdx = idx
	m.repeaterTarget = session.Target
	m.repeaterInput.SetValue(session.Request)
	m.repeaterSending = session.Sending
	m.repeaterLastStatus = session.LastStatus
	m.repeaterLastDuration = session.LastDuration
	m.repeaterLastRaw = append(m.repeaterLastRaw[:0], session.LastRaw...)
	m.repeaterCancelFn = session.CancelFn
	m.repeaterHistory = append(m.repeaterHistory[:0], session.History...)
	m.repeaterHistoryIdx = session.HistoryIdx
	if session.Sending {
		m.repeaterRespVp.SetContent("Sending...")
	} else if session.HasError {
		m.repeaterRespVp.SetContent(errorStyle.Render(session.Response))
	} else {
		m.repeaterRespVp.SetContent(wrapText(session.Response, m.repeaterRespVp.Width))
	}
	m.repeaterRespVp.GotoTop()
	if m.repeaterFocusReq {
		m.repeaterInput.Focus()
	} else {
		m.repeaterInput.Blur()
	}
}

func (m *Model) openRepeaterSession(target, rawReq string) {
	m.syncActiveRepeaterSessionFromUI()
	session := RepeaterSession{
		ID:      m.nextRepeaterSessionID,
		Label:   repeaterSessionLabel(rawReq),
		Target:  target,
		Request: rawReq,
		History: []RepeaterHistoryEntry{{
			Request:    rawReq,
			Response:   "",
			StatusCode: 0,
			Duration:   0,
		}},
		HistoryIdx: 0,
	}
	m.nextRepeaterSessionID++
	m.repeaterSessions = append(m.repeaterSessions, session)
	m.loadRepeaterSessionIntoUI(len(m.repeaterSessions) - 1)
	m.state = StateRepeater
	m.repeaterFocusReq = true
	m.repeaterInput.Focus()
	m.markUIStateDirty()
}

func (m *Model) cycleRepeaterSession(delta int) {
	if len(m.repeaterSessions) <= 1 {
		return
	}
	m.syncActiveRepeaterSessionFromUI()
	next := m.activeRepeaterIdx + delta
	if next < 0 {
		next = len(m.repeaterSessions) - 1
	} else if next >= len(m.repeaterSessions) {
		next = 0
	}
	m.loadRepeaterSessionIntoUI(next)
	m.markUIStateDirty()
}

func (m *Model) closeActiveRepeaterSession() {
	if len(m.repeaterSessions) == 0 {
		m.state = StateList
		return
	}

	session := m.activeRepeaterSession()
	if session != nil && session.CancelFn != nil {
		session.CancelFn()
	}

	idx := m.activeRepeaterIdx
	m.repeaterSessions = append(m.repeaterSessions[:idx], m.repeaterSessions[idx+1:]...)
	if len(m.repeaterSessions) == 0 {
		m.repeaterTarget = ""
		m.repeaterInput.SetValue("")
		m.repeaterRespVp.SetContent("")
		m.repeaterSending = false
		m.repeaterLastStatus = 0
		m.repeaterLastDuration = 0
		m.repeaterLastRaw = nil
		m.repeaterCancelFn = nil
		m.repeaterHistory = nil
		m.repeaterHistoryIdx = 0
		m.activeRepeaterIdx = 0
		m.state = StateList
		return
	}

	if idx >= len(m.repeaterSessions) {
		idx = len(m.repeaterSessions) - 1
	}
	m.loadRepeaterSessionIntoUI(idx)
	m.markUIStateDirty()
}

func (m *Model) repeaterSessionStrip(width int) string {
	if len(m.repeaterSessions) == 0 || width <= 0 {
		return ""
	}

	start := max(0, m.activeRepeaterIdx-2)
	end := min(len(m.repeaterSessions), start+5)
	if end-start < 5 {
		start = max(0, end-5)
	}

	parts := make([]string, 0, end-start+2)
	if start > 0 {
		parts = append(parts, mutedStyle.Render("…"))
	}
	for i := start; i < end; i++ {
		label := fmt.Sprintf("%d %s", i+1, m.repeaterSessions[i].Label)
		if m.repeaterSessions[i].Sending {
			label += " *"
		}
		style := mutedStyle
		if i == m.activeRepeaterIdx {
			style = highlightStyle
		}
		parts = append(parts, style.Render("["+label+"]"))
	}
	if end < len(m.repeaterSessions) {
		parts = append(parts, mutedStyle.Render("…"))
	}

	strip := strings.Join(parts, " ")
	if lipgloss.Width(strip) > width {
		return lipgloss.NewStyle().MaxWidth(width).Render(strip)
	}
	return strip
}

func keyChip(key, label string) string {
	color := lipgloss.TerminalColor(DraculaCyan)
	switch key {
	case "Enter":
		key = "↵"
		color = DraculaOrange
	case "r":
		color = DraculaCyan
	case "h", "h/H":
		color = DraculaGreen
	case "d":
		color = DraculaOrange
	case "R":
		color = DraculaRed
	case "m":
		color = DraculaYellow
	case "L":
		color = DraculaPink
	case ":":
		color = DraculaCyan
	case "q", "Esc", "Esc/q", "m/q/Esc":
		color = DraculaRed
	case "x":
		color = DraculaPurple
	case "D":
		color = DraculaOrange
	case "f":
		color = DraculaGreen
	case "e":
		color = DraculaYellow
	case "Tab":
		color = DraculaPink
	case "Ctrl+R":
		color = DraculaGreen
	case "Ctrl+P/N":
		color = DraculaPurple
	case "1-5":
		color = DraculaPink
	}

	k := lipgloss.NewStyle().
		Bold(true).
		Foreground(color).
		Render(key)

	l := lipgloss.NewStyle().Foreground(lipgloss.Color("#6272A4")).Render(" " + label)
	return k + l
}

func renderEvasionSummary(rows []engine.EvasionScoreboardRow) string {
	if len(rows) == 0 {
		return mutedStyle.Render("WAF Bypass Summary: none recorded")
	}
	var sb strings.Builder
	sb.WriteString("WAF Bypass Summary\n")
	sb.WriteString("Technique | Attempts | Bypasses | Rate%\n")
	sb.WriteString("--- | ---: | ---: | ---:\n")
	for _, row := range rows {
		fmt.Fprintf(&sb, "%s | %d | %d | %.1f%%\n", row.Technique, row.Attempts, row.Bypasses, row.Rate*100)
	}
	return sb.String()
}

func hasLabel(labels []string, target string) bool {
	for _, label := range labels {
		if strings.EqualFold(strings.TrimSpace(label), target) {
			return true
		}
	}
	return false
}

func anomalyRowStyle(r engine.Result) lipgloss.Style {
	if r.IsEagleAlert {
		// Slightly tint the full row to make drift alerts stand out while scrolling.
		return lipgloss.NewStyle().Background(lipgloss.Color("#3a2632"))
	}
	return lipgloss.NewStyle()
}

type contentTypeRow struct {
	label string
	count int
}

func (m *Model) renderCardTable(title string, headers []string, rows [][]string) string {
	width := m.width - 6
	if width < 20 {
		width = 40
	}

	if len(headers) == 0 && len(rows) == 0 {
		return renderCard(title, "", width, false)
	}

	cols := len(headers)
	if len(rows) > 0 && len(rows[0]) > cols {
		cols = len(rows[0])
	}
	widths := make([]int, cols)
	for i, header := range headers {
		if i < len(widths) {
			widths[i] = lipgloss.Width(header)
		}
	}
	for _, row := range rows {
		for i := 0; i < cols && i < len(row); i++ {
			if cellWidth := lipgloss.Width(row[i]); cellWidth > widths[i] {
				widths[i] = cellWidth
			}
		}
	}

	var sb strings.Builder

	showHeaders := true
	if len(headers) == 2 && headers[0] == "Signal" && headers[1] == "Value" {
		showHeaders = false
	} else if len(headers) == 1 && headers[0] == "Event" {
		showHeaders = false
	} else if len(headers) == 0 {
		showHeaders = false
	}

	if showHeaders {
		for i, header := range headers {
			sb.WriteString(mutedStyle.Render(header))
			padding := widths[i] - lipgloss.Width(header)
			if padding > 0 {
				sb.WriteString(strings.Repeat(" ", padding))
			}
			if i < cols-1 {
				sb.WriteString("   ")
			}
		}
		sb.WriteString("\n\n")
	}

	for rIdx, row := range rows {
		for i := 0; i < cols; i++ {
			cell := ""
			if i < len(row) {
				cell = row[i]
			}
			sb.WriteString(cell)
			padding := widths[i] - lipgloss.Width(cell)
			if padding > 0 {
				sb.WriteString(strings.Repeat(" ", padding))
			}
			if i < cols-1 {
				sb.WriteString("   ")
			}
		}
		if rIdx < len(rows)-1 {
			sb.WriteString("\n")
		}
	}

	return renderCard(title, sb.String(), width, false)
}

func renderCard(title string, body string, width int, active bool) string {
	style := paneStyle
	if active {
		style = paneActiveStyle
	}
	header := lipgloss.NewStyle().
		Bold(true).
		Foreground(DraculaBg).
		Background(DraculaPurple).
		Padding(0, 1).
		Width(width - 4).
		Render(" " + title + " ")

	return style.Width(width).Render(
		lipgloss.JoinVertical(lipgloss.Top, header, body),
	)
}

func buildTopContentTypes(rows []engine.Result, limit int) []contentTypeRow {
	if limit < 1 {
		limit = 1
	}
	counts := make(map[string]int)
	for _, hit := range rows {
		label := strings.TrimSpace(hit.ContentType)
		if label == "" {
			label = "unknown"
		}
		counts[label]++
	}

	if len(counts) == 0 {
		return nil
	}

	out := make([]contentTypeRow, 0, len(counts))
	for label, count := range counts {
		out = append(out, contentTypeRow{label: label, count: count})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].count != out[j].count {
			return out[i].count > out[j].count
		}
		return out[i].label < out[j].label
	})

	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (m *Model) renderDashboardView() {
	if !m.dashboardDirty && m.dashboardCacheValid && m.dashboardCache != "" {
		m.viewport.SetContent(m.dashboardCache)
		return
	}

	rows := m.Engine.EvasionSummaryRows()
	wafSummary := renderEvasionSummary(rows)

	m.Engine.Config.RLock()
	workers := m.Engine.Config.MaxWorkers
	delay := m.Engine.Config.Delay
	proxyOut := m.Engine.Config.ProxyOut
	m.Engine.Config.RUnlock()

	currentRPS := atomic.LoadInt64(&m.Engine.CurrentRPS)
	queueSize := m.Engine.QueueSize()
	processed := atomic.LoadInt64(&m.Engine.ProcessedLines)
	total := atomic.LoadInt64(&m.Engine.TotalLines)
	autoFilterSuppressed := atomic.LoadInt64(&m.Engine.AutoFilterSuppressed)
	simhashSuppressed := atomic.LoadInt64(&m.Engine.SimhashSuppressed)
	harvestedPaths := atomic.LoadInt64(&m.Engine.HarvestedPaths)
	tuiDropped := atomic.LoadInt64(&m.Engine.TUIDropped)
	logDropped := m.Engine.LogEventsDropped.Load()

	// Look for this section inside renderDashboardView()
	overview := strings.Join([]string{
		mutedStyle.Render("Live metrics, updated while the scan runs."),
		m.renderDashboardTabBar(),
		// Replace the fmt.Sprintf("%s %s %s", ...) block with this:
		lipgloss.JoinHorizontal(lipgloss.Center,
			renderStatusBadge(DraculaPink, "◌", "AF", autoFilterSuppressed),
			" ",
			renderStatusBadge(DraculaCyan, "⬢", "S404", simhashSuppressed),
			" ",
			mutedStyle.Render(fmt.Sprintf("Harvested:%d Queue:%d TUI-dropped:%d Log-dropped:%d", harvestedPaths, queueSize, tuiDropped, logDropped)),
		),
		fmt.Sprintf(
			"Workers: %d  Active: %d  Current RPS: %d  Peak RPS: %d  Avg RT: %s  Delay: %s",
			workers,
			atomic.LoadInt64(&m.activeWorkers),
			currentRPS,
			m.peakRPS,
			m.avgResponseTime.Round(time.Millisecond),
			delay.Round(time.Millisecond),
		),
		fmt.Sprintf("Proxy rotation: %d  Proxy configured: %s  Progress: %d/%d",
			m.totalProxyRotations,
			func() string {
				if strings.TrimSpace(proxyOut) == "" {
					return "no"
				}
				return "yes"
			}(),
			processed,
			total,
		),
	}, "\n")

	var body string
	switch m.dashboardTab {
	case DashboardTabErrors:
		body = m.renderErrorAnalysisDashboard()
	case DashboardTabDiscovery:
		body = m.renderDiscoveryDashboard()
	case DashboardTabNetwork:
		body = m.renderNetworkDashboard()
	case DashboardTabTimeline:
		body = m.renderTimelineDashboard()
	default:
		body = m.renderPerformanceDashboard()
	}

	content := strings.Join([]string{overview, wafSummary, body}, "\n\n")
	m.viewport.SetContent(content)
	m.dashboardCache = content
	m.dashboardCacheValid = true
	m.dashboardDirty = false
}

func (m *Model) appendSystemLog(ev engine.LogEvent) {
	relative := relativeScanTime(m.startTime, ev.Timestamp)
	searchParts := []string{
		strings.ToLower(relative),
		strings.ToLower(string(ev.Level)),
		strings.ToLower(string(ev.Category)),
		strings.ToLower(string(ev.Type)),
		strings.ToLower(ev.Message),
	}
	path := ""
	if ev.Metadata != nil {
		keys := make([]string, 0, len(ev.Metadata))
		for k := range ev.Metadata {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			val := fmt.Sprintf("%v", ev.Metadata[k])
			searchParts = append(searchParts, strings.ToLower(k), strings.ToLower(val))
			if path == "" && (k == "path" || k == "target" || k == "url") {
				path = val
			}
		}
	}
	m.systemLogs.append(systemLogEntry{
		Event:      ev,
		Rendered:   formatLogEvent(ev, relative),
		Relative:   relative,
		SearchText: strings.Join(searchParts, " "),
		HasDetail:  len(ev.Metadata) > 0,
		Path:       path,
	})
	m.logsChanged = true
	m.logPanelDirty = true
	m.dashboardDirty = true
	m.logEventsSinceRender++
}

func dashboardTabLabel(tab DashboardTab) string {
	switch tab {
	case DashboardTabErrors:
		return "Errors"
	case DashboardTabDiscovery:
		return "Discovery"
	case DashboardTabNetwork:
		return "Network"
	case DashboardTabTimeline:
		return "Timeline"
	default:
		return "Performance"
	}
}

func dashboardRangeLabel(idx int) string {
	switch DashboardRange(idx) {
	case DashboardRange5m:
		return "5m"
	case DashboardRangeAll:
		return "All"
	default:
		return "30s"
	}
}

func (m *Model) dashboardSampleLimit() int {
	switch DashboardRange(m.dashboardRangeIdx) {
	case DashboardRange5m:
		return 300
	case DashboardRangeAll:
		return 1000
	default:
		return 30
	}
}

func (m *Model) cycleDashboardRange() {
	m.dashboardRangeIdx++
	if m.dashboardRangeIdx > int(DashboardRangeAll) {
		m.dashboardRangeIdx = int(DashboardRange30s)
	}
}

func sampleIntHistory(values []int64, limit int) []int64 {
	if limit <= 0 || len(values) == 0 {
		return nil
	}
	if len(values) > limit {
		values = values[len(values)-limit:]
	}
	out := make([]int64, len(values))
	copy(out, values)
	return out
}

func sampleFloatHistory(values []float64, limit int) []float64 {
	if limit <= 0 || len(values) == 0 {
		return nil
	}
	if len(values) > limit {
		values = values[len(values)-limit:]
	}
	out := make([]float64, len(values))
	copy(out, values)
	return out
}

func sampleIntSlice(values []int, limit int) []int64 {
	if limit <= 0 || len(values) == 0 {
		return nil
	}
	if len(values) > limit {
		values = values[len(values)-limit:]
	}
	out := make([]int64, len(values))
	for i, v := range values {
		out[i] = int64(v)
	}
	return out
}

func averageIntHistory(values []int64) float64 {
	if len(values) == 0 {
		return 0
	}
	var total int64
	for _, v := range values {
		total += v
	}
	return float64(total) / float64(len(values))
}

func averageFloatHistory(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	var total float64
	for _, v := range values {
		total += v
	}
	return total / float64(len(values))
}

func maxInt64(values []int64) int64 {
	var max int64
	for i, v := range values {
		if i == 0 || v > max {
			max = v
		}
	}
	return max
}

func renderFloatSparkline(values []float64, width int) string {
	if len(values) == 0 {
		return strings.Repeat("▁", width)
	}
	ints := make([]int64, len(values))
	for i, v := range values {
		ints[i] = int64(math.Round(v * 100))
	}
	return renderSparkline(ints, width)
}

func renderSizedBars(items map[string]int64, width int) string {
	if len(items) == 0 {
		return mutedStyle.Render("none")
	}
	type barItem struct {
		label string
		count int64
	}
	rows := make([]barItem, 0, len(items))
	var total int64
	for label, count := range items {
		rows = append(rows, barItem{label: label, count: count})
		total += count
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].count != rows[j].count {
			return rows[i].count > rows[j].count
		}
		return rows[i].label < rows[j].label
	})
	if len(rows) > 8 {
		rows = rows[:8]
	}
	var sb strings.Builder
	if width < 10 {
		width = 10
	}
	for _, row := range rows {
		pct := 0.0
		if total > 0 {
			pct = float64(row.count) / float64(total)
		}
		fill := int(math.Round(pct * float64(width)))
		if fill < 1 && row.count > 0 {
			fill = 1
		}
		if fill > width {
			fill = width
		}
		fmt.Fprintf(&sb, "%s %s %s\n", highlightStyle.Render(padOrTrim(row.label, 22)), statusStyle.Render(strings.Repeat("█", fill)), mutedStyle.Render(fmt.Sprintf("%d", row.count)))
	}
	return strings.TrimRight(sb.String(), "\n")
}

func padOrTrim(text string, width int) string {
	runes := []rune(text)
	if len(runes) == width {
		return text
	}
	if len(runes) > width {
		if width <= 1 {
			return string(runes[:1])
		}
		return string(runes[:width-1]) + "…"
	}
	return text + strings.Repeat(" ", width-len(runes))
}

func formatBytesEstimate(bytes int64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	}
	units := []string{"KiB", "MiB", "GiB", "TiB"}
	value := float64(bytes) / 1024.0
	unitIdx := 0
	for value >= 1024 && unitIdx < len(units)-1 {
		value /= 1024.0
		unitIdx++
	}
	return fmt.Sprintf("%.1f %s", value, units[unitIdx])
}

func statusCategoryLabel(status int) string {
	switch {
	case status >= 200 && status < 300:
		return "2xx"
	case status >= 300 && status < 400:
		return "3xx"
	case status >= 400 && status < 500:
		return "4xx"
	case status >= 500:
		return "5xx"
	default:
		return "other"
	}
}

func logEventMetadataString(meta map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if meta == nil {
			continue
		}
		if v, ok := meta[key]; ok {
			if s := strings.TrimSpace(fmt.Sprint(v)); s != "" && s != "<nil>" {
				return s
			}
		}
	}
	return ""
}

func logEventMetadataBool(meta map[string]interface{}, key string) bool {
	if meta == nil {
		return false
	}
	v, ok := meta[key]
	if !ok {
		return false
	}
	b, ok := v.(bool)
	return ok && b
}

func logEventMetadataInt64(meta map[string]interface{}, key string) int64 {
	if meta == nil {
		return 0
	}
	v, ok := meta[key]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case int:
		return int64(n)
	case int64:
		return n
	case float64:
		return int64(n)
	case float32:
		return int64(n)
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return i
		}
	}
	return 0
}

func logEventPath(ev engine.LogEvent) string {
	if path := logEventMetadataString(ev.Metadata, "path", "url", "endpoint"); path != "" {
		return path
	}
	msg := ev.Message
	if idx := strings.Index(msg, " "); idx >= 0 {
		candidate := strings.TrimSpace(msg[idx+1:])
		if strings.HasPrefix(candidate, "/") {
			return candidate
		}
	}
	return ""
}

func (m *Model) renderDashboardTabBar() string {
	tabs := []DashboardTab{
		DashboardTabPerformance,
		DashboardTabErrors,
		DashboardTabDiscovery,
		DashboardTabNetwork,
		DashboardTabTimeline,
	}
	parts := make([]string, 0, len(tabs)+1)
	for idx, tab := range tabs {
		label := fmt.Sprintf("%d %s", idx+1, dashboardTabLabel(tab))
		styled := mutedStyle.Render(label)
		if tab == m.dashboardTab {
			styled = highlightStyle.Render(label)
		}
		parts = append(parts, styled)
	}
	parts = append(parts, mutedStyle.Render(fmt.Sprintf("range:%s  tab:%s", dashboardRangeLabel(m.dashboardRangeIdx), dashboardTabLabel(m.dashboardTab))))
	return strings.Join(parts, "  ")
}

func (m *Model) renderPerformanceDashboard() string {
	window := m.dashboardSampleLimit()
	rpsSamples := sampleIntHistory(m.rpsHistoryFull, window)
	rps30 := sampleIntHistory(m.rpsHistoryFull, 30)
	rps300 := sampleIntHistory(m.rpsHistoryFull, 300)
	utilSamples := sampleFloatHistory(m.workerUtilizationHistory, window)
	errorSamples := sampleFloatHistory(m.errorRateHistory, window)
	queueSamples := sampleIntSlice(m.queueDepthHistory, window)
	queueSize := m.Engine.QueueSize()

	currentRPS := atomic.LoadInt64(&m.Engine.CurrentRPS)
	peakRPS := m.peakRPS
	if len(rpsSamples) > 0 {
		if samplePeak := maxInt64(rpsSamples); samplePeak > peakRPS {
			peakRPS = samplePeak
		}
	}

	avgRPS := averageIntHistory(rpsSamples)
	workerUtil := averageFloatHistory(utilSamples) * 100
	currentUtil := 0.0
	m.Engine.Config.RLock()
	maxWorkers := m.Engine.Config.MaxWorkers
	m.Engine.Config.RUnlock()
	if maxWorkers > 0 {
		currentUtil = float64(atomic.LoadInt64(&m.activeWorkers)) / float64(maxWorkers) * 100
	}

	metricsRows := [][]string{{
		strconv.Itoa(window),
		strconv.FormatInt(currentRPS, 10),
		fmt.Sprintf("%.1f", avgRPS),
		strconv.FormatInt(peakRPS, 10),
		fmt.Sprintf("%.1f%%", currentUtil),
		fmt.Sprintf("%.1f%%", workerUtil),
		strconv.Itoa(queueSize),
	}}

	parts := []string{
		m.renderCardTable(
			"Performance Trends",
			[]string{"Window", "Current RPS", "Avg RPS", "Peak RPS", "Current Util", "Avg Util", "Queue"},
			metricsRows,
		),
		fmt.Sprintf("%s %s", mutedStyle.Render("RPS 30s"), highlightStyle.Render(renderSparkline(rps30, 30))),
		fmt.Sprintf("%s %s", mutedStyle.Render("RPS 5m"), highlightStyle.Render(renderSparkline(rps300, 50))),
		fmt.Sprintf("%s %s", mutedStyle.Render("Worker utilization"), highlightStyle.Render(renderFloatSparkline(utilSamples, 30))),
		fmt.Sprintf("%s %s", mutedStyle.Render("Queue depth"), highlightStyle.Render(renderSparkline(queueSamples, 30))),
		fmt.Sprintf("%s %s", mutedStyle.Render("Error rate / min"), errorStyle.Render(renderFloatSparkline(errorSamples, 30))),
	}
	return strings.Join(parts, "\n\n")
}

func (m *Model) renderErrorAnalysisDashboard() string {
	connErr := atomic.LoadInt64(&m.Engine.CountConnErr)
	fiveXX := int64(0)
	timeoutErr := int64(0)
	rateLimitErr := int64(0)
	errorPathCounts := make(map[string]int64)
	retryAttempts := int64(0)
	retrySuccesses := int64(0)
	entries := m.systemLogEntries()

	for _, entry := range entries {
		ev := entry.Event
		lower := strings.ToLower(ev.Message)
		if ev.Level == engine.LogLevelError || ev.Type == engine.EventNetworkError || strings.Contains(lower, "error") {
			if path := logEventPath(ev); path != "" {
				errorPathCounts[path]++
			}
		}
		if strings.Contains(lower, "timeout") {
			timeoutErr++
		}
		if strings.Contains(lower, "rate limit") || ev.Type == engine.EventRateLimitHit {
			rateLimitErr++
		}
		if ev.Type == engine.EventRetryAttempt {
			retryAttempts++
			if logEventMetadataBool(ev.Metadata, "success") || strings.EqualFold(logEventMetadataString(ev.Metadata, "outcome", "result"), "success") {
				retrySuccesses++
			}
		}
	}

	for _, hit := range m.hits {
		if hit.StatusCode >= 500 {
			fiveXX++
		}
		if hit.StatusCode == 429 {
			rateLimitErr++
		}
		if hit.StatusCode >= 400 && hit.StatusCode < 500 {
			if path := hit.Path; path != "" {
				errorPathCounts[path]++
			}
		}
	}

	retryRate := mutedStyle.Render("n/a")
	if retryAttempts > 0 {
		retryRate = statusStyle.Render(fmt.Sprintf("%.1f%%", float64(retrySuccesses)/float64(retryAttempts)*100))
	}

	pathRows := [][]string{}
	if len(errorPathCounts) > 0 {
		type pair struct {
			path  string
			count int64
		}
		pairs := make([]pair, 0, len(errorPathCounts))
		for path, count := range errorPathCounts {
			pairs = append(pairs, pair{path: path, count: count})
		}
		sort.Slice(pairs, func(i, j int) bool {
			if pairs[i].count != pairs[j].count {
				return pairs[i].count > pairs[j].count
			}
			return pairs[i].path < pairs[j].path
		})
		if len(pairs) > 5 {
			pairs = pairs[:5]
		}
		for _, pair := range pairs {
			pathRows = append(pathRows, []string{pair.path, strconv.FormatInt(pair.count, 10)})
		}
	}
	if len(pathRows) == 0 {
		pathRows = append(pathRows, []string{mutedStyle.Render("none yet"), mutedStyle.Render("0")})
	}

	buckets := [][]string{
		{"Connection errors", strconv.FormatInt(connErr, 10)},
		{"Timeouts", strconv.FormatInt(timeoutErr, 10)},
		{"5xx responses", strconv.FormatInt(fiveXX, 10)},
		{"Rate limiting", strconv.FormatInt(rateLimitErr, 10)},
		{"Retries", strconv.FormatInt(atomic.LoadInt64(&m.totalRetries), 10)},
		{"Retry success", retryRate},
	}

	parts := []string{
		m.renderCardTable("Error Analysis", []string{"Signal", "Value"}, buckets),
		fmt.Sprintf("%s %s", mutedStyle.Render("Error rate trend"), errorStyle.Render(renderFloatSparkline(m.errorRateHistory, 30))),
		m.renderCardTable("Most Common Error Paths", []string{"Path", "Hits"}, pathRows),
	}
	return strings.Join(parts, "\n\n")
}

func (m *Model) renderDiscoveryDashboard() string {
	interesting := make([]string, 0, 10)
	entries := m.systemLogEntries()
	for i := len(entries) - 1; i >= 0 && len(interesting) < 10; i-- {
		ev := entries[i].Event
		switch ev.Type {
		case engine.EventHarvestDiscovery, engine.EventHarvestJSAnalysisComplete, engine.EventWAFBypassAttempt, engine.EventWAFBypassOutcome, engine.EventTimingOracleCalibrated, engine.EventSimhashCluster, engine.EventAutoFilterTriggered:
			interesting = append(interesting, entries[i].Rendered)
		}
	}
	for i := len(m.hits) - 1; i >= 0 && len(interesting) < 10; i-- {
		hit := m.hits[i]
		switch {
		case len(hit.DiscoveredParams) > 0:
			interesting = append(interesting, fmt.Sprintf("%s discovered params: %s", hit.Path, strings.Join(hit.DiscoveredParams, ", ")))
		case hit.IsEagleAlert:
			interesting = append(interesting, fmt.Sprintf("%s %s", hit.Path, hit.EagleSummary()))
		case hit.ContentDrift:
			interesting = append(interesting, fmt.Sprintf("%s content drift detected (%d -> %d bytes)", hit.Path, hit.OldSize, hit.Size))
		}
	}
	if len(interesting) == 0 {
		interesting = append(interesting, mutedStyle.Render("No discoveries yet."))
	} else {
		for i, j := 0, len(interesting)-1; i < j; i, j = i+1, j-1 {
			interesting[i], interesting[j] = interesting[j], interesting[i]
		}
	}

	contentTypes := buildTopContentTypes(m.hits, 8)
	contentRows := [][]string{}
	if len(contentTypes) > 0 {
		totalHits := len(m.hits)
		for _, row := range contentTypes {
			share := 0.0
			if totalHits > 0 {
				share = float64(row.count) / float64(totalHits) * 100
			}
			contentRows = append(contentRows, []string{
				row.label,
				strconv.Itoa(row.count),
				fmt.Sprintf("%.1f%%", share),
				strings.Repeat("█", int(math.Round(share/5))+1),
			})
		}
	}
	if len(contentRows) == 0 {
		contentRows = append(contentRows, []string{mutedStyle.Render("none"), "0", "0%", ""})
	}

	redirectRows := [][]string{}
	for i := len(m.hits) - 1; i >= 0 && len(redirectRows) < 5; i-- {
		hit := m.hits[i]
		if hit.Redirect != "" {
			redirectRows = append(redirectRows, []string{hit.Path, hit.Redirect})
		}
	}
	if len(redirectRows) == 0 {
		redirectRows = append(redirectRows, []string{mutedStyle.Render("none"), mutedStyle.Render("no redirects recorded")})
	}

	sourceCounts := map[string]int64{
		"JS":    0,
		"HTML":  0,
		"API":   0,
		"Other": 0,
	}
	for _, entry := range entries {
		ev := entry.Event
		switch ev.Type {
		case engine.EventHarvestJSAnalysisComplete:
			sourceCounts["JS"] += logEventMetadataInt64(ev.Metadata, "script_urls")
		case engine.EventHarvestParseError:
			msg := strings.ToLower(ev.Message)
			switch {
			case strings.Contains(msg, "html"):
				sourceCounts["HTML"]++
			case strings.Contains(msg, "openapi") || strings.Contains(msg, "graphql"):
				sourceCounts["API"]++
			default:
				sourceCounts["Other"]++
			}
		case engine.EventHarvestDiscovery:
			sourceCounts["Other"]++
		}
	}
	sourceRows := [][]string{
		{"JS", strconv.FormatInt(sourceCounts["JS"], 10)},
		{"HTML", strconv.FormatInt(sourceCounts["HTML"], 10)},
		{"API", strconv.FormatInt(sourceCounts["API"], 10)},
		{"Other", strconv.FormatInt(sourceCounts["Other"], 10)},
	}

	parts := []string{
		m.renderCardTable("Recent Interesting Findings", []string{"Event"}, func() [][]string {
			rows := make([][]string, 0, len(interesting))
			for _, item := range interesting {
				rows = append(rows, []string{item})
			}
			return rows
		}()),
		m.renderCardTable("Content Type Distribution", []string{"Type", "Count", "Share", "Bar"}, contentRows),
		m.renderCardTable("Redirect Chains", []string{"From", "To"}, redirectRows),
		m.renderCardTable("Harvested by Source", []string{"Source", "Count"}, sourceRows),
	}
	return strings.Join(parts, "\n\n")
}

func (m *Model) renderNetworkDashboard() string {
	proxyEvents := make([]string, 0, 5)
	rateLimitEvents := make([]string, 0, 5)
	entries := m.systemLogEntries()
	for i := len(entries) - 1; i >= 0 && (len(proxyEvents) < 5 || len(rateLimitEvents) < 5); i-- {
		ev := entries[i].Event
		switch ev.Type {
		case engine.EventProxyRotated:
			if len(proxyEvents) < 5 {
				proxyEvents = append(proxyEvents, entries[i].Rendered)
			}
		case engine.EventRateLimitHit:
			if len(rateLimitEvents) < 5 {
				rateLimitEvents = append(rateLimitEvents, entries[i].Rendered)
			}
		}
	}
	if len(proxyEvents) == 0 {
		proxyEvents = append(proxyEvents, mutedStyle.Render("No proxy rotations recorded."))
	}
	if len(rateLimitEvents) == 0 {
		rateLimitEvents = append(rateLimitEvents, mutedStyle.Render("No rate limiting events recorded."))
	}

	type durationAgg struct {
		total time.Duration
		count int64
	}
	buckets := map[string]*durationAgg{
		"2xx":   &durationAgg{},
		"3xx":   &durationAgg{},
		"4xx":   &durationAgg{},
		"5xx":   &durationAgg{},
		"other": &durationAgg{},
	}
	var bytesIn, bytesOut int64
	for _, hit := range m.hits {
		label := statusCategoryLabel(hit.StatusCode)
		bucket := buckets[label]
		if bucket == nil {
			bucket = buckets["other"]
		}
		if hit.Duration > 0 {
			bucket.total += hit.Duration
			bucket.count++
		}
		bytesIn += int64(len(hit.ResponseBytes))
		if len(hit.RequestBytes) > 0 {
			bytesOut += int64(len(hit.RequestBytes))
		} else if hit.Request != "" {
			bytesOut += int64(len(hit.Request))
		}
	}
	durationRows := [][]string{}
	for _, label := range []string{"2xx", "3xx", "4xx", "5xx", "other"} {
		bucket := buckets[label]
		avg := time.Duration(0)
		if bucket.count > 0 {
			avg = time.Duration(int64(bucket.total) / bucket.count)
		}
		durationRows = append(durationRows, []string{
			label,
			strconv.FormatInt(bucket.count, 10),
			avg.Round(time.Millisecond).String(),
		})
	}
	bandwidthRows := [][]string{
		{"Bytes received", formatBytesEstimate(bytesIn)},
		{"Bytes sent", formatBytesEstimate(bytesOut)},
		{"Estimated total", formatBytesEstimate(bytesIn + bytesOut)},
	}

	proxyRows := [][]string{
		{"Configured proxy", func() string {
			m.Engine.Config.RLock()
			defer m.Engine.Config.RUnlock()
			if strings.TrimSpace(m.Engine.Config.ProxyOut) == "" {
				return "no"
			}
			return "yes"
		}()},
		{"Rotations", strconv.FormatInt(m.totalProxyRotations, 10)},
	}

	parts := []string{
		m.renderCardTable("Network Intelligence", []string{"Signal", "Value"}, proxyRows),
		fmt.Sprintf("%s %s", mutedStyle.Render("Proxy rotation trail"), highlightStyle.Render(strings.Join(proxyEvents, "\n"))),
		fmt.Sprintf("%s %s", mutedStyle.Render("Rate limiting"), orangeStyle.Render(strings.Join(rateLimitEvents, "\n"))),
		m.renderCardTable("Average Response Time by Status Category", []string{"Category", "Samples", "Avg"}, durationRows),
		m.renderCardTable("Bandwidth Estimates", []string{"Metric", "Value"}, bandwidthRows),
	}
	return strings.Join(parts, "\n\n")
}

func (m *Model) renderTimelineDashboard() string {
	critical := make([]engine.LogEvent, 0, 20)
	for _, entry := range m.systemLogEntries() {
		ev := entry.Event
		if ev.Level == engine.LogLevelWarning || ev.Level == engine.LogLevelError {
			critical = append(critical, ev)
		}
	}
	if len(critical) > 20 {
		critical = critical[len(critical)-20:]
	}
	lines := make([]string, 0, len(critical))
	for _, ev := range critical {
		lines = append(lines, formatLogEvent(ev, relativeScanTime(m.startTime, ev.Timestamp)))
	}
	if len(lines) == 0 {
		lines = append(lines, mutedStyle.Render("No critical events yet."))
	}
	rows := make([][]string, 0, len(lines))
	for _, line := range lines {
		rows = append(rows, []string{line})
	}
	return m.renderCardTable("Critical Event Timeline", []string{"Event"}, rows)
}

func (m *Model) exportMetricsSnapshot() (string, error) {
	type snapshot struct {
		ExportedAt               time.Time         `json:"exported_at"`
		Target                   string            `json:"target"`
		Tab                      string            `json:"tab"`
		Range                    string            `json:"range"`
		CurrentRPS               int64             `json:"current_rps"`
		PeakRPS                  int64             `json:"peak_rps"`
		AverageResponseTime      time.Duration     `json:"average_response_time"`
		TotalErrors              int64             `json:"total_errors"`
		TotalRetries             int64             `json:"total_retries"`
		TotalProxyRotations      int64             `json:"total_proxy_rotations"`
		ActiveWorkers            int64             `json:"active_workers"`
		WorkerUtilizationHistory []float64         `json:"worker_utilization_history"`
		ErrorRateHistory         []float64         `json:"error_rate_history"`
		RPSHistory               []int64           `json:"rps_history"`
		QueueDepthHistory        []int             `json:"queue_depth_history"`
		RecentLogs               []engine.LogEvent `json:"recent_logs"`
		RecentHits               []engine.Result   `json:"recent_hits"`
	}

	eng := m.Engine
	target := ""
	currentRPS := int64(0)
	if eng != nil {
		target = eng.BaseURL()
		currentRPS = atomic.LoadInt64(&eng.CurrentRPS)
	}
	snap := snapshot{
		ExportedAt:               time.Now(),
		Target:                   target,
		Tab:                      dashboardTabLabel(m.dashboardTab),
		Range:                    dashboardRangeLabel(m.dashboardRangeIdx),
		CurrentRPS:               currentRPS,
		PeakRPS:                  m.peakRPS,
		AverageResponseTime:      m.avgResponseTime,
		TotalErrors:              atomic.LoadInt64(&m.totalErrors),
		TotalRetries:             atomic.LoadInt64(&m.totalRetries),
		TotalProxyRotations:      atomic.LoadInt64(&m.totalProxyRotations),
		ActiveWorkers:            atomic.LoadInt64(&m.activeWorkers),
		WorkerUtilizationHistory: sampleFloatHistory(m.workerUtilizationHistory, m.dashboardSampleLimit()),
		ErrorRateHistory:         sampleFloatHistory(m.errorRateHistory, m.dashboardSampleLimit()),
		RPSHistory:               sampleIntHistory(m.rpsHistoryFull, m.dashboardSampleLimit()),
		QueueDepthHistory: func() []int {
			limit := m.dashboardSampleLimit()
			if limit <= 0 || len(m.queueDepthHistory) == 0 {
				return nil
			}
			if len(m.queueDepthHistory) > limit {
				return append([]int(nil), m.queueDepthHistory[len(m.queueDepthHistory)-limit:]...)
			}
			return append([]int(nil), m.queueDepthHistory...)
		}(),
		RecentLogs: func() []engine.LogEvent {
			entries := m.systemLogEntries()
			if len(entries) == 0 {
				return nil
			}
			start := len(entries) - 50
			if start < 0 {
				start = 0
			}
			out := make([]engine.LogEvent, 0, len(entries)-start)
			for _, entry := range entries[start:] {
				out = append(out, entry.Event)
			}
			return out
		}(),
		RecentHits: func() []engine.Result {
			if len(m.hits) == 0 {
				return nil
			}
			start := len(m.hits) - 50
			if start < 0 {
				start = 0
			}
			return append([]engine.Result(nil), m.hits[start:]...)
		}(),
	}

	filename := fmt.Sprintf("dirfuzz-metrics-%s.json", time.Now().Format("20060102-150405"))
	file, err := os.Create(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	if err := enc.Encode(snap); err != nil {
		return "", err
	}
	return filename, nil
}

func logLevelEnabled(filters map[engine.LogLevel]bool, level engine.LogLevel) bool {
	if len(filters) == 0 {
		return true
	}
	enabled, ok := filters[level]
	return !ok || enabled
}

func logFilterMask(filters map[engine.LogLevel]bool) int {
	mask := 0
	if logLevelEnabled(filters, engine.LogLevelDebug) {
		mask |= 1 << 0
	}
	if logLevelEnabled(filters, engine.LogLevelInfo) {
		mask |= 1 << 1
	}
	if logLevelEnabled(filters, engine.LogLevelWarning) {
		mask |= 1 << 2
	}
	if logLevelEnabled(filters, engine.LogLevelError) {
		mask |= 1 << 3
	}
	if logLevelEnabled(filters, engine.LogLevelSuccess) {
		mask |= 1 << 4
	}
	return mask
}

func logCategoryIcon(category engine.LogCategory) string {
	switch category {
	case engine.LogCategorySystem:
		return "🔧"
	case engine.LogCategoryWorker:
		return "⚙️"
	case engine.LogCategoryNetwork:
		return "🌐"
	case engine.LogCategoryPlugin:
		return "🧩"
	case engine.LogCategoryDiscovery:
		return "🔍"
	case engine.LogCategoryFilter:
		return "🧹"
	default:
		return "•"
	}
}

func logCategoryStyle(category engine.LogCategory) lipgloss.Style {
	switch category {
	case engine.LogCategoryNetwork:
		return lipgloss.NewStyle().Foreground(DraculaCyan).Bold(true)
	case engine.LogCategoryDiscovery:
		return lipgloss.NewStyle().Foreground(DraculaYellow).Bold(true)
	case engine.LogCategoryFilter:
		return lipgloss.NewStyle().Foreground(DraculaPurple).Bold(true)
	case engine.LogCategoryWorker:
		return lipgloss.NewStyle().Foreground(DraculaPink).Bold(true)
	case engine.LogCategoryPlugin:
		return lipgloss.NewStyle().Foreground(DraculaOrange).Bold(true)
	default:
		return mutedStyle
	}
}

func logLevelStyle(level engine.LogLevel) lipgloss.Style {
	switch level {
	case engine.LogLevelError:
		return errorStyle
	case engine.LogLevelWarning:
		return orangeStyle
	case engine.LogLevelSuccess:
		return statusStyle
	case engine.LogLevelInfo:
		return highlightStyle
	case engine.LogLevelDebug:
		return separatorStyle
	default:
		return mutedStyle
	}
}

func (m *Model) logSearchActive(entry systemLogEntry) bool {
	term := strings.TrimSpace(strings.ToLower(m.logSearchTerm))
	if term == "" {
		return true
	}
	return strings.Contains(entry.SearchText, term)
}

func (m *Model) visibleSystemLogEntries() []systemLogEntry {
	entries := m.systemLogEntries()
	visible := make([]systemLogEntry, 0, len(entries))
	for _, entry := range entries {
		if !logLevelEnabled(m.logFilters, entry.Event.Level) {
			continue
		}
		if !m.logSearchActive(entry) {
			continue
		}
		visible = append(visible, entry)
	}
	return visible
}

func relativeScanTime(start time.Time, ts time.Time) string {
	if ts.IsZero() {
		ts = time.Now()
	}
	if start.IsZero() {
		return "+0s"
	}
	if ts.Before(start) {
		return "+0s"
	}
	return fmt.Sprintf("+%s", ts.Sub(start).Round(time.Millisecond))
}

func (m *Model) formatSystemLogEntry(entry systemLogEntry, selected bool) string {
	category := logCategoryStyle(entry.Event.Category)
	level := logLevelStyle(entry.Event.Level)
	cursor := " "
	if selected {
		cursor = selectedCursorStyle.Render("▌")
	}
	expandMark := " "
	if entry.HasDetail {
		if m.logDetailsExpanded {
			expandMark = "▼"
		} else {
			expandMark = "▶"
		}
	}
	parts := []string{
		mutedStyle.Render(entry.Relative),
		category.Render(logCategoryIcon(entry.Event.Category) + " " + string(entry.Event.Category)),
		level.Render(string(entry.Event.Level)),
		pinkStyle.Render(string(entry.Event.Type)),
	}
	message := entry.Event.Message
	if term := strings.TrimSpace(m.logSearchTerm); term != "" && strings.Contains(strings.ToLower(entry.SearchText), strings.ToLower(term)) {
		message = highlightStyle.Bold(true).Render(entry.Event.Message)
	}
	parts = append(parts, message)
	if entry.Path != "" {
		parts = append(parts, mutedStyle.Render("↩ "+entry.Path))
	}
	line := strings.Join(parts, " ")
	if m.errorPulseOn && (entry.Event.Level == engine.LogLevelError || entry.Event.Level == engine.LogLevelWarning) {
		line = errorStyle.Bold(true).Render(line)
	}
	if selected {
		line = selectedRowStyle.Render(fmt.Sprintf("%s %s %s", cursor, expandMark, line))
	} else {
		line = fmt.Sprintf("%s %s %s", cursor, expandMark, line)
	}
	return line
}

func (m *Model) renderRelatedLogsSection(selected *engine.Result) string {
	if selected == nil {
		return ""
	}
	entries := m.systemLogEntries()
	if len(entries) == 0 {
		return ""
	}
	var related []string
	for _, entry := range entries {
		if !logLevelEnabled(m.logFilters, entry.Event.Level) {
			continue
		}
		path := entry.Path
		if path == "" {
			if v, ok := entry.Event.Metadata["path"].(string); ok {
				path = v
			}
		}
		if path != selected.Path {
			continue
		}
		if selected.StatusCode == 403 && entry.Event.Type != engine.EventWAFBypassAttempt && entry.Event.Type != engine.EventWAFBypassOutcome {
			continue
		}
		related = append(related, m.formatSystemLogEntry(entry, false))
	}
	if len(related) == 0 {
		return ""
	}
	title := fmt.Sprintf(" Related Logs for %s ", selected.Path)
	if selected.StatusCode == 403 {
		title = fmt.Sprintf(" WAF Context for %s ", selected.Path)
	}
	body := strings.Join(related, "\n")
	return paneStyle.Width(max(20, m.width-2)).Render(
		lipgloss.JoinVertical(lipgloss.Left,
			renderPaneHeader(requestPaneHeaderStyle, max(10, m.width-4), title),
			separatorStyle.Render(strings.Repeat("─", max(10, m.width-4))),
			body,
		),
	)
}

func (m *Model) renderLogsPanel() string {
	if m.logViewport.Width <= 0 || m.logViewport.Height <= 0 {
		return ""
	}

	entries := m.visibleSystemLogEntries()
	lines := make([]string, 0, len(entries))
	highlighted := strings.TrimSpace(strings.ToLower(m.logSearchTerm))
	for i, entry := range entries {
		selected := i == m.logSelectedIndex
		line := m.formatSystemLogEntry(entry, selected)
		if highlighted != "" && strings.Contains(strings.ToLower(entry.SearchText), highlighted) {
			line = highlightStyle.Render(line)
		}
		lines = append(lines, line)
		if m.logDetailsExpanded && entry.HasDetail {
			detailParts := []string{}
			if entry.Path != "" {
				detailParts = append(detailParts, mutedStyle.Render("    path="+entry.Path))
			}
			if len(entry.Event.Metadata) > 0 {
				keys := make([]string, 0, len(entry.Event.Metadata))
				for k := range entry.Event.Metadata {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				kv := make([]string, 0, len(keys))
				for _, k := range keys {
					kv = append(kv, fmt.Sprintf("%s=%v", k, entry.Event.Metadata[k]))
				}
				detailParts = append(detailParts, mutedStyle.Render("    "+strings.Join(kv, "  ")))
			}
			if len(detailParts) > 0 {
				lines = append(lines, detailParts...)
			}
		}
	}
	if len(lines) == 0 {
		lines = append(lines, mutedStyle.Render("No system logs match the current filters."))
	}

	if m.logViewport.Height <= 0 {
		m.logViewport.Height = 1
	}
	maxOffset := max(0, len(lines)-m.logViewport.Height)
	if m.logPanelAutoScroll || m.logPanelScrollOffset < 0 || m.logPanelScrollOffset > maxOffset {
		m.logPanelScrollOffset = maxOffset
		m.logPanelAutoScroll = true
	}
	if m.logSelectedIndex < 0 {
		m.logSelectedIndex = 0
	}
	if len(entries) > 0 && m.logSelectedIndex >= len(entries) {
		m.logSelectedIndex = len(entries) - 1
	}
	start := m.logPanelScrollOffset
	if m.logSelectedIndex >= 0 && m.logSelectedIndex < len(entries) && len(lines) > 0 {
		selectedLine := 0
		for i := 0; i < m.logSelectedIndex && i < len(entries); i++ {
			selectedLine++
			if m.logDetailsExpanded && entries[i].HasDetail {
				if entries[i].Path != "" {
					selectedLine++
				}
				if len(entries[i].Event.Metadata) > 0 {
					selectedLine++
				}
			}
		}
		if selectedLine < start {
			start = selectedLine
		}
		if selectedLine >= start+m.logViewport.Height {
			start = selectedLine - m.logViewport.Height + 1
		}
	}
	if start > maxOffset {
		start = maxOffset
	}
	m.logPanelScrollOffset = start
	end := start + m.logViewport.Height
	if end > len(lines) {
		end = len(lines)
	}
	if start > end {
		start = end
	}
	cacheKey := fmt.Sprintf("%d:%d:%d:%d:%d:%t:%s:%t", start, m.logViewport.Height, m.logViewport.Width, len(lines), logFilterMask(m.logFilters), m.state == StateLogsPanel, m.logSearchTerm, m.logDetailsExpanded)
	if !m.logPanelDirty && m.logPanelCacheValid && m.logPanelCacheKey == cacheKey {
		return m.logPanelCache
	}
	content := strings.Join(lines[start:end], "\n")
	m.logViewport.SetContent(content)
	headerLabel := fmt.Sprintf(" %s System Logs ", logCategoryIcon(engine.LogCategorySystem))
	if m.logDetailsExpanded {
		headerLabel += mutedStyle.Render(" [x collapse details]")
	} else {
		headerLabel += mutedStyle.Render(" [x expand details]")
	}
	if term := strings.TrimSpace(m.logSearchTerm); term != "" {
		headerLabel += mutedStyle.Render(fmt.Sprintf(" [search: %s]", term))
	}
	panelStyle := paneStyle
	if m.state == StateLogsPanel {
		panelStyle = paneActiveStyle
	}
	if m.errorPulseOn {
		panelStyle = panelStyle.BorderForeground(DraculaRed)
	}
	panelWidth := m.width - 2
	if panelWidth < 20 {
		panelWidth = 20
	}
	header := renderPaneHeader(requestPaneHeaderStyle, m.logViewport.Width, headerLabel)
	rendered := panelStyle.Width(panelWidth).Height(m.logPanelHeight).Render(
		lipgloss.JoinVertical(lipgloss.Top,
			header,
			separatorStyle.Render(strings.Repeat("─", m.logViewport.Width)),
			m.logViewport.View(),
		),
	)
	m.cacheLogPanel(rendered, cacheKey)
	return rendered
}

func (m *Model) cacheLogPanel(content string, key string) {
	m.logPanelCache = content
	m.logPanelCacheKey = key
	m.logPanelCacheValid = true
	m.logPanelDirty = false
}

func (m *Model) toggleDashboardView() {
	if m.state == StateDashboard {
		m.state = StateList
		m.renderListView()
		return
	}
	m.state = StateDashboard
	m.renderDashboardView()
}

func (m *Model) cycleMetricsView() {
	switch m.state {
	case StateList:
		if m.showLogsPanel {
			m.showLogsPanel = false
			m.state = StateList
			m.renderListView()
			return
		}
		m.state = StateDashboard
		m.renderDashboardView()
	case StateDashboard:
		m.showLogsPanel = true
		m.previousState = StateList
		m.state = StateLogsPanel
		m.logPanelAutoScroll = true
		m.logPanelScrollOffset = max(0, len(m.systemLogEntries())-m.logViewport.Height)
		m.renderListView()
	case StateLogsPanel:
		m.showLogsPanel = false
		m.state = StateList
		m.renderListView()
	default:
		m.toggleDashboardView()
	}
}

func (m *Model) toggleLogsPanel() {
	m.showLogsPanel = !m.showLogsPanel
	if m.showLogsPanel {
		m.previousState = m.state
		if m.state == StateList {
			m.state = StateLogsPanel
		}
		m.logPanelAutoScroll = true
		m.logPanelScrollOffset = max(0, len(m.systemLogEntries())-m.logViewport.Height)
		m.renderLogsPanel()
		return
	}
	if m.state == StateLogsPanel {
		if m.previousState == StateLogsPanel || m.previousState == 0 {
			m.state = StateList
		} else {
			m.state = m.previousState
		}
		switch m.state {
		case StateList:
			m.renderListView()
		case StateDashboard:
			m.renderDashboardView()
		}
	}
}

func renderSparkline(values []int64, width int) string {
	if width <= 0 {
		return ""
	}
	if len(values) == 0 {
		return strings.Repeat("▁", width)
	}

	if len(values) > width {
		values = values[len(values)-width:]
	}

	blocks := []rune("▁▂▃▄▅▆▇█")
	minV, maxV := values[0], values[0]
	for _, v := range values {
		if v < minV {
			minV = v
		}
		if v > maxV {
			maxV = v
		}
	}

	var out strings.Builder
	for _, v := range values {
		idx := 0
		if maxV > minV {
			idx = int((v - minV) * int64(len(blocks)-1) / (maxV - minV))
		}
		out.WriteRune(blocks[idx])
	}

	if out.Len() < width {
		return strings.Repeat("▁", width-out.Len()) + out.String()
	}

	return out.String()
}

func clampFloat(v, minV, maxV float64) float64 {
	if v < minV {
		return minV
	}
	if v > maxV {
		return maxV
	}
	return v
}

func hexToRGB(hex string) (int64, int64, int64) {
	hex = strings.TrimPrefix(hex, "#")
	if len(hex) != 6 {
		return 255, 255, 255
	}
	r, errR := strconv.ParseInt(hex[0:2], 16, 64)
	g, errG := strconv.ParseInt(hex[2:4], 16, 64)
	b, errB := strconv.ParseInt(hex[4:6], 16, 64)
	if errR != nil || errG != nil || errB != nil {
		return 255, 255, 255
	}
	return r, g, b
}

func lerpHexColor(startHex, endHex string, t float64) string {
	t = clampFloat(t, 0, 1)
	sr, sg, sb := hexToRGB(startHex)
	er, eg, eb := hexToRGB(endHex)

	r := int64(float64(sr) + (float64(er-sr) * t))
	g := int64(float64(sg) + (float64(eg-sg) * t))
	b := int64(float64(sb) + (float64(eb-sb) * t))

	return fmt.Sprintf("#%02x%02x%02x", r, g, b)
}

func progressFillColor(progressPct float64) lipgloss.Color {
	progressPct = clampFloat(progressPct, 0, 100)
	if progressPct <= 70 {
		t := progressPct / 70.0
		return lipgloss.Color(lerpHexColor(string(DraculaGreen), string(DraculaYellow), t))
	}
	t := (progressPct - 70.0) / 30.0
	return lipgloss.Color(lerpHexColor(string(DraculaYellow), string(DraculaOrange), t))
}

func renderProgressBar(width int, progressPct float64, style lipgloss.Style) string {
	if width < 1 {
		return ""
	}

	progressPct = clampFloat(progressPct, 0, 100)
	fillUnits := (progressPct / 100.0) * float64(width)
	full := int(fillUnits)
	remainder := fillUnits - float64(full)

	if full > width {
		full = width
	}

	var fill strings.Builder
	if full > 0 {
		fill.WriteString(strings.Repeat("█", full))
	}

	partialAdded := false
	if full < width {
		partialIdx := int(remainder * 8)
		if partialIdx > 0 {
			partialRunes := []rune("▏▎▍▌▋▊▉")
			if partialIdx > len(partialRunes) {
				partialIdx = len(partialRunes)
			}
			fill.WriteRune(partialRunes[partialIdx-1])
			partialAdded = true
		}
	}

	used := full
	if partialAdded {
		used++
	}
	if used > width {
		used = width
	}

	empty := strings.Repeat("░", width-used)

	return style.Render(fill.String()) + mutedStyle.Render(empty)
}

type CommandSuggestion struct {
	Text        string
	Description string
}

func suggestionDropdownWidth(suggestions []CommandSuggestion, maxWidth int) int {
	if maxWidth < 16 {
		return 16
	}

	width := 20
	for _, s := range suggestions {
		candidate := len([]rune(s.Text)) + len([]rune(s.Description)) + 6
		if candidate > width {
			width = candidate
		}
	}

	if width > maxWidth {
		width = maxWidth
	}
	if width < 16 {
		width = 16
	}

	return width
}

func renderSuggestionDropdown(suggestions []CommandSuggestion, selectedIdx, width int) string {
	if len(suggestions) == 0 {
		return ""
	}

	if width < 16 {
		width = 16
	}

	maxVisible := 6
	start := 0
	if selectedIdx >= maxVisible {
		start = selectedIdx - maxVisible + 1
	}
	end := start + maxVisible
	if end > len(suggestions) {
		end = len(suggestions)
	}

	innerWidth := width - 4
	if innerWidth < 1 {
		innerWidth = 1
	}

	var lines []string
	for i := start; i < end; i++ {
		prefix := "  "
		style := autocompleteItemStyle
		if i == selectedIdx {
			prefix = "▸ "
			style = autocompleteSelectedStyle
		}

		s := suggestions[i]
		leftText := prefix + s.Text

		content := leftText
		if s.Description != "" {
			targetLeftWidth := 15
			actualLeftWidth := len([]rune(leftText))
			pad := targetLeftWidth - actualLeftWidth
			if pad < 2 {
				pad = 2
			}
			content += strings.Repeat(" ", pad) + mutedStyle.Render(s.Description)
		}

		line := style.Width(innerWidth).Render(content)
		lines = append(lines, line)
	}

	return autocompleteBoxStyle.Width(width).Render(strings.Join(lines, "\n"))
}

// CommandDef defines a TUI command.
type CommandDef struct {
	Name        string
	Description string
	Args        string
	Handler     func(m *Model, args string) string
}

// TickMsg is sent on each tick.
type TickMsg time.Time

// ViewState defines which screen the user is looking at
type ViewState int

const (
	StateList ViewState = iota
	StateDashboard
	StateLogsPanel
	StateDetail
	StateHexView
	StateDiffView
	StateCommand
	StateRepeater
)

type DashboardTab int

const (
	DashboardTabPerformance DashboardTab = iota
	DashboardTabErrors
	DashboardTabDiscovery
	DashboardTabNetwork
	DashboardTabTimeline
)

type DashboardRange int

const (
	DashboardRange30s DashboardRange = iota
	DashboardRange5m
	DashboardRangeAll
)

// RepeaterResultMsg is the message returned after a repeater request.
type RepeaterResultMsg struct {
	SessionID   int
	RawResponse *httpclient.RawResponse
	Err         error
	Duration    time.Duration
}

type RepeaterHistoryEntry struct {
	Request    string
	Response   string
	StatusCode int
	Duration   time.Duration
}

type RepeaterSession struct {
	ID           int
	Label        string
	Target       string
	Request      string
	Response     string
	HasError     bool
	Sending      bool
	LastStatus   int
	LastDuration time.Duration
	LastRaw      []byte
	CancelFn     context.CancelFunc
	History      []RepeaterHistoryEntry
	HistoryIdx   int
}

// Model is the BubbleTea model for the TUI.
type Model struct {
	Engine                   *engine.Engine
	resultsCh                <-chan engine.Result
	logEventsCh              <-chan engine.LogEvent
	viewport                 viewport.Model
	logViewport              viewport.Model
	textInput                textinput.Model
	logs                     []string
	logLineHits              []*engine.Result
	systemLogs               systemLogRingBuffer
	logFilters               map[engine.LogLevel]bool
	rpsHistoryFull           []int64
	workerUtilizationHistory []float64
	errorRateHistory         []float64
	queueDepthHistory        []int
	totalErrors              int64
	totalRetries             int64
	totalProxyRotations      int64
	peakRPS                  int64
	avgResponseTime          time.Duration
	activeWorkers            int64
	responseSamples          int64
	lastMetricsTick          time.Time
	lastErrorCount           int64
	dashboardTab             DashboardTab
	dashboardRangeIdx        int
	dashboardDirty           bool
	dashboardCache           string
	dashboardCacheValid      bool
	logPanelDirty            bool
	logPanelAutoScroll       bool
	logPanelScrollOffset     int
	logEventsSinceRender     int
	logPanelCache            string
	logPanelCacheKey         string
	logPanelCacheValid       bool
	logSearchTerm            string
	logDetailsExpanded       bool
	logSelectedIndex         int
	errorPulseOn             bool
	errorPulseUntil          time.Time
	hits                     []engine.Result // Keep track of hits to view them later
	rpsHistory               []int64
	commandMode              bool
	width, height            int
	ready                    bool

	// View State
	state ViewState

	// List View Selection
	selectedIndex int
	listScrollIdx int // How far down the list we have scrolled
	atBottom      bool

	// Detail Viewports
	reqViewport       viewport.Model
	resViewport       viewport.Model
	hexViewport       viewport.Model
	diffLeftViewport  viewport.Model
	diffRightViewport viewport.Model
	cmdOutput         []string
	cmdViewport       viewport.Model

	// Repeater state
	repeaterInput         textarea.Model
	repeaterRespVp        viewport.Model
	repeaterTarget        string
	repeaterSending       bool
	repeaterFocusReq      bool
	repeaterLastStatus    int
	repeaterLastDuration  time.Duration
	repeaterLastRaw       []byte
	repeaterCancelFn      context.CancelFunc
	repeaterHistory       []RepeaterHistoryEntry
	repeaterHistoryIdx    int
	repeaterSessions      []RepeaterSession
	activeRepeaterIdx     int
	nextRepeaterSessionID int

	// Hex view state
	hexSelectedIndex int
	hexTarget        HexViewTarget

	// Diff view state
	diffReference   *DiffSample
	diffCurrent     *DiffSample
	diffCompactOnly bool

	// Telemetry display
	startTime       time.Time
	lastProgressPct float64
	cachedFillStyle lipgloss.Style
	footerBarStyle  lipgloss.Style

	// Command history
	cmdHistory    []string
	cmdHistoryIdx int

	// Available commands
	commands []CommandDef

	// Autocomplete state
	suggestions    []CommandSuggestion
	selectedSugIdx int

	// State
	quitting          bool
	pendingTarget     string
	previousState     ViewState
	commandPulseOn    bool
	logsChanged       bool
	showLogsPanel     bool
	logPanelHeight    int
	historyMode       string
	historyUIPath     string
	anomalyFilterOnly bool
	uiStateDirty      bool
	uiStateDirtyAt    time.Time
	logIndexByKey     map[string]int
	hitIndexByKey     map[string]int
	markedHitKeys     map[string]bool

	// Status messages
	statusMessage string
	statusExpiry  time.Time
}

// NewModel initializes the TUI model.
func NewModel(eng *engine.Engine, resultsCh <-chan engine.Result, logEventsCh <-chan engine.LogEvent) Model {
	ti := textinput.New()
	ti.Prompt = ""
	ti.Placeholder = "Type ':' to enter command mode, 'q' to quit, 'Enter' on a hit to view details"
	ti.CharLimit = 256
	ti.Width = 80

	vp := viewport.New(80, 20)
	vp.SetContent("")
	logVp := viewport.New(80, 10)
	logVp.SetContent("")

	reqVp := viewport.New(40, 20)
	resVp := viewport.New(40, 20)
	hexVp := viewport.New(80, 20)
	diffLeftVp := viewport.New(40, 20)
	diffRightVp := viewport.New(40, 20)
	cmdVp := viewport.New(80, 10)

	ta := textarea.New()
	ta.Placeholder = "GET / HTTP/1.1..."
	ta.ShowLineNumbers = false
	ta.FocusedStyle.Base = lipgloss.NewStyle()
	ta.BlurredStyle.Base = lipgloss.NewStyle()
	ta.Prompt = ""
	ta.FocusedStyle.CursorLine = lipgloss.NewStyle()

	repeaterVp := viewport.New(40, 20)

	m := Model{
		Engine:            eng,
		resultsCh:         resultsCh,
		logEventsCh:       logEventsCh,
		viewport:          vp,
		logViewport:       logVp,
		reqViewport:       reqVp,
		resViewport:       resVp,
		hexViewport:       hexVp,
		diffLeftViewport:  diffLeftVp,
		diffRightViewport: diffRightVp,
		diffCompactOnly:   true,
		cmdViewport:       cmdVp,
		textInput:         ti,
		logs:              []string{},
		logLineHits:       []*engine.Result{},
		systemLogs:        newSystemLogRingBuffer(maxLogEntries),
		logFilters: map[engine.LogLevel]bool{
			engine.LogLevelDebug:   true,
			engine.LogLevelInfo:    true,
			engine.LogLevelWarning: true,
			engine.LogLevelError:   true,
			engine.LogLevelSuccess: true,
		},
		rpsHistoryFull:           []int64{},
		workerUtilizationHistory: []float64{},
		errorRateHistory:         []float64{},
		queueDepthHistory:        []int{},
		hits:                     []engine.Result{},
		rpsHistory:               []int64{},
		cmdOutput:                []string{},
		startTime:                time.Now(),
		state:                    StateList,
		commandPulseOn:           true,
		atBottom:                 true,
		showLogsPanel:            false,
		logPanelHeight:           8,
		logPanelAutoScroll:       true,
		logSearchTerm:            "",
		logDetailsExpanded:       false,
		logSelectedIndex:         0,
		logIndexByKey:            make(map[string]int),
		hitIndexByKey:            make(map[string]int),
		markedHitKeys:            make(map[string]bool),
		errorPulseOn:             false,
		dashboardTab:             DashboardTabPerformance,
		dashboardRangeIdx:        int(DashboardRange30s),
		dashboardDirty:           true,
		repeaterInput:            ta,
		repeaterRespVp:           repeaterVp,
		repeaterFocusReq:         true,
		repeaterLastRaw:          nil,
		nextRepeaterSessionID:    1,
		lastProgressPct:          -1,
	}
	m.initCommands()
	return m
}

// initCommands registers all available TUI commands.
func (m *Model) initCommands() {
	m.commands = []CommandDef{
		{Name: "help", Description: "Show all commands", Args: "", Handler: func(m *Model, args string) string {
			var sb strings.Builder
			sb.WriteString(pinkStyle.Render("=== DirFuzz Commands ===") + "\n")
			for _, cmd := range m.commands {
				line := fmt.Sprintf("  :%s", cmd.Name)
				if cmd.Args != "" {
					line += " " + cmd.Args
				}
				sb.WriteString(highlightStyle.Render(line) + " - " + mutedStyle.Render(cmd.Description) + "\n")
			}
			return sb.String()
		}},
		{Name: "mark", Description: "Mark the selected hit as interesting", Args: "", Handler: func(m *Model, args string) string {
			return m.setSelectedHitMarked(true)
		}},
		{Name: "unmark", Description: "Remove the interesting mark from the selected hit", Args: "", Handler: func(m *Model, args string) string {
			return m.setSelectedHitMarked(false)
		}},
		{Name: "togglemark", Description: "Toggle the interesting mark on the selected hit", Args: "", Handler: func(m *Model, args string) string {
			return m.toggleSelectedHitMarked()
		}},
		{Name: "anomalies", Description: "Toggle or set anomaly-only hit view", Args: "[on|off|toggle]", Handler: func(m *Model, args string) string {
			switch strings.ToLower(strings.TrimSpace(args)) {
			case "", "toggle":
				return m.toggleAnomalyFilterOnly()
			case "on":
				return m.setAnomalyFilterOnly(true)
			case "off":
				return m.setAnomalyFilterOnly(false)
			default:
				return errorStyle.Render("Usage: :anomalies [on|off|toggle]")
			}
		}},
		{Name: "metrics", Description: "Open or close the live dashboard", Args: "", Handler: func(m *Model, args string) string {
			m.toggleDashboardView()
			if m.state == StateDashboard {
				return statusStyle.Render("[*] Dashboard opened")
			}
			return statusStyle.Render("[*] Dashboard closed")
		}},
		{Name: "logs", Description: "Search, filter, clear, or export log events", Args: "<filter|search|clear|export> ...", Handler: func(m *Model, args string) string {
			parts := strings.Fields(strings.TrimSpace(args))
			if len(parts) == 0 {
				return errorStyle.Render("Usage: :logs <filter|search|clear|export> ...")
			}
			switch strings.ToLower(parts[0]) {
			case "filter":
				if len(parts) < 2 {
					return errorStyle.Render("Usage: :logs filter <level|all|none>")
				}
				tokens := strings.Split(parts[1], ",")
				changed := []string{}
				for _, token := range tokens {
					level := strings.ToLower(strings.TrimSpace(token))
					switch level {
					case "debug":
						m.logFilters[engine.LogLevelDebug] = !m.logFilters[engine.LogLevelDebug]
						changed = append(changed, "debug")
					case "info":
						m.logFilters[engine.LogLevelInfo] = !m.logFilters[engine.LogLevelInfo]
						changed = append(changed, "info")
					case "warning", "warn":
						m.logFilters[engine.LogLevelWarning] = !m.logFilters[engine.LogLevelWarning]
						changed = append(changed, "warning")
					case "error":
						m.logFilters[engine.LogLevelError] = !m.logFilters[engine.LogLevelError]
						changed = append(changed, "error")
					case "success":
						m.logFilters[engine.LogLevelSuccess] = !m.logFilters[engine.LogLevelSuccess]
						changed = append(changed, "success")
					case "all":
						m.logFilters[engine.LogLevelDebug] = true
						m.logFilters[engine.LogLevelInfo] = true
						m.logFilters[engine.LogLevelWarning] = true
						m.logFilters[engine.LogLevelError] = true
						m.logFilters[engine.LogLevelSuccess] = true
						changed = append(changed, "all")
					case "none":
						m.logFilters[engine.LogLevelDebug] = false
						m.logFilters[engine.LogLevelInfo] = false
						m.logFilters[engine.LogLevelWarning] = false
						m.logFilters[engine.LogLevelError] = false
						m.logFilters[engine.LogLevelSuccess] = false
						changed = append(changed, "none")
					default:
						return errorStyle.Render("Usage: :logs filter <debug|info|warning|error|success|all|none>")
					}
				}
				m.logPanelDirty = true
				m.dashboardDirty = true
				m.renderLogsPanel()
				return statusStyle.Render(fmt.Sprintf("[*] Logs filter updated: %s", strings.Join(changed, ", ")))
			case "search":
				term := strings.TrimSpace(strings.Join(parts[1:], " "))
				m.logSearchTerm = term
				m.logSelectedIndex = 0
				m.logPanelAutoScroll = true
				m.logPanelDirty = true
				m.dashboardDirty = true
				if !m.showLogsPanel {
					m.toggleLogsPanel()
				} else if m.state != StateLogsPanel {
					m.previousState = m.state
					m.state = StateLogsPanel
					m.renderLogsPanel()
				}
				return statusStyle.Render(fmt.Sprintf("[*] Log search set to %q", term))
			case "clear":
				m.clearScanLogs()
				m.renderLogsPanel()
				return statusStyle.Render("[*] Log buffer cleared")
			case "export":
				if len(parts) < 2 {
					return errorStyle.Render("Usage: :logs export <file>")
				}
				file := strings.TrimSpace(strings.Join(parts[1:], " "))
				if err := m.exportLogsToFile(file); err != nil {
					return errorStyle.Render(fmt.Sprintf("Log export failed: %v", err))
				}
				return statusStyle.Render(fmt.Sprintf("[*] Logs exported to %s", file))
			default:
				return errorStyle.Render("Usage: :logs <filter|search|clear|export> ...")
			}
		}},
		{Name: "spider", Description: "Toggle dynamic HTML/JS scraping", Args: "", Handler: func(m *Model, args string) string {
			m.Engine.Config.RLock()
			current := m.Engine.Config.Spidering
			m.Engine.Config.RUnlock()
			m.Engine.Config.Lock()
			m.Engine.Config.Spidering = !current
			m.Engine.Config.Unlock()
			m.Engine.RefreshConfigSnapshot()
			if !current {
				return statusStyle.Render("[*] Spidering enabled (dynamic link extraction)")
			}
			return orangeStyle.Render("[*] Spidering disabled")
		}},
		{Name: "pause", Description: "Pause/resume scanning", Args: "", Handler: func(m *Model, args string) string {
			m.Engine.Config.RLock()
			p := m.Engine.Config.IsPaused
			m.Engine.Config.RUnlock()
			m.Engine.SetPaused(!p)
			if p {
				return statusStyle.Render("[*] Scan resumed")
			}
			return orangeStyle.Render("[*] Scan paused")
		}},
		{Name: "threads", Description: "Set worker count", Args: "<n>", Handler: func(m *Model, args string) string {
			n, err := strconv.Atoi(strings.TrimSpace(args))
			if err != nil || n < 1 {
				return errorStyle.Render("Usage: :threads <number>")
			}
			m.Engine.SetWorkerCount(n)
			return statusStyle.Render(fmt.Sprintf("[*] Workers set to %d", n))
		}},
		{Name: "delay", Description: "Set delay (ms)", Args: "<ms>", Handler: func(m *Model, args string) string {
			ms, err := strconv.Atoi(strings.TrimSpace(args))
			if err != nil || ms < 0 {
				return errorStyle.Render("Usage: :delay <milliseconds>")
			}
			m.Engine.SetDelay(time.Duration(ms) * time.Millisecond)
			return statusStyle.Render(fmt.Sprintf("[*] Delay set to %dms", ms))
		}},
		{Name: "rps", Description: "Set requests per second (0=unlimited)", Args: "<n>", Handler: func(m *Model, args string) string {
			n, err := strconv.Atoi(strings.TrimSpace(args))
			if err != nil || n < 0 {
				return errorStyle.Render("Usage: :rps <number>")
			}
			m.Engine.SetRPS(n)
			if n == 0 {
				return statusStyle.Render("[*] RPS: unlimited")
			}
			return statusStyle.Render(fmt.Sprintf("[*] RPS limit set to %d", n))
		}},
		{Name: "ua", Description: "Change User-Agent", Args: "<string>", Handler: func(m *Model, args string) string {
			if strings.TrimSpace(args) == "" {
				return errorStyle.Render("Usage: :ua <user-agent>")
			}
			m.Engine.UpdateUserAgent(strings.TrimSpace(args))
			return statusStyle.Render("[*] User-Agent updated")
		}},
		{Name: "header", Description: "Add header (key:value)", Args: "<key:value>", Handler: func(m *Model, args string) string {
			parts := strings.SplitN(strings.TrimSpace(args), ":", 2)
			if len(parts) != 2 {
				return errorStyle.Render("Usage: :header Key:Value")
			}
			m.Engine.AddHeader(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
			return statusStyle.Render(fmt.Sprintf("[*] Header set: %s: %s", parts[0], parts[1]))
		}},
		{Name: "rmheader", Description: "Remove header", Args: "<key>", Handler: func(m *Model, args string) string {
			if args == "" {
				return errorStyle.Render("Usage: :rmheader <key>")
			}
			m.Engine.RemoveHeader(strings.TrimSpace(args))
			return statusStyle.Render(fmt.Sprintf("[*] Header removed: %s", args))
		}},
		{Name: "addcode", Description: "Add match status code", Args: "<code>", Handler: func(m *Model, args string) string {
			code, err := strconv.Atoi(strings.TrimSpace(args))
			if err != nil {
				return errorStyle.Render("Usage: :addcode <code>")
			}
			m.Engine.AddMatchCode(code)
			return statusStyle.Render(fmt.Sprintf("[*] Added match code: %d", code))
		}},
		{Name: "rmcode", Description: "Remove match status code", Args: "<code>", Handler: func(m *Model, args string) string {
			code, err := strconv.Atoi(strings.TrimSpace(args))
			if err != nil {
				return errorStyle.Render("Usage: :rmcode <code>")
			}
			m.Engine.RemoveMatchCode(code)
			return statusStyle.Render(fmt.Sprintf("[*] Removed match code: %d", code))
		}},
		{Name: "filter", Description: "Add filtered size", Args: "<size>", Handler: func(m *Model, args string) string {
			size, err := strconv.Atoi(strings.TrimSpace(args))
			if err != nil {
				return errorStyle.Render("Usage: :filter <size>")
			}
			m.Engine.AddFilterSize(size)
			return statusStyle.Render(fmt.Sprintf("[*] Filtering size: %d", size))
		}},
		{Name: "rmfilter", Description: "Remove filtered size", Args: "<size>", Handler: func(m *Model, args string) string {
			size, err := strconv.Atoi(strings.TrimSpace(args))
			if err != nil {
				return errorStyle.Render("Usage: :rmfilter <size>")
			}
			m.Engine.RemoveFilterSize(size)
			return statusStyle.Render(fmt.Sprintf("[*] Removed filter size: %d", size))
		}},
		{Name: "addext", Description: "Add extension", Args: "<ext>", Handler: func(m *Model, args string) string {
			ext := strings.TrimSpace(args)
			if ext == "" {
				return errorStyle.Render("Usage: :addext <extension>")
			}
			m.Engine.AddExtension(ext)
			return statusStyle.Render(fmt.Sprintf("[*] Added extension: %s", ext))
		}},
		{Name: "rmext", Description: "Remove extension", Args: "<ext>", Handler: func(m *Model, args string) string {
			ext := strings.TrimSpace(args)
			if ext == "" {
				return errorStyle.Render("Usage: :rmext <extension>")
			}
			m.Engine.RemoveExtension(ext)
			return statusStyle.Render(fmt.Sprintf("[*] Removed extension: %s", ext))
		}},
		{Name: "mutate", Description: "Toggle mutation", Args: "", Handler: func(m *Model, args string) string {
			m.Engine.Config.RLock()
			current := m.Engine.Config.Mutate
			m.Engine.Config.RUnlock()
			m.Engine.SetMutation(!current)
			if !current {
				return statusStyle.Render("[*] Mutation enabled")
			}
			return orangeStyle.Render("[*] Mutation disabled")
		}},
		{Name: "wordlist", Description: "Change wordlist", Args: "<path>", Handler: func(m *Model, args string) string {
			path := strings.TrimSpace(args)
			if path == "" {
				return errorStyle.Render("Usage: :wordlist <path>")
			}
			if _, err := os.Stat(path); err != nil {
				return errorStyle.Render(fmt.Sprintf("Error: %v", err))
			}
			m.Engine.Config.Lock()
			m.Engine.Config.WordlistPath = path
			m.Engine.Config.Unlock()
			m.Engine.RefreshConfigSnapshot()
			return statusStyle.Render(fmt.Sprintf("[*] Wordlist queued: %s (run :restart to apply)", path))
		}},
		{Name: "changeurl", Description: "Change target URL", Args: "<url>", Handler: func(m *Model, args string) string {
			targetURL := strings.TrimSpace(args)
			if targetURL == "" {
				return errorStyle.Render("Usage: :changeurl <url>")
			}
			parsed, err := url.Parse(targetURL)
			if err != nil {
				return errorStyle.Render(fmt.Sprintf("Error: invalid target URL: %v", err))
			}
			if parsed.Scheme == "" || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
				return errorStyle.Render("Error: invalid target URL: must be http(s)://host")
			}
			m.pendingTarget = targetURL
			return statusStyle.Render(fmt.Sprintf("[*] Target URL queued: %s (run :restart to apply)", targetURL))
		}},
		{Name: "methods", Description: "Set HTTP methods (comma-separated, empty to clear)", Args: "<methods>", Handler: func(m *Model, args string) string {
			arg := strings.TrimSpace(args)
			if arg == "" {
				m.Engine.Config.Lock()
				m.Engine.Config.Methods = []string{}
				m.Engine.Config.Unlock()
				m.Engine.RefreshConfigSnapshot()
				return statusStyle.Render("[*] Methods cleared (run :restart to apply)")
			}
			parts := strings.Split(arg, ",")
			methods := make([]string, 0, len(parts))
			for _, p := range parts {
				p = strings.ToUpper(strings.TrimSpace(p))
				if p == "" {
					continue
				}
				switch p {
				case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE":
					methods = append(methods, p)
				default:
					return errorStyle.Render(fmt.Sprintf("Unsupported HTTP method: %s", p))
				}
			}
			m.Engine.Config.Lock()
			m.Engine.Config.Methods = methods
			m.Engine.Config.Unlock()
			m.Engine.RefreshConfigSnapshot()
			return statusStyle.Render(fmt.Sprintf("[*] Methods queued: %s (run :restart to apply)", strings.Join(methods, ",")))
		}},
		{Name: "restart", Description: "Restart scan", Args: "", Handler: func(m *Model, args string) string {
			if m.pendingTarget != "" {
				if err := m.Engine.SetTarget(m.pendingTarget); err != nil {
					return errorStyle.Render(fmt.Sprintf("Error applying pending target URL: %v", err))
				}
				m.pendingTarget = ""
			}
			if err := m.Engine.Restart(); err != nil {
				return errorStyle.Render(fmt.Sprintf("Error: %v", err))
			}
			if m.historyAppendEnabled() {
				m.resetAfterRestartPreservingHistory()
			} else {
				m.clearScanLogs()
			}
			return statusStyle.Render("[*] Scan restarted")
		}},
		{Name: "copy-request", Description: "Copy active repeater request to the clipboard", Args: "", Handler: func(m *Model, args string) string {
			if err := m.copyRepeaterRequest(); err != nil {
				return errorStyle.Render(fmt.Sprintf("Copy request failed: %v", err))
			}
			return statusStyle.Render("[*] Repeater request copied to clipboard")
		}},
		{Name: "copy-response", Description: "Copy active repeater response to the clipboard", Args: "", Handler: func(m *Model, args string) string {
			if err := m.copyRepeaterResponse(); err != nil {
				return errorStyle.Render(fmt.Sprintf("Copy response failed: %v", err))
			}
			return statusStyle.Render("[*] Repeater response copied to clipboard")
		}},
		{Name: "copy-both", Description: "Copy active repeater request and response", Args: "", Handler: func(m *Model, args string) string {
			if err := m.copyRepeaterBoth(); err != nil {
				return errorStyle.Render(fmt.Sprintf("Copy request/response failed: %v", err))
			}
			return statusStyle.Render("[*] Repeater request and response copied to clipboard")
		}},
		{Name: "copy-curl", Description: "Copy the active repeater request as curl", Args: "", Handler: func(m *Model, args string) string {
			if err := m.copyRepeaterCurl(); err != nil {
				return errorStyle.Render(fmt.Sprintf("Copy curl failed: %v", err))
			}
			return statusStyle.Render("[*] Repeater curl command copied to clipboard")
		}},
		{Name: "export-request", Description: "Export the active repeater request to a file", Args: "[file]", Handler: func(m *Model, args string) string {
			path, err := m.exportRepeaterRequest(strings.TrimSpace(args))
			if err != nil {
				return errorStyle.Render(fmt.Sprintf("Export request failed: %v", err))
			}
			return statusStyle.Render(fmt.Sprintf("[*] Repeater request exported to %s", path))
		}},
		{Name: "config", Description: "Show current config", Args: "", Handler: func(m *Model, args string) string {
			m.Engine.Config.RLock()
			ua := m.Engine.Config.UserAgent
			delay := m.Engine.Config.Delay
			headers := make(map[string]string, len(m.Engine.Config.Headers))
			for k, v := range m.Engine.Config.Headers {
				headers[k] = v
			}

			filters := make([]int, 0, len(m.Engine.Config.FilterSizes))
			for size := range m.Engine.Config.FilterSizes {
				filters = append(filters, size)
			}

			matchCodes := make([]int, 0, len(m.Engine.Config.MatchCodes))
			for code := range m.Engine.Config.MatchCodes {
				matchCodes = append(matchCodes, code)
			}

			exts := make([]string, len(m.Engine.Config.Extensions))
			copy(exts, m.Engine.Config.Extensions)
			methods := make([]string, len(m.Engine.Config.Methods))
			copy(methods, m.Engine.Config.Methods)

			workers := m.Engine.Config.MaxWorkers
			recursive := m.Engine.Config.Recursive
			maxDepth := m.Engine.Config.MaxDepth
			mutate := m.Engine.Config.Mutate
			smartAPI := m.Engine.Config.SmartAPI
			followRedir := m.Engine.Config.FollowRedirects
			maxRedirects := m.Engine.Config.MaxRedirects
			matchRegex := m.Engine.Config.MatchRegex
			filterRegex := m.Engine.Config.FilterRegex
			filterWords := m.Engine.Config.FilterWords
			filterLines := m.Engine.Config.FilterLines
			matchWords := m.Engine.Config.MatchWords
			matchLines := m.Engine.Config.MatchLines
			body := m.Engine.Config.RequestBody
			wordlist := m.Engine.Config.WordlistPath
			outputFmt := m.Engine.Config.OutputFormat
			outputFile := m.Engine.Config.OutputFile
			filterDurMin := m.Engine.Config.FilterRTMin
			filterDurMax := m.Engine.Config.FilterRTMax
			proxyOut := m.Engine.Config.ProxyOut
			timeout := m.Engine.Config.Timeout
			insecure := m.Engine.Config.Insecure
			autoFilterThreshold := m.Engine.Config.AutoFilterThreshold
			simhashThreshold := m.Engine.Config.SimhashThreshold
			simhashClusterLimit := m.Engine.Config.SimhashClusterLimit
			h2Mode := m.Engine.Config.H2Mode
			h2Streams := m.Engine.Config.H2ConcurrentStreams
			timeOracle := m.Engine.Config.TimingOracle
			timeOracleK := m.Engine.Config.TimeOracleK
			timeOracleN := m.Engine.Config.TimeOracleN
			timeTrim := m.Engine.Config.TimeTrim
			harvest := m.Engine.Config.Harvest
			harvestJS := m.Engine.Config.HarvestJS
			harvestAPI := m.Engine.Config.HarvestAPI
			harvestResponse := m.Engine.Config.HarvestResponse
			harvestResponseDepth := m.Engine.Config.HarvestResponseDepth
			harvestResponseFetch := m.Engine.Config.HarvestResponseFetch
			evasionLimit := m.Engine.Config.EvasionLimit
			maxRetries := m.Engine.Config.MaxRetries
			saveRaw := m.Engine.Config.SaveRaw
			spidering := m.Engine.Config.Spidering
			bypass403 := m.Engine.Config.FourOhThreeBypass
			wafEvasion := m.Engine.Config.WAFEvasion
			verbTamper := m.Engine.Config.VerbTamper
			antiBot := m.Engine.Config.AntiBotFallback
			allowPrivate := m.Engine.Config.AllowPrivateTargets
			excludePaths := make([]string, len(m.Engine.Config.ExcludePathPatterns))
			copy(excludePaths, m.Engine.Config.ExcludePathPatterns)
			oobEnabled := m.Engine.Config.OOBEnabled
			interactshServer := m.Engine.Config.InteractshServer
			m.Engine.Config.RUnlock()

			sort.Ints(filters)
			sort.Ints(matchCodes)

			headerKeys := make([]string, 0, len(headers))
			for k := range headers {
				headerKeys = append(headerKeys, k)
			}
			sort.Strings(headerKeys)

			intsToCSV := func(nums []int) string {
				parts := make([]string, len(nums))
				for i, n := range nums {
					parts[i] = strconv.Itoa(n)
				}
				return strings.Join(parts, ",")
			}

			targetSwitch := m.Engine.BaseURL()
			target := targetSwitch
			if m.pendingTarget != "" {
				targetSwitch = m.pendingTarget
				target = m.pendingTarget + " (pending restart)"
			}
			wrapWidth := m.cmdViewport.Width - 6
			if wrapWidth < 40 {
				wrapWidth = 80
			}

			var sb strings.Builder
			writeLine := func(line string) {
				sb.WriteString(wrapText(line, wrapWidth))
				sb.WriteString("\n")
			}

			writeLine("=== Command Line Invocation ===")
			writeLine(strings.Join(os.Args, " "))
			writeLine("")

			writeLine("=== Current Config ===")
			writeLine(fmt.Sprintf("Target: %s", target))
			if wordlist != "" {
				writeLine(fmt.Sprintf("Wordlist: %s", wordlist))
			}
			writeLine(fmt.Sprintf("Workers: %d", workers))
			writeLine(fmt.Sprintf("Delay: %s", delay))
			writeLine(fmt.Sprintf("UA: %s", ua))
			if len(exts) > 0 {
				writeLine(fmt.Sprintf("Extensions: %s", strings.Join(exts, ",")))
			}
			if len(methods) > 0 {
				writeLine(fmt.Sprintf("Methods: %s", strings.Join(methods, ",")))
			}
			if len(matchCodes) > 0 {
				writeLine(fmt.Sprintf("MatchCodes: %s", intsToCSV(matchCodes)))
			}
			if len(filters) > 0 {
				writeLine(fmt.Sprintf("FilterSizes: %s", intsToCSV(filters)))
			}
			if len(headerKeys) > 0 {
				writeLine("Headers:")
				for _, k := range headerKeys {
					writeLine(fmt.Sprintf("  - %s: %s", k, headers[k]))
				}
			}
			writeLine(fmt.Sprintf("Recursive: %v (depth: %d)", recursive, maxDepth))
			writeLine(fmt.Sprintf("Mutate: %v", mutate))
			writeLine(fmt.Sprintf("Follow: %v (max-redirects: %d)", followRedir, maxRedirects))
			writeLine(fmt.Sprintf("OutputFmt: %s", outputFmt))
			if outputFile != "" {
				writeLine(fmt.Sprintf("OutputFile: %s", outputFile))
			}
			writeLine(fmt.Sprintf("HistoryMode: %s", m.historyMode))
			writeLine(fmt.Sprintf("Timeout: %s", timeout))
			writeLine(fmt.Sprintf("InsecureTLS: %v", insecure))
			writeLine(fmt.Sprintf("SmartAPI: %v", smartAPI))
			writeLine(fmt.Sprintf("AutoFilterThreshold: %d", autoFilterThreshold))
			writeLine(fmt.Sprintf("SimhashThreshold: %d", simhashThreshold))
			writeLine(fmt.Sprintf("SimhashClusterLimit: %d", simhashClusterLimit))
			writeLine(fmt.Sprintf("H2Mode: %v", h2Mode))
			writeLine(fmt.Sprintf("H2ConcurrentStreams: %d", h2Streams))
			writeLine(fmt.Sprintf("Retries: %d", maxRetries))
			writeLine(fmt.Sprintf("Spidering: %v", spidering))
			writeLine(fmt.Sprintf("Bypass403: %v", bypass403))
			writeLine(fmt.Sprintf("WAFEvasion: %v", wafEvasion))
			writeLine(fmt.Sprintf("VerbTamper: %v", verbTamper))
			writeLine(fmt.Sprintf("AntiBotFallback: %v", antiBot))
			writeLine(fmt.Sprintf("AllowPrivate: %v", allowPrivate))
			if len(excludePaths) > 0 {
				writeLine(fmt.Sprintf("ExcludePaths: %s", strings.Join(excludePaths, ", ")))
			}
			writeLine(fmt.Sprintf("OOBEnabled: %v", oobEnabled))
			if oobEnabled && interactshServer != "" {
				writeLine(fmt.Sprintf("InteractshServer: %s", interactshServer))
			}
			if matchRegex != "" {
				writeLine(fmt.Sprintf("MatchRegex: %s", matchRegex))
			}
			if filterRegex != "" {
				writeLine(fmt.Sprintf("FilterRegex: %s", filterRegex))
			}
			if filterWords >= 0 {
				writeLine(fmt.Sprintf("FilterWords: %d", filterWords))
			}
			if filterLines >= 0 {
				writeLine(fmt.Sprintf("FilterLines: %d", filterLines))
			}
			if matchWords >= 0 {
				writeLine(fmt.Sprintf("MatchWords: %d", matchWords))
			}
			if matchLines >= 0 {
				writeLine(fmt.Sprintf("MatchLines: %d", matchLines))
			}
			if filterDurMin > 0 {
				writeLine(fmt.Sprintf("RTmin: %s", filterDurMin))
			}
			if filterDurMax > 0 {
				writeLine(fmt.Sprintf("RTmax: %s", filterDurMax))
			}
			if proxyOut != "" {
				writeLine(fmt.Sprintf("ProxyOut: %s", proxyOut))
			}
			if body != "" {
				writeLine(fmt.Sprintf("Body: %s", body))
			}

			writeLine("")
			writeLine("CLI switches (effective now):")
			writeLine(fmt.Sprintf("  -u %s", targetSwitch))
			if wordlist != "" {
				writeLine(fmt.Sprintf("  -w %s", wordlist))
			}
			if workers != 50 {
				writeLine(fmt.Sprintf("  -t %d", workers))
			}
			if delay > 0 {
				writeLine(fmt.Sprintf("  -delay %s", delay))
			}
			if ua != "" {
				writeLine(fmt.Sprintf("  -ua %q", ua))
			}
			for _, k := range headerKeys {
				if strings.EqualFold(k, "Cookie") {
					writeLine(fmt.Sprintf("  -b %q", headers[k]))
				} else {
					writeLine(fmt.Sprintf("  -h %q", fmt.Sprintf("%s: %s", k, headers[k])))
				}
			}
			if len(exts) > 0 {
				writeLine(fmt.Sprintf("  -e %s", strings.Join(exts, ",")))
			}
			if len(matchCodes) > 0 {
				writeLine(fmt.Sprintf("  -mc %s", intsToCSV(matchCodes)))
			}
			if len(filters) > 0 {
				writeLine(fmt.Sprintf("  -fs %s", intsToCSV(filters)))
			}
			if mutate {
				writeLine("  -mutate")
			}
			if recursive {
				writeLine("  -r")
			}
			if maxDepth != 3 {
				writeLine(fmt.Sprintf("  -depth %d", maxDepth))
			}
			if len(methods) > 0 {
				writeLine(fmt.Sprintf("  -m %s", strings.Join(methods, ",")))
			}
			if smartAPI {
				writeLine("  -smart-api")
			}
			if body != "" {
				writeLine(fmt.Sprintf("  -d %q", body))
			}
			if followRedir {
				writeLine("  -follow")
			}
			if maxRedirects != 5 {
				writeLine(fmt.Sprintf("  -max-redirects %d", maxRedirects))
			}
			if matchRegex != "" {
				writeLine(fmt.Sprintf("  -mr %q", matchRegex))
			}
			if filterRegex != "" {
				writeLine(fmt.Sprintf("  -fr %q", filterRegex))
			}
			if filterWords >= 0 {
				writeLine(fmt.Sprintf("  -fw %d", filterWords))
			}
			if filterLines >= 0 {
				writeLine(fmt.Sprintf("  -fl %d", filterLines))
			}
			if matchWords >= 0 {
				writeLine(fmt.Sprintf("  -mw %d", matchWords))
			}
			if matchLines >= 0 {
				writeLine(fmt.Sprintf("  -ml %d", matchLines))
			}
			if filterDurMin > 0 {
				writeLine(fmt.Sprintf("RTmin: %s", filterDurMin))
			}
			if filterDurMax > 0 {
				writeLine(fmt.Sprintf("RTmax: %s", filterDurMax))
			}
			if outputFmt != "" {
				writeLine(fmt.Sprintf("  -of %s", outputFmt))
			}
			if outputFile != "" {
				writeLine(fmt.Sprintf("  -o %s", outputFile))
			}
			if timeout > 0 {
				writeLine(fmt.Sprintf("  -timeout %s", timeout))
			}
			if insecure {
				writeLine("  -k")
			}
			if saveRaw {
				writeLine("  --save-raw")
			}
			if proxyOut != "" {
				writeLine(fmt.Sprintf("  -proxy-out %s", proxyOut))
			}
			if autoFilterThreshold != engine.DefaultAutoFilterThreshold {
				writeLine(fmt.Sprintf("  -af %d", autoFilterThreshold))
			}
			if simhashThreshold != engine.DefaultSimhashThreshold {
				writeLine(fmt.Sprintf("  --simhash-threshold %d", simhashThreshold))
			}
			if simhashClusterLimit != engine.DefaultSimhashClusterLimit {
				writeLine(fmt.Sprintf("  --simhash-cluster %d", simhashClusterLimit))
			}
			if h2Mode {
				writeLine("  --h2")
			}
			if h2Streams != engine.DefaultH2ConcurrentStreams {
				writeLine(fmt.Sprintf("  --h2-streams %d", h2Streams))
			}
			if timeOracle {
				writeLine("  --time-oracle")
			}
			if timeOracleK != engine.TimingOracleDefaultK {
				writeLine(fmt.Sprintf("  --time-k %.2f", timeOracleK))
			}
			if timeOracleN != engine.TimingOracleDefaultRepeatN {
				writeLine(fmt.Sprintf("  --time-n %d", timeOracleN))
			}
			if timeTrim {
				writeLine("  --time-trim")
			}
			if harvest {
				writeLine("  --harvest")
			}
			if harvestJS {
				writeLine("  --harvest-js")
			}
			if harvestAPI {
				writeLine("  --harvest-api")
			}
			if harvestResponse {
				writeLine("  --harvest-response")
			}
			if harvestResponseDepth != engine.DefaultHarvestResponseDepth {
				writeLine(fmt.Sprintf("  --harvest-response-depth %d", harvestResponseDepth))
			}
			if harvestResponseFetch != engine.DefaultHarvestResponseFetch {
				writeLine(fmt.Sprintf("  --harvest-response-fetch %d", harvestResponseFetch))
			}
			if evasionLimit != engine.DefaultEvasionLimit {
				writeLine(fmt.Sprintf("  --evasion-limit %d", evasionLimit))
			}
			if spidering {
				writeLine("  --spider")
			}
			if maxRetries > 0 {
				writeLine(fmt.Sprintf("  -retry %d", maxRetries))
			}
			if bypass403 {
				writeLine("  --bypass-403")
			}
			if wafEvasion {
				writeLine("  --waf-evasion")
			}
			if verbTamper {
				writeLine("  --verb-tamper")
			}
			if !antiBot {
				writeLine("  --anti-bot-fallback=false")
			}
			if allowPrivate {
				writeLine("  --allow-private")
			}
			for _, pat := range excludePaths {
				writeLine(fmt.Sprintf("  --exclude-path %q", pat))
			}
			if oobEnabled {
				writeLine("  --oob")
			}
			if oobEnabled && interactshServer != "" {
				writeLine(fmt.Sprintf("  --oob-server %s", interactshServer))
			}

			return strings.TrimRight(sb.String(), "\n")
		}},
		{Name: "mr", Description: "Set match regex", Args: "<pattern>", Handler: func(m *Model, args string) string {
			pattern := strings.TrimSpace(args)
			if err := m.Engine.SetMatchRegex(pattern); err != nil {
				return errorStyle.Render(fmt.Sprintf("Invalid regex: %v", err))
			}
			if pattern == "" {
				return statusStyle.Render("[*] Match regex cleared")
			}
			return statusStyle.Render(fmt.Sprintf("[*] Match regex set: %s", pattern))
		}},
		{Name: "fr", Description: "Set filter regex", Args: "<pattern>", Handler: func(m *Model, args string) string {
			pattern := strings.TrimSpace(args)
			if err := m.Engine.SetFilterRegex(pattern); err != nil {
				return errorStyle.Render(fmt.Sprintf("Invalid regex: %v", err))
			}
			if pattern == "" {
				return statusStyle.Render("[*] Filter regex cleared")
			}
			return statusStyle.Render(fmt.Sprintf("[*] Filter regex set: %s", pattern))
		}},
		{Name: "fw", Description: "Filter by word count (-1 = off)", Args: "<count>", Handler: func(m *Model, args string) string {
			n, err := strconv.Atoi(strings.TrimSpace(args))
			if err != nil {
				return errorStyle.Render("Usage: :fw <number>")
			}
			m.Engine.Config.Lock()
			m.Engine.Config.FilterWords = n
			m.Engine.Config.Unlock()
			m.Engine.RefreshConfigSnapshot()
			if n < 0 {
				return statusStyle.Render("[*] Word filter disabled")
			}
			return statusStyle.Render(fmt.Sprintf("[*] Filter words: %d", n))
		}},
		{Name: "fl", Description: "Filter by line count (-1 = off)", Args: "<count>", Handler: func(m *Model, args string) string {
			n, err := strconv.Atoi(strings.TrimSpace(args))
			if err != nil {
				return errorStyle.Render("Usage: :fl <number>")
			}
			m.Engine.Config.Lock()
			m.Engine.Config.FilterLines = n
			m.Engine.Config.Unlock()
			m.Engine.RefreshConfigSnapshot()
			if n < 0 {
				return statusStyle.Render("[*] Line filter disabled")
			}
			return statusStyle.Render(fmt.Sprintf("[*] Filter lines: %d", n))
		}},
		{Name: "follow", Description: "Toggle redirect following", Args: "", Handler: func(m *Model, args string) string {
			m.Engine.Config.RLock()
			current := m.Engine.Config.FollowRedirects
			m.Engine.Config.RUnlock()
			m.Engine.SetFollowRedirects(!current)
			if !current {
				return statusStyle.Render("[*] Follow redirects enabled")
			}
			return orangeStyle.Render("[*] Follow redirects disabled")
		}},
		{Name: "saveraw", Description: "Enable/disable saving raw request/response (on|off)", Args: "<on|off>", Handler: func(m *Model, args string) string {
			arg := strings.ToLower(strings.TrimSpace(args))
			if arg == "on" || arg == "true" || arg == "1" {
				m.Engine.Config.Lock()
				m.Engine.Config.SaveRaw = true
				m.Engine.Config.Unlock()
				m.Engine.RefreshConfigSnapshot()
				return statusStyle.Render("[*] --save-raw enabled (applies to subsequent requests; run :restart to immediately reapply scanner)")
			}
			if arg == "off" || arg == "false" || arg == "0" {
				m.Engine.Config.Lock()
				m.Engine.Config.SaveRaw = false
				m.Engine.Config.Unlock()
				m.Engine.RefreshConfigSnapshot()
				return orangeStyle.Render("[*] --save-raw disabled")
			}
			return errorStyle.Render("Usage: :saveraw <on|off>")
		}},
		{Name: "body", Description: "Set request body for POST/PUT", Args: "<body>", Handler: func(m *Model, args string) string {
			m.Engine.Config.Lock()
			m.Engine.Config.RequestBody = strings.TrimSpace(args)
			m.Engine.Config.Unlock()
			m.Engine.RefreshConfigSnapshot()
			if args == "" {
				return statusStyle.Render("[*] Request body cleared")
			}
			return statusStyle.Render("[*] Request body set")
		}},
		{Name: "rtmin", Description: "Set min response time filter (e.g. 500ms, 0 = off)", Args: "<duration>", Handler: func(m *Model, args string) string {
			arg := strings.TrimSpace(args)
			if arg == "" || arg == "0" || arg == "off" {
				m.Engine.Config.Lock()
				m.Engine.Config.FilterRTMin = 0
				m.Engine.Config.Unlock()
				m.Engine.RefreshConfigSnapshot()
				return statusStyle.Render("[*] Min response time filter disabled")
			}
			d, err := time.ParseDuration(arg)
			if err != nil {
				return errorStyle.Render("Usage: :rtmin <duration> (e.g. 500ms, 1s)")
			}
			m.Engine.Config.Lock()
			m.Engine.Config.FilterRTMin = d
			m.Engine.Config.Unlock()
			m.Engine.RefreshConfigSnapshot()
			return statusStyle.Render(fmt.Sprintf("[*] Min response time filter: %s", d))
		}},
		{Name: "rtmax", Description: "Set max response time filter (e.g. 5s, 0 = off)", Args: "<duration>", Handler: func(m *Model, args string) string {
			arg := strings.TrimSpace(args)
			if arg == "" || arg == "0" || arg == "off" {
				m.Engine.Config.Lock()
				m.Engine.Config.FilterRTMax = 0
				m.Engine.Config.Unlock()
				m.Engine.RefreshConfigSnapshot()
				return statusStyle.Render("[*] Max response time filter disabled")
			}
			d, err := time.ParseDuration(arg)
			if err != nil {
				return errorStyle.Render("Usage: :rtmax <duration> (e.g. 5s, 10s)")
			}
			m.Engine.Config.Lock()
			m.Engine.Config.FilterRTMax = d
			m.Engine.Config.Unlock()
			m.Engine.RefreshConfigSnapshot()
			return statusStyle.Render(fmt.Sprintf("[*] Max response time filter: %s", d))
		}},
		{Name: "proxyout", Description: "Set proxy-out for Burp replay (empty = off)", Args: "<url>", Handler: func(m *Model, args string) string {
			addr := strings.TrimSpace(args)
			m.Engine.Config.Lock()
			m.Engine.Config.ProxyOut = addr
			if addr == "" || addr == "off" {
				m.Engine.Config.ProxyOut = ""
				m.Engine.Config.Unlock()
				m.Engine.RefreshConfigSnapshot()
				return statusStyle.Render("[*] Proxy-out disabled")
			}
			m.Engine.Config.Unlock()
			m.Engine.RefreshConfigSnapshot()
			return statusStyle.Render(fmt.Sprintf("[*] Proxy-out: %s", addr))
		}},
		{Name: "clear", Description: "Clear log output", Args: "", Handler: func(m *Model, args string) string {
			m.clearScanLogs()
			return ""
		}},
		{Name: "clearcmd", Description: "Clear command panel output", Args: "", Handler: func(m *Model, args string) string {
			m.cmdOutput = []string{}
			m.cmdViewport.SetContent("")
			return ""
		}},
	}
}

func tickCmd() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg {
		return TickMsg(t)
	})
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(tickCmd(), m.listenForResults(), m.listenForLogEvents())
}

// ResultMsg wraps a result coming from the engine.
type ResultMsg engine.Result

// ResultStreamClosedMsg is sent when the engine result stream closes.
type ResultStreamClosedMsg struct{}

// LogEventMsg wraps a log event coming from the engine.
type LogEventMsg engine.LogEvent

type systemLogEntry struct {
	Event      engine.LogEvent
	Rendered   string
	Relative   string
	SearchText string
	HasDetail  bool
	Path       string
}

type systemLogRingBuffer struct {
	entries []systemLogEntry
	start   int
	size    int
}

func newSystemLogRingBuffer(capacity int) systemLogRingBuffer {
	return systemLogRingBuffer{entries: make([]systemLogEntry, capacity)}
}

func (r *systemLogRingBuffer) reset() {
	r.start = 0
	r.size = 0
	for i := range r.entries {
		r.entries[i] = systemLogEntry{}
	}
}

func (r *systemLogRingBuffer) append(entry systemLogEntry) {
	if len(r.entries) == 0 {
		return
	}
	if r.size < len(r.entries) {
		idx := (r.start + r.size) % len(r.entries)
		r.entries[idx] = entry
		r.size++
		return
	}
	r.entries[r.start] = entry
	r.start = (r.start + 1) % len(r.entries)
}

func (r *systemLogRingBuffer) snapshot() []systemLogEntry {
	if r.size == 0 || len(r.entries) == 0 {
		return nil
	}
	out := make([]systemLogEntry, r.size)
	for i := 0; i < r.size; i++ {
		out[i] = r.entries[(r.start+i)%len(r.entries)]
	}
	return out
}

func (m *Model) systemLogEntries() []systemLogEntry {
	return m.systemLogs.snapshot()
}

func (m *Model) systemLogEvents() []engine.LogEvent {
	entries := m.systemLogEntries()
	if len(entries) == 0 {
		return nil
	}
	out := make([]engine.LogEvent, len(entries))
	for i, entry := range entries {
		out[i] = entry.Event
	}
	return out
}

// listenForResults returns a command that reads from the Results channel.
func (m Model) listenForResults() tea.Cmd {
	return func() tea.Msg {
		result, ok := <-m.resultsCh
		if !ok {
			return ResultStreamClosedMsg{}
		}
		return ResultMsg(result)
	}
}

func (m Model) listenForLogEvents() tea.Cmd {
	return func() tea.Msg {
		event, ok := <-m.logEventsCh
		if !ok {
			return nil
		}
		return LogEventMsg(event)
	}
}

func formatHTTPResponse(raw string) string {
	// Split headers and body
	parts := strings.SplitN(raw, "\n\n", 2)
	if len(parts) != 2 {
		return raw // Fallback if no body
	}
	headers := parts[0]
	body := parts[1]

	// Attempt 1: Pretty Print JSON
	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, []byte(body), "", "  "); err == nil {
		return headers + "\n\n" + prettyJSON.String()
	}

	// Attempt 2: Un-minify HTML/XML
	if strings.Contains(strings.ToLower(headers), "text/html") || strings.Contains(strings.ToLower(headers), "xml") {
		// Force newlines between adjacent tags
		body = strings.ReplaceAll(body, "><", ">\n<")
		// Force newlines after common block endings
		body = strings.ReplaceAll(body, "</script>", "</script>\n")
		body = strings.ReplaceAll(body, "</div>", "</div>\n")
		return headers + "\n\n" + body
	}

	return raw
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		headerHeight := 6
		// Keep footer minimal for sizing; command panel will be overlaid instead
		footerMinHeight := 1
		vpHeight := m.height - headerHeight - footerMinHeight
		if vpHeight < 5 {
			vpHeight = 5
		}
		vpWidth := m.width
		if vpWidth < 20 {
			vpWidth = 20
		}

		paneOuterWidth := (vpWidth - 2) / 2
		paneInnerWidth := paneOuterWidth - 4 // Account for 2 border cells + 2 padding cells

		if !m.ready {
			m.viewport = viewport.New(vpWidth, vpHeight)
			m.viewport.SetContent(strings.Join(m.logs, "\n"))
			m.logPanelHeight = int(float64(vpHeight) * 0.4)
			if m.logPanelHeight < 6 {
				m.logPanelHeight = 6
			}
			if m.logPanelHeight > vpHeight-6 {
				m.logPanelHeight = vpHeight / 3
			}
			if m.logPanelHeight < 6 {
				m.logPanelHeight = 6
			}
			m.logViewport = viewport.New(vpWidth-6, m.logPanelHeight-3)
			m.logViewport.SetContent("")
			m.cmdViewport = viewport.New(vpWidth, 12)
			m.cmdViewport.SetContent(strings.Join(m.cmdOutput, "\n"))

			// Detail viewports
			m.reqViewport = viewport.New(paneInnerWidth, vpHeight-2)
			m.resViewport = viewport.New(paneInnerWidth, vpHeight-2)
			m.hexViewport = viewport.New(vpWidth-4, vpHeight-2)
			m.diffLeftViewport = viewport.New(paneInnerWidth, vpHeight-2)
			m.diffRightViewport = viewport.New(paneInnerWidth, vpHeight-2)

			m.ready = true
		} else {
			m.viewport.Width = vpWidth
			m.viewport.Height = vpHeight
			m.cmdViewport.Width = vpWidth
			m.cmdViewport.Height = 12

			m.reqViewport.Width = paneInnerWidth
			m.reqViewport.Height = vpHeight - 2
			m.resViewport.Width = paneInnerWidth
			m.resViewport.Height = vpHeight - 2
			m.hexViewport.Width = vpWidth - 4
			m.hexViewport.Height = vpHeight - 2
			m.diffLeftViewport.Width = paneInnerWidth
			m.diffLeftViewport.Height = vpHeight - 2
			m.diffRightViewport.Width = paneInnerWidth
			m.diffRightViewport.Height = vpHeight - 2
			m.logPanelHeight = int(float64(vpHeight) * 0.4)
			if m.logPanelHeight < 6 {
				m.logPanelHeight = 6
			}
			if m.logPanelHeight > vpHeight-6 {
				m.logPanelHeight = vpHeight / 3
			}
			m.logViewport.Width = vpWidth - 6
			if m.logViewport.Width < 20 {
				m.logViewport.Width = 20
			}
			m.logViewport.Height = m.logPanelHeight - 3
			if m.logViewport.Height < 3 {
				m.logViewport.Height = 3
			}
		}
		m.repeaterInput.SetWidth(paneInnerWidth)
		m.repeaterInput.SetHeight(vpHeight - 4)
		m.repeaterRespVp.Width = paneInnerWidth
		m.repeaterRespVp.Height = vpHeight - 4
		m.cmdViewport.Width = vpWidth
		m.cmdViewport.Height = 12
		m.logViewport.Width = vpWidth - 6
		if m.logViewport.Width < 20 {
			m.logViewport.Width = 20
		}
		m.logViewport.Height = m.logPanelHeight - 3
		if m.logViewport.Height < 3 {
			m.logViewport.Height = 3
		}
		m.textInput.Width = vpWidth - 7
		m.footerBarStyle = lipgloss.NewStyle().Foreground(DraculaCyan).Bold(true).Width(m.width).PaddingLeft(2)
		if m.state == StateHexView {
			m.updateHexView()
		} else if m.state == StateDiffView {
			m.updateDiffView()
		} else if m.state == StateRepeater && len(m.repeaterSessions) > 0 {
			m.syncActiveRepeaterSessionFromUI()
			m.loadRepeaterSessionIntoUI(m.activeRepeaterIdx)
		}

	case TickMsg:
		// Clear expired status messages
		if !m.statusExpiry.IsZero() && time.Now().After(m.statusExpiry) {
			m.statusMessage = ""
			m.statusExpiry = time.Time{}
		}
		if m.uiStateDirty && time.Since(m.uiStateDirtyAt) >= uiStateAutosaveDebounceDur {
			_ = m.FlushPersistedUIState()
		}
		if m.errorPulseOn && !m.errorPulseUntil.IsZero() && time.Now().After(m.errorPulseUntil) {
			m.errorPulseOn = false
			m.logPanelDirty = true
		}
		m.Engine.UpdateRPS()
		now := time.Time(msg)
		currentRPS := atomic.LoadInt64(&m.Engine.CurrentRPS)
		if currentRPS > m.peakRPS {
			m.peakRPS = currentRPS
		}
		m.rpsHistory = append(m.rpsHistory, currentRPS)
		if len(m.rpsHistory) > 30 {
			m.rpsHistory = m.rpsHistory[len(m.rpsHistory)-30:]
		}
		m.rpsHistoryFull = append(m.rpsHistoryFull, currentRPS)
		if len(m.rpsHistoryFull) > 1000 {
			m.rpsHistoryFull = m.rpsHistoryFull[len(m.rpsHistoryFull)-1000:]
		}
		m.queueDepthHistory = append(m.queueDepthHistory, m.Engine.QueueSize())
		if len(m.queueDepthHistory) > 1000 {
			m.queueDepthHistory = m.queueDepthHistory[len(m.queueDepthHistory)-1000:]
		}
		m.Engine.Config.RLock()
		maxWorkers := m.Engine.Config.MaxWorkers
		m.Engine.Config.RUnlock()
		utilization := 0.0
		if maxWorkers > 0 {
			utilization = float64(atomic.LoadInt64(&m.activeWorkers)) / float64(maxWorkers)
		}
		m.workerUtilizationHistory = append(m.workerUtilizationHistory, utilization)
		if len(m.workerUtilizationHistory) > 1000 {
			m.workerUtilizationHistory = m.workerUtilizationHistory[len(m.workerUtilizationHistory)-1000:]
		}
		totalErrors := atomic.LoadInt64(&m.totalErrors)
		if m.lastMetricsTick.IsZero() {
			m.lastMetricsTick = now
			m.lastErrorCount = totalErrors
		}
		elapsed := now.Sub(m.lastMetricsTick)
		if elapsed <= 0 {
			elapsed = time.Second
		}
		errorDelta := totalErrors - m.lastErrorCount
		errorRate := 0.0
		if elapsed > 0 {
			errorRate = float64(errorDelta) / elapsed.Minutes()
		}
		m.errorRateHistory = append(m.errorRateHistory, errorRate)
		if len(m.errorRateHistory) > 1000 {
			m.errorRateHistory = m.errorRateHistory[len(m.errorRateHistory)-1000:]
		}
		m.lastMetricsTick = now
		m.lastErrorCount = totalErrors
		m.commandPulseOn = !m.commandPulseOn
		activeState := m.state
		if activeState == StateLogsPanel {
			activeState = m.previousState
			if activeState == StateLogsPanel || activeState == 0 {
				activeState = StateList
			}
		}
		if m.logsChanged {
			if activeState == StateDashboard {
				m.renderDashboardView()
			} else {
				m.renderListView()
			}
			m.logsChanged = false
		}
		if m.dashboardDirty && activeState == StateDashboard {
			m.renderDashboardView()
		}
		if m.logPanelDirty && (m.showLogsPanel || m.state == StateLogsPanel) {
			m.renderLogsPanel()
			m.logPanelDirty = false
			m.logEventsSinceRender = 0
		}
		cmds = append(cmds, tickCmd())

	case ResultMsg:
		result := engine.Result(msg)
		if result.Duration > 0 {
			m.responseSamples++
			if m.responseSamples == 1 {
				m.avgResponseTime = result.Duration
			} else {
				total := m.avgResponseTime*time.Duration(m.responseSamples-1) + result.Duration
				m.avgResponseTime = total / time.Duration(m.responseSamples)
			}
		}
		if result.IsAutoFilter {
			msgStr := ""
			if result.Headers != nil {
				msgStr = result.Headers["Msg"]
			}
			if msgStr != "" {
				m.appendLog(orangeStyle.Render(fmt.Sprintf("[!] %s: %s", result.Path, msgStr)), nil)
			}
		} else if result.IsEagleAlert {
			m.appendLog(yellowStyle.Render(fmt.Sprintf("[EAGLE] %s %s", result.Path, result.EagleSummary())), &result)
		} else {
			m.appendLog(formatResult(result), &result)
		}
		m.dashboardDirty = true
		cmds = append(cmds, m.listenForResults())

	case ResultStreamClosedMsg:
		m.quitting = true
		return m, tea.Quit

	case LogEventMsg:
		event := engine.LogEvent(msg)
		m.appendSystemLog(event)
		countedError := false
		switch event.Type {
		case engine.EventWorkerStarted:
			m.activeWorkers++
		case engine.EventWorkerStopped:
			if m.activeWorkers > 0 {
				m.activeWorkers--
			}
		case engine.EventProxyRotated:
			m.totalProxyRotations++
		case engine.EventRetryAttempt:
			m.totalRetries++
		case engine.EventRateLimitHit, engine.EventNetworkError, engine.EventHarvestParseError:
			m.totalErrors++
			countedError = true
		}
		if event.Level == engine.LogLevelError && !countedError {
			m.totalErrors++
			countedError = true
		}
		if event.Level == engine.LogLevelWarning && !countedError {
			m.totalErrors++
		}
		if event.Level == engine.LogLevelError || event.Level == engine.LogLevelWarning {
			m.errorPulseOn = true
			m.errorPulseUntil = time.Now().Add(750 * time.Millisecond)
			m.logPanelDirty = true
		}
		cmds = append(cmds, m.listenForLogEvents())

	case RepeaterResultMsg:
		idx := m.findRepeaterSessionIndex(msg.SessionID)
		if idx >= 0 {
			session := &m.repeaterSessions[idx]
			session.Sending = false
			session.CancelFn = nil
			if msg.Err != nil {
				session.HasError = true
				session.Response = fmt.Sprintf("Error: %v", msg.Err)
				session.LastStatus = 0
				session.LastDuration = 0
				session.LastRaw = nil
			} else {
				session.HasError = false
				session.LastRaw = append(session.LastRaw[:0], msg.RawResponse.Raw...)
				content := strings.ReplaceAll(string(msg.RawResponse.Raw), "\r\n", "\n")
				content = formatHTTPResponse(content)
				if len(content) > 50_000 {
					content = content[:50_000] + "\n\n[... truncated for display ...]"
				}
				session.Response = content
				session.LastStatus = msg.RawResponse.StatusCode
				session.LastDuration = msg.Duration

				if session.HistoryIdx < len(session.History)-1 {
					session.History = session.History[:session.HistoryIdx+1]
				}
				session.History = append(session.History, RepeaterHistoryEntry{
					Request:    session.Request,
					Response:   content,
					StatusCode: msg.RawResponse.StatusCode,
					Duration:   msg.Duration,
				})
				if len(session.History) > 15 {
					session.History = session.History[1:]
				}
				session.HistoryIdx = len(session.History) - 1
			}

			if idx == m.activeRepeaterIdx {
				m.loadRepeaterSessionIntoUI(idx)
			}
			m.markUIStateDirty()
		}

	case tea.KeyMsg:
		if m.state == StateRepeater {
			switch msg.String() {
			case "ctrl+c":
				m.syncActiveRepeaterSessionFromUI()
				if m.repeaterCancelFn != nil {
					m.repeaterCancelFn()
				}
				m.quitting = true
				return m, tea.Quit
			case "ctrl+p":
				if m.repeaterHistoryIdx > 0 {
					m.repeaterHistoryIdx--
					entry := m.repeaterHistory[m.repeaterHistoryIdx]
					m.repeaterInput.SetValue(entry.Request)
					m.repeaterRespVp.SetContent(wrapText(entry.Response, m.repeaterRespVp.Width))
					if session := m.activeRepeaterSession(); session != nil {
						session.Request = entry.Request
						session.Response = entry.Response
						session.HasError = false
					}
					m.repeaterLastStatus = entry.StatusCode
					m.repeaterLastDuration = entry.Duration
					m.repeaterRespVp.GotoTop()
					m.syncActiveRepeaterSessionFromUI()
				}
				return m, nil
			case "ctrl+n":
				if m.repeaterHistoryIdx < len(m.repeaterHistory)-1 {
					m.repeaterHistoryIdx++
					entry := m.repeaterHistory[m.repeaterHistoryIdx]
					m.repeaterInput.SetValue(entry.Request)
					m.repeaterRespVp.SetContent(wrapText(entry.Response, m.repeaterRespVp.Width))
					if session := m.activeRepeaterSession(); session != nil {
						session.Request = entry.Request
						session.Response = entry.Response
						session.HasError = false
					}
					m.repeaterLastStatus = entry.StatusCode
					m.repeaterLastDuration = entry.Duration
					m.repeaterRespVp.GotoTop()
					m.syncActiveRepeaterSessionFromUI()
				}
				return m, nil
			case "ctrl+r":
				if !m.repeaterSending {
					m.repeaterSending = true
					m.repeaterRespVp.SetContent("Sending...")
					rawReq := m.repeaterInput.Value()
					rawReq = strings.ReplaceAll(rawReq, "\r\n", "\n") // Sanitize mixed endings
					rawReq = strings.ReplaceAll(rawReq, "\n", "\r\n") // Enforce strict HTTP CRLF
					ctx, cancel := context.WithCancel(context.Background())
					m.repeaterCancelFn = cancel
					session := m.activeRepeaterSession()
					if session != nil {
						session.Request = m.repeaterInput.Value()
						session.Target = m.repeaterTarget
						session.Sending = true
						session.CancelFn = cancel
						return m, sendRepeaterRequest(m.Engine, m.repeaterTarget, rawReq, session.ID, ctx)
					}
				}
			case "ctrl+y":
				if err := m.copyRepeaterRequest(); err != nil {
					m.statusMessage = errorStyle.Render(fmt.Sprintf("Copy request failed: %v", err))
				} else {
					m.statusMessage = statusStyle.Render("Repeater request copied to clipboard")
				}
				m.statusExpiry = time.Now().Add(3 * time.Second)
				return m, nil
			case "alt+y":
				if err := m.copyRepeaterResponse(); err != nil {
					m.statusMessage = errorStyle.Render(fmt.Sprintf("Copy response failed: %v", err))
				} else {
					m.statusMessage = statusStyle.Render("Repeater response copied to clipboard")
				}
				m.statusExpiry = time.Now().Add(3 * time.Second)
				return m, nil
			case "alt+b":
				if err := m.copyRepeaterBoth(); err != nil {
					m.statusMessage = errorStyle.Render(fmt.Sprintf("Copy request/response failed: %v", err))
				} else {
					m.statusMessage = statusStyle.Render("Repeater request and response copied to clipboard")
				}
				m.statusExpiry = time.Now().Add(3 * time.Second)
				return m, nil
			case "alt+c":
				if err := m.copyRepeaterCurl(); err != nil {
					m.statusMessage = errorStyle.Render(fmt.Sprintf("Copy curl failed: %v", err))
				} else {
					m.statusMessage = statusStyle.Render("Repeater curl command copied to clipboard")
				}
				m.statusExpiry = time.Now().Add(3 * time.Second)
				return m, nil
			case "alt+w":
				path, err := m.exportRepeaterRequest("")
				if err != nil {
					m.statusMessage = errorStyle.Render(fmt.Sprintf("Export request failed: %v", err))
				} else {
					m.statusMessage = statusStyle.Render(fmt.Sprintf("Repeater request exported to %s", path))
				}
				m.statusExpiry = time.Now().Add(3 * time.Second)
				return m, nil
			case "[":
				m.cycleRepeaterSession(-1)
				return m, nil
			case "]":
				m.cycleRepeaterSession(1)
				return m, nil
			case "ctrl+w":
				m.closeActiveRepeaterSession()
				return m, nil
			case "y":
				if !m.repeaterFocusReq {
					if err := m.copyRepeaterRequest(); err != nil {
						m.statusMessage = errorStyle.Render(fmt.Sprintf("Copy request failed: %v", err))
					} else {
						m.statusMessage = statusStyle.Render("Repeater request copied to clipboard")
					}
					m.statusExpiry = time.Now().Add(3 * time.Second)
					return m, nil
				}
			case "Y":
				if !m.repeaterFocusReq {
					if err := m.copyRepeaterResponse(); err != nil {
						m.statusMessage = errorStyle.Render(fmt.Sprintf("Copy response failed: %v", err))
					} else {
						m.statusMessage = statusStyle.Render("Repeater response copied to clipboard")
					}
					m.statusExpiry = time.Now().Add(3 * time.Second)
					return m, nil
				}
			case "C":
				if !m.repeaterFocusReq {
					if err := m.copyRepeaterCurl(); err != nil {
						m.statusMessage = errorStyle.Render(fmt.Sprintf("Copy curl failed: %v", err))
					} else {
						m.statusMessage = statusStyle.Render("Repeater curl command copied to clipboard")
					}
					m.statusExpiry = time.Now().Add(3 * time.Second)
					return m, nil
				}
			case "w":
				if !m.repeaterFocusReq {
					path, err := m.exportRepeaterRequest("")
					if err != nil {
						m.statusMessage = errorStyle.Render(fmt.Sprintf("Export request failed: %v", err))
					} else {
						m.statusMessage = statusStyle.Render(fmt.Sprintf("Repeater request exported to %s", path))
					}
					m.statusExpiry = time.Now().Add(3 * time.Second)
					return m, nil
				}
			case "tab":
				m.repeaterFocusReq = !m.repeaterFocusReq
				if m.repeaterFocusReq {
					m.repeaterInput.Focus()
				} else {
					m.repeaterInput.Blur()
				}
				m.markUIStateDirty()
			case "esc":
				m.syncActiveRepeaterSessionFromUI()
				if m.repeaterCancelFn != nil {
					m.repeaterCancelFn()
				}
				m.state = StateList
			default:
				if m.repeaterFocusReq {
					m.repeaterInput, cmd = m.repeaterInput.Update(msg)
					m.syncActiveRepeaterSessionFromUI()
					cmds = append(cmds, cmd)
				} else {
					m.repeaterRespVp, cmd = m.repeaterRespVp.Update(msg)
					cmds = append(cmds, cmd)
				}
			}
			return m, tea.Batch(cmds...)
		}

		switch msg.String() {
		case "ctrl+c":
			m.quitting = true
			return m, tea.Quit

		case "q":
			if m.state == StateDashboard || m.state == StateDetail || m.state == StateHexView || m.state == StateDiffView || m.state == StateRepeater {
				m.state = StateList
				m.renderListView()
				return m, nil
			}
			if !m.commandMode {
				m.quitting = true
				return m, tea.Quit
			}

		case ":":
			if !m.commandMode && m.state == StateList {
				m.commandMode = true
				m.state = StateCommand
				m.commandPulseOn = true
				m.textInput.SetValue("")
				m.textInput.Focus()
				m.suggestions = nil
				m.selectedSugIdx = 0
				return m, nil
			}

		case "esc":
			if m.commandMode {
				m.commandMode = false
				m.state = StateList
				m.commandPulseOn = false
				m.textInput.Blur()
				m.suggestions = nil
				return m, nil
			}
			if m.state == StateDashboard || m.state == StateDetail || m.state == StateHexView || m.state == StateDiffView {
				m.state = StateList
				m.renderListView()
				return m, nil
			}

		case "enter":
			if m.commandMode {
				val := strings.TrimSpace(m.textInput.Value())
				if val != "" {
					output := m.executeCommand(val)
					if output != "" {
						m.appendCmd(output)
					}
					m.cmdHistory = append(m.cmdHistory, val)
					m.cmdHistoryIdx = len(m.cmdHistory)
				}
				m.textInput.SetValue("")
				m.suggestions = nil
				m.selectedSugIdx = 0
				m.commandMode = true
				m.state = StateCommand
				m.commandPulseOn = true
				m.textInput.Focus()
				return m, nil
			}

			if m.state == StateList {
				if m.selectedIndex >= 0 && m.selectedIndex < len(m.logLineHits) && m.logLineHits[m.selectedIndex] != nil {
					m.state = StateDetail
					m.updateDetailView()
				} else {
					m.statusMessage = mutedStyle.Render("No request data for this line.")
					m.statusExpiry = time.Now().Add(2 * time.Second)
				}
				return m, nil
			}
			if m.state == StateLogsPanel {
				if !m.jumpToSelectedLogResult() {
					m.statusMessage = mutedStyle.Render("No linked result for this log entry.")
					m.statusExpiry = time.Now().Add(2 * time.Second)
				}
				return m, nil
			}
			if m.state == StateDashboard {
				return m, nil
			}

		case "up", "k":
			if m.state == StateLogsPanel {
				m.moveLogSelection(-1)
				return m, nil
			}
			if m.commandMode && len(m.suggestions) > 0 {
				m.selectedSugIdx--
				if m.selectedSugIdx < 0 {
					m.selectedSugIdx = len(m.suggestions) - 1
				}
				return m, nil
			}
			if m.commandMode && len(m.cmdHistory) > 0 {
				if m.cmdHistoryIdx > 0 {
					m.cmdHistoryIdx--
					m.textInput.SetValue(m.cmdHistory[m.cmdHistoryIdx])
					m.textInput.SetCursor(len(m.textInput.Value()))
					return m, nil
				}
			}

			if m.state == StateList {
				m.moveListSelection(-1)
				return m, nil
			}
			if m.state == StateDashboard {
				m.viewport.LineUp(1)
				return m, nil
			}
			if m.state == StateDetail || m.state == StateHexView || m.state == StateDiffView {
				m.reqViewport.LineUp(1)
				m.resViewport.LineUp(1)
				m.hexViewport.LineUp(1)
				m.diffLeftViewport.LineUp(1)
				m.diffRightViewport.LineUp(1)
				return m, nil
			}
			if m.state == StateCommand {
				m.cmdViewport.LineUp(1)
				return m, nil
			}

		case "down", "j":
			if m.state == StateLogsPanel {
				m.moveLogSelection(1)
				return m, nil
			}
			if m.commandMode && len(m.suggestions) > 0 {
				m.selectedSugIdx++
				if m.selectedSugIdx >= len(m.suggestions) {
					m.selectedSugIdx = 0
				}
				return m, nil
			}
			if m.commandMode && len(m.cmdHistory) > 0 {
				if m.cmdHistoryIdx < len(m.cmdHistory)-1 {
					m.cmdHistoryIdx++
					m.textInput.SetValue(m.cmdHistory[m.cmdHistoryIdx])
					m.textInput.SetCursor(len(m.textInput.Value()))
					return m, nil
				}
			}

			if m.state == StateList {
				m.moveListSelection(1)
				return m, nil
			}
			if m.state == StateDashboard {
				m.viewport.LineDown(1)
				return m, nil
			}
			if m.state == StateDetail || m.state == StateHexView || m.state == StateDiffView {
				m.reqViewport.LineDown(1)
				m.resViewport.LineDown(1)
				m.hexViewport.LineDown(1)
				m.diffLeftViewport.LineDown(1)
				m.diffRightViewport.LineDown(1)
				return m, nil
			}
			if m.state == StateCommand {
				m.cmdViewport.LineDown(1)
				return m, nil
			}

		case "pagedown":
			if m.state == StateLogsPanel {
				m.moveLogSelection(max(1, m.logViewport.Height))
				return m, nil
			}
			if m.state == StateList {
				m.pageListSelection(max(1, m.viewport.Height))
			} else if m.state == StateDashboard {
				m.viewport.ViewDown()
			} else if m.state == StateDetail || m.state == StateHexView || m.state == StateDiffView {
				m.reqViewport.ViewDown()
				m.resViewport.ViewDown()
				m.hexViewport.ViewDown()
				m.diffLeftViewport.ViewDown()
				m.diffRightViewport.ViewDown()
			}
			return m, nil

		case "pageup":
			if m.state == StateLogsPanel {
				m.moveLogSelection(-max(1, m.logViewport.Height))
				return m, nil
			}
			if m.state == StateList {
				m.pageListSelection(-max(1, m.viewport.Height))
			} else if m.state == StateDashboard || m.state == StateDetail || m.state == StateHexView || m.state == StateDiffView {
				if m.state == StateDashboard {
					m.viewport.ViewUp()
				}
				m.reqViewport.ViewUp()
				m.resViewport.ViewUp()
				m.hexViewport.ViewUp()
				m.diffLeftViewport.ViewUp()
				m.diffRightViewport.ViewUp()
			}
			return m, nil

		case "tab":
			if m.state == StateHexView {
				m.toggleHexTarget()
				return m, nil
			}
			if m.commandMode && len(m.suggestions) > 0 {
				val := m.textInput.Value()
				if strings.HasPrefix(val, "wordlist ") {
					// Append the completion instead of replacing the whole string
					base := val
					lastSlash := strings.LastIndex(val, "/")
					if lastSlash != -1 {
						base = val[:lastSlash+1]
					} else {
						base = "wordlist "
					}

					suggestion := m.suggestions[m.selectedSugIdx].Text
					if strings.HasSuffix(suggestion, "/") {
						newVal := base + suggestion
						m.textInput.SetValue(newVal)
						m.textInput.SetCursor(len(newVal))
						// Trigger new completion
						m.updateSuggestions(newVal)
					} else {
						newVal := base + suggestion + " "
						m.textInput.SetValue(newVal)
						m.textInput.SetCursor(len(newVal))
						m.suggestions = nil
					}
				} else {
					newVal := m.suggestions[m.selectedSugIdx].Text + " "
					m.textInput.SetValue(newVal)
					m.textInput.SetCursor(len(newVal))
					m.suggestions = nil
				}
				return m, nil
			}
		}

		if m.commandMode {
			var cmd tea.Cmd
			m.textInput, cmd = m.textInput.Update(msg)
			cmds = append(cmds, cmd)

			// Autocomplete
			val := m.textInput.Value()
			m.updateSuggestions(val)

			return m, tea.Batch(cmds...)
		}

		// Non-command mode key shortcuts
		switch msg.String() {
		case "r":
			if m.state == StateList && m.selectedIndex >= 0 && m.selectedIndex < len(m.logLineHits) {
				selectedHit := m.logLineHits[m.selectedIndex]
				if selectedHit != nil && selectedHit.Request != "" {
					cleanReq := strings.ReplaceAll(selectedHit.Request, "\r\n", "\n")
					m.openRepeaterSession(m.Engine.BaseURL(), cleanReq)
				} else {
					m.statusMessage = errorStyle.Render("No raw request available. Use --save-raw and restart.")
					m.statusExpiry = time.Now().Add(3 * time.Second)
				}
			}
		case "R":
			switch m.state {
			case StateList, StateDetail:
				m.saveDiffReferenceFromSelected()
			case StateRepeater:
				m.saveDiffReferenceFromReplay()
			}
		case "d":
			switch m.state {
			case StateList, StateDetail:
				if m.openDiffViewFromSelected() {
					return m, nil
				}
			case StateRepeater:
				if m.openDiffViewFromReplay() {
					return m, nil
				}
			}
		case "D":
			if m.state == StateRepeater {
				if m.openDiffViewFromReplay() {
					return m, nil
				}
			}
		case "c":
			if m.state == StateDiffView {
				m.statusMessage = statusStyle.Render(m.toggleDiffMode())
				m.statusExpiry = time.Now().Add(3 * time.Second)
				return m, nil
			}
		case "h":
			if m.state == StateList || m.state == StateDetail {
				if m.openHexView(HexViewRequest) {
					return m, nil
				}
				if m.openHexView(HexViewResponse) {
					return m, nil
				}
				m.statusMessage = errorStyle.Render("No raw bytes available. Use --save-raw and retry.")
				m.statusExpiry = time.Now().Add(3 * time.Second)
			}
		case "H":
			if m.state == StateList || m.state == StateDetail {
				if m.openHexView(HexViewResponse) {
					return m, nil
				}
				if m.openHexView(HexViewRequest) {
					return m, nil
				}
				m.statusMessage = errorStyle.Render("No raw bytes available. Use --save-raw and retry.")
				m.statusExpiry = time.Now().Add(3 * time.Second)
			}
		case "p":
			m.Engine.Config.RLock()
			p := m.Engine.Config.IsPaused
			m.Engine.Config.RUnlock()
			m.Engine.SetPaused(!p)
			if p {
				m.appendCmd(statusStyle.Render("[*] Scan resumed"))
			} else {
				m.appendCmd(orangeStyle.Render("[*] Scan paused"))
			}
		case "?":
			output := m.commands[0].Handler(m, "")
			m.appendCmd(output)
		case "1", "2", "3", "4", "5":
			if m.state == StateDashboard {
				m.dashboardTab = DashboardTab(int(msg.String()[0] - '1'))
				m.dashboardDirty = true
				m.renderDashboardView()
				return m, nil
			}
		case "f":
			if m.state == StateDashboard {
				m.cycleDashboardRange()
				m.dashboardDirty = true
				m.renderDashboardView()
				return m, nil
			}
		case "e":
			if m.state == StateDashboard {
				path, err := m.exportMetricsSnapshot()
				if err != nil {
					m.statusMessage = errorStyle.Render(fmt.Sprintf("Metrics export failed: %v", err))
				} else {
					m.statusMessage = statusStyle.Render(fmt.Sprintf("Metrics exported to %s", path))
				}
				m.statusExpiry = time.Now().Add(3 * time.Second)
				return m, nil
			}
		case "m":
			m.cycleMetricsView()
			return m, nil
		case "a":
			if m.state == StateList || m.state == StateDetail {
				m.statusMessage = m.toggleAnomalyFilterOnly()
				m.statusExpiry = time.Now().Add(3 * time.Second)
				return m, nil
			}
		case "t":
			if m.state == StateList || m.state == StateDetail {
				m.statusMessage = m.toggleSelectedHitMarked()
				m.statusExpiry = time.Now().Add(3 * time.Second)
				return m, nil
			}
		case "L":
			m.toggleLogsPanel()
			return m, nil
		case "x":
			if m.state == StateLogsPanel {
				m.logDetailsExpanded = !m.logDetailsExpanded
				m.logPanelDirty = true
				m.renderLogsPanel()
				return m, nil
			}
		}
	}

	return m, tea.Batch(cmds...)
}

func wrapText(text string, width int) string {
	if width <= 0 {
		return text
	}
	return wrap.String(text, width)
}

// isBinaryString returns true when the string contains non-UTF8 bytes or a
// high proportion of non-printable characters—likely a binary response.
func isBinaryString(s string) bool {
	if s == "" {
		return false
	}
	if !utf8.ValidString(s) {
		return true
	}
	total := 0
	printable := 0
	for _, r := range s {
		total++
		if r == '\n' || r == '\r' || r == '\t' {
			printable++
			continue
		}
		if unicode.IsPrint(r) {
			printable++
		}
	}
	if total == 0 {
		return false
	}
	return float64(printable)/float64(total) < 0.90
}

func (m *Model) updateDetailView() {
	var selectedHit *engine.Result
	if m.selectedIndex >= 0 && m.selectedIndex < len(m.logLineHits) {
		selectedHit = m.logLineHits[m.selectedIndex]
	}

	var reqContent, resContent string

	if selectedHit != nil {
		reqContent = "No raw request available. Use --save-raw to include raw request/response; set follow redirects or disable body filters if using HEAD."
		if selectedHit.MarkedInteresting {
			reqContent = yellowStyle.Render("★ Marked interesting") + "\n\n" + reqContent
		}
		if selectedHit.Note != "" {
			reqContent = selectedHit.Note + "\n\n" + reqContent
		}
		if selectedHit.Request != "" {
			reqContent = selectedHit.Request
			if selectedHit.MarkedInteresting {
				reqContent = yellowStyle.Render("★ Marked interesting") + "\n\n" + reqContent
			}
			if selectedHit.Note != "" {
				reqContent = selectedHit.Note + "\n\n" + reqContent
			}
			if isBinaryString(reqContent) {
				reqContent = fmt.Sprintf("[Binary request: %d bytes]\nUse --save-raw to persist to disk.", len(selectedHit.Request))
			}
		}

		resContent = "No raw response available. Use --save-raw to include raw request/response."
		if selectedHit.MarkedInteresting {
			resContent = yellowStyle.Render("★ Marked interesting") + "\n\n" + resContent
		}
		if selectedHit.Note != "" {
			resContent = selectedHit.Note + "\n\n" + resContent
		}
		if selectedHit.Response != "" {
			resContent = selectedHit.Response
			if selectedHit.MarkedInteresting {
				resContent = yellowStyle.Render("★ Marked interesting") + "\n\n" + resContent
			}
			if selectedHit.Note != "" {
				resContent = selectedHit.Note + "\n\n" + resContent
			}
			if isBinaryString(resContent) {
				ctype := selectedHit.ContentType
				if ctype == "" {
					ctype = "binary"
				}
				resContent = fmt.Sprintf("[Binary response: %s, %d bytes]\nUse --save-raw to persist to disk.", ctype, len(selectedHit.Response))
			}
		}
	} else {
		placeholder := mutedStyle.Render("\n\n  (Select a valid hit to view request/response details)")
		reqContent = placeholder
		resContent = placeholder
	}

	// Wrap text to viewport width to prevent horizontal overflow
	m.reqViewport.SetContent(wrapText(reqContent, m.reqViewport.Width))
	m.resViewport.SetContent(wrapText(resContent, m.resViewport.Width))

	m.reqViewport.GotoTop()
	m.resViewport.GotoTop()
}

func (m *Model) renderListView() {
	if len(m.logs) == 0 {
		m.viewport.SetContent("")
		return
	}

	visibleIndexes := m.visibleListIndexes()
	selectedPos := m.normalizeVisibleSelection(visibleIndexes)
	if len(visibleIndexes) == 0 {
		if m.anomalyFilterOnly {
			m.viewport.SetContent(mutedStyle.Render("No anomaly findings yet. Press 'a' to return to the full list."))
		} else {
			m.viewport.SetContent("")
		}
		return
	}
	m.syncVisibleScroll(visibleIndexes, selectedPos)

	var visibleLines []string
	start := m.listScrollIdx
	end := start + m.viewport.Height
	if end > len(visibleIndexes) {
		end = len(visibleIndexes)
	}

	for visibleIdx := start; visibleIdx < end; visibleIdx++ {
		i := visibleIndexes[visibleIdx]
		line := m.logs[i]

		var lineHit *engine.Result
		if i < len(m.logLineHits) {
			lineHit = m.logLineHits[i]
		}

		if i == m.selectedIndex {
			selectedRow := fmt.Sprintf("%s %s %s %s", selectedCursorStyle.Render("▌"), renderTriageMarker(lineHit), renderSeverityMarker(lineHit), line)
			visibleLines = append(visibleLines, selectedRowStyle.Render(selectedRow))
			continue
		}

		cursor := severityNeutralStyle.Render(" ")
		triage := renderTriageMarker(lineHit)
		severity := renderSeverityMarker(lineHit)
		visibleLines = append(visibleLines, fmt.Sprintf("%s %s %s %s", cursor, triage, severity, line))
	}

	m.viewport.SetContent(strings.Join(visibleLines, "\n"))
}

func (m *Model) updateSuggestions(val string) {
	m.suggestions = nil
	if val == "" {
		return
	}

	if strings.HasPrefix(val, "wordlist ") {
		path := strings.TrimPrefix(val, "wordlist ")
		dir := "."
		base := path

		lastSlash := strings.LastIndex(path, "/")
		if lastSlash != -1 {
			dir = path[:lastSlash]
			base = path[lastSlash+1:]
			if dir == "" {
				dir = "/"
			}
		}

		entries, err := os.ReadDir(dir)
		if err == nil {
			for _, entry := range entries {
				name := entry.Name()
				if strings.HasPrefix(name, base) {
					if entry.IsDir() {
						m.suggestions = append(m.suggestions, CommandSuggestion{Text: name + "/"})
					} else {
						m.suggestions = append(m.suggestions, CommandSuggestion{Text: name})
					}
				}
			}
		}
		m.selectedSugIdx = 0
		return
	}

	for _, c := range m.commands {
		if strings.HasPrefix(c.Name, val) {
			m.suggestions = append(m.suggestions, CommandSuggestion{Text: c.Name, Description: c.Description})
		}
	}
	m.selectedSugIdx = 0
}

func (m *Model) clearScanLogs() {
	m.logs = []string{}
	m.logLineHits = []*engine.Result{}
	m.systemLogs.reset()
	m.hits = []engine.Result{}
	m.logIndexByKey = make(map[string]int)
	m.hitIndexByKey = make(map[string]int)
	m.viewport.SetContent("")
	m.logViewport.SetContent("")
	m.selectedIndex = 0
	m.listScrollIdx = 0
	m.atBottom = true
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
	m.logPanelAutoScroll = true
	m.errorPulseOn = false
	m.errorPulseUntil = time.Time{}
}

func (m *Model) moveLogSelection(delta int) {
	entries := m.visibleSystemLogEntries()
	if len(entries) == 0 {
		m.logSelectedIndex = 0
		m.logPanelScrollOffset = 0
		return
	}
	m.logSelectedIndex += delta
	if m.logSelectedIndex < 0 {
		m.logSelectedIndex = 0
	}
	if m.logSelectedIndex >= len(entries) {
		m.logSelectedIndex = len(entries) - 1
	}
	m.logPanelAutoScroll = false
	m.logPanelDirty = true
}

func (m *Model) jumpToSelectedLogResult() bool {
	entries := m.visibleSystemLogEntries()
	if m.logSelectedIndex < 0 || m.logSelectedIndex >= len(entries) {
		return false
	}
	entry := entries[m.logSelectedIndex]
	path := entry.Path
	if path == "" && entry.Event.Metadata != nil {
		if v, ok := entry.Event.Metadata["path"].(string); ok {
			path = v
		}
	}
	if path == "" {
		return false
	}
	for i := range m.logLineHits {
		if m.logLineHits[i] != nil && m.logLineHits[i].Path == path {
			m.selectedIndex = i
			if m.selectedIndex < 0 {
				m.selectedIndex = 0
			}
			if m.selectedIndex < m.listScrollIdx {
				m.listScrollIdx = m.selectedIndex
			}
			if m.selectedIndex >= m.listScrollIdx+m.viewport.Height {
				m.listScrollIdx = m.selectedIndex - m.viewport.Height + 1
				if m.listScrollIdx < 0 {
					m.listScrollIdx = 0
				}
			}
			m.state = StateList
			m.renderListView()
			return true
		}
	}
	return false
}

func (m *Model) exportLogsToFile(path string) error {
	entries := m.visibleSystemLogEntries()
	var sb strings.Builder
	for _, entry := range entries {
		sb.WriteString(fmt.Sprintf("%s | %s | %s | %s | %s", entry.Relative, entry.Event.Level, entry.Event.Category, entry.Event.Type, entry.Event.Message))
		if entry.Path != "" {
			sb.WriteString(" | path=" + entry.Path)
		}
		if len(entry.Event.Metadata) > 0 {
			keys := make([]string, 0, len(entry.Event.Metadata))
			for k := range entry.Event.Metadata {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				sb.WriteString(fmt.Sprintf(" | %s=%v", k, entry.Event.Metadata[k]))
			}
		}
		sb.WriteString("\n")
	}
	return os.WriteFile(path, []byte(sb.String()), 0o644)
}

func (m *Model) appendLog(text string, hit *engine.Result) {
	if text == "" && hit == nil {
		return
	}
	if hit != nil {
		hitCopy := *hit
		m.applyMarkedHit(&hitCopy)
		if text == "" {
			text = formatResult(hitCopy)
		}
		hit = &hitCopy
	}
	if hit != nil && m.historyAppendEnabled() {
		m.upsertHistoryHit(text, *hit)
		return
	}

	if len(m.logs) >= maxLogEntries {
		m.logs = m.logs[1:]
		m.logLineHits = m.logLineHits[1:]
		if m.selectedIndex > 0 {
			m.selectedIndex--
		}
		if m.listScrollIdx > 0 {
			m.listScrollIdx--
		}
	}

	m.logs = append(m.logs, text)
	if hit != nil {
		if len(m.hits) >= maxLogEntries {
			m.hits = m.hits[1:]
		}
		m.hits = append(m.hits, *hit)
		hitCopy := *hit
		m.logLineHits = append(m.logLineHits, &hitCopy)
	} else {
		m.logLineHits = append(m.logLineHits, nil)
	}

	// Auto-scroll to bottom if we are at the bottom
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

func (m *Model) appendCmd(text string) {
	if text == "" {
		return
	}
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		if line != "" {
			m.cmdOutput = append(m.cmdOutput, line)
		}
	}
	if len(m.cmdOutput) > maxCmdLines {
		m.cmdOutput = m.cmdOutput[len(m.cmdOutput)-maxCmdLines:]
	}
	m.cmdViewport.SetContent(strings.Join(m.cmdOutput, "\n"))
	m.cmdViewport.GotoBottom()
}

// executeCommand parses and runs a TUI command.
func (m *Model) executeCommand(input string) string {
	parts := strings.SplitN(input, " ", 2)
	name := strings.ToLower(parts[0])
	args := ""
	if len(parts) > 1 {
		args = parts[1]
	}

	for _, cmd := range m.commands {
		if cmd.Name == name {
			return cmd.Handler(m, args)
		}
	}
	return errorStyle.Render(fmt.Sprintf("Unknown command: %s (type :help for list)", name))
}

// formatResult formats a result for display.
func formatResult(r engine.Result) string {
	methodStr := r.Method
	if methodStr == "" {
		methodStr = "GET"
	}

	rowStyle := anomalyRowStyle(r)

	statusColor := statusStyle
	switch {
	case r.StatusCode >= 200 && r.StatusCode < 300:
		statusColor = status2xxStyle
	case r.StatusCode >= 300 && r.StatusCode < 400:
		statusColor = status3xxStyle
	case r.StatusCode == 403:
		statusColor = status403Style
	case r.StatusCode >= 400 && r.StatusCode < 500:
		statusColor = status4xxStyle
	case r.StatusCode >= 500:
		statusColor = status5xxStyle
	}

	extras := ""
	if r.StatusCode == 403 && r.Forbidden403Type != "" {
		forbidden403Style := mutedStyle
		switch r.Forbidden403Type {
		case "CF_WAF_BLOCK":
			forbidden403Style = forbiddenCFWAFStyle
		case "CF_ADMIN_403":
			forbidden403Style = forbiddenCFAdminStyle
		case "NGINX_403":
			forbidden403Style = forbiddenNginxStyle
		case "GENERIC_403":
			forbidden403Style = mutedStyle
		}
		extras += forbidden403Style.Render(fmt.Sprintf(" [%s]", r.Forbidden403Type))
	}
	if r.Redirect != "" {
		extras += mutedStyle.Render(fmt.Sprintf(" -> %s", r.Redirect))
	}
	if val, ok := r.Headers["Server"]; ok {
		extras += mutedStyle.Render(fmt.Sprintf(" [Server: %s]", val))
	}
	if val, ok := r.Headers["X-Powered-By"]; ok {
		extras += mutedStyle.Render(fmt.Sprintf(" [X-Powered-By: %s]", val))
	}
	if r.ContentType != "" {
		extras += mutedStyle.Render(fmt.Sprintf(" [%s]", r.ContentType))
	}
	if r.Duration > 0 {
		durationStyle := mutedStyle
		if hasLabel(r.Labels, "TIMING-ORACLE") {
			durationStyle = lipgloss.NewStyle().Foreground(DraculaPink).Bold(true)
		}
		extras += durationStyle.Render(fmt.Sprintf(" [%s]", r.Duration.Round(time.Millisecond)))
	}
	if len(r.DiscoveredParams) > 0 {
		extras += mutedStyle.Render(fmt.Sprintf(" [Params: %s]", strings.Join(r.DiscoveredParams, ",")))
	}
	if len(r.Labels) > 0 {
		extras += mutedStyle.Render(fmt.Sprintf(" [Labels: %s]", strings.Join(r.Labels, ",")))
	}
	if r.Confidence != "" {
		extras += mutedStyle.Render(fmt.Sprintf(" [Conf: %s]", r.Confidence))
	}

	return rowStyle.Render(fmt.Sprintf("%s %s %s %s %s %s%s",
		statusColor.Render(fmt.Sprintf("[%d]", r.StatusCode)),
		pinkStyle.Render(methodStr),
		highlightStyle.Render(r.Path),
		mutedStyle.Render(fmt.Sprintf("(Size:%d", r.Size)),
		mutedStyle.Render(fmt.Sprintf("W:%d L:%d)", r.Words, r.Lines)),
		extras,
		"",
	))
}

func formatLogEvent(ev engine.LogEvent, relative string) string {
	timestamp := ev.Timestamp
	if timestamp.IsZero() {
		timestamp = time.Now()
	}

	metaParts := make([]string, 0, len(ev.Metadata))
	if len(ev.Metadata) > 0 {
		keys := make([]string, 0, len(ev.Metadata))
		for k := range ev.Metadata {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			metaParts = append(metaParts, fmt.Sprintf("%s=%v", k, ev.Metadata[k]))
		}
	}

	levelStyle := logLevelStyle(ev.Level)
	categoryStyle := logCategoryStyle(ev.Category)
	parts := []string{
		mutedStyle.Render(timestamp.Format("15:04:05")),
		mutedStyle.Render(relative),
		levelStyle.Render(string(ev.Level)),
		categoryStyle.Render(logCategoryIcon(ev.Category) + " " + string(ev.Category)),
		pinkStyle.Render(string(ev.Type)),
	}
	message := ev.Message
	if message == "" {
		message = "(no message)"
	}
	parts = append(parts, message)
	if len(metaParts) > 0 {
		parts = append(parts, mutedStyle.Render("["+strings.Join(metaParts, " ")+"]"))
	}
	return strings.Join(parts, " ")
}

func (m *Model) View() string {
	if m.quitting {
		summary := renderEvasionSummary(m.Engine.EvasionSummaryRows())
		return "\n  " + mutedStyle.Render("DirFuzz finished. Goodbye!") + "\n\n  " + summary + "\n"
	}

	if !m.ready {
		return "Initializing..."
	}

	// Header
	elapsed := time.Since(m.startTime).Round(time.Second)
	total := atomic.LoadInt64(&m.Engine.TotalLines)
	processed := atomic.LoadInt64(&m.Engine.ProcessedLines)
	count200 := atomic.LoadInt64(&m.Engine.Count200)
	count403 := atomic.LoadInt64(&m.Engine.Count403)
	count404 := atomic.LoadInt64(&m.Engine.Count404)
	count429 := atomic.LoadInt64(&m.Engine.Count429)
	count500 := atomic.LoadInt64(&m.Engine.Count500)
	connErr := atomic.LoadInt64(&m.Engine.CountConnErr)
	autoFilterSuppressed := atomic.LoadInt64(&m.Engine.AutoFilterSuppressed)
	simhashSuppressed := atomic.LoadInt64(&m.Engine.SimhashSuppressed)
	harvestedPaths := atomic.LoadInt64(&m.Engine.HarvestedPaths)

	m.Engine.Config.RLock()
	paused := m.Engine.Config.IsPaused
	wordlistPath := m.Engine.Config.WordlistPath
	m.Engine.Config.RUnlock()

	progressPct := float64(0)
	if total > 0 {
		progressPct = float64(processed) / float64(total) * 100
	}

	if math.Abs(progressPct-m.lastProgressPct) > 1.0 {
		m.lastProgressPct = progressPct
		m.cachedFillStyle = lipgloss.NewStyle().Foreground(progressFillColor(progressPct))
	}

	// Status text (RUNNING or PAUSED)
	statusText := lipgloss.NewStyle().Foreground(DraculaGreen).Bold(true).Render("RUNNING")
	if paused {
		if m.commandPulseOn {
			statusText = lipgloss.NewStyle().Foreground(DraculaOrange).Bold(true).Render("PAUSED")
		} else {
			statusText = lipgloss.NewStyle().Foreground(DraculaRed).Bold(true).Render("PAUSED")
		}
	}

	// 1. Re-calculate stable widths
	availableWidth := m.width - 2
	if availableWidth < 10 {
		availableWidth = 10
	}

	// Row 1: Title, URL, Wordlist, Status, Elapsed
	separator := mutedStyle.Render(" │ ")
	titleStr := titleStyle.Render(" 🦇 DirFuzz ")
	urlStr := highlightStyle.Render(m.Engine.BaseURL())
	wordlistStr := mutedStyle.Render(wordlistPath)

	titleURL := fmt.Sprintf("%s%s%s%s%s", titleStr, separator, urlStr, separator, wordlistStr)
	statusElapsed := fmt.Sprintf("%s  %s", statusText, mutedStyle.Render(elapsed.String()))

	leftW := (availableWidth * 6) / 10
	rightW := availableWidth - leftW
	row1Left := lipgloss.NewStyle().Width(leftW).Align(lipgloss.Left).Render(titleURL)
	row1Right := lipgloss.NewStyle().Width(rightW).Align(lipgloss.Right).Render(statusElapsed)
	row1 := lipgloss.JoinHorizontal(lipgloss.Top, row1Left, row1Right)

	// Row 2: Badges
	var badgeItems []string
	badgeItems = append(badgeItems, renderStatusBadge(DraculaGreen, "✓", "2xx", count200))
	badgeItems = append(badgeItems, renderStatusBadge(DraculaOrange, "⛔", "403", count403))
	badgeItems = append(badgeItems, renderStatusBadge(DraculaPurple, "❓", "404", count404))
	badgeItems = append(badgeItems, renderStatusBadge(DraculaYellow, "🐢", "429", count429))
	badgeItems = append(badgeItems, renderStatusBadge(DraculaRed, "💥", "5xx", count500))
	badgeItems = append(badgeItems, renderStatusBadge(DraculaPink, "⚠", "Err", connErr))
	badgeItems = append(badgeItems, renderStatusBadge(DraculaPink, "◌", "AF", autoFilterSuppressed))
	badgeItems = append(badgeItems, renderStatusBadge(DraculaCyan, "⬢", "S404", simhashSuppressed))
	badgeItems = append(badgeItems, renderStatusBadge(DraculaGreen, "🌿", "Harvest", harvestedPaths))

	var spacedBadges []string
	for i, b := range badgeItems {
		spacedBadges = append(spacedBadges, b)
		if i < len(badgeItems)-1 {
			spacedBadges = append(spacedBadges, " ")
		}
	}
	row2 := lipgloss.JoinHorizontal(lipgloss.Left, spacedBadges...)

	// Format with commas helper
	formatComma := func(n int64) string {
		in := strconv.FormatInt(n, 10)
		var out []byte
		for i, c := range in {
			if i > 0 && (len(in)-i)%3 == 0 {
				out = append(out, ',')
			}
			out = append(out, byte(c))
		}
		return string(out)
	}

	etaStr := "N/A"
	if processed > 0 && total > processed {
		timePerItem := float64(elapsed) / float64(processed)
		remaining := float64(total - processed)
		eta := time.Duration(timePerItem * remaining)
		etaStr = "~" + eta.Round(time.Second).String()
	} else if processed == total && total > 0 {
		etaStr = "Done"
	}

	// Row 3: Progress, ETA
	progressTextLeft := mutedStyle.Render("PROGRESS    ")
	barWidth := 20
	bar := renderProgressBar(barWidth, progressPct, m.cachedFillStyle)

	pctStr := m.cachedFillStyle.Render(fmt.Sprintf("%5.1f%%", progressPct))
	countsStr := mutedStyle.Render(fmt.Sprintf("%s / %s", formatComma(processed), formatComma(total)))
	etaLabel := mutedStyle.Render(" │  ETA ")
	etaValue := lipgloss.NewStyle().Foreground(DraculaCyan).Render(etaStr)

	row3Content := lipgloss.JoinHorizontal(lipgloss.Center,
		progressTextLeft,
		bar,
		"        ",
		pctStr,
		" ",
		countsStr,
		etaLabel,
		etaValue,
	)

	row3 := lipgloss.NewStyle().Width(availableWidth).Align(lipgloss.Left).Render(row3Content)

	// Final Header Assembly
	headerContent := lipgloss.NewStyle().
		Padding(0, 1, 1, 1). // Top, Right, Bottom, Left
		Render(lipgloss.JoinVertical(lipgloss.Left,
			row1,
			row2,
			row3,
		))

	sep := separatorStyle.Render(strings.Repeat("─", m.width))
	header := lipgloss.JoinVertical(lipgloss.Top, headerContent, sep)

	var mainContent string
	remainingHeight := m.height - lipgloss.Height(header) - 1
	if remainingHeight < 1 {
		remainingHeight = 1
	}

	activeState := m.state
	if activeState == StateLogsPanel {
		activeState = m.previousState
		if activeState == StateLogsPanel || activeState == 0 {
			activeState = StateList
		}
	}
	logsVisible := (m.showLogsPanel || m.state == StateLogsPanel) && activeState != StateCommand
	logPanelSeparator := separatorStyle.Render(strings.Repeat("─", m.width))
	var logPanelRender string
	var actualLogPanelHeight int
	if logsVisible {
		logPanelRender = m.renderLogsPanel()
		if logPanelRender != "" {
			actualLogPanelHeight = lipgloss.Height(logPanelRender) + 1
		}
	}

	if activeState == StateList {
		contentHeight := remainingHeight
		contentHeight -= actualLogPanelHeight
		if contentHeight < 5 {
			contentHeight = 5
		}
		m.viewport.Height = contentHeight
		mainContent = m.viewport.View()
	} else if activeState == StateDashboard {
		contentHeight := remainingHeight
		contentHeight -= actualLogPanelHeight
		if contentHeight < 5 {
			contentHeight = 5
		}
		m.viewport.Height = contentHeight
		m.renderDashboardView()
		mainContent = m.viewport.View()
	} else if activeState == StateDetail {
		vpHeight := remainingHeight
		vpHeight -= actualLogPanelHeight
		if vpHeight < 5 {
			vpHeight = 5
		}
		relatedRender := ""
		relatedHeight := 0
		if m.selectedIndex >= 0 && m.selectedIndex < len(m.logLineHits) && m.logLineHits[m.selectedIndex] != nil {
			relatedRender = m.renderRelatedLogsSection(m.logLineHits[m.selectedIndex])
			if relatedRender != "" {
				relatedHeight = lipgloss.Height(relatedRender) + 1
				maxRelatedHeight := int(float64(vpHeight) * 0.4)
				if maxRelatedHeight < 5 {
					maxRelatedHeight = 5
				}
				if relatedHeight > maxRelatedHeight {
					relatedRender = lipgloss.NewStyle().MaxHeight(maxRelatedHeight - 1).Render(relatedRender)
					relatedHeight = maxRelatedHeight
				}
			}
		}
		paneHeight := vpHeight - relatedHeight
		if paneHeight < 6 {
			paneHeight = 6
		}
		paneOuterWidth := (m.width - 2) / 2
		innerPaneHeight := paneHeight - 2
		if innerPaneHeight < 4 {
			innerPaneHeight = 4
		}

		reqHeader := renderPaneHeader(requestPaneHeaderStyle, m.reqViewport.Width, "Request")
		resHeader := renderPaneHeader(responsePaneHeaderStyle, m.resViewport.Width, "Response")

		m.reqViewport.Height = innerPaneHeight - 1
		m.resViewport.Height = innerPaneHeight - 1
		if m.reqViewport.Height < 3 {
			m.reqViewport.Height = 3
		}
		if m.resViewport.Height < 3 {
			m.resViewport.Height = 3
		}
		reqPane := paneStyle.Width(paneOuterWidth - 2).Height(innerPaneHeight).Render(
			lipgloss.JoinVertical(lipgloss.Top,
				reqHeader,
				m.reqViewport.View(),
			),
		)
		resPane := paneStyle.Width(paneOuterWidth - 2).Height(innerPaneHeight).Render(
			lipgloss.JoinVertical(lipgloss.Top,
				resHeader,
				m.resViewport.View(),
			),
		)
		spacer := strings.Repeat(" ", m.width-(paneOuterWidth*2))
		mainContent = lipgloss.JoinHorizontal(lipgloss.Top, reqPane, spacer, resPane)
		if relatedRender != "" {
			mainContent = lipgloss.JoinVertical(lipgloss.Left,
				mainContent,
				separatorStyle.Render(strings.Repeat("─", m.width)),
				relatedRender,
			)
		}
	} else if activeState == StateHexView {
		vpHeight := remainingHeight
		vpHeight -= actualLogPanelHeight
		if vpHeight < 5 {
			vpHeight = 5
		}
		hexPaneWidth := m.width - 2
		if hexPaneWidth < 20 {
			hexPaneWidth = 20
		}
		m.hexViewport.Height = vpHeight - 4
		if m.hexViewport.Height < 3 {
			m.hexViewport.Height = 3
		}

		hexHeader := renderPaneHeader(requestPaneHeaderStyle, m.hexViewport.Width, m.hexViewHeader())
		hexSeparator := separatorStyle.Render(strings.Repeat("─", m.hexViewport.Width))
		hexPane := paneStyle.Width(hexPaneWidth).Height(vpHeight - 2).Render(
			lipgloss.JoinVertical(lipgloss.Top,
				hexHeader,
				hexSeparator,
				m.hexViewport.View(),
			),
		)
		mainContent = hexPane
	} else if activeState == StateDiffView {
		vpHeight := remainingHeight
		vpHeight -= actualLogPanelHeight
		if vpHeight < 5 {
			vpHeight = 5
		}
		paneOuterWidth := (m.width - 2) / 2
		leftTitle := "Reference"
		rightTitle := "Current"
		if m.diffReference != nil && m.diffReference.Title != "" {
			leftTitle = m.diffReference.Title
		}
		if m.diffCurrent != nil && m.diffCurrent.Title != "" {
			rightTitle = m.diffCurrent.Title
		}

		leftHeader := renderPaneHeader(diffHeaderStyle, m.diffLeftViewport.Width, leftTitle)
		rightHeader := renderPaneHeader(diffHeaderStyle, m.diffRightViewport.Width, rightTitle)
		m.diffLeftViewport.Height = vpHeight - 4
		m.diffRightViewport.Height = vpHeight - 4
		if m.diffLeftViewport.Height < 3 {
			m.diffLeftViewport.Height = 3
		}
		if m.diffRightViewport.Height < 3 {
			m.diffRightViewport.Height = 3
		}
		leftPane := paneStyle.Width(paneOuterWidth - 2).Height(vpHeight - 2).Render(
			lipgloss.JoinVertical(lipgloss.Top,
				leftHeader,
				separatorStyle.Render(strings.Repeat("─", m.diffLeftViewport.Width)),
				m.diffLeftViewport.View(),
			),
		)
		rightPane := paneStyle.Width(paneOuterWidth - 2).Height(vpHeight - 2).Render(
			lipgloss.JoinVertical(lipgloss.Top,
				rightHeader,
				separatorStyle.Render(strings.Repeat("─", m.diffRightViewport.Width)),
				m.diffRightViewport.View(),
			),
		)
		spacer := strings.Repeat(" ", m.width-(paneOuterWidth*2))
		mainContent = lipgloss.JoinHorizontal(lipgloss.Top, leftPane, spacer, rightPane)
	} else if m.state == StateCommand {
		mainContent = m.viewport.View()
	} else if activeState == StateRepeater {
		vpHeight := remainingHeight
		vpHeight -= actualLogPanelHeight
		if len(m.repeaterSessions) > 1 {
			vpHeight--
		}
		if vpHeight < 6 {
			vpHeight = 6
		}
		paneOuterWidth := (m.width - 2) / 2

		reqTitle := "✏  Repeater"
		if session := m.activeRepeaterSession(); session != nil {
			reqTitle = fmt.Sprintf("✏  Repeater [%d/%d] %s", m.activeRepeaterIdx+1, len(m.repeaterSessions), session.Label)
		}
		reqHeader := renderPaneHeader(requestPaneHeaderStyle, m.repeaterInput.Width(), reqTitle)
		var resHeader string
		if m.repeaterSending {
			resHeader = renderPaneHeader(responsePaneHeaderStyle, m.repeaterRespVp.Width, "Response ─── [⟳ Sending…]")
		} else {
			statusColor := statusStyle
			switch {
			case m.repeaterLastStatus >= 200 && m.repeaterLastStatus < 300:
				statusColor = status2xxStyle
			case m.repeaterLastStatus >= 300 && m.repeaterLastStatus < 400:
				statusColor = status3xxStyle
			case m.repeaterLastStatus == 403:
				statusColor = status403Style
			case m.repeaterLastStatus >= 400 && m.repeaterLastStatus < 500:
				statusColor = status4xxStyle
			case m.repeaterLastStatus >= 500:
				statusColor = status5xxStyle
			}
			resHeaderText := "Response"
			if m.repeaterLastStatus > 0 {
				statusText := http.StatusText(m.repeaterLastStatus)
				if statusText == "" {
					statusText = "Status"
				}
				resHeaderText = fmt.Sprintf("Response ─── [%s %s · %s]",
					statusColor.Render(strconv.Itoa(m.repeaterLastStatus)),
					statusColor.Render(statusText),
					mutedStyle.Render(m.repeaterLastDuration.Round(time.Millisecond).String()),
				)
			}
			resHeader = renderPaneHeader(responsePaneHeaderStyle, m.repeaterRespVp.Width, resHeaderText)
		}
		m.repeaterInput.SetHeight(vpHeight - 4)
		m.repeaterRespVp.Height = vpHeight - 4
		if m.repeaterRespVp.Height < 3 {
			m.repeaterRespVp.Height = 3
		}

		leftStyle := paneStyle
		rightStyle := paneStyle
		if m.repeaterFocusReq {
			leftStyle = paneActiveStyle
		} else {
			rightStyle = paneActiveStyle
		}

		separatorReq := separatorStyle.Render(strings.Repeat("─", m.repeaterInput.Width()))
		separatorRes := separatorStyle.Render(strings.Repeat("─", m.repeaterRespVp.Width))

		reqPane := leftStyle.Width(paneOuterWidth - 2).Height(vpHeight - 2).Render(
			lipgloss.JoinVertical(lipgloss.Top,
				reqHeader,
				separatorReq,
				m.repeaterInput.View(),
			),
		)
		resPane := rightStyle.Width(paneOuterWidth - 2).Height(vpHeight - 2).Render(
			lipgloss.JoinVertical(lipgloss.Top,
				resHeader,
				separatorRes,
				m.repeaterRespVp.View(),
			),
		)
		spacer := strings.Repeat(" ", m.width-(paneOuterWidth*2))
		mainContent = lipgloss.JoinHorizontal(lipgloss.Top, reqPane, spacer, resPane)
		if strip := m.repeaterSessionStrip(max(1, m.width-2)); strip != "" {
			mainContent = lipgloss.JoinVertical(lipgloss.Left, strip, mainContent)
		}
	}

	// Footer
	var leftChips string
	if m.statusMessage != "" {
		leftChips = m.statusMessage
	} else {
		if m.state == StateLogsPanel {
			leftChips = strings.Join([]string{
				keyChip("Enter", "jump"),
				keyChip("x", "detail"),
				keyChip("L", "logs"),
				keyChip("m", "dashboard"),
				keyChip("Esc/q", "back"),
				keyChip("Up/Down/PgUp/PgDn", "navigate"),
			}, "  ")
		} else if m.state == StateList {
			leftChips = strings.Join([]string{
				keyChip("Enter", "detail"),
				keyChip("r", "repeater"),
				keyChip("a", "anomalies"),
				keyChip("t", "mark"),
				keyChip("h/H", "hex"),
				keyChip("d", "diff"),
				keyChip("R", "bookmark"),
				keyChip("m", "dashboard"),
				keyChip("L", "logs"),
				keyChip(":", "commands"),
				keyChip("q", "quit"),
			}, "  ")
		} else if m.state == StateDashboard {
			leftChips = strings.Join([]string{
				keyChip("1-5", "tabs"),
				keyChip("f", "range"),
				keyChip("e", "export"),
				keyChip("L", "logs"),
				keyChip("m/q/Esc", "back"),
				keyChip("Up/Down/PgUp/PgDn", "scroll"),
			}, "  ")
		} else if m.state == StateDetail {
			leftChips = strings.Join([]string{
				keyChip("a", "anomalies"),
				keyChip("t", "mark"),
				keyChip("R", "bookmark"),
				keyChip("d", "diff"),
				keyChip("h/H", "hex"),
				keyChip("L", "logs"),
				keyChip("x", "related logs"),
				keyChip("Esc/q", "back"),
				keyChip("Up/Down", "scroll"),
			}, "  ")
		} else if m.state == StateHexView {
			leftChips = strings.Join([]string{
				keyChip("R", "bookmark"),
				keyChip("d", "diff"),
				keyChip("D", "replay diff"),
				keyChip("L", "logs"),
				keyChip("Tab", "switch request/response"),
				keyChip("Esc/q", "back"),
			}, "  ")
		} else if m.state == StateDiffView {
			leftChips = strings.Join([]string{
				keyChip("c", "compact/full"),
				keyChip("L", "logs"),
				keyChip("Esc/q", "back"),
				keyChip("Up/Down", "scroll"),
				keyChip("PgUp/PgDn", "page"),
			}, "  ")
		} else if m.state == StateRepeater {
			leftChips = strings.Join([]string{
				keyChip("R", "bookmark"),
				keyChip("D", "diff replay"),
				keyChip("Tab", "focus"),
				keyChip("Ctrl+R", "send"),
				keyChip("Ctrl+Y", "req"),
				keyChip("Alt+Y/B/C/W", "copy/export"),
				keyChip("Ctrl+P/N", "hist"),
				keyChip("[/]", "session"),
				keyChip("Ctrl+W", "close"),
				keyChip("Esc/q", "back"),
			}, "  ")
		} else {
			leftChips = strings.Join([]string{
				keyChip(":", "commands"),
				keyChip("p", "pause"),
				keyChip("q", "quit"),
				keyChip("r", "repeater"),
			}, "  ")
		}
	}

	var footerBody string
	var rightIndicator string
	if m.Engine != nil && m.Engine.Config.IsPaused {
		rightIndicator = lipgloss.NewStyle().Foreground(DraculaOrange).Render("● PAUSED  ") + mutedStyle.Render("v4.0.0")
	} else {
		rightIndicator = lipgloss.NewStyle().Foreground(DraculaGreen).Blink(true).Render("● SCANNING  ") + mutedStyle.Render("v4.0.0")
	}

	lWidth := lipgloss.Width(leftChips)
	rWidth := lipgloss.Width(rightIndicator)
	spc := m.width - 2 - lWidth - rWidth
	if spc < 0 {
		spc = 0
	}

	footerBody = m.footerBarStyle.Render(leftChips + strings.Repeat(" ", spc) + rightIndicator)
	if m.state == StateCommand {
		panelBorderColor := DraculaCyan
		if m.commandPulseOn {
			panelBorderColor = DraculaPurple
		}

		cmdInnerWidth := m.width - 6
		if cmdInnerWidth < 20 {
			cmdInnerWidth = 20
		}

		cmdPanelStyle := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(panelBorderColor).
			Width(m.width-2).
			Height(12).
			Padding(0, 1)

		cmdTitle := pinkStyle.Render(" ⌘ Command Palette ") +
			mutedStyle.Render(" (Esc to close, ':help' for commands) ")
		promptLine := cmdPromptStyle.Render(":") + m.textInput.View()

		suggestionsBlock := ""
		if len(m.suggestions) > 0 {
			dropdownWidth := suggestionDropdownWidth(m.suggestions, cmdInnerWidth)
			suggestionsBlock = renderSuggestionDropdown(m.suggestions, m.selectedSugIdx, dropdownWidth)
		}

		cmdSections := []string{
			cmdTitle,
			m.cmdViewport.View(),
			separatorStyle.Render(strings.Repeat("─", cmdInnerWidth)),
		}
		if suggestionsBlock != "" {
			cmdSections = append(cmdSections, suggestionsBlock)
		}
		cmdSections = append(cmdSections, promptLine)

		cmdContent := lipgloss.JoinVertical(lipgloss.Top, cmdSections...)
		footerBody = cmdPanelStyle.Render(cmdContent)
	}
	// Footer (keep minimal - command panel will overlay the bottom of main content)
	footer := footerBody

	bodyContent := mainContent

	if logsVisible && logPanelRender != "" {
		bodyContent = lipgloss.JoinVertical(lipgloss.Top,
			mainContent,
			logPanelSeparator,
			logPanelRender,
		)
	}

	paddedContent := lipgloss.NewStyle().
		Width(m.width).
		Height(remainingHeight).
		AlignVertical(lipgloss.Top).
		Render(bodyContent)

	// If command panel is active, overlay it by replacing the last `bottomBandHeight` lines
	if m.state == StateCommand {
		panel := footerBody
		panelLines := strings.Split(panel, "\n")

		// Use actual panel height (don't force fixed bottomBandHeight)
		panelHeight := len(panelLines)
		if panelHeight > remainingHeight {
			// Trim panel if terminal is too small
			panelLines = panelLines[panelHeight-remainingHeight:]
			panelHeight = len(panelLines)
		}

		mainLines := strings.Split(paddedContent, "\n")
		// Ensure mainLines length equals remainingHeight by padding if necessary
		if len(mainLines) < remainingHeight {
			padCount := remainingHeight - len(mainLines)
			for i := 0; i < padCount; i++ {
				mainLines = append(mainLines, strings.Repeat(" ", m.width))
			}
		}

		// Replace the last panelHeight lines of mainLines with panelLines
		start := len(mainLines) - panelHeight
		if start < 0 {
			start = 0
		}
		for i := 0; i < panelHeight && start+i < len(mainLines); i++ {
			mainLines[start+i] = panelLines[i]
		}

		paddedContent = strings.Join(mainLines, "\n")
		// Keep footer minimal line below overlay
		footer = ""
	}

	// Compose final screen
	return lipgloss.JoinVertical(lipgloss.Top, header, paddedContent, footer)
}

func parseRawRequestTarget(rawReq, baseURL string) (string, error) {
	lines := strings.Split(strings.ReplaceAll(rawReq, "\r\n", "\n"), "\n")
	if len(lines) == 0 {
		return "", fmt.Errorf("empty request")
	}

	parts := strings.SplitN(lines[0], " ", 3)
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid request line")
	}
	path := parts[1]

	host := ""
	for _, line := range lines[1:] {
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			hostParts := strings.SplitN(line, ":", 2)
			if len(hostParts) == 2 {
				host = strings.TrimSpace(hostParts[1])
				break
			}
		}
	}
	if host == "" {
		return "", fmt.Errorf("host header not found")
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	scheme := base.Scheme
	if strings.HasSuffix(host, ":443") {
		scheme = "https"
	} else if strings.HasSuffix(host, ":80") {
		scheme = "http"
	}

	if !strings.Contains(host, ":") {
		if scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	return fmt.Sprintf("%s://%s%s", scheme, host, path), nil
}

func sendRepeaterRequest(eng *engine.Engine, repeaterTarget string, rawReq string, sessionID int, ctx context.Context) tea.Cmd {
	return func() tea.Msg {
		targetURL, err := parseRawRequestTarget(rawReq, repeaterTarget)
		if err != nil {
			return RepeaterResultMsg{SessionID: sessionID, Err: err}
		}

		eng.Config.RLock()
		proxy := eng.Config.ProxyOut
		insecure := eng.Config.Insecure
		timeout := eng.Config.Timeout
		eng.Config.RUnlock()

		if timeout <= 0 {
			timeout = 10 * time.Second
		}

		start := time.Now()
		resp, err := httpclient.SendRawRequestWithContext(ctx, targetURL, []byte(rawReq), timeout, proxy, insecure)
		duration := time.Since(start)

		return RepeaterResultMsg{SessionID: sessionID, RawResponse: resp, Err: err, Duration: duration}
	}
}
