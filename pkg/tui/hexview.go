package tui

import (
	"encoding/hex"
	"fmt"
	"strings"

	"dirfuzz/pkg/engine"

	"github.com/charmbracelet/lipgloss"
)

// HexViewTarget describes which raw payload the hex viewer is showing.
type HexViewTarget int

const (
	HexViewRequest HexViewTarget = iota
	HexViewResponse
)

var (
	hexOffsetStyle  = lipgloss.NewStyle().Foreground(DraculaPurple).Bold(true)
	hexByteStyle    = lipgloss.NewStyle().Foreground(DraculaFg)
	hexControlStyle = lipgloss.NewStyle().Foreground(DraculaOrange).Bold(true)
	hexCRLFStyle    = lipgloss.NewStyle().Foreground(DraculaGreen).Bold(true)
	hexASCIIStyle   = lipgloss.NewStyle().Foreground(DraculaFg)
	hexDimStyle     = lipgloss.NewStyle().Foreground(DraculaComment)
	hexMissingStyle = lipgloss.NewStyle().Foreground(DraculaComment)
)

func (m *Model) currentHexHit() *engine.Result {
	idx := m.selectedIndex
	if m.state == StateHexView {
		idx = m.hexSelectedIndex
	}
	if idx < 0 || idx >= len(m.logLineHits) {
		return nil
	}
	return m.logLineHits[idx]
}

func (m *Model) openHexView(target HexViewTarget) bool {
	hit := m.currentHexHit()
	if hit == nil {
		return false
	}
	if len(hexTargetBytes(hit, target)) == 0 {
		return false
	}

	m.hexSelectedIndex = m.selectedIndex
	m.hexTarget = target
	m.state = StateHexView
	m.updateHexView()
	return true
}

func (m *Model) toggleHexTarget() {
	hit := m.currentHexHit()
	if hit == nil {
		return
	}

	next := HexViewRequest
	if m.hexTarget == HexViewRequest {
		next = HexViewResponse
	}

	if len(hexTargetBytes(hit, next)) == 0 {
		return
	}

	m.hexTarget = next
	m.updateHexView()
}

func (m *Model) hexViewHeader() string {
	hit := m.currentHexHit()
	if hit == nil {
		return "Hex View"
	}

	label := "Request"
	if m.hexTarget == HexViewResponse {
		label = "Response"
	}

	raw := hexTargetBytes(hit, m.hexTarget)
	return fmt.Sprintf("Hex View - %s (%d bytes)", label, len(raw))
}

func (m *Model) updateHexView() {
	hit := m.currentHexHit()
	if hit == nil {
		m.hexViewport.SetContent("No selected hit available.")
		return
	}

	raw := hexTargetBytes(hit, m.hexTarget)
	if len(raw) == 0 {
		m.hexViewport.SetContent("No raw bytes available. Enable --save-raw and retry.")
		m.hexViewport.GotoTop()
		return
	}

	m.hexViewport.SetContent(styleHexDump(hex.Dump(raw), raw))
	m.hexViewport.GotoTop()
}

func hexTargetBytes(hit *engine.Result, target HexViewTarget) []byte {
	if hit == nil {
		return nil
	}
	if target == HexViewResponse {
		return hit.ResponseBytes
	}
	return hit.RequestBytes
}

func styleHexDump(dump string, raw []byte) string {
	dump = strings.TrimSuffix(dump, "\n")
	if dump == "" {
		return ""
	}

	lines := strings.Split(dump, "\n")
	var out strings.Builder
	for lineIdx, line := range lines {
		start := lineIdx * 16
		end := start + 16
		if end > len(raw) {
			end = len(raw)
		}
		if start > len(raw) {
			start = len(raw)
		}
		out.WriteString(styleHexDumpLine(line, raw[start:end]))
		if lineIdx < len(lines)-1 {
			out.WriteByte('\n')
		}
	}

	return out.String()
}

func styleHexDumpLine(line string, rawLine []byte) string {
	if line == "" {
		return line
	}

	asciiStart := strings.Index(line, "|")
	if asciiStart < 0 {
		return line
	}

	var out strings.Builder
	out.WriteString(hexOffsetStyle.Render(line[:8]))

	cursor := 8
	hexBytes := len(rawLine)
	for i := 0; i < hexBytes; i++ {
		pos := 10 + i*3
		if i >= 8 {
			pos++
		}
		if pos > len(line) {
			break
		}
		if cursor < pos {
			out.WriteString(line[cursor:pos])
		}

		tokenEnd := pos + 2
		if tokenEnd > len(line) {
			tokenEnd = len(line)
		}
		token := line[pos:tokenEnd]
		out.WriteString(styleHexToken(rawLine[i], token))
		cursor = tokenEnd
	}

	if cursor < asciiStart {
		out.WriteString(line[cursor:asciiStart])
	}

	asciiEnd := strings.LastIndex(line, "|")
	if asciiEnd < 0 || asciiEnd <= asciiStart {
		out.WriteString(line[asciiStart:])
		return out.String()
	}

	out.WriteByte('|')
	ascii := line[asciiStart+1 : asciiEnd]
	for i := 0; i < len(ascii); i++ {
		if i >= len(rawLine) {
			out.WriteString(hexMissingStyle.Render(string(ascii[i])))
			continue
		}
		out.WriteString(styleHexASCII(rawLine[i], string(ascii[i])))
	}
	out.WriteByte('|')
	if asciiEnd+1 < len(line) {
		out.WriteString(line[asciiEnd+1:])
	}
	return out.String()
}

func styleHexToken(b byte, token string) string {
	switch {
	case b == '\r' || b == '\n':
		return hexCRLFStyle.Render(token)
	case b < 0x20 || b == 0x7f:
		return hexControlStyle.Render(token)
	case b == ' ':
		return hexDimStyle.Render(token)
	default:
		return hexByteStyle.Render(token)
	}
}

func styleHexASCII(b byte, ch string) string {
	switch {
	case b == '\r' || b == '\n':
		return hexCRLFStyle.Render(ch)
	case b < 0x20 || b == 0x7f:
		return hexControlStyle.Render(ch)
	default:
		return hexASCIIStyle.Render(ch)
	}
}
