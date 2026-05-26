package tui

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
)

func (m *Model) activeRepeaterRequestText() (string, error) {
	m.syncActiveRepeaterSessionFromUI()
	req := m.repeaterInput.Value()
	if strings.TrimSpace(req) == "" {
		return "", fmt.Errorf("no repeater request available")
	}
	return req, nil
}

func (m *Model) activeRepeaterResponseText() (string, error) {
	m.syncActiveRepeaterSessionFromUI()
	session := m.activeRepeaterSession()
	if session == nil || strings.TrimSpace(session.Response) == "" {
		return "", fmt.Errorf("no repeater response available")
	}
	return session.Response, nil
}

func (m *Model) copyRepeaterRequest() error {
	req, err := m.activeRepeaterRequestText()
	if err != nil {
		return err
	}
	return copyTextToClipboard(req)
}

func (m *Model) copyRepeaterResponse() error {
	resp, err := m.activeRepeaterResponseText()
	if err != nil {
		return err
	}
	return copyTextToClipboard(resp)
}

func (m *Model) copyRepeaterBoth() error {
	req, err := m.activeRepeaterRequestText()
	if err != nil {
		return err
	}
	resp, err := m.activeRepeaterResponseText()
	if err != nil {
		return err
	}
	return copyTextToClipboard(req + "\n\n" + resp)
}

func (m *Model) copyRepeaterCurl() error {
	req, err := m.activeRepeaterRequestText()
	if err != nil {
		return err
	}
	curlCmd, err := buildCurlCommand(req, m.repeaterTarget)
	if err != nil {
		return err
	}
	return copyTextToClipboard(curlCmd)
}

func (m *Model) exportRepeaterRequest(path string) (string, error) {
	req, err := m.activeRepeaterRequestText()
	if err != nil {
		return "", err
	}

	if strings.TrimSpace(path) == "" {
		tmp, err := os.CreateTemp("", "dirfuzz-repeater-*.http")
		if err != nil {
			return "", err
		}
		path = tmp.Name()
		if _, err := tmp.WriteString(req); err != nil {
			tmp.Close()
			return "", err
		}
		if err := tmp.Close(); err != nil {
			return "", err
		}
		return path, nil
	}

	if err := os.WriteFile(path, []byte(req), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func buildCurlCommand(rawReq, baseURL string) (string, error) {
	targetURL, err := parseRawRequestTarget(rawReq, baseURL)
	if err != nil {
		return "", err
	}

	req, body, err := parseRawRequest(rawReq)
	if err != nil {
		return "", err
	}

	quote := shellQuotePOSIX
	binary := "curl"
	if runtime.GOOS == "windows" {
		quote = shellQuotePowerShell
		binary = "curl.exe"
	}

	parts := []string{
		binary,
		"-i",
		"--path-as-is",
		"-X", quote(req.Method),
		quote(targetURL),
	}

	if req.Host != "" {
		parts = append(parts, "-H", quote("Host: "+req.Host))
	}

	keys := make([]string, 0, len(req.Header))
	for key := range req.Header {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if strings.EqualFold(key, "Content-Length") {
			continue
		}
		for _, value := range req.Header.Values(key) {
			parts = append(parts, "-H", quote(fmt.Sprintf("%s: %s", key, value)))
		}
	}

	if len(body) > 0 {
		parts = append(parts, "--data-binary", quote(string(body)))
	}

	return strings.Join(parts, " "), nil
}

func parseRawRequest(rawReq string) (*http.Request, []byte, error) {
	normalized := strings.ReplaceAll(rawReq, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	head := normalized
	bodyPart := ""
	if parts := strings.SplitN(normalized, "\n\n", 2); len(parts) == 2 {
		head = parts[0]
		bodyPart = parts[1]
	}
	wire := strings.ReplaceAll(head, "\n", "\r\n")
	if bodyPart != "" {
		if !strings.Contains(strings.ToLower(head), "\ncontent-length:") &&
			!strings.Contains(strings.ToLower(head), "\ntransfer-encoding:") {
			wire += fmt.Sprintf("\r\nContent-Length: %d", len(bodyPart))
		}
		wire += "\r\n\r\n" + bodyPart
	} else {
		wire += "\r\n\r\n"
	}

	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(wire)))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse raw request: %w", err)
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		req.Body.Close()
		return nil, nil, fmt.Errorf("failed to read raw request body: %w", err)
	}
	req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(body))

	return req, body, nil
}

func copyTextToClipboard(text string) error {
	candidates := clipboardCommandCandidates()
	for _, candidate := range candidates {
		if len(candidate) == 0 {
			continue
		}
		if _, err := exec.LookPath(candidate[0]); err != nil {
			continue
		}
		cmd := exec.Command(candidate[0], candidate[1:]...)
		cmd.Stdin = strings.NewReader(text)
		if output, err := cmd.CombinedOutput(); err == nil {
			return nil
		} else if len(output) > 0 {
			return fmt.Errorf("clipboard command %s failed: %s", candidate[0], strings.TrimSpace(string(output)))
		}
	}
	return fmt.Errorf("no supported clipboard utility found; use :export-request or Alt+W instead")
}

func clipboardCommandCandidates() [][]string {
	switch runtime.GOOS {
	case "windows":
		return [][]string{{"clip"}}
	case "darwin":
		return [][]string{{"pbcopy"}}
	default:
		return [][]string{
			{"wl-copy"},
			{"xclip", "-selection", "clipboard"},
			{"xsel", "--clipboard", "--input"},
		}
	}
}

func shellQuotePOSIX(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}

func shellQuotePowerShell(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}
