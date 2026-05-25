package engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// WebhookPayload is the payload sent to Slack/Discord/generic webhooks.
type WebhookPayload struct {
	Type      string `json:"type"`
	Path      string `json:"path"`
	Status    int    `json:"status"`
	OldStatus int    `json:"old_status,omitempty"`
	Size      int    `json:"size"`
	Delta     int    `json:"delta,omitempty"`
	Target    string `json:"target"`
	Time      string `json:"time"`
}

// SendWebhook posts a WebhookPayload to the given URL.
func SendWebhook(webhookURL string, payload WebhookPayload) error {
	u, parseErr := url.Parse(webhookURL)
	if parseErr != nil {
		return fmt.Errorf("webhook: invalid URL: %w", parseErr)
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("webhook: invalid URL: missing scheme or host")
	}
	if err := validateOutboundHostname(u.Hostname(), false); err != nil {
		return fmt.Errorf("webhook SSRF guard: %w", err)
	}

	var body []byte
	var err error

	if strings.Contains(webhookURL, "hooks.slack.com") {
		text := fmt.Sprintf("[%s] %s %s (status %d, size %d)",
			strings.ToUpper(payload.Type), payload.Target, payload.Path, payload.Status, payload.Size)
		slackBody := map[string]interface{}{
			"text": text,
			"attachments": []map[string]interface{}{
				{"color": "#FF0000", "text": fmt.Sprintf("Delta: %d bytes | Old status: %d", payload.Delta, payload.OldStatus)},
			},
		}
		body, err = json.Marshal(slackBody)
	} else if strings.Contains(webhookURL, "discord.com/api/webhooks") {
		color := 0xFF0000
		if payload.Type == "content_drift" {
			color = 0xFFA500
		}
		discordBody := map[string]interface{}{
			"embeds": []map[string]interface{}{
				{
					"title":       fmt.Sprintf("[%s] %s", strings.ToUpper(payload.Type), payload.Path),
					"description": fmt.Sprintf("Target: %s\nStatus: %d | Size: %d | Delta: %d", payload.Target, payload.Status, payload.Size, payload.Delta),
					"color":       color,
				},
			},
		}
		body, err = json.Marshal(discordBody)
	} else {
		body, err = json.Marshal(payload)
	}

	if err != nil {
		return fmt.Errorf("webhook marshal: %w", err)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook: non-2xx response %d", resp.StatusCode)
	}
	return nil
}

// newWebhookPayload builds a WebhookPayload from a scan result.
func newWebhookPayload(r Result, payloadType string, target string) WebhookPayload {
	return WebhookPayload{
		Type:      payloadType,
		Path:      r.Path,
		Status:    r.StatusCode,
		OldStatus: r.OldStatusCode,
		Size:      r.Size,
		Delta:     r.DriftDeltaBytes,
		Target:    target,
		Time:      time.Now().UTC().Format(time.RFC3339),
	}
}
