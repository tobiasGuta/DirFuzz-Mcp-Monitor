package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	notifyclient "github.com/projectdiscovery/notify/pkg/client"
	notifyproviders "github.com/projectdiscovery/notify/pkg/providers"
	notifytypes "github.com/projectdiscovery/notify/pkg/types"
)

func defaultNotifyProviderConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(".config", "notify", "provider-config.yaml")
	}
	return filepath.Join(home, notifytypes.DefaultProviderConfigLocation)
}

func newNotifyClient(cfg monitorConfig) (*notifyclient.Client, string, error) {
	configPath := strings.TrimSpace(cfg.NotifyProviderConfig)
	if configPath == "" {
		configPath = defaultNotifyProviderConfigPath()
	}

	if st, err := os.Stat(configPath); err == nil && !st.IsDir() {
		client, err := notifyclient.New(nil, &notifytypes.Options{
			ProviderConfig: configPath,
			Silent:         true,
			NoColor:        true,
			Bulk:           true,
		})
		if err != nil {
			return nil, configPath, err
		}
		return client, configPath, nil
	}

	if strings.TrimSpace(cfg.DiscordWebhook) != "" {
		providers := &notifyproviders.ProviderOptions{
			Custom: []*notifyproviders.CustomOptions{
				{
					ID:               "legacy-discord",
					CustomWebhookURL: cfg.DiscordWebhook,
					CustomMethod:     http.MethodPost,
					CustomFormat:     "{{data}}",
					CustomHeaders: map[string]string{
						"Content-Type": "application/json",
					},
				},
			},
		}
		client, err := notifyclient.New(providers, &notifytypes.Options{
			Silent:  true,
			NoColor: true,
			Bulk:    true,
		})
		if err != nil {
			return nil, configPath, err
		}
		return client, configPath, nil
	}

	return nil, configPath, nil
}

func formatFindingNotification(target string, interval time.Duration, findings []finding) string {
	if len(findings) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("DirFuzz Monitor - Changes Detected\n")
	b.WriteString("Target: ")
	b.WriteString(target)
	b.WriteString("\nNext scan in: ")
	b.WriteString(interval.String())
	b.WriteString("\n\n")

	for _, f := range findings {
		switch f.Type {
		case findingStatusChange:
			fmt.Fprintf(&b, "- status change: %s %d -> %d\n", f.Path, f.OldStatus, f.NewStatus)
		case findingContentChange:
			oldShort := shortHash(f.OldHash)
			newShort := shortHash(f.NewHash)
			fmt.Fprintf(&b, "- content change: %s hash %s -> %s\n", f.Path, oldShort, newShort)
		case findingBodySizeChange:
			fmt.Fprintf(&b, "- size change: %s %d -> %d\n", f.Path, f.OldSize, f.NewSize)
		case findingNewEndpoint:
			fmt.Fprintf(&b, "- new endpoint: %s returned %d\n", f.Path, f.NewStatus)
		}
	}

	return b.String()
}

func formatOOBNotification(target, protocol, fullID, remoteAddress string) string {
	return fmt.Sprintf(
		"DirFuzz Monitor - OOB Interaction Detected\nTarget: %s\nProtocol: %s\nID: %s\nRemote: %s",
		target,
		protocol,
		fullID,
		remoteAddress,
	)
}

func shortHash(hash string) string {
	if len(hash) <= 8 {
		return hash
	}
	return hash[:8]
}
