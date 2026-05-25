package main

import (
	"log/slog"
	"sync"
	"time"

	interactclient "github.com/projectdiscovery/interactsh/pkg/client"
	interactserver "github.com/projectdiscovery/interactsh/pkg/server"
	notifyclient "github.com/projectdiscovery/notify/pkg/client"
)

func startOOBPolling(client *interactclient.Client, cfg monitorConfig, logger *slog.Logger, notifyClient *notifyclient.Client) error {
	if client == nil {
		return nil
	}

	var seen sync.Map
	return client.StartPolling(5*time.Second, func(interaction *interactserver.Interaction) {
		if interaction == nil {
			return
		}
		key := interaction.Protocol + "|" + interaction.FullId + "|" + interaction.RemoteAddress + "|" + interaction.Timestamp.UTC().Format(time.RFC3339Nano)
		if _, loaded := seen.LoadOrStore(key, struct{}{}); loaded {
			return
		}

		logger.Warn("out-of-band interaction detected",
			"protocol", interaction.Protocol,
			"full_id", interaction.FullId,
			"remote_address", interaction.RemoteAddress,
		)

		if notifyClient == nil {
			return
		}

		message := formatOOBNotification(cfg.Target, interaction.Protocol, interaction.FullId, interaction.RemoteAddress)
		if err := notifyClient.Send(message); err != nil {
			logger.Error("failed to send oob notify message", "error", err)
		}
	})
}
