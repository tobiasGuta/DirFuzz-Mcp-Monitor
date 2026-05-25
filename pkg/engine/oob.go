package engine

import (
	"fmt"

	interactclient "github.com/projectdiscovery/interactsh/pkg/client"
)

const defaultInteractshServers = "oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me"

func NewInteractshClient(serverURL, token string) (*interactclient.Client, error) {
	opts := *interactclient.DefaultOptions
	if serverURL != "" {
		opts.ServerURL = serverURL
	} else if opts.ServerURL == "" {
		opts.ServerURL = defaultInteractshServers
	}
	if token != "" {
		opts.Token = token
	}
	return interactclient.New(&opts)
}

func (e *Engine) SetInteractshClient(client *interactclient.Client, payload string, owned bool) {
	e.interactshMu.Lock()
	old := e.InteractshClient
	oldOwned := e.interactshClientOwned
	e.InteractshClient = client
	e.interactshClientOwned = owned
	e.InteractshPayload = payload
	if e.InteractshPayload == "" && client != nil {
		e.InteractshPayload = client.URL()
	}
	e.interactshMu.Unlock()

	if old != nil && oldOwned && old != client {
		_ = old.StopPolling()
		_ = old.Close()
	}
}

func (e *Engine) ensureInteractshClient() error {
	e.interactshMu.RLock()
	existing := e.InteractshClient
	e.interactshMu.RUnlock()
	if existing != nil {
		return nil
	}
	if !e.Config.OOBEnabled {
		return nil
	}

	client, err := NewInteractshClient(e.Config.InteractshServer, e.Config.InteractshToken)
	if err != nil {
		return fmt.Errorf("create interactsh client: %w", err)
	}
	e.SetInteractshClient(client, client.URL(), true)
	return nil
}

func (e *Engine) InteractshURL() string {
	e.interactshMu.RLock()
	payload := e.InteractshPayload
	client := e.InteractshClient
	e.interactshMu.RUnlock()
	if client == nil {
		return ""
	}
	if payload != "" {
		return payload
	}
	e.interactshMu.Lock()
	defer e.interactshMu.Unlock()
	if e.InteractshPayload == "" && e.InteractshClient != nil {
		e.InteractshPayload = e.InteractshClient.URL()
	}
	return e.InteractshPayload
}

func (e *Engine) closeInteractshClient() {
	e.interactshMu.Lock()
	client := e.InteractshClient
	owned := e.interactshClientOwned
	e.InteractshClient = nil
	e.InteractshPayload = ""
	e.interactshClientOwned = false
	e.interactshMu.Unlock()

	if client == nil || !owned {
		return
	}
	_ = client.StopPolling()
	_ = client.Close()
}

func (e *Engine) attachSharedInteractshClient(client *interactclient.Client) {
	if client == nil {
		return
	}
	e.SetInteractshClient(client, "", false)
}
