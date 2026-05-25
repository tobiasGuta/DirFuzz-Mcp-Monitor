package providers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/projectdiscovery/notify/pkg/types"
)

type SlackOptions struct {
	ID              string `yaml:"id,omitempty"`
	SlackChannel    string `yaml:"slack_channel,omitempty"`
	SlackUsername   string `yaml:"slack_username,omitempty"`
	SlackFormat     string `yaml:"slack_format,omitempty"`
	SlackIconEmoji  string `yaml:"slack_icon_emoji,omitempty"`
	SlackWebhookURL string `yaml:"slack_webhook_url,omitempty"`
}

type DiscordOptions struct {
	ID                string `yaml:"id,omitempty"`
	DiscordChannel    string `yaml:"discord_channel,omitempty"`
	DiscordUsername   string `yaml:"discord_username,omitempty"`
	DiscordFormat     string `yaml:"discord_format,omitempty"`
	DiscordWebhookURL string `yaml:"discord_webhook_url,omitempty"`
}

type TelegramOptions struct {
	ID                string `yaml:"id,omitempty"`
	TelegramAPIKey    string `yaml:"telegram_api_key,omitempty"`
	TelegramChatID    string `yaml:"telegram_chat_id,omitempty"`
	TelegramFormat    string `yaml:"telegram_format,omitempty"`
	TelegramParseMode string `yaml:"telegram_parsemode,omitempty"`
}

type PushoverOptions struct {
	ID               string   `yaml:"id,omitempty"`
	PushoverUserKey  string   `yaml:"pushover_user_key,omitempty"`
	PushoverAPIToken string   `yaml:"pushover_api_token,omitempty"`
	PushoverFormat   string   `yaml:"pushover_format,omitempty"`
	PushoverDevices  []string `yaml:"pushover_devices,omitempty"`
}

type SMTPOptions struct {
	ID                  string   `yaml:"id,omitempty"`
	SMTPServer          string   `yaml:"smtp_server,omitempty"`
	SMTPUsername        string   `yaml:"smtp_username,omitempty"`
	SMTPPassword        string   `yaml:"smtp_password,omitempty"`
	FromAddress         string   `yaml:"from_address,omitempty"`
	SMTPCc              []string `yaml:"smtp_cc,omitempty"`
	SMTPFormat          string   `yaml:"smtp_format,omitempty"`
	Subject             string   `yaml:"subject,omitempty"`
	SMTPHTML            bool     `yaml:"smtp_html,omitempty"`
	SMTPDisableStartTLS bool     `yaml:"smtp_disable_starttls,omitempty"`
}

type GoogleChatOptions struct {
	ID               string `yaml:"id,omitempty"`
	Key              string `yaml:"key,omitempty"`
	Token            string `yaml:"token,omitempty"`
	Space            string `yaml:"space,omitempty"`
	GoogleChatFormat string `yaml:"google_chat_format,omitempty"`
}

type TeamsOptions struct {
	ID              string `yaml:"id,omitempty"`
	TeamsWebhookURL string `yaml:"teams_webhook_url,omitempty"`
	TeamsFormat     string `yaml:"teams_format,omitempty"`
}

type GotifyOptions struct {
	ID               string `yaml:"id,omitempty"`
	GotifyHost       string `yaml:"gotify_host,omitempty"`
	GotifyPort       string `yaml:"gotify_port,omitempty"`
	GotifyToken      string `yaml:"gotify_token,omitempty"`
	GotifyFormat     string `yaml:"gotify_format,omitempty"`
	GotifyDisableTLS bool   `yaml:"gotify_disabletls,omitempty"`
	GotifyTitle      string `yaml:"gotify_title,omitempty"`
}

type CustomOptions struct {
	ID               string            `yaml:"id,omitempty"`
	CustomWebhookURL string            `yaml:"custom_webhook_url,omitempty"`
	CustomMethod     string            `yaml:"custom_method,omitempty"`
	CustomFormat     string            `yaml:"custom_format,omitempty"`
	CustomHeaders    map[string]string `yaml:"custom_headers,omitempty"`
	CustomSprig      string            `yaml:"custom_sprig,omitempty"`
}

type ProviderOptions struct {
	Slack      []*SlackOptions      `yaml:"slack,omitempty"`
	Discord    []*DiscordOptions    `yaml:"discord,omitempty"`
	Pushover   []*PushoverOptions   `yaml:"pushover,omitempty"`
	SMTP       []*SMTPOptions       `yaml:"smtp,omitempty"`
	Teams      []*TeamsOptions      `yaml:"teams,omitempty"`
	Telegram   []*TelegramOptions   `yaml:"telegram,omitempty"`
	GoogleChat []*GoogleChatOptions `yaml:"googlechat,omitempty"`
	Custom     []*CustomOptions     `yaml:"custom,omitempty"`
	Gotify     []*GotifyOptions     `yaml:"gotify,omitempty"`
}

type Provider interface {
	Send(message, cliFormat string) error
}

type Client struct {
	providers []Provider
	options   *types.Options
}

func New(providerOptions *ProviderOptions, options *types.Options) (*Client, error) {
	if options == nil {
		options = &types.Options{}
	}

	if providerOptions == nil {
		if options.ProviderConfig == "" {
			options.ProviderConfig = defaultProviderConfigPath()
		}
		loaded, err := loadProviderOptions(options.ProviderConfig)
		if err != nil {
			return nil, err
		}
		providerOptions = loaded
	}

	providers := make([]Provider, 0, len(providerOptions.Slack)+len(providerOptions.Discord)+len(providerOptions.Pushover)+len(providerOptions.SMTP)+len(providerOptions.Teams)+len(providerOptions.Telegram)+len(providerOptions.GoogleChat)+len(providerOptions.Custom)+len(providerOptions.Gotify))
	for _, p := range providerOptions.Slack {
		if p != nil && strings.TrimSpace(p.SlackWebhookURL) != "" {
			providers = append(providers, slackProvider{opt: p})
		}
	}
	for _, p := range providerOptions.Discord {
		if p != nil && strings.TrimSpace(p.DiscordWebhookURL) != "" {
			providers = append(providers, discordProvider{opt: p})
		}
	}
	for _, p := range providerOptions.Teams {
		if p != nil && strings.TrimSpace(p.TeamsWebhookURL) != "" {
			providers = append(providers, teamsProvider{opt: p})
		}
	}
	for _, p := range providerOptions.Telegram {
		if p != nil && strings.TrimSpace(p.TelegramAPIKey) != "" {
			providers = append(providers, telegramProvider{opt: p})
		}
	}
	for _, p := range providerOptions.Pushover {
		if p != nil && strings.TrimSpace(p.PushoverAPIToken) != "" && strings.TrimSpace(p.PushoverUserKey) != "" {
			providers = append(providers, pushoverProvider{opt: p})
		}
	}
	for _, p := range providerOptions.Gotify {
		if p != nil && strings.TrimSpace(p.GotifyHost) != "" && strings.TrimSpace(p.GotifyToken) != "" {
			providers = append(providers, gotifyProvider{opt: p})
		}
	}
	for _, p := range providerOptions.GoogleChat {
		if p != nil && (strings.TrimSpace(p.Key) != "" || strings.TrimSpace(p.Token) != "") {
			providers = append(providers, googleChatProvider{opt: p})
		}
	}
	for _, p := range providerOptions.Custom {
		if p != nil && strings.TrimSpace(p.CustomWebhookURL) != "" {
			providers = append(providers, customProvider{opt: p})
		}
	}

	if len(providers) == 0 {
		return nil, errors.New("notify: no providers configured")
	}

	return &Client{providers: providers, options: options}, nil
}

func (c *Client) Send(message string) error {
	if c == nil {
		return errors.New("notify: nil client")
	}
	if c.options != nil && c.options.MessageFormat != "" {
		message = renderTemplate(c.options.MessageFormat, message)
	}
	var errs []error
	for _, p := range c.providers {
		if err := p.Send(message, c.options.MessageFormat); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func defaultProviderConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(".config", "notify", "provider-config.yaml")
	}
	return filepath.Join(home, types.DefaultProviderConfigLocation)
}

func loadProviderOptions(path string) (*ProviderOptions, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("notify: load provider config %s: %w", path, err)
	}
	var opts ProviderOptions
	if err := yaml.Unmarshal(data, &opts); err != nil {
		return nil, fmt.Errorf("notify: parse provider config %s: %w", path, err)
	}
	return &opts, nil
}

func renderTemplate(format, message string) string {
	if format == "" {
		return message
	}
	quoted := strconvQuote(message)
	out := strings.ReplaceAll(format, "{{dataJsonString}}", quoted)
	out = strings.ReplaceAll(out, "{{data}}", message)
	return out
}

func strconvQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func postJSON(client *http.Client, method, rawURL string, headers map[string]string, body any) error {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return err
		}
	}
	req, err := http.NewRequest(method, rawURL, &buf)
	if err != nil {
		return err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if body != nil && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("notify webhook returned status %d", resp.StatusCode)
	}
	return nil
}

type slackProvider struct{ opt *SlackOptions }
type discordProvider struct{ opt *DiscordOptions }
type teamsProvider struct{ opt *TeamsOptions }
type telegramProvider struct{ opt *TelegramOptions }
type pushoverProvider struct{ opt *PushoverOptions }
type gotifyProvider struct{ opt *GotifyOptions }
type googleChatProvider struct{ opt *GoogleChatOptions }
type customProvider struct{ opt *CustomOptions }

func (p slackProvider) Send(message, _ string) error {
	cli := &http.Client{Timeout: 10 * time.Second}
	payload := map[string]any{
		"text":       renderTemplate(p.opt.SlackFormat, message),
		"username":   p.opt.SlackUsername,
		"icon_emoji": p.opt.SlackIconEmoji,
	}
	return postJSON(cli, http.MethodPost, p.opt.SlackWebhookURL, nil, payload)
}

func (p discordProvider) Send(message, _ string) error {
	cli := &http.Client{Timeout: 10 * time.Second}
	payload := map[string]any{
		"content": renderTemplate(p.opt.DiscordFormat, message),
	}
	return postJSON(cli, http.MethodPost, p.opt.DiscordWebhookURL, nil, payload)
}

func (p teamsProvider) Send(message, _ string) error {
	cli := &http.Client{Timeout: 10 * time.Second}
	payload := map[string]any{
		"text": renderTemplate(p.opt.TeamsFormat, message),
	}
	return postJSON(cli, http.MethodPost, p.opt.TeamsWebhookURL, nil, payload)
}

func (p telegramProvider) Send(message, _ string) error {
	cli := &http.Client{Timeout: 10 * time.Second}
	u := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", url.PathEscape(p.opt.TelegramAPIKey))
	form := url.Values{}
	form.Set("chat_id", p.opt.TelegramChatID)
	form.Set("text", renderTemplate(p.opt.TelegramFormat, message))
	if p.opt.TelegramParseMode != "" {
		form.Set("parse_mode", p.opt.TelegramParseMode)
	}
	req, err := http.NewRequest(http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := cli.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("telegram returned status %d", resp.StatusCode)
	}
	return nil
}

func (p pushoverProvider) Send(message, _ string) error {
	cli := &http.Client{Timeout: 10 * time.Second}
	form := url.Values{}
	form.Set("token", p.opt.PushoverAPIToken)
	form.Set("user", p.opt.PushoverUserKey)
	form.Set("message", renderTemplate(p.opt.PushoverFormat, message))
	if len(p.opt.PushoverDevices) > 0 {
		form.Set("device", strings.Join(p.opt.PushoverDevices, ","))
	}
	req, err := http.NewRequest(http.MethodPost, "https://api.pushover.net/1/messages.json", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := cli.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("pushover returned status %d", resp.StatusCode)
	}
	return nil
}

func (p gotifyProvider) Send(message, _ string) error {
	scheme := "https"
	if p.opt.GotifyDisableTLS {
		scheme = "http"
	}
	host := p.opt.GotifyHost
	if p.opt.GotifyPort != "" && !strings.Contains(host, ":") {
		host = host + ":" + p.opt.GotifyPort
	}
	rawURL := scheme + "://" + host + "/message?token=" + url.QueryEscape(p.opt.GotifyToken)
	cli := &http.Client{Timeout: 10 * time.Second}
	payload := map[string]any{
		"message": renderTemplate(p.opt.GotifyFormat, message),
		"title":   p.opt.GotifyTitle,
	}
	return postJSON(cli, http.MethodPost, rawURL, nil, payload)
}

func (p googleChatProvider) Send(message, _ string) error {
	cli := &http.Client{Timeout: 10 * time.Second}
	text := renderTemplate(p.opt.GoogleChatFormat, message)
	payload := map[string]any{"text": text}
	rawURL := ""
	if p.opt.Key != "" && p.opt.Token != "" && p.opt.Space != "" {
		rawURL = fmt.Sprintf("https://chat.googleapis.com/v1/spaces/%s/messages?key=%s&token=%s", url.PathEscape(p.opt.Space), url.QueryEscape(p.opt.Key), url.QueryEscape(p.opt.Token))
	}
	if rawURL == "" {
		return errors.New("google chat provider missing key/token/space")
	}
	return postJSON(cli, http.MethodPost, rawURL, nil, payload)
}

func (p customProvider) Send(message, _ string) error {
	cli := &http.Client{Timeout: 10 * time.Second}
	formatted := renderTemplate(p.opt.CustomFormat, message)
	method := strings.ToUpper(strings.TrimSpace(p.opt.CustomMethod))
	if method == "" {
		method = http.MethodPost
	}
	headers := make(map[string]string, len(p.opt.CustomHeaders))
	for k, v := range p.opt.CustomHeaders {
		headers[k] = v
	}

	if method == http.MethodGet {
		u, err := url.Parse(p.opt.CustomWebhookURL)
		if err != nil {
			return err
		}
		q := u.Query()
		q.Set("data", formatted)
		u.RawQuery = q.Encode()
		req, err := http.NewRequest(method, u.String(), nil)
		if err != nil {
			return err
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := cli.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("custom provider returned status %d", resp.StatusCode)
		}
		return nil
	}

	body := strings.NewReader(formatted)
	req, err := http.NewRequest(method, p.opt.CustomWebhookURL, body)
	if err != nil {
		return err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := cli.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("custom provider returned status %d", resp.StatusCode)
	}
	return nil
}
