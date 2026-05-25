package types

const DefaultProviderConfigLocation = ".config/notify/provider-config.yaml"

type Options struct {
	Verbose            bool     `yaml:"verbose,omitempty"`
	NoColor            bool     `yaml:"no_color,omitempty"`
	Silent             bool     `yaml:"silent,omitempty"`
	Version            bool     `yaml:"version,omitempty"`
	ProviderConfig     string   `yaml:"provider_config,omitempty"`
	Providers          []string `yaml:"providers,omitempty"`
	IDs                []string `yaml:"ids,omitempty"`
	Proxy              string   `yaml:"proxy,omitempty"`
	RateLimit          int      `yaml:"rate_limit,omitempty"`
	Delay              int      `yaml:"delay,omitempty"`
	MessageFormat      string   `yaml:"message_format,omitempty"`
	Stdin              bool     `yaml:"stdin,omitempty"`
	Bulk               bool     `yaml:"bulk,omitempty"`
	CharLimit          int      `yaml:"char_limit,omitempty"`
	Data               string   `yaml:"data,omitempty"`
	DisableUpdateCheck bool     `yaml:"disable_update_check,omitempty"`
}
