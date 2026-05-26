package main

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

type scanProfile struct {
	Target               string              `yaml:"target" json:"target"`
	Wordlist             string              `yaml:"wordlist" json:"wordlist"`
	ParamWordlist        string              `yaml:"param_wordlist" json:"param_wordlist"`
	Threads              int                 `yaml:"threads" json:"threads"`
	Delay                time.Duration       `yaml:"delay" json:"delay"`
	RPS                  int                 `yaml:"rps" json:"rps"`
	UserAgent            string              `yaml:"user_agent" json:"user_agent"`
	Headers              []string            `yaml:"headers" json:"headers"`
	AuthMatrix           map[string][]string `yaml:"auth_matrix" json:"auth_matrix"`
	Cookie               string              `yaml:"cookie" json:"cookie"`
	Methods              string              `yaml:"methods" json:"methods"`
	Body                 string              `yaml:"body" json:"body"`
	Follow               bool                `yaml:"follow" json:"follow"`
	MaxRedirects         int                 `yaml:"max_redirects" json:"max_redirects"`
	Timeout              time.Duration       `yaml:"timeout" json:"timeout"`
	Insecure             bool                `yaml:"insecure" json:"insecure"`
	MatchCodes           string              `yaml:"match_codes" json:"match_codes"`
	FilterSizes          string              `yaml:"filter_sizes" json:"filter_sizes"`
	Extensions           string              `yaml:"extensions" json:"extensions"`
	MatchRegex           string              `yaml:"match_regex" json:"match_regex"`
	FilterRegex          string              `yaml:"filter_regex" json:"filter_regex"`
	FilterWords          int                 `yaml:"filter_words" json:"filter_words"`
	FilterLines          int                 `yaml:"filter_lines" json:"filter_lines"`
	MatchWords           int                 `yaml:"match_words" json:"match_words"`
	MatchLines           int                 `yaml:"match_lines" json:"match_lines"`
	RTMin                time.Duration       `yaml:"rt_min" json:"rt_min"`
	RTMax                time.Duration       `yaml:"rt_max" json:"rt_max"`
	OutputFormat         string              `yaml:"output_format" json:"output_format"`
	OutputFile           string              `yaml:"output_file" json:"output_file"`
	HistoryMode          string              `yaml:"history_mode" json:"history_mode"`
	ReportFile           string              `yaml:"report_file" json:"report_file"`
	ReportFormat         string              `yaml:"report_format" json:"report_format"`
	SaveRaw              bool                `yaml:"save_raw" json:"save_raw"`
	Recursive            bool                `yaml:"recursive" json:"recursive"`
	RecursivePrune       *bool               `yaml:"recursive_prune" json:"recursive_prune"`
	MaxDepth             int                 `yaml:"max_depth" json:"max_depth"`
	Mutate               bool                `yaml:"mutate" json:"mutate"`
	SmartAPI             bool                `yaml:"smart_api" json:"smart_api"`
	AutoFilterThreshold  int                 `yaml:"auto_filter_threshold" json:"auto_filter_threshold"`
	SimhashThreshold     int                 `yaml:"simhash_threshold" json:"simhash_threshold"`
	SimhashClusterLimit  int                 `yaml:"simhash_cluster_limit" json:"simhash_cluster_limit"`
	H2Mode               bool                `yaml:"h2" json:"h2"`
	H2ConcurrentStreams  int                 `yaml:"h2_streams" json:"h2_streams"`
	TimingOracle         bool                `yaml:"time_oracle" json:"time_oracle"`
	TimeOracleK          float64             `yaml:"time_k" json:"time_k"`
	TimeOracleN          int                 `yaml:"time_n" json:"time_n"`
	TimeTrim             bool                `yaml:"time_trim" json:"time_trim"`
	Harvest              bool                `yaml:"harvest" json:"harvest"`
	HarvestJS            bool                `yaml:"harvest_js" json:"harvest_js"`
	HarvestAPI           bool                `yaml:"harvest_api" json:"harvest_api"`
	HarvestResponse      bool                `yaml:"harvest_response" json:"harvest_response"`
	HarvestResponseDepth int                 `yaml:"harvest_response_depth" json:"harvest_response_depth"`
	HarvestResponseFetch int                 `yaml:"harvest_response_fetch" json:"harvest_response_fetch"`
	EvasionLimit         int                 `yaml:"evasion_limit" json:"evasion_limit"`
	MaxRetries           int                 `yaml:"max_retries" json:"max_retries"`
	DryRun               bool                `yaml:"dry_run" json:"dry_run"`
	EagleFile            string              `yaml:"eagle_file" json:"eagle_file"`
	Resume               bool                `yaml:"resume" json:"resume"`
	ResumeFile           string              `yaml:"resume_file" json:"resume_file"`
	Calibrate            bool                `yaml:"calibrate" json:"calibrate"`
	ProxyFile            string              `yaml:"proxy_file" json:"proxy_file"`
	ProxyOut             string              `yaml:"proxy_out" json:"proxy_out"`
	PluginMatch          string              `yaml:"plugin_match" json:"plugin_match"`
	PluginMutate         string              `yaml:"plugin_mutate" json:"plugin_mutate"`
	NoTUI                bool                `yaml:"no_tui" json:"no_tui"`
	Verbose              bool                `yaml:"verbose" json:"verbose"`
	AntiBotFallback      *bool               `yaml:"anti_bot_fallback" json:"anti_bot_fallback"`
}

func applyProfile(cfg *cliConfig, set map[string]bool) error {
	data, err := os.ReadFile(cfg.Profile)
	if err != nil {
		return err
	}
	var p scanProfile
	// Initialize default values for int flags where 0 is meaningful.
	p.FilterWords = -1
	p.FilterLines = -1
	p.MatchWords = -1
	p.MatchLines = -1
	p.AutoFilterThreshold = -1
	p.SimhashThreshold = -1
	p.SimhashClusterLimit = -1
	p.H2ConcurrentStreams = -1
	p.TimeOracleN = -1
	p.TimeOracleK = -1
	p.EvasionLimit = -1

	if err := yaml.Unmarshal(data, &p); err != nil {
		return err
	}

	if !set["u"] && p.Target != "" {
		cfg.Target = p.Target
	}
	if !set["w"] && p.Wordlist != "" {
		cfg.Wordlist = p.Wordlist
	}
	if !set["param-wordlist"] && !set["param-wordlists"] && p.ParamWordlist != "" {
		cfg.ParamWordlist = p.ParamWordlist
	}
	if !set["t"] && p.Threads > 0 {
		cfg.Threads = p.Threads
	}
	if !set["delay"] && p.Delay > 0 {
		cfg.Delay = p.Delay
	}
	if !set["rps"] && p.RPS > 0 {
		cfg.RPS = p.RPS
	}
	if !set["ua"] && p.UserAgent != "" {
		cfg.UserAgent = p.UserAgent
	}
	if !set["H"] && len(p.Headers) > 0 {
		cfg.Headers = p.Headers
	}
	if !set["auth"] && len(p.AuthMatrix) > 0 {
		cfg.AuthMatrix = p.AuthMatrix
	}
	if !set["b"] && p.Cookie != "" {
		cfg.Cookie = p.Cookie
	}
	if !set["m"] && p.Methods != "" {
		cfg.Methods = p.Methods
	}
	if !set["d"] && p.Body != "" {
		cfg.Body = p.Body
	}
	if !set["follow"] && p.Follow {
		cfg.Follow = true
	}
	if !set["max-redirects"] && p.MaxRedirects > 0 {
		cfg.MaxRedirects = p.MaxRedirects
	}
	if !set["timeout"] && p.Timeout > 0 {
		cfg.Timeout = p.Timeout
	}
	if !set["k"] && p.Insecure {
		cfg.Insecure = true
	}
	if !set["mc"] && p.MatchCodes != "" {
		cfg.MatchCodes = p.MatchCodes
	}
	if !set["fs"] && p.FilterSizes != "" {
		cfg.FilterSizes = p.FilterSizes
	}
	if !set["e"] && p.Extensions != "" {
		cfg.Extensions = p.Extensions
	}
	if !set["mr"] && p.MatchRegex != "" {
		cfg.MatchRegex = p.MatchRegex
	}
	if !set["fr"] && p.FilterRegex != "" {
		cfg.FilterRegex = p.FilterRegex
	}
	if !set["fw"] && p.FilterWords != -1 {
		cfg.FilterWords = p.FilterWords
	}
	if !set["fl"] && p.FilterLines != -1 {
		cfg.FilterLines = p.FilterLines
	}
	if !set["mw"] && p.MatchWords != -1 {
		cfg.MatchWords = p.MatchWords
	}
	if !set["ml"] && p.MatchLines != -1 {
		cfg.MatchLines = p.MatchLines
	}
	if !set["rt-min"] && p.RTMin > 0 {
		cfg.RTMin = p.RTMin
	}
	if !set["rt-max"] && p.RTMax > 0 {
		cfg.RTMax = p.RTMax
	}
	if !set["of"] && p.OutputFormat != "" {
		cfg.OutputFormat = p.OutputFormat
	}
	if !set["o"] && p.OutputFile != "" {
		cfg.OutputFile = p.OutputFile
	}
	if !set["history-mode"] && p.HistoryMode != "" {
		cfg.HistoryMode = normalizeHistoryMode(p.HistoryMode)
	}
	if !set["report"] && p.ReportFile != "" {
		cfg.ReportFile = p.ReportFile
	}
	if !set["report-format"] && p.ReportFormat != "" {
		cfg.ReportFormat = p.ReportFormat
	}
	if !set["save-raw"] && p.SaveRaw {
		cfg.SaveRaw = true
	}
	if !set["r"] && p.Recursive {
		cfg.Recursive = true
	}
	if !set["recursive-prune"] && p.RecursivePrune != nil {
		cfg.RecursivePrune = *p.RecursivePrune
	}
	if !set["depth"] && p.MaxDepth > 0 {
		cfg.MaxDepth = p.MaxDepth
	}
	if !set["mutate"] && p.Mutate {
		cfg.Mutate = true
	}
	if !set["smart-api"] && p.SmartAPI {
		cfg.SmartAPI = true
	}
	if !set["af"] && p.AutoFilterThreshold != -1 {
		cfg.AutoFilterThreshold = p.AutoFilterThreshold
	}
	if !set["simhash-threshold"] && p.SimhashThreshold != -1 {
		cfg.SimhashThreshold = p.SimhashThreshold
	}
	if !set["simhash-cluster"] && p.SimhashClusterLimit != -1 {
		cfg.SimhashClusterLimit = p.SimhashClusterLimit
	}
	if !set["h2"] && p.H2Mode {
		cfg.H2Mode = true
	}
	if !set["h2-streams"] && p.H2ConcurrentStreams != -1 {
		cfg.H2ConcurrentStreams = p.H2ConcurrentStreams
	}
	if !set["time-oracle"] && p.TimingOracle {
		cfg.TimingOracle = true
	}
	if !set["time-k"] && p.TimeOracleK > 0 {
		cfg.TimeOracleK = p.TimeOracleK
	}
	if !set["time-n"] && p.TimeOracleN != -1 {
		cfg.TimeOracleN = p.TimeOracleN
	}
	if !set["time-trim"] && p.TimeTrim {
		cfg.TimeTrim = true
	}
	if !set["harvest"] && p.Harvest {
		cfg.Harvest = true
	}
	if !set["harvest-js"] && p.HarvestJS {
		cfg.HarvestJS = true
	}
	if !set["harvest-api"] && p.HarvestAPI {
		cfg.HarvestAPI = true
	}
	if !set["harvest-response"] && p.HarvestResponse {
		cfg.HarvestResponse = true
	}
	if !set["harvest-response-depth"] && p.HarvestResponseDepth > 0 {
		cfg.HarvestResponseDepth = p.HarvestResponseDepth
	}
	if !set["harvest-response-fetch"] && p.HarvestResponseFetch > 0 {
		cfg.HarvestResponseFetch = p.HarvestResponseFetch
	}
	if !set["evasion-limit"] && p.EvasionLimit != -1 {
		cfg.EvasionLimit = p.EvasionLimit
	}
	if !set["retry"] && p.MaxRetries > 0 {
		cfg.MaxRetries = p.MaxRetries
	}
	if !set["dry-run"] && p.DryRun {
		cfg.DryRun = true
	}
	if !set["eagle"] && p.EagleFile != "" {
		cfg.EagleFile = p.EagleFile
	}
	if !set["resume"] && p.Resume {
		cfg.Resume = true
	}
	if !set["resume-file"] && p.ResumeFile != "" {
		cfg.ResumeFile = p.ResumeFile
	}
	if !set["calibrate"] && p.Calibrate {
		cfg.Calibrate = true
	}
	if !set["proxy"] && p.ProxyFile != "" {
		cfg.ProxyFile = p.ProxyFile
	}
	if !set["proxy-out"] && p.ProxyOut != "" {
		cfg.ProxyOut = p.ProxyOut
	}
	if !set["plugin-match"] && p.PluginMatch != "" {
		cfg.PluginMatch = p.PluginMatch
	}
	if !set["plugin-mutate"] && p.PluginMutate != "" {
		cfg.PluginMutate = p.PluginMutate
	}
	if !set["no-tui"] && p.NoTUI {
		cfg.NoTUI = true
	}
	if !set["v"] && p.Verbose {
		cfg.Verbose = true
	}
	if !set["anti-bot-fallback"] && p.AntiBotFallback != nil {
		cfg.AntiBotFallback = *p.AntiBotFallback
	}
	return nil
}

func inferReportFormat(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".html", ".htm":
		return "html"
	default:
		return "markdown"
	}
}
