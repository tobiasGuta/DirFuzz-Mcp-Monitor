package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"dirfuzz/pkg/engine"
)

const (
	cliVersion        = "4.0.0"
	defaultMatchCodes = "200,204,301,302,307,308,401,403,405,500"
	defaultResumeFile = ".dirfuzz-resume.json"
)

func parseFlags() cliConfig {
	// ── Meta ─────────────────────────────────────────────────────────────────
	showVersion := flag.Bool("version", false, "Print version and exit")
	noTUI := flag.Bool("no-tui", false, "Disable the TUI — print results to stdout (good for piping)")
	verbose := flag.Bool("v", false, "Verbose: log every request, not only hits (no-tui mode only)")

	// ── Required ─────────────────────────────────────────────────────────────
	target := flag.String("u", "", "Target URL to fuzz  (required)")
	wordlist := flag.String("w", "", "Path to wordlist file  (required, unless -resume)")
	paramWordlist := flag.String("param-wordlist", "", "Path to parameter wordlist; enables automatic parameter fuzzing when set")
	flag.StringVar(paramWordlist, "param-wordlists", "", "Alias for --param-wordlist")
	profile := flag.String("profile", "", "Path to YAML/JSON scan profile; explicit CLI flags override profile values")

	// ── Workers / throttle ────────────────────────────────────────────────────
	threads := flag.Int("t", engine.DefaultWorkerCount, "Number of concurrent workers")
	delay := flag.Duration("delay", 0, "Fixed delay between requests per worker (e.g. 100ms)")
	rps := flag.Int("rps", 0, "Global requests-per-second cap  (0 = unlimited)")

	// ── HTTP ─────────────────────────────────────────────────────────────────
	ua := flag.String("ua", "", "Override the User-Agent header")
	cookie := flag.String("b", "", "Cookie header value  (shorthand for -H 'Cookie: …')")
	methods := flag.String("m", "", "HTTP methods, comma-separated  (default: GET)")
	verbTamper := flag.Bool(
		"verb-tamper",
		false,
		"Inject X-HTTP-Method-Override / X-Forwarded-Method headers alongside every non-GET method (requires -m with non-GET verbs)",
	)
	body := flag.String("d", "", "Request body for POST / PUT")
	follow := flag.Bool("follow", false, "Follow HTTP redirects")
	maxRedirects := flag.Int("max-redirects", engine.DefaultMaxRedirects, "Maximum redirects to follow")
	timeout := flag.Duration("timeout", engine.DefaultHTTPTimeout, "Per-request timeout  (e.g. 5s)")
	maxDuration := flag.Duration("max-duration", engine.DefaultMaxScanDuration, "Maximum total scan duration before shutdown (e.g. 60s, 0 = unlimited)")
	insecure := flag.Bool("k", false, "Skip TLS certificate verification")
	oob := flag.Bool("oob", false, "Enable out-of-band Interactsh payload generation and polling")
	oobServer := flag.String("oob-server", "", "Interactsh server URL(s) to use for OOB payloads")
	oobToken := flag.String("oob-token", "", "Interactsh authentication token")

	// ── Matching / filtering ─────────────────────────────────────────────────
	matchCodes := flag.String("mc", defaultMatchCodes, "Status codes to treat as hits, comma-separated")
	filterSizes := flag.String("fs", "", "Response sizes to filter out (bytes), comma-separated")
	extensions := flag.String("e", "", "Extensions to append, comma-separated  (e.g. php,html,js)")
	matchRegex := flag.String("mr", "", "Only surface results whose body matches this regex")
	filterRegex := flag.String("fr", "", "Discard results whose body matches this regex")
	filterWords := flag.Int("fw", -1, "Filter results with exactly N words  (-1 = off)")
	filterLines := flag.Int("fl", -1, "Filter results with exactly N lines  (-1 = off)")
	matchWords := flag.Int("mw", -1, "Only surface results with exactly N words  (-1 = off)")
	matchLines := flag.Int("ml", -1, "Only surface results with exactly N lines  (-1 = off)")
	rtMin := flag.Duration("rt-min", 0, "Filter responses faster than this  (e.g. 200ms)")
	rtMax := flag.Duration("rt-max", 0, "Filter responses slower than this  (e.g. 5s)")

	// ── Output ───────────────────────────────────────────────────────────────
	outputFormat := flag.String("of", "", "Output format: jsonl | csv | url  (default: jsonl when -o is set)")
	outputFile := flag.String("o", "", "Write results to this file")
	historyMode := flag.String("history-mode", HistoryModeOverwrite, "Output history mode: overwrite | append  (append requires -o with JSONL)")
	reportFile := flag.String("report", "", "Write a Markdown/HTML summary report to this file")
	headerAudit := flag.Bool(
		"header-audit",
		false,
		"After the scan, analyse security headers on every result and print a findings summary (appended to --report if set)",
	)
	reportFormat := flag.String("report-format", "", "Report format: markdown | html  (inferred from -report extension when empty)")
	saveRaw := flag.Bool("save-raw", false, "Save raw HTTP request/response bytes in results")

	// ── Scan modes ───────────────────────────────────────────────────────────
	recursive := flag.Bool("r", false, "Recursive directory scanning")
	recursivePrune := flag.Bool("recursive-prune", true, "Prune low-value static/resource branches during recursive scanning")
	maxDepth := flag.Int("depth", engine.DefaultMaxDepth, "Maximum recursion depth  (requires -r)")
	mutate := flag.Bool("mutate", false, "Append backup/swap suffixes to every hit (.bak, .old, ~, …)")
	smartAPI := flag.Bool("smart-api", false, "Multi-method fuzzing only on API-style paths (/api/, /v1/, …)")
	autoFilterThreshold := flag.Int("af", engine.DefaultAutoFilterThreshold,
		"Auto-filter: suppress repeated same-size responses after N occurrences")
	simhashThreshold := flag.Int("simhash-threshold", engine.DefaultSimhashThreshold,
		"Soft-404 SimHash Hamming distance threshold")
	simhashClusterLimit := flag.Int("simhash-cluster", engine.DefaultSimhashClusterLimit,
		"Soft-404 SimHash cluster size before suppression")
	h2Mode := flag.Bool("h2", false, "Send fuzzing requests over HTTP/2 (ALPN h2 or h2c)")
	h2Streams := flag.Int("h2-streams", engine.DefaultH2ConcurrentStreams, "Max concurrent HTTP/2 streams per connection")
	timeOracle := flag.Bool("time-oracle", false, "Use response-time oracle mode for blind path enumeration")
	timeK := flag.Float64("time-k", engine.TimingOracleDefaultK, "Timing oracle sigma multiplier")
	timeN := flag.Int("time-n", engine.TimingOracleDefaultRepeatN, "Timing oracle requests per path")
	timeTrim := flag.Bool("time-trim", false, "Trim highest and lowest timing samples before analysis")
	harvest := flag.Bool("harvest", false, "Harvest endpoints from JS, OpenAPI, GraphQL, and generic response bodies before scanning")
	harvestJS := flag.Bool("harvest-js", false, "Harvest endpoints from JavaScript only")
	harvestAPI := flag.Bool("harvest-api", false, "Harvest endpoints from OpenAPI and GraphQL only")
	harvestResponse := flag.Bool("harvest-response", false, "Harvest endpoints from generic HTTP responses, especially JSON API bodies")
	harvestPassive := flag.Bool("harvest-passive", false, "Harvest passive URLs from Wayback, Common Crawl, and AlienVault OTX before scanning")
	harvestSourceMaps := flag.Bool("harvest-sourcemaps", false, "Harvest routes from JavaScript source maps when .js responses expose one")
	harvestResponseDepth := flag.Int("harvest-response-depth", engine.DefaultHarvestResponseDepth, "Maximum follow-up depth for response-driven endpoint harvesting")
	harvestResponseFetch := flag.Int("harvest-response-fetch", engine.DefaultHarvestResponseFetch, "Maximum number of follow-up response fetches for response-driven harvesting")
	harvestOTXKey := flag.String("harvest-otx-key", "", "AlienVault OTX API key for passive URL harvesting")
	evasionLimit := flag.Int("evasion-limit", engine.DefaultEvasionLimit, "Max bypass techniques to try per path")
	maxRetries := flag.Int("retry", 0, "Retry failed requests up to N times on connection error")
	dryRun := flag.Bool("dry-run", false, "Estimate request volume and exit without sending traffic")
	maxWSFrames := flag.Int("max-ws-frames", 5000, "Maximum number of WebSocket frames to store in memory")
	fourOhThreeBypass := flag.Bool("bypass-403", false, "On every 403 hit, retry with path and header bypass techniques (X-Original-URL, dot-slash, url-encoding, …)")
	antiBotFallback := flag.Bool("anti-bot-fallback", true, "Enable the headless browser anti-bot fallback when WAF or challenge responses are detected")
	swarm := flag.Bool("swarm", false, "Enable distributed worker mode for large authorized scans")
	swarmProvider := flag.String("swarm-provider", "", "Swarm provider backend: local or lambda")
	swarmNodes := flag.Int("swarm-nodes", 4, "Number of worker nodes to fan out across")
	swarmChunkSize := flag.Int("swarm-chunk-size", 5000, "Wordlist lines per worker chunk")
	swarmWorker := flag.Bool("swarm-worker", false, "Internal worker entrypoint")

	// ── Eagle mode ───────────────────────────────────────────────────────────
	eagleFile := flag.String("eagle", "",
		"Eagle mode: path to a previous scan JSONL — highlights changed/new endpoints")

	// ── Resume ───────────────────────────────────────────────────────────────
	resume := flag.Bool("resume", false, "Resume a previous scan from the saved state file")
	resumeFile := flag.String("resume-file", defaultResumeFile, "Path of the resume-state JSON file")

	// ── Calibration ──────────────────────────────────────────────────────────
	calibrate := flag.Bool("calibrate", false,
		"Auto-calibrate: probe random paths to detect wildcard / soft-404 responses")

	// ── Proxy ────────────────────────────────────────────────────────────────
	proxyFile := flag.String("proxy", "", "Path to proxy list  (HTTP / SOCKS5 URLs, one per line)")
	proxyOut := flag.String("proxy-out", "",
		"Forward every hit to this proxy for manual review  (e.g. http://127.0.0.1:8080)")

	// ── Lua plugins ──────────────────────────────────────────────────────────
	pluginMatch := flag.String(
		"plugin-match",
		"",
		"Lua plugin providing match(r) for custom hit logic",
	)

	pluginMutate := flag.String(
		"plugin-mutate",
		"",
		"Lua plugin providing mutate(word) for custom payload generation",
	)

	activePoC := flag.String(
		"active-poc",
		"",
		"Lua PoC plugin with active HTTP requests via http_send()",
	)

	// ── Ssrf Protection ──────────────────────────────────────────────────────────

	allowPrivate := flag.Bool(
		"allow-private",
		false,
		"Allow scanning private/internal IP ranges (disable SSRF protection)",
	)

	// ── Multi-value ──────────────────────────────────────────────────────────
	var headers multiFlag
	flag.Var(&headers, "H", "Add a custom header  (format: 'Key: Value', repeatable)")
	var authEntries multiFlag
	flag.Var(&authEntries, "auth", "Add an auth role mapping as role=Header: Value||Header2: Value2 (repeatable)")

	flag.Usage = printUsage
	flag.Parse()
	setFlags := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) { setFlags[f.Name] = true })

	if *showVersion {
		fmt.Fprintf(os.Stderr, "DirFuzz v%s\n", cliVersion)
		os.Exit(0)
	}

	// Infer output format when -o is provided without -of.
	outFmt := *outputFormat
	if outFmt == "" && *outputFile != "" {
		outFmt = engine.DefaultOutputFormat // "jsonl"
	}

	cfg := cliConfig{
		Target:        *target,
		Wordlist:      *wordlist,
		Profile:       *profile,
		ParamWordlist: *paramWordlist,

		Threads:     *threads,
		Delay:       *delay,
		RPS:         *rps,
		MaxDuration: *maxDuration,

		UserAgent:    *ua,
		Headers:      []string(headers),
		AuthMatrix:   nil,
		Cookie:       *cookie,
		Methods:      *methods,
		VerbTamper:   *verbTamper,
		Body:         *body,
		Follow:       *follow,
		MaxRedirects: *maxRedirects,
		Timeout:      *timeout,
		Insecure:     *insecure,
		OOB:          *oob,
		OOBServer:    *oobServer,
		OOBToken:     *oobToken,

		MatchCodes:  *matchCodes,
		FilterSizes: *filterSizes,
		Extensions:  *extensions,
		MatchRegex:  *matchRegex,
		FilterRegex: *filterRegex,
		FilterWords: *filterWords,
		FilterLines: *filterLines,
		MatchWords:  *matchWords,
		MatchLines:  *matchLines,
		RTMin:       *rtMin,
		RTMax:       *rtMax,

		OutputFormat: outFmt,
		OutputFile:   *outputFile,
		HistoryMode:  normalizeHistoryMode(*historyMode),
		ReportFile:   *reportFile,
		HeaderAudit:  *headerAudit,
		ReportFormat: *reportFormat,
		SaveRaw:      *saveRaw,

		Recursive:            *recursive,
		RecursivePrune:       *recursivePrune,
		MaxDepth:             *maxDepth,
		Mutate:               *mutate,
		SmartAPI:             *smartAPI,
		AutoFilterThreshold:  *autoFilterThreshold,
		SimhashThreshold:     *simhashThreshold,
		SimhashClusterLimit:  *simhashClusterLimit,
		H2Mode:               *h2Mode,
		H2ConcurrentStreams:  *h2Streams,
		TimingOracle:         *timeOracle,
		TimeOracleK:          *timeK,
		TimeOracleN:          *timeN,
		TimeTrim:             *timeTrim,
		Harvest:              *harvest,
		HarvestJS:            *harvestJS,
		HarvestAPI:           *harvestAPI,
		HarvestResponse:      *harvestResponse,
		HarvestPassive:       *harvest || *harvestPassive,
		HarvestSourceMaps:    *harvestSourceMaps,
		HarvestResponseDepth: *harvestResponseDepth,
		HarvestResponseFetch: *harvestResponseFetch,
		HarvestOTXKey:        *harvestOTXKey,
		EvasionLimit:         *evasionLimit,
		MaxRetries:           *maxRetries,
		DryRun:               *dryRun,
		MaxWSFrames:          *maxWSFrames,
		FourOhThreeBypass:    *fourOhThreeBypass,
		AntiBotFallback:      *antiBotFallback,

		EagleFile: *eagleFile,

		Resume:     *resume,
		ResumeFile: *resumeFile,

		Calibrate: *calibrate,

		ProxyFile: *proxyFile,
		ProxyOut:  *proxyOut,

		PluginMatch:  *pluginMatch,
		PluginMutate: *pluginMutate,
		ActivePoC:    *activePoC,

		NoTUI:   *noTUI,
		Verbose: *verbose,

		AllowPrivate: *allowPrivate,
	}

	if authMatrix, err := parseAuthMatrix([]string(authEntries)); err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid -auth value: %v\n", err)
		os.Exit(1)
	} else {
		cfg.AuthMatrix = authMatrix
	}

	if cfg.Profile != "" {
		if err := applyProfile(&cfg, setFlags); err != nil {
			fmt.Fprintf(os.Stderr, "error: loading profile: %v\n", err)
			os.Exit(1)
		}
	}
	if cfg.OutputFormat == "" && cfg.OutputFile != "" {
		cfg.OutputFormat = engine.DefaultOutputFormat
	}
	cfg.HistoryMode = normalizeHistoryMode(cfg.HistoryMode)
	if cfg.ReportFormat == "" && cfg.ReportFile != "" {
		cfg.ReportFormat = inferReportFormat(cfg.ReportFile)
	}
	if cfg.ParamWordlist != "" {
		words, err := loadWordlistEntries(cfg.ParamWordlist)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: loading --param-wordlist: %v\n", err)
			os.Exit(1)
		}
		cfg.ParamWords = words
	}

	if *swarm {
		cfg.Swarm = true
		cfg.SwarmProvider = strings.ToLower(strings.TrimSpace(*swarmProvider))
		cfg.SwarmNodes = *swarmNodes
		cfg.SwarmChunkSize = *swarmChunkSize
	}
	if *swarmWorker {
		cfg.SwarmWorker = true
	}

	if cfg.ActivePoC == "" && !cfg.SwarmWorker {
		if cfg.Target == "" {
			fmt.Fprintln(os.Stderr, "error: -u <target> is required")
			fmt.Fprintln(os.Stderr)
			flag.Usage()
			os.Exit(1)
		}
		if cfg.Wordlist == "" && !cfg.Resume {
			fmt.Fprintln(os.Stderr, "error: -w <wordlist> is required (or pass -resume to resume a previous scan)")
			fmt.Fprintln(os.Stderr)
			flag.Usage()
			os.Exit(1)
		}
	}

	if cfg.Threads < 1 {
		fmt.Fprintln(os.Stderr, "error: -t must be >= 1")
		os.Exit(1)
	}
	if cfg.H2ConcurrentStreams < 1 {
		fmt.Fprintln(os.Stderr, "error: --h2-streams must be >= 1")
		os.Exit(1)
	}
	if cfg.TimeOracleK <= 0 {
		fmt.Fprintln(os.Stderr, "error: --time-k must be > 0")
		os.Exit(1)
	}
	if cfg.TimeOracleN < 1 {
		fmt.Fprintln(os.Stderr, "error: --time-n must be >= 1")
		os.Exit(1)
	}
	if cfg.EvasionLimit < 1 {
		fmt.Fprintln(os.Stderr, "error: --evasion-limit must be >= 1")
		os.Exit(1)
	}
	if cfg.SimhashThreshold < 0 {
		fmt.Fprintln(os.Stderr, "error: --simhash-threshold must be >= 0")
		os.Exit(1)
	}
	if cfg.SimhashClusterLimit < 1 {
		fmt.Fprintln(os.Stderr, "error: --simhash-cluster must be >= 1")
		os.Exit(1)
	}
	if err := validateHistoryMode(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if cfg.H2Mode && cfg.ProxyFile != "" {
		fmt.Fprintln(os.Stderr, "error: --h2 cannot be used together with --proxy")
		os.Exit(1)
	}
	if cfg.Swarm {
		if cfg.SwarmNodes < 1 {
			fmt.Fprintln(os.Stderr, "error: --swarm-nodes must be >= 1")
			os.Exit(1)
		}
		if cfg.SwarmChunkSize < 1 {
			fmt.Fprintln(os.Stderr, "error: --swarm-chunk-size must be >= 1")
			os.Exit(1)
		}
		if cfg.SwarmProvider == "" {
			cfg.SwarmProvider = "local"
		}
	}
	return cfg
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `DirFuzz v%s — high-performance directory fuzzer

Usage:
  dirfuzz -u <target> -w <wordlist> [options]

Quick examples:
  dirfuzz -u https://example.com -w wordlists/common.txt
  dirfuzz -u https://example.com -w wordlists/common.txt -e php,html -mc 200,301,403
  dirfuzz -u https://example.com -w wordlists/common.txt --no-tui -o results.jsonl
  dirfuzz -u https://example.com -w wordlists/common.txt -o results.jsonl --history-mode append
  dirfuzz -u https://example.com -w wordlists/common.txt -r -depth 3 --calibrate
  dirfuzz -u https://example.com -w wordlists/common.txt --eagle prev.jsonl
  dirfuzz -u https://example.com -w wordlists/common.txt --swarm --swarm-provider=lambda

All flags:
`, cliVersion)
	flag.PrintDefaults()
}

// csvInts splits a comma-separated string of integers. Returns nil, nil for
// empty input. Returns an error for any non-integer token.
func csvInts(raw string) ([]int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	parts := splitTrimmed(raw)
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		var n int
		if _, err := fmt.Sscanf(p, "%d", &n); err != nil {
			return nil, fmt.Errorf("invalid integer %q in list", p)
		}
		out = append(out, n)
	}
	return out, nil
}

// splitTrimmed splits s on commas, trims whitespace from each token, and
// drops empty tokens.
func splitTrimmed(s string) []string {
	raw := strings.Split(s, ",")
	out := make([]string, 0, len(raw))
	for _, p := range raw {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func loadWordlistEntries(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(strings.TrimRight(scanner.Text(), "\r"))
		if line == "" {
			continue
		}
		entries = append(entries, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

// mustCSVInts wraps csvInts and exits on error.
func mustCSVInts(raw, flagName string) []int {
	vals, err := csvInts(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid value for %s: %v\n", flagName, err)
		os.Exit(1)
	}
	return vals
}
