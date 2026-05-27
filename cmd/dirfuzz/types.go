package main

import (
	"fmt"
	"strings"
	"time"
)

// multiFlag lets the same flag be specified multiple times.
// e.g. -H "Authorization: Bearer tok" -H "X-Custom: val"
type multiFlag []string

func (f *multiFlag) String() string     { return strings.Join(*f, ", ") }
func (f *multiFlag) Set(s string) error { *f = append(*f, s); return nil }

func boolPtr(v bool) *bool { return &v }

// cliConfig holds all values parsed from command-line flags.
// It is built once in parseFlags() and passed to run().
type cliConfig struct {
	// ── Required ─────────────────────────────────────────────────────────────
	Target        string
	Wordlist      string
	Profile       string
	ParamWordlist string
	ParamWords    []string

	// ── Workers / throttle ────────────────────────────────────────────────────
	Threads     int
	Delay       time.Duration
	RPS         int
	MaxDuration time.Duration

	// ── HTTP behaviour ───────────────────────────────────────────────────────
	UserAgent    string
	Headers      []string // raw "Key: Value" strings from -H
	AuthMatrix   map[string][]string
	Cookie       string // shorthand for -H "Cookie: …"
	Methods      string // comma-separated HTTP verbs
	VerbTamper   bool
	Body         string // request body for POST / PUT
	Follow       bool
	MaxRedirects int
	Timeout      time.Duration
	Insecure     bool
	OOB          bool
	OOBServer    string
	OOBToken     string

	// ── Matching / filtering ─────────────────────────────────────────────────
	MatchCodes   string // comma-separated, e.g. "200,301,403"
	FilterSizes  string // comma-separated response byte sizes to drop
	Extensions   string // comma-separated extensions to append
	MatchRegex   string
	FilterRegex  string
	ExcludePaths []string
	FilterWords  int
	FilterLines  int
	MatchWords   int
	MatchLines   int
	RTMin        time.Duration
	RTMax        time.Duration

	// ── Output ───────────────────────────────────────────────────────────────
	OutputFormat string // jsonl | csv | url
	OutputFile   string
	HistoryMode  string // overwrite | append
	ReportFile   string
	HeaderAudit  bool
	ReportFormat string // markdown | html
	SaveRaw      bool

	// ── Scan modes ───────────────────────────────────────────────────────────
	Recursive            bool
	RecursivePrune       bool
	MaxDepth             int
	Mutate               bool
	SmartAPI             bool
	AutoFilterThreshold  int
	SimhashThreshold     int
	SimhashClusterLimit  int
	H2Mode               bool
	H2ConcurrentStreams  int
	TimingOracle         bool
	TimeOracleK          float64
	TimeOracleN          int
	TimeTrim             bool
	Harvest              bool
	HarvestJS            bool
	HarvestAPI           bool
	HarvestResponse      bool
	HarvestPassive       bool
	HarvestSourceMaps    bool
	HarvestResponseDepth int
	HarvestResponseFetch int
	HarvestOTXKey        string
	EvasionLimit         int
	MaxRetries           int
	DryRun               bool
	MaxWSFrames          int
	FourOhThreeBypass    bool
	AntiBotFallback      bool
	Swarm                bool
	SwarmProvider        string
	SwarmNodes           int
	SwarmChunkSize       int
	SwarmWorker          bool

	// ── Eagle mode (differential scan) ───────────────────────────────────────
	EagleFile string // path to previous JSONL baseline

	// ── Resume ───────────────────────────────────────────────────────────────
	Resume     bool
	ResumeFile string

	// ── Auto-calibration ─────────────────────────────────────────────────────
	Calibrate bool

	// ── Proxy ────────────────────────────────────────────────────────────────
	ProxyFile string // path to proxy list (SOCKS5 / HTTP, one per line)
	ProxyOut  string // forward every hit to this proxy (Burp / ZAP)


	// ── Nuclei Integration ───────────────────────────────────────────────────
	Nuclei     bool
	NucleiArgs string

	// ── Display ──────────────────────────────────────────────────────────────
	NoTUI   bool // disable TUI, print to stdout
	Verbose bool // print every request, not only hits

	// ── Ssrf ──────────────────────────────────────────────────────────────
	AllowPrivate bool
}

func parseAuthMatrix(entries []string) (map[string][]string, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	out := make(map[string][]string)
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid auth matrix entry %q: expected role=Header: Value||Header2: Value2", entry)
		}
		role := strings.TrimSpace(parts[0])
		if role == "" {
			return nil, fmt.Errorf("invalid auth matrix entry %q: empty role", entry)
		}
		rawHeaders := strings.TrimSpace(parts[1])
		if rawHeaders == "" {
			return nil, fmt.Errorf("invalid auth matrix entry %q: empty header list", entry)
		}
		for _, hdr := range strings.Split(rawHeaders, "||") {
			hdr = strings.TrimSpace(hdr)
			if hdr == "" {
				continue
			}
			if !strings.Contains(hdr, ":") {
				return nil, fmt.Errorf("invalid auth matrix header %q for role %q: expected Key: Value", hdr, role)
			}
			out[role] = append(out[role], hdr)
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	return normalizeAuthMatrix(out)
}

func normalizeAuthMatrix(matrix map[string][]string) (map[string][]string, error) {
	if len(matrix) == 0 {
		return nil, nil
	}
	out := make(map[string][]string, len(matrix))
	for role, headers := range matrix {
		role = strings.TrimSpace(role)
		if role == "" {
			return nil, fmt.Errorf("invalid auth matrix: empty role name")
		}
		for _, hdr := range headers {
			hdr = strings.TrimSpace(hdr)
			if hdr == "" {
				continue
			}
			if !strings.Contains(hdr, ":") {
				return nil, fmt.Errorf("invalid auth matrix header %q for role %q: expected Key: Value", hdr, role)
			}
			out[role] = append(out[role], hdr)
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}
