package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

// SwarmWorkerConfig carries the scan settings that are safe to serialize to a
// worker runtime.
type SwarmWorkerConfig struct {
	Threads             int                 `json:"threads"`
	UserAgent           string              `json:"user_agent,omitempty"`
	Headers             map[string]string   `json:"headers,omitempty"`
	AuthMatrix          map[string][]string `json:"auth_matrix,omitempty"`
	MatchCodes          []int               `json:"match_codes,omitempty"`
	FilterSizes         []int               `json:"filter_sizes,omitempty"`
	MatchRegex          string              `json:"match_regex,omitempty"`
	FilterRegex         string              `json:"filter_regex,omitempty"`
	Extensions          []string            `json:"extensions,omitempty"`
	Methods             []string            `json:"methods,omitempty"`
	Timeout             time.Duration       `json:"timeout,omitempty"`
	Insecure            bool                `json:"insecure,omitempty"`
	Delay               time.Duration       `json:"delay,omitempty"`
	RPS                 int                 `json:"rps,omitempty"`
	FollowRedirects     bool                `json:"follow_redirects,omitempty"`
	MaxRedirects        int                 `json:"max_redirects,omitempty"`
	RequestBody         string              `json:"request_body,omitempty"`
	FilterWords         int                 `json:"filter_words,omitempty"`
	FilterLines         int                 `json:"filter_lines,omitempty"`
	MatchWords          int                 `json:"match_words,omitempty"`
	MatchLines          int                 `json:"match_lines,omitempty"`
	FilterRTMin         time.Duration       `json:"filter_rt_min,omitempty"`
	FilterRTMax         time.Duration       `json:"filter_rt_max,omitempty"`
	ProxyOut            string              `json:"proxy_out,omitempty"`
	SaveRaw             bool                `json:"save_raw,omitempty"`
	AntiBotFallback     bool                `json:"anti_bot_fallback,omitempty"`
	AllowPrivateTargets bool                `json:"allow_private_targets,omitempty"`
	Recursive           bool                `json:"recursive,omitempty"`
	MaxDepth            int                 `json:"max_depth,omitempty"`
	SmartAPI            bool                `json:"smart_api,omitempty"`
	Mutate              bool                `json:"mutate,omitempty"`
	AutoFilterThreshold int                 `json:"auto_filter_threshold,omitempty"`
	SimhashThreshold    int                 `json:"simhash_threshold,omitempty"`
	SimhashClusterLimit int                 `json:"simhash_cluster_limit,omitempty"`
	H2Mode              bool                `json:"h2_mode,omitempty"`
	H2ConcurrentStreams int                 `json:"h2_concurrent_streams,omitempty"`
	TimingOracle        bool                `json:"timing_oracle,omitempty"`
	TimeOracleK         float64             `json:"time_oracle_k,omitempty"`
	TimeOracleN         int                 `json:"time_oracle_n,omitempty"`
	TimeTrim            bool                `json:"time_trim,omitempty"`
	Harvest             bool                `json:"harvest,omitempty"`
	HarvestJS           bool                `json:"harvest_js,omitempty"`
	HarvestAPI          bool                `json:"harvest_api,omitempty"`
	EvasionLimit        int                 `json:"evasion_limit,omitempty"`
	MaxRetries          int                 `json:"max_retries,omitempty"`
	VerbTamper          bool                `json:"verb_tamper,omitempty"`
	FourOhThreeBypass   bool                `json:"four_oh_three_bypass,omitempty"`
	ProxyFile           string              `json:"proxy_file,omitempty"`
	EagleFile           string              `json:"eagle_file,omitempty"`
	PluginMatch         string              `json:"plugin_match,omitempty"`
	PluginMutate        string              `json:"plugin_mutate,omitempty"`
}

// SwarmWorkerRequest describes a single worker invocation.
type SwarmWorkerRequest struct {
	Target        string            `json:"target"`
	WordlistChunk []string          `json:"wordlist_chunk"`
	Config        SwarmWorkerConfig `json:"config"`
}

// SwarmWorkerResponse contains serialized findings from a worker node.
type SwarmWorkerResponse struct {
	Results  []Result `json:"results"`
	Warnings []string `json:"warnings,omitempty"`
}

// SwarmProvider executes worker requests.
type SwarmProvider interface {
	Invoke(ctx context.Context, req SwarmWorkerRequest) (SwarmWorkerResponse, error)
}

// LocalSwarmProvider runs worker requests in-process.
type LocalSwarmProvider struct{}

func (LocalSwarmProvider) Invoke(ctx context.Context, req SwarmWorkerRequest) (SwarmWorkerResponse, error) {
	return RunSwarmWorker(ctx, req)
}

// LambdaSwarmProvider invokes a Lambda-backed worker runtime.
type LambdaSwarmProvider struct {
	client       *lambda.Client
	functionName string
}

// NewLambdaSwarmProvider creates a provider using the default AWS credential
// chain and the supplied Lambda function name.
func NewLambdaSwarmProvider(ctx context.Context, functionName string) (*LambdaSwarmProvider, error) {
	functionName = strings.TrimSpace(functionName)
	if functionName == "" {
		return nil, fmt.Errorf("lambda function name is required")
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	return &LambdaSwarmProvider{
		client:       lambda.NewFromConfig(cfg),
		functionName: functionName,
	}, nil
}

func (p *LambdaSwarmProvider) Invoke(ctx context.Context, req SwarmWorkerRequest) (SwarmWorkerResponse, error) {
	if p == nil || p.client == nil {
		return SwarmWorkerResponse{}, fmt.Errorf("lambda provider is not configured")
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return SwarmWorkerResponse{}, err
	}

	out, err := p.client.Invoke(ctx, &lambda.InvokeInput{
		FunctionName:   aws.String(p.functionName),
		InvocationType: lambdatypes.InvocationTypeRequestResponse,
		Payload:        payload,
	})
	if err != nil {
		return SwarmWorkerResponse{}, err
	}
	if out.FunctionError != nil && *out.FunctionError != "" {
		return SwarmWorkerResponse{}, fmt.Errorf("lambda function error: %s", *out.FunctionError)
	}
	var resp SwarmWorkerResponse
	if len(out.Payload) == 0 {
		return resp, nil
	}
	if err := json.Unmarshal(out.Payload, &resp); err != nil {
		return SwarmWorkerResponse{}, fmt.Errorf("decoding lambda payload: %w", err)
	}
	return resp, nil
}

// RunSwarmWorker executes a worker scan using the regular engine but emits
// serialized JSON-friendly findings instead of TUI output.
func RunSwarmWorker(ctx context.Context, req SwarmWorkerRequest) (SwarmWorkerResponse, error) {
	req.Config.normalize()
	if req.Target == "" {
		return SwarmWorkerResponse{}, fmt.Errorf("missing target")
	}
	if len(req.WordlistChunk) == 0 {
		return SwarmWorkerResponse{}, nil
	}

	tmp, err := os.CreateTemp("", "dirfuzz-swarm-*.txt")
	if err != nil {
		return SwarmWorkerResponse{}, err
	}
	defer os.Remove(tmp.Name())

	for _, line := range req.WordlistChunk {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		if _, err := tmp.WriteString(line + "\n"); err != nil {
			tmp.Close()
			return SwarmWorkerResponse{}, err
		}
	}
	if err := tmp.Close(); err != nil {
		return SwarmWorkerResponse{}, err
	}

	threads := req.Config.Threads
	if threads < MinWorkerCount {
		threads = MinWorkerCount
	}
	eng := NewEngine(threads, DefaultBloomFilterSize, DefaultBloomFilterFP)
	defer eng.Shutdown()
	eng.emitLogEvent(LogLevelInfo, LogCategorySystem, EventWorkerStarted, "swarm worker engine initialized", map[string]interface{}{
		"target":  req.Target,
		"threads": threads,
	})

	if err := applySwarmConfig(eng, req.Config); err != nil {
		return SwarmWorkerResponse{}, err
	}
	if err := eng.SetTarget(req.Target); err != nil {
		return SwarmWorkerResponse{}, err
	}
	if req.Config.H2Mode {
		if err := eng.RefreshH2Client(); err != nil {
			return SwarmWorkerResponse{}, err
		}
	}

	eng.Start()
	eng.KickoffScanner(tmp.Name(), 0)
	go func() {
		<-ctx.Done()
		eng.Shutdown()
	}()
	go func() {
		eng.Wait()
		eng.Shutdown()
	}()

	resp := SwarmWorkerResponse{
		Results:  make([]Result, 0, len(req.WordlistChunk)),
		Warnings: make([]string, 0, 4),
	}
	for res := range eng.Results {
		if res.IsAutoFilter {
			if msg := strings.TrimSpace(res.Headers["Msg"]); msg != "" {
				resp.Warnings = append(resp.Warnings, msg)
			}
			continue
		}
		resp.Results = append(resp.Results, res)
	}
	if err := ctx.Err(); err != nil {
		return resp, err
	}
	eng.emitLogEvent(LogLevelSuccess, LogCategorySystem, EventWorkerStopped, fmt.Sprintf("swarm worker finished with %d result(s)", len(resp.Results)), map[string]interface{}{
		"results":  len(resp.Results),
		"warnings": len(resp.Warnings),
	})
	return resp, nil
}

func applySwarmConfig(e *Engine, cfg SwarmWorkerConfig) error {
	if e == nil {
		return fmt.Errorf("nil engine")
	}
	cfg.normalize()

	if cfg.UserAgent != "" {
		e.UpdateUserAgent(cfg.UserAgent)
	}
	if len(cfg.Headers) > 0 {
		for k, v := range cfg.Headers {
			e.AddHeader(k, v)
		}
	}
	if len(cfg.MatchCodes) > 0 || len(cfg.FilterSizes) > 0 {
		e.ConfigureFilters(cfg.MatchCodes, cfg.FilterSizes)
	}
	for _, ext := range cfg.Extensions {
		e.AddExtension(strings.TrimPrefix(strings.TrimSpace(ext), "."))
	}
	if cfg.MatchRegex != "" {
		if err := e.SetMatchRegex(cfg.MatchRegex); err != nil {
			return err
		}
	}
	if cfg.FilterRegex != "" {
		if err := e.SetFilterRegex(cfg.FilterRegex); err != nil {
			return err
		}
	}

	e.UpdateConfig(func(c *Config) {
		c.MaxWorkers = cfg.Threads
		c.Timeout = cfg.Timeout
		c.Insecure = cfg.Insecure
		c.Delay = cfg.Delay
		c.FollowRedirects = cfg.FollowRedirects
		c.MaxRedirects = cfg.MaxRedirects
		c.RequestBody = cfg.RequestBody
		c.FilterWords = cfg.FilterWords
		c.FilterLines = cfg.FilterLines
		c.MatchWords = cfg.MatchWords
		c.MatchLines = cfg.MatchLines
		c.FilterRTMin = cfg.FilterRTMin
		c.FilterRTMax = cfg.FilterRTMax
		c.ProxyOut = cfg.ProxyOut
		c.SaveRaw = cfg.SaveRaw
		c.AntiBotFallback = cfg.AntiBotFallback
		c.AllowPrivateTargets = cfg.AllowPrivateTargets
		c.Recursive = cfg.Recursive
		c.MaxDepth = cfg.MaxDepth
		c.SmartAPI = cfg.SmartAPI
		c.Mutate = cfg.Mutate
		c.AutoFilterThreshold = cfg.AutoFilterThreshold
		c.SimhashThreshold = cfg.SimhashThreshold
		c.SimhashClusterLimit = cfg.SimhashClusterLimit
		c.H2Mode = cfg.H2Mode
		c.H2ConcurrentStreams = cfg.H2ConcurrentStreams
		c.TimingOracle = cfg.TimingOracle
		c.TimeOracleK = cfg.TimeOracleK
		c.TimeOracleN = cfg.TimeOracleN
		c.TimeTrim = cfg.TimeTrim
		c.Harvest = cfg.Harvest
		c.HarvestJS = cfg.HarvestJS
		c.HarvestAPI = cfg.HarvestAPI
		c.EvasionLimit = cfg.EvasionLimit
		c.MaxRetries = cfg.MaxRetries
		c.VerbTamper = cfg.VerbTamper
		c.FourOhThreeBypass = cfg.FourOhThreeBypass
		if len(cfg.Methods) > 0 {
			c.Methods = append([]string(nil), cfg.Methods...)
		}
		if len(cfg.AuthMatrix) > 0 {
			c.AuthMatrix = copyAuthMatrix(cfg.AuthMatrix)
		}
	})

	if cfg.ProxyFile != "" {
		if err := e.LoadProxies(cfg.ProxyFile); err != nil {
			return err
		}
	}
	if cfg.EagleFile != "" {
		if err := e.LoadPreviousScan(cfg.EagleFile); err != nil {
			return err
		}
	}
	return nil
}

func (c *SwarmWorkerConfig) normalize() {
	if c.Threads < MinWorkerCount {
		c.Threads = MinWorkerCount
	}
	if c.MaxRedirects <= 0 {
		c.MaxRedirects = DefaultMaxRedirects
	}
	if c.H2ConcurrentStreams <= 0 {
		c.H2ConcurrentStreams = DefaultH2ConcurrentStreams
	}
	if c.AutoFilterThreshold <= 0 {
		c.AutoFilterThreshold = DefaultAutoFilterThreshold
	}
	if c.SimhashThreshold < 0 {
		c.SimhashThreshold = DefaultSimhashThreshold
	}
	if c.SimhashClusterLimit <= 0 {
		c.SimhashClusterLimit = DefaultSimhashClusterLimit
	}
	if c.EvasionLimit <= 0 {
		c.EvasionLimit = DefaultEvasionLimit
	}
	if c.TimeOracleK <= 0 {
		c.TimeOracleK = TimingOracleDefaultK
	}
	if c.TimeOracleN <= 0 {
		c.TimeOracleN = TimingOracleDefaultRepeatN
	}
	if c.Timeout <= 0 {
		c.Timeout = DefaultHTTPTimeout
	}
}

// AggregateSwarmResults applies exact deduplication and similarity-based
// suppression across worker results.
func AggregateSwarmResults(results []Result, simhashThreshold int, clusterLimit int) []Result {
	if len(results) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(results))
	clusters := make([]resultCluster, 0, 32)
	out := make([]Result, 0, len(results))

	for _, res := range results {
		key := resultIdentityKey(res)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		if simhashThreshold >= 0 && clusterLimit > 0 {
			fp := resultSimilarityFingerprint(res)
			if idx := findResultCluster(clusters, fp, simhashThreshold); idx >= 0 {
				if clusters[idx].count >= clusterLimit {
					continue
				}
				clusters[idx].count++
			} else {
				clusters = append(clusters, resultCluster{fingerprint: fp, count: 1})
			}
		}

		out = append(out, res)
	}

	return out
}

type resultCluster struct {
	fingerprint uint64
	count       int
}

func findResultCluster(clusters []resultCluster, fp uint64, threshold int) int {
	for i, cluster := range clusters {
		if hammingDistance(fp, cluster.fingerprint) <= threshold {
			return i
		}
	}
	return -1
}

func resultIdentityKey(res Result) string {
	var b strings.Builder
	b.WriteString(strconv.Itoa(res.StatusCode))
	b.WriteByte('|')
	b.WriteString(res.Method)
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(res.Size))
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(res.Words))
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(res.Lines))
	b.WriteByte('|')
	b.WriteString(res.ContentType)
	b.WriteByte('|')
	b.WriteString(res.Redirect)
	b.WriteByte('|')
	b.WriteString(res.Confidence)
	b.WriteByte('|')
	if len(res.Labels) > 0 {
		labels := append([]string(nil), res.Labels...)
		sort.Strings(labels)
		b.WriteString(strings.Join(labels, ","))
	}
	b.WriteByte('|')
	if len(res.DiscoveredParams) > 0 {
		params := append([]string(nil), res.DiscoveredParams...)
		sort.Strings(params)
		b.WriteString(strings.Join(params, ","))
	}
	b.WriteByte('|')
	if len(res.Headers) > 0 {
		keys := make([]string, 0, len(res.Headers))
		for k := range res.Headers {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			b.WriteString(k)
			b.WriteByte('=')
			b.WriteString(res.Headers[k])
			b.WriteByte(';')
		}
	}
	return b.String()
}

func resultSimilarityFingerprint(res Result) uint64 {
	var b strings.Builder
	b.WriteString(strconv.Itoa(res.StatusCode))
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(res.Size))
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(res.Words))
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(res.Lines))
	b.WriteByte('|')
	b.WriteString(res.ContentType)
	b.WriteByte('|')
	b.WriteString(res.Redirect)
	b.WriteByte('|')
	b.WriteString(res.Confidence)
	b.WriteByte('|')
	if len(res.Labels) > 0 {
		labels := append([]string(nil), res.Labels...)
		sort.Strings(labels)
		b.WriteString(strings.Join(labels, ","))
	}
	b.WriteByte('|')
	if len(res.DiscoveredParams) > 0 {
		params := append([]string(nil), res.DiscoveredParams...)
		sort.Strings(params)
		b.WriteString(strings.Join(params, ","))
	}
	b.WriteByte('|')
	if len(res.Headers) > 0 {
		keys := make([]string, 0, len(res.Headers))
		for k := range res.Headers {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			b.WriteString(k)
			b.WriteByte('=')
			b.WriteString(res.Headers[k])
			b.WriteByte(';')
		}
	}
	return simhashBody([]byte(b.String()))
}

func copyAuthMatrix(in map[string][]string) map[string][]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string][]string, len(in))
	for role, headers := range in {
		out[role] = append([]string(nil), headers...)
	}
	return out
}

var _ SwarmProvider = LocalSwarmProvider{}
var _ SwarmProvider = (*LambdaSwarmProvider)(nil)
