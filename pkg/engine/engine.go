package engine

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"dirfuzz/pkg/httpclient"
	"dirfuzz/pkg/netutil"

	"github.com/bits-and-blooms/bloom/v3"
	"golang.org/x/time/rate"
)

var linkRegex = regexp.MustCompile(`(?i)(?:href|src|action)=['"]([^'"]+)['"]`)

// ─── Log events ───────────────────────────────────────────────────────────────

type LogLevel string

const (
	LogLevelDebug   LogLevel = "DEBUG"
	LogLevelInfo    LogLevel = "INFO"
	LogLevelWarning LogLevel = "WARNING"
	LogLevelError   LogLevel = "ERROR"
	LogLevelSuccess LogLevel = "SUCCESS"
)

type LogCategory string

const (
	LogCategorySystem    LogCategory = "SYSTEM"
	LogCategoryWorker    LogCategory = "WORKER"
	LogCategoryNetwork   LogCategory = "NETWORK"
	LogCategoryPlugin    LogCategory = "PLUGIN"
	LogCategoryDiscovery LogCategory = "DISCOVERY"
	LogCategoryFilter    LogCategory = "FILTER"
)

type EventType string

const (
	EventWorkerStarted             EventType = "WorkerStarted"
	EventWorkerStopped             EventType = "WorkerStopped"
	EventProxyRotated              EventType = "ProxyRotated"
	EventRateLimitHit              EventType = "RateLimitHit"
	EventRetryAttempt              EventType = "RetryAttempt"
	EventHarvestDiscovery          EventType = "HarvestDiscovery"
	EventHarvestParseError         EventType = "HarvestParseError"
	EventHarvestJSAnalysisComplete EventType = "HarvestJSAnalysisComplete"
	EventAutoFilterTriggered       EventType = "AutoFilterTriggered"
	EventSimhashCluster            EventType = "SimhashCluster"
	EventWAFBypassAttempt          EventType = "WAFBypassAttempt"
	EventWAFBypassOutcome          EventType = "WAFBypassOutcome"
	EventTimingOracleStarted       EventType = "TimingOracleStarted"
	EventTimingOracleCalibrated    EventType = "TimingOracleCalibrated"
	EventNetworkError              EventType = "NetworkError"
)

type LogEvent struct {
	Timestamp time.Time              `json:"timestamp"`
	Level     LogLevel               `json:"level"`
	Category  LogCategory            `json:"category"`
	Type      EventType              `json:"type"`
	Message   string                 `json:"message"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// ─── Config types ─────────────────────────────────────────────────────────────

// SizeRange represents an inclusive min–max byte-size range used for filtering.
type SizeRange struct {
	Min int
	Max int
}

// Config holds all runtime configuration for the engine.
type Config struct {
	sync.RWMutex
	UserAgent            string
	Headers              map[string]string
	MatchCodes           map[int]bool
	FilterSizes          map[int]bool
	FilterSizeRanges     []SizeRange // NEW: filter responses whose size falls in any of these ranges
	MatchContentTypes    []string    // NEW: only surface responses whose Content-Type contains one of these strings
	FilterContentTypes   []string    // NEW: discard responses whose Content-Type contains any of these strings
	MatchRegex           string
	FilterRegex          string
	Extensions           []string
	Methods              []string
	AuthMatrix           map[string][]string
	SmartAPI             bool
	Mutate               bool
	Recursive            bool
	MaxDepth             int
	IsPaused             bool
	Delay                time.Duration
	MaxWorkers           int
	FollowRedirects      bool
	MaxRedirects         int
	AllowPrivateTargets  bool
	RequestBody          string
	FilterWords          int
	FilterLines          int
	MatchWords           int
	MatchLines           int
	OutputFormat         string
	FilterRTMin          time.Duration
	FilterRTMax          time.Duration
	ProxyOut             string
	WordlistPath         string
	OutputFile           string
	Timeout              time.Duration
	Insecure             bool
	AntiBotFallback      bool
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
	HarvestResponseDepth int
	HarvestResponseFetch int
	ParamWordlist        []string
	EvasionLimit         int
	MaxRetries           int
	SaveRaw              bool // NEW: include raw request/response bytes in Result
	WAFEvasion           bool
	VerbTamper           bool
	FourOhThreeBypass    bool // retry 403s with path and header bypass techniques
	Spidering            bool // NEW: dynamic HTML/JS scraping
	WebhookURL           string
	WebhookOnNew         bool
	WebhookOnDrift       bool
}

// configSnapshot is an immutable view of the frequently-read configuration
// fields used by workers. Workers load a pointer to this snapshot once per
// job to avoid repeatedly allocating and copying maps on hot paths.
type configSnapshot struct {
	MaxWorkers           int
	IsPaused             bool
	UserAgent            string
	Headers              map[string]string
	MatchCodes           map[int]bool
	FilterSizes          map[int]bool
	FilterSizeRanges     []SizeRange
	MatchContentTypes    []string
	FilterContentTypes   []string
	FollowRedirects      bool
	MaxRedirects         int
	RequestBody          string
	FilterWords          int
	FilterLines          int
	MatchWords           int
	MatchLines           int
	FilterRTMin          time.Duration
	FilterRTMax          time.Duration
	ProxyOut             string
	Timeout              time.Duration
	SaveRaw              bool
	AntiBotFallback      bool
	AuthMatrix           map[string][]string
	Methods              []string
	SmartAPI             bool
	Extensions           []string
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
	HarvestResponseDepth int
	HarvestResponseFetch int
	ParamWordlist        []string
	EvasionLimit         int
	Mutate               bool
	Recursive            bool
	MaxDepth             int
	WordlistPath         string
	WAFEvasion           bool
	VerbTamper           bool
	FourOhThreeBypass    bool
	Spidering            bool
	// HeadersTemplate is the pre-built header block (with any {PAYLOAD}
	// placeholders intact) that workers can quickly clone and substitute
	// the payload into without reconstructing the header map each job.
	HeadersTemplate string
}

// ─── Job & Result ─────────────────────────────────────────────────────────────

// Job represents a single scan task.
type Job struct {
	Path         string
	Depth        int
	HarvestDepth int
	Method       string
	RunID        int64
	ExtraHeaders map[string]string
}

// Result holds the details of a successful fuzzing hit.
//
// URL and Path intentionally overlap:
//   - URL is the fully qualified URL when the engine has a concrete target.
//   - Path is the discovered relative path or fallback identifier.
//
// Callers that need a stable absolute target should prefer URL when present and
// fall back to Path only for scans that were not started with SetTarget.
type Result struct {
	Path             string            `json:"path"`
	Method           string            `json:"method,omitempty"`
	StatusCode       int               `json:"status"`
	Forbidden403Type string            `json:"forbidden_403_type,omitempty"`
	Size             int               `json:"length"`
	Words            int               `json:"words,omitempty"`
	Lines            int               `json:"lines,omitempty"`
	ContentType      string            `json:"content_type,omitempty"`
	Labels           []string          `json:"labels,omitempty"`
	Confidence       string            `json:"confidence,omitempty"`
	Duration         time.Duration     `json:"duration,omitempty"`
	Redirect         string            `json:"redirect,omitempty"`
	Headers          map[string]string `json:"headers,omitempty"`
	IsEagleAlert     bool              `json:"eagle_alert,omitempty"`
	OldStatusCode    int               `json:"old_status,omitempty"`
	IsAutoFilter     bool              `json:"auto_filter,omitempty"`
	URL              string            `json:"url,omitempty"`
	Request          string            `json:"request,omitempty"`  // only populated when SaveRaw=true
	Response         string            `json:"response,omitempty"` // only populated when SaveRaw=true
	RequestBytes     []byte            `json:"-"`
	ResponseBytes    []byte            `json:"-"`
	ContentDrift     bool              `json:"content_drift,omitempty"`
	OldSize          int               `json:"old_size,omitempty"`
	OldWords         int               `json:"old_words,omitempty"`
	DriftDeltaBytes  int               `json:"drift_delta_bytes,omitempty"`
	DiscoveredParams []string          `json:"discovered_params,omitempty"`
}

// replayTask carries everything needed to replay a hit through an outbound proxy.
type replayTask struct {
	proxyAddr   string
	fullURL     string
	method      string
	ua          string
	headers     map[string]string
	requestBody string
	payload     string
}

// scannerContext holds the engine's cancellation state safely
type scannerContext struct {
	ctx    context.Context
	cancel context.CancelFunc
}

func (e *Engine) emitLogEvent(level LogLevel, category LogCategory, typ EventType, message string, metadata map[string]interface{}) {
	if e == nil || e.LogEvents == nil {
		return
	}
	defer func() {
		_ = recover()
	}()
	ev := LogEvent{
		Timestamp: time.Now(),
		Level:     level,
		Category:  category,
		Type:      typ,
		Message:   message,
		Metadata:  metadata,
	}
	select {
	case e.LogEvents <- ev:
	default:
	}
}

// ─── Sharded Bloom Filter ─────────────────────────────────────────────────────

const bloomFilterShards = 32

type shardedBloomFilter struct {
	filters   []*bloom.BloomFilter
	locks     []sync.Mutex
	numShards uint32
}

func newShardedBloomFilter(numShards uint32, expectedItems uint, falsePositiveRate float64) *shardedBloomFilter {
	sbf := &shardedBloomFilter{
		filters:   make([]*bloom.BloomFilter, numShards),
		locks:     make([]sync.Mutex, numShards),
		numShards: numShards,
	}
	itemsPerShard := expectedItems / uint(numShards)
	if itemsPerShard == 0 {
		itemsPerShard = 1
	}
	for i := uint32(0); i < numShards; i++ {
		sbf.filters[i] = bloom.NewWithEstimates(itemsPerShard, falsePositiveRate)
	}
	return sbf
}

func (sbf *shardedBloomFilter) TestAndAddString(key string) bool {
	hasher := fnv.New32a()
	hasher.Write([]byte(key))
	shardIndex := hasher.Sum32() % sbf.numShards

	sbf.locks[shardIndex].Lock()
	isDuplicate := sbf.filters[shardIndex].TestAndAddString(key)
	sbf.locks[shardIndex].Unlock()
	return isDuplicate
}

func (sbf *shardedBloomFilter) marshalBinary() ([]byte, error) {
	var out bytes.Buffer
	if err := binary.Write(&out, binary.LittleEndian, sbf.numShards); err != nil {
		return nil, err
	}
	for i := uint32(0); i < sbf.numShards; i++ {
		sbf.locks[i].Lock()
		var shardBuf bytes.Buffer
		_, err := sbf.filters[i].WriteTo(&shardBuf)
		sbf.locks[i].Unlock()
		if err != nil {
			return nil, err
		}
		shardBytes := shardBuf.Bytes()
		if err := binary.Write(&out, binary.LittleEndian, uint64(len(shardBytes))); err != nil {
			return nil, err
		}
		if _, err := out.Write(shardBytes); err != nil {
			return nil, err
		}
	}
	return out.Bytes(), nil
}

func (sbf *shardedBloomFilter) unmarshalBinary(data []byte) error {
	r := bytes.NewReader(data)
	var numShards uint32
	if err := binary.Read(r, binary.LittleEndian, &numShards); err != nil {
		return err
	}
	if numShards != sbf.numShards {
		return fmt.Errorf("bloom shard mismatch: file=%d engine=%d", numShards, sbf.numShards)
	}

	for i := uint32(0); i < sbf.numShards; i++ {
		var shardLen uint64
		if err := binary.Read(r, binary.LittleEndian, &shardLen); err != nil {
			return err
		}
		if shardLen > uint64(r.Len()) {
			return fmt.Errorf("invalid bloom shard length %d", shardLen)
		}
		shardBytes := make([]byte, shardLen)
		if _, err := io.ReadFull(r, shardBytes); err != nil {
			return err
		}

		sbf.locks[i].Lock()
		_, err := sbf.filters[i].ReadFrom(bytes.NewReader(shardBytes))
		sbf.locks[i].Unlock()
		if err != nil {
			return err
		}
	}
	return nil
}

// ─── Engine ───────────────────────────────────────────────────────────────────

// Engine represents the core memory-queue system for the brute-forcer.
//
// Concurrency contract:
//   - Stats and EvasionSummaryRows are safe to call from any goroutine.
//   - Results and LogEvents are owned by the engine and may be read concurrently;
//     only Shutdown closes them.
//   - Start, KickoffScanner, and Shutdown coordinate internal goroutines and may
//     be invoked by the MCP/CLI orchestration layer without external locking.
type Engine struct {
	RunID         int64
	jobs          chan Job
	wg            sync.WaitGroup
	shardedFilter *shardedBloomFilter
	numWorkers    int
	targetLock    sync.RWMutex
	baseURL       string
	host          string
	Config        *Config
	scannerCtx    atomic.Pointer[scannerContext]
	scannerWg     sync.WaitGroup
	activeJobs    sync.WaitGroup
	Results       chan Result
	LogEvents     chan LogEvent

	// Eagle Mode State
	PreviousState map[string]int
	eagleLock     sync.RWMutex

	// Proxy Rotation
	proxies     []string
	proxyIndex  uint64
	proxyDialer bool

	// Rate Limiters (Per-Host)
	limiters     map[string]*rate.Limiter
	limitersLock sync.RWMutex
	currentLimit rate.Limit
	currentBurst int

	// Progress tracking
	TotalLines         int64
	ProcessedLines     int64
	requestsDispatched atomic.Int64
	resultsCollected   atomic.Int64
	startedAtUnix      atomic.Int64
	isRunning          atomic.Bool
	activeWorkers      atomic.Int64

	// Transform plugin
	transformPlugin *PluginRequestTransformer

	// Worker management
	workerLock   sync.Mutex
	workerStopCh chan struct{}

	// Telemetry (Atomic counters)
	Count200             int64
	Count403             int64
	Count404             int64
	Count429             int64
	Count500             int64
	CountConnErr         int64
	AutoFilterSuppressed int64
	SimhashSuppressed    int64
	HarvestedPaths       int64

	// RPS calculation
	// `lastProcessed` and `lastTick` are accessed concurrently; use
	// atomic operations on the int64 fields to avoid data races.
	lastProcessed int64 // atomic: last processed count snapshot
	lastTick      int64 // atomic: unixNano timestamp of last tick
	CurrentRPS    int64

	// Smart Filter State
	fpMutex            sync.RWMutex
	fpCounts           map[string]int
	manualFilterSizes  map[int]bool
	autoFilterSizes    map[int]bool
	simhashClusters    map[uint64]int
	simhashClusterLock sync.Mutex
	evasionAttempted   sync.Map

	// SimHash soft-404 clustering settings.
	SimhashThreshold    int
	SimhashClusterLimit int
	EvasionScoreboard   *EvasionScoreboard
	wafStateMu          sync.RWMutex
	wafDetected         bool
	wafVendorGuess      string

	// HTTP/2 client path.
	H2Client    *http.Client
	h2StreamSem chan struct{}

	// Anti-bot fallback state shared across workers.
	antiBot *antiBotManager

	// Timing oracle state (calibrated at scan startup when enabled).
	timingOracle *TimingOracle

	// Auto-throttle state
	autoThrottle     bool
	alreadyThrottled int32 // atomic: prevents repeated firing

	// Per-host HEAD rejection cache (replaces the single global headRejected flag)
	headRejectedHosts sync.Map // map[string]*int32

	// TUIDropped counts results the TUI channel dropped due to backpressure.
	TUIDropped int64
	// LogEventsDropped counts system log events dropped on the TUI fanout path.
	LogEventsDropped atomic.Int64

	// Resume support
	ResumeFile string

	// Compiled regexes (cached)
	matchRe  atomic.Pointer[regexp.Regexp]
	filterRe atomic.Pointer[regexp.Regexp]

	// Lua plugins
	matchPlugin  *PluginMatcher
	mutatePlugin *PluginMutator

	// Scope domain for recursion
	scopeDomain string

	// Bounded concurrency for recursive wordlist scanners
	recursiveSem chan struct{}

	// Bounded outbound proxy replay queue + workers
	replayCh chan replayTask
	// Bounded hidden-parameter fuzzing queue + workers.
	paramTaskChan chan ParamTask
	paramTaskSeen sync.Map
	paramTasksWg  sync.WaitGroup
	// Cached immutable config snapshot read by workers.
	configSnap atomic.Pointer[configSnapshot]
	// Cached outbound HTTP clients for proxy replay to avoid creating a new
	// Transport/Client per replay task (reduces GC pressure and enables
	// connection/TLS session reuse).
	replayClients sync.Map // map[string]*http.Client
	paramFuzzWg   sync.WaitGroup
	// Ensure Shutdown only runs once to avoid double-closing channels.
	shutdownOnce       sync.Once
	changeWordlistLock sync.Mutex
}

// ─── Constant classification strings ─────────────────────────────────────────

const (
	Forbidden403TypeCFWAFBlock = "CF_WAF_BLOCK"
	Forbidden403TypeCFAdmin403 = "CF_ADMIN_403"
	Forbidden403TypeNginx403   = "NGINX_403"
	Forbidden403TypeGeneric403 = "GENERIC_403"
)

const (
	paramTaskQueueSize = 256
)

// ─── Result helpers ───────────────────────────────────────────────────────────

// String returns a string representation of the result for CLI output.
func (r Result) String() string {
	extras := ""
	if r.Redirect != "" {
		extras += fmt.Sprintf(" -> %s", r.Redirect)
	}
	if val, ok := r.Headers["Server"]; ok {
		extras += fmt.Sprintf(" [Server: %s]", val)
	}
	if val, ok := r.Headers["X-Powered-By"]; ok {
		extras += fmt.Sprintf(" [X-Powered-By: %s]", val)
	}
	if r.Forbidden403Type != "" {
		extras += fmt.Sprintf(" [%s]", r.Forbidden403Type)
	}
	if r.ContentType != "" {
		extras += fmt.Sprintf(" [%s]", r.ContentType)
	}
	if r.Duration > 0 {
		extras += fmt.Sprintf(" [%s]", r.Duration.Round(time.Millisecond))
	}
	if len(r.DiscoveredParams) > 0 {
		extras += fmt.Sprintf(" [Params: %s]", strings.Join(r.DiscoveredParams, ","))
	}
	if len(r.Labels) > 0 {
		extras += fmt.Sprintf(" [Labels: %s]", strings.Join(r.Labels, ","))
	}
	if r.Confidence != "" {
		extras += fmt.Sprintf(" [Conf: %s]", r.Confidence)
	}
	methodStr := r.Method
	if methodStr == "" {
		methodStr = "HEAD/GET"
	}
	return fmt.Sprintf("[+] [%s] HIT: %s (Status: %d, Size: %d, Words: %d, Lines: %d)%s",
		methodStr, r.Path, r.StatusCode, r.Size, r.Words, r.Lines, extras)
}

// ToCSV returns a CSV-formatted line for the result.
func (r Result) ToCSV() []string {
	methodStr := r.Method
	if methodStr == "" {
		methodStr = "GET"
	}
	return []string{
		methodStr,
		r.URL,
		r.Path,
		strconv.Itoa(r.StatusCode),
		strconv.Itoa(r.Size),
		strconv.Itoa(r.Words),
		strconv.Itoa(r.Lines),
		r.ContentType,
		r.Redirect,
		r.Duration.Round(time.Millisecond).String(),
	}
}

// Classify403 identifies known types of 403 responses based on body/header signals.
func Classify403(body []byte, headers string) string {
	// Only scan the first N bytes for known WAF signatures to avoid
	// allocating a lowercase copy of very large bodies.
	const maxScan = 8 * 1024
	limit := maxScan
	if len(body) < limit {
		limit = len(body)
	}
	lowerBody := bytes.ToLower(body[:limit])
	hasCFWAFBlock := bytes.Contains(lowerBody, []byte("attention required! | cloudflare")) ||
		bytes.Contains(lowerBody, []byte("sorry, you have been blocked")) ||
		bytes.Contains(lowerBody, []byte("cf-error-details"))
	if hasCFWAFBlock {
		return Forbidden403TypeCFWAFBlock
	}

	hasCFAdmin403 := bytes.Contains(lowerBody, []byte("request forbidden by administrative rules"))
	hasNginx403 := bytes.Contains(lowerBody, []byte("<center>nginx</center>"))

	normalizedHeaders := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(headers, "\r\n", "\n"), "\r", "\n"))
	headerLines := strings.Split(normalizedHeaders, "\n")
	hasCfRay := false
	hasCfCacheStatus := false
	for _, line := range headerLines {
		idx := strings.Index(line, ":")
		if idx == -1 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		switch key {
		case "cf-ray":
			hasCfRay = true
		case "cf-cache-status":
			hasCfCacheStatus = true
		}
	}

	if hasCFAdmin403 && (hasCfRay || hasCfCacheStatus) {
		return Forbidden403TypeCFAdmin403
	}
	if hasNginx403 && !hasCfRay {
		return Forbidden403TypeNginx403
	}
	return Forbidden403TypeGeneric403
}

// WriteCSVHeader writes a CSV header to the given writer.
func WriteCSVHeader(w *csv.Writer) {
	w.Write([]string{"Method", "URL", "Path", "Status", "Size", "Words", "Lines", "ContentType", "Redirect", "Duration"})
}

// ─── Engine constructor ───────────────────────────────────────────────────────

// NewEngine initialises a new Engine with a worker pool and a Bloom filter.
func NewEngine(numWorkers int, expectedItems uint, falsePositiveRate float64) *Engine {
	burst := numWorkers
	if burst < MinRateLimitBurst {
		burst = MinRateLimitBurst
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Create bounded replay queue and start workers.
	replayCh := make(chan replayTask, ReplayQueueSize)

	e := &Engine{
		jobs:          make(chan Job, DefaultJobQueueSize),
		shardedFilter: newShardedBloomFilter(bloomFilterShards, expectedItems, falsePositiveRate),
		numWorkers:    numWorkers,
		limiters:      make(map[string]*rate.Limiter),
		currentLimit:  rate.Inf,
		currentBurst:  burst,
		Config: &Config{
			UserAgent:           "DirFuzz/2.0",
			Headers:             make(map[string]string),
			MatchCodes:          make(map[int]bool),
			FilterSizes:         make(map[int]bool),
			IsPaused:            false,
			Delay:               0,
			MaxWorkers:          numWorkers,
			MaxRedirects:        DefaultMaxRedirects,
			FilterWords:         -1,
			FilterLines:         -1,
			MatchWords:          -1,
			MatchLines:          -1,
			OutputFormat:        DefaultOutputFormat,
			Timeout:             DefaultHTTPTimeout,
			Insecure:            false,
			AntiBotFallback:     true,
			AllowPrivateTargets: false,
			AutoFilterThreshold: DefaultAutoFilterThreshold,
			SimhashThreshold:    DefaultSimhashThreshold,
			SimhashClusterLimit: DefaultSimhashClusterLimit,
			H2ConcurrentStreams: DefaultH2ConcurrentStreams,
			TimeOracleK:         TimingOracleDefaultK,
			TimeOracleN:         TimingOracleDefaultRepeatN,
			EvasionLimit:        DefaultEvasionLimit,
		},
		Results:           make(chan Result, ResultsChannelSize),
		LogEvents:         make(chan LogEvent, 5000),
		antiBot:           newAntiBotManager(),
		fpCounts:          make(map[string]int),
		manualFilterSizes: make(map[int]bool),
		autoFilterSizes:   make(map[int]bool),
		simhashClusters:   make(map[uint64]int),
		EvasionScoreboard: NewEvasionScoreboard(),
		lastTick:          time.Now().UnixNano(),
		autoThrottle:      true,
		recursiveSem:      make(chan struct{}, MaxConcurrentRecursions),
		replayCh:          replayCh,
		workerStopCh:      make(chan struct{}),
	}

	e.scannerCtx.Store(&scannerContext{ctx: ctx, cancel: cancel})

	// Launch bounded replay workers.
	for i := 0; i < ReplayWorkers; i++ {
		go func() {
			for task := range replayCh {
				e.execReplay(task)
			}
		}()
	}

	paramWorkers := numWorkers / 4
	if paramWorkers < 1 {
		paramWorkers = 1
	}
	e.paramTaskChan = make(chan ParamTask, paramTaskQueueSize)
	e.startParamFuzzWorkers(paramWorkers)

	// Initialize worker-facing immutable config snapshot.
	e.buildAndStoreConfigSnapshot()

	return e
}

// ─── Proxy helpers ────────────────────────────────────────────────────────────

// LoadProxies loads a list of proxies from a file (SOCKS5 or HTTP).
func (e *Engine) LoadProxies(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	var proxies []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			proxies = append(proxies, line)
		}
	}
	e.proxies = proxies
	if len(proxies) > 0 {
		e.proxyDialer = true
		fmt.Printf("[*] Loaded %d proxies from %s\n", len(proxies), path)
	}
	return scanner.Err()
}

// GetNextProxy returns the next proxy in the list using round-robin.
func (e *Engine) GetNextProxy() string {
	if len(e.proxies) == 0 {
		return ""
	}
	idx := atomic.AddUint64(&e.proxyIndex, 1)
	proxy := e.proxies[(idx-1)%uint64(len(e.proxies))]
	e.emitLogEvent(LogLevelInfo, LogCategoryNetwork, EventProxyRotated, fmt.Sprintf("rotated to proxy %s", proxy), map[string]interface{}{
		"proxy": proxy,
		"index": idx - 1,
	})
	return proxy
}

// ─── Scan state / Eagle Mode ─────────────────────────────────────────────────

// LoadPreviousScan loads a previous JSONL scan file for differential scanning.
func (e *Engine) LoadPreviousScan(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	e.eagleLock.Lock()
	defer e.eagleLock.Unlock()

	if e.PreviousState == nil {
		e.PreviousState = make(map[string]int)
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var res Result
		if err := json.Unmarshal(scanner.Bytes(), &res); err != nil {
			continue
		}
		e.PreviousState[res.Path] = res.StatusCode
	}
	return scanner.Err()
}

// ─── Rate limiting ────────────────────────────────────────────────────────────

// SetRPS updates the rate limiter settings dynamically.
func (e *Engine) SetRPS(rps int) {
	var limit rate.Limit
	var burst int
	if rps <= 0 {
		limit = rate.Inf
		burst = e.currentBurst
		if burst < MinRateLimitBurst {
			burst = MinRateLimitBurst
		}
	} else {
		limit = rate.Limit(rps)
		burst = rps
		if burst < MinRateLimitBurst {
			burst = MinRateLimitBurst
		}
	}
	e.limitersLock.Lock()
	e.currentLimit = limit
	e.currentBurst = burst
	for _, l := range e.limiters {
		l.SetLimit(limit)
		l.SetBurst(burst)
	}
	e.limitersLock.Unlock()
}

// UpdateRateLimiterFromDelay updates the rate limiter based on the delay setting.
func (e *Engine) UpdateRateLimiterFromDelay() {
	e.Config.RLock()
	d := e.Config.Delay
	workers := e.Config.MaxWorkers
	e.Config.RUnlock()

	var limit rate.Limit
	var b int
	if d <= 0 {
		limit = rate.Inf
		b = workers
		if b < 10 {
			b = 10
		}
	} else {
		rps := float64(workers) / d.Seconds()
		if rps < 1 {
			rps = 1
		}
		limit = rate.Limit(rps)
		b = workers
	}

	e.limitersLock.Lock()
	e.currentLimit = limit
	e.currentBurst = b
	for _, l := range e.limiters {
		l.SetLimit(limit)
		l.SetBurst(b)
	}
	e.limitersLock.Unlock()
}

func (e *Engine) getLimiter(host string) *rate.Limiter {
	e.limitersLock.RLock()
	l, exists := e.limiters[host]
	e.limitersLock.RUnlock()
	if exists {
		return l
	}

	e.limitersLock.Lock()
	defer e.limitersLock.Unlock()
	if l, exists := e.limiters[host]; exists {
		return l
	}
	newLimiter := rate.NewLimiter(e.currentLimit, e.currentBurst)
	e.limiters[host] = newLimiter
	return newLimiter
}

// buildAndStoreConfigSnapshot creates an immutable snapshot of the fields
// that workers read on the hot path and stores it atomically.
func (e *Engine) buildAndStoreConfigSnapshot() {
	e.Config.RLock()
	s := &configSnapshot{
		MaxWorkers:           e.Config.MaxWorkers,
		IsPaused:             e.Config.IsPaused,
		UserAgent:            e.Config.UserAgent,
		Headers:              make(map[string]string, len(e.Config.Headers)),
		MatchCodes:           make(map[int]bool, len(e.Config.MatchCodes)),
		FilterSizes:          make(map[int]bool, len(e.Config.FilterSizes)),
		FilterSizeRanges:     make([]SizeRange, len(e.Config.FilterSizeRanges)),
		MatchContentTypes:    make([]string, len(e.Config.MatchContentTypes)),
		FilterContentTypes:   make([]string, len(e.Config.FilterContentTypes)),
		FollowRedirects:      e.Config.FollowRedirects,
		MaxRedirects:         e.Config.MaxRedirects,
		RequestBody:          e.Config.RequestBody,
		FilterWords:          e.Config.FilterWords,
		FilterLines:          e.Config.FilterLines,
		MatchWords:           e.Config.MatchWords,
		MatchLines:           e.Config.MatchLines,
		FilterRTMin:          e.Config.FilterRTMin,
		FilterRTMax:          e.Config.FilterRTMax,
		ProxyOut:             e.Config.ProxyOut,
		Timeout:              e.Config.Timeout,
		SaveRaw:              e.Config.SaveRaw,
		AntiBotFallback:      e.Config.AntiBotFallback,
		AuthMatrix:           make(map[string][]string, len(e.Config.AuthMatrix)),
		Methods:              make([]string, len(e.Config.Methods)),
		SmartAPI:             e.Config.SmartAPI,
		Extensions:           make([]string, len(e.Config.Extensions)),
		AutoFilterThreshold:  e.Config.AutoFilterThreshold,
		SimhashThreshold:     e.Config.SimhashThreshold,
		SimhashClusterLimit:  e.Config.SimhashClusterLimit,
		H2Mode:               e.Config.H2Mode,
		H2ConcurrentStreams:  e.Config.H2ConcurrentStreams,
		TimingOracle:         e.Config.TimingOracle,
		TimeOracleK:          e.Config.TimeOracleK,
		TimeOracleN:          e.Config.TimeOracleN,
		TimeTrim:             e.Config.TimeTrim,
		Harvest:              e.Config.Harvest,
		HarvestJS:            e.Config.HarvestJS,
		HarvestAPI:           e.Config.HarvestAPI,
		HarvestResponse:      e.Config.HarvestResponse,
		HarvestResponseDepth: e.Config.HarvestResponseDepth,
		HarvestResponseFetch: e.Config.HarvestResponseFetch,
		EvasionLimit:         e.Config.EvasionLimit,
		Mutate:               e.Config.Mutate,
		Recursive:            e.Config.Recursive,
		MaxDepth:             e.Config.MaxDepth,
		WordlistPath:         e.Config.WordlistPath,
		WAFEvasion:           e.Config.WAFEvasion,
		VerbTamper:           e.Config.VerbTamper,
		FourOhThreeBypass:    e.Config.FourOhThreeBypass,
		Spidering:            e.Config.Spidering,
	}
	// Honor User-Agent header override: worker formerly extracted UA from
	// headers if present and removed it from the header map.
	ua := s.UserAgent
	for k, v := range e.Config.Headers {
		if strings.EqualFold(k, "User-Agent") {
			ua = normalizeUserAgent(v)
			continue
		}
		s.Headers[k] = v
	}
	s.UserAgent = ua

	// Pre-build a headers template string so workers don't reconstruct the
	// header block on every job. Use a deterministic key order to keep
	// output stable.
	var hdrKeys []string
	for k := range s.Headers {
		hdrKeys = append(hdrKeys, k)
	}
	sort.Strings(hdrKeys)
	var hb strings.Builder
	for _, k := range hdrKeys {
		v := s.Headers[k]
		hb.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	s.HeadersTemplate = hb.String()

	for k, v := range e.Config.MatchCodes {
		s.MatchCodes[k] = v
	}
	for k, v := range e.Config.FilterSizes {
		s.FilterSizes[k] = v
	}
	copy(s.FilterSizeRanges, e.Config.FilterSizeRanges)
	copy(s.MatchContentTypes, e.Config.MatchContentTypes)
	copy(s.FilterContentTypes, e.Config.FilterContentTypes)
	for role, headers := range e.Config.AuthMatrix {
		s.AuthMatrix[role] = append([]string(nil), headers...)
	}
	copy(s.Methods, e.Config.Methods)
	copy(s.Extensions, e.Config.Extensions)
	s.ParamWordlist = append(s.ParamWordlist, e.Config.ParamWordlist...)
	e.Config.RUnlock()
	e.SimhashThreshold = s.SimhashThreshold
	e.SimhashClusterLimit = s.SimhashClusterLimit

	e.configSnap.Store(s)
}

// RefreshConfigSnapshot publishes direct Config edits to workers. Prefer the
// Engine setter methods when possible; this exists for grouped config updates.
func (e *Engine) RefreshConfigSnapshot() {
	e.buildAndStoreConfigSnapshot()
}

// UpdateConfig applies grouped configuration edits under the Config lock and
// publishes the updated immutable snapshot to workers.
func (e *Engine) UpdateConfig(fn func(*Config)) {
	e.Config.Lock()
	fn(e.Config)
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()
}

// ─── Config helpers ───────────────────────────────────────────────────────────

// ConfigureFilters sets the matching status codes and filtering sizes.
func (e *Engine) ConfigureFilters(mc []int, fs []int) {
	e.Config.Lock()
	for _, code := range mc {
		e.Config.MatchCodes[code] = true
	}
	for _, size := range fs {
		e.Config.FilterSizes[size] = true
		e.manualFilterSizes[size] = true
	}
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()
}

func (e *Engine) SetMatchRegex(pattern string) error {
	if pattern == "" {
		e.matchRe.Store(nil)
		e.Config.Lock()
		e.Config.MatchRegex = ""
		e.Config.Unlock()
		e.buildAndStoreConfigSnapshot()
		return nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	e.matchRe.Store(re)
	e.Config.Lock()
	e.Config.MatchRegex = pattern
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()
	return nil
}

func (e *Engine) SetFilterRegex(pattern string) error {
	if pattern == "" {
		e.filterRe.Store(nil)
		e.Config.Lock()
		e.Config.FilterRegex = ""
		e.Config.Unlock()
		e.buildAndStoreConfigSnapshot()
		return nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	e.filterRe.Store(re)
	e.Config.Lock()
	e.Config.FilterRegex = pattern
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()
	return nil
}

func (e *Engine) SetMatchPlugin(plugin *PluginMatcher)  { e.matchPlugin = plugin }
func (e *Engine) SetMutatePlugin(plugin *PluginMutator) { e.mutatePlugin = plugin }

func (e *Engine) UpdateUserAgent(ua string) {
	e.Config.Lock()
	normalized := normalizeUserAgent(ua)
	if normalized == "" {
		normalized = "DirFuzz/2.0"
	}
	e.Config.UserAgent = normalized
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()
}

func normalizeUserAgent(ua string) string {
	ua = strings.TrimSpace(ua)
	const prefix = "User-Agent:"
	if len(ua) >= len(prefix) && strings.EqualFold(ua[:len(prefix)], prefix) {
		ua = strings.TrimSpace(ua[len(prefix):])
	}
	return ua
}

func (e *Engine) SetDelay(d time.Duration) {
	e.Config.Lock()
	e.Config.Delay = d
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()
	e.UpdateRateLimiterFromDelay()
}

func (e *Engine) AddHeader(key, val string) {
	e.Config.Lock()
	if strings.EqualFold(strings.TrimSpace(key), "User-Agent") {
		e.Config.UserAgent = normalizeUserAgent(val)
		if e.Config.UserAgent == "" {
			e.Config.UserAgent = "DirFuzz/2.0"
		}
		for hk := range e.Config.Headers {
			if strings.EqualFold(hk, "User-Agent") {
				delete(e.Config.Headers, hk)
			}
		}
		e.Config.Unlock()
		e.buildAndStoreConfigSnapshot()
		return
	}
	e.Config.Headers[key] = val
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()
}

func (e *Engine) RemoveHeader(key string) {
	e.Config.Lock()
	delete(e.Config.Headers, key)
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()
}

func (e *Engine) ConfigSnapshot() (ua string, filters []int, headers map[string]string, delay time.Duration, exts []string, follow bool) {
	e.Config.RLock()
	defer e.Config.RUnlock()
	ua = e.Config.UserAgent
	delay = e.Config.Delay
	for size := range e.Config.FilterSizes {
		filters = append(filters, size)
	}
	headers = make(map[string]string)
	for k, v := range e.Config.Headers {
		headers[k] = v
	}
	exts = make([]string, len(e.Config.Extensions))
	copy(exts, e.Config.Extensions)
	follow = e.Config.FollowRedirects
	return
}

func (e *Engine) AddFilterSize(size int) {
	e.Config.Lock()
	e.Config.FilterSizes[size] = true
	e.manualFilterSizes[size] = true
	delete(e.autoFilterSizes, size)
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()
}

func (e *Engine) AddAutoFilterSize(size int) {
	e.Config.Lock()
	e.Config.FilterSizes[size] = true
	if !e.manualFilterSizes[size] {
		e.autoFilterSizes[size] = true
	}
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()
}

func (e *Engine) RemoveFilterSize(size int) {
	e.Config.Lock()
	delete(e.Config.FilterSizes, size)
	delete(e.manualFilterSizes, size)
	delete(e.autoFilterSizes, size)
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()
}

func (e *Engine) clearAutoFilterSizes() {
	e.Config.Lock()
	for size := range e.autoFilterSizes {
		if !e.manualFilterSizes[size] {
			delete(e.Config.FilterSizes, size)
		}
	}
	e.autoFilterSizes = make(map[int]bool)
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()
}

func (e *Engine) clearSimhashClusters() {
	e.simhashClusterLock.Lock()
	e.simhashClusters = make(map[uint64]int)
	e.simhashClusterLock.Unlock()
}

// isSimhashSoftFour tracks a SimHash cluster and returns true once the cluster
// has reached the suppression limit.
func (e *Engine) isSimhashSoftFour(bodyHash uint64) bool {
	threshold := e.SimhashThreshold
	if threshold < 0 {
		threshold = 0
	}
	limit := e.SimhashClusterLimit
	if limit <= 0 {
		return false
	}

	e.simhashClusterLock.Lock()
	defer e.simhashClusterLock.Unlock()

	for centroid, count := range e.simhashClusters {
		if hammingDistance(centroid, bodyHash) <= threshold {
			count++
			e.simhashClusters[centroid] = count
			return count >= limit
		}
	}

	e.simhashClusters[bodyHash] = 1
	return false
}

func (e *Engine) AddMatchCode(code int) {
	e.Config.Lock()
	e.Config.MatchCodes[code] = true
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()
}

func (e *Engine) RemoveMatchCode(code int) {
	e.Config.Lock()
	delete(e.Config.MatchCodes, code)
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()
}

func (e *Engine) AddExtension(ext string) {
	e.Config.Lock()
	for _, x := range e.Config.Extensions {
		if x == ext {
			e.Config.Unlock()
			return
		}
	}
	e.Config.Extensions = append(e.Config.Extensions, ext)
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()
}

func (e *Engine) RemoveExtension(ext string) {
	e.Config.Lock()
	var newExts []string
	for _, x := range e.Config.Extensions {
		if x != ext {
			newExts = append(newExts, x)
		}
	}
	e.Config.Extensions = newExts
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()
}

func (e *Engine) SetMutation(active bool) {
	e.Config.Lock()
	e.Config.Mutate = active
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()
}

func (e *Engine) SetPaused(paused bool) {
	e.Config.Lock()
	e.Config.IsPaused = paused
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()
}

func (e *Engine) SetFollowRedirects(follow bool) {
	e.Config.Lock()
	e.Config.FollowRedirects = follow
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()
}

// ─── Per-host HEAD rejection ──────────────────────────────────────────────────

// headRejectedForHost returns the per-host atomic flag for HEAD rejection.
func (e *Engine) headRejectedForHost(host string) *int32 {
	val, _ := e.headRejectedHosts.LoadOrStore(host, new(int32))
	return val.(*int32)
}

func (e *Engine) isHeadRejected(host string) bool {
	return atomic.LoadInt32(e.headRejectedForHost(host)) == 1
}

func (e *Engine) markHeadRejected(host string) {
	atomic.StoreInt32(e.headRejectedForHost(host), 1)
}

// ─── Target management ────────────────────────────────────────────────────────

func validateOutboundHostname(hostname string, allowPrivate bool) error {
	if !allowPrivate && netutil.IsPrivateHost(hostname) {
		return fmt.Errorf("SSRF protection: target %q resolves to a private or loopback address", hostname)
	}
	return nil
}

func sanitizeHeaderToken(s string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}

// SetTarget sets the target URL and extracts the host.
// It rejects private/loopback IP ranges to prevent SSRF when driven via MCP.
func (e *Engine) SetTarget(targetURL string) error {
	targetURL = strings.ReplaceAll(targetURL, "{payload}", "{PAYLOAD}")

	u, err := url.Parse(targetURL)
	if err != nil {
		return err
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("invalid URL: missing scheme or host")
	}

	hostname := u.Hostname()
	// Respect engine-level override to allow private/loopback targets.
	e.Config.RLock()
	allow := e.Config.AllowPrivateTargets
	e.Config.RUnlock()
	if err := validateOutboundHostname(hostname, allow); err != nil {
		return err
	}

	e.targetLock.Lock()
	e.baseURL = targetURL
	e.host = u.Host
	if e.scopeDomain == "" {
		e.scopeDomain = hostname
	}
	e.targetLock.Unlock()
	if err := e.RefreshH2Client(); err != nil {
		return err
	}
	return nil
}

// RefreshH2Client rebuilds the shared HTTP/2 client when H2 mode is enabled.
// It is safe to call after the target URL changes or when H2 settings change.
func (e *Engine) RefreshH2Client() error {
	e.Config.RLock()
	h2Mode := e.Config.H2Mode
	streams := e.Config.H2ConcurrentStreams
	timeout := e.Config.Timeout
	insecure := e.Config.Insecure
	e.Config.RUnlock()

	if !h2Mode {
		e.H2Client = nil
		e.h2StreamSem = nil
		return nil
	}

	baseURL := e.BaseURL()
	if baseURL == "" {
		return fmt.Errorf("H2 mode requires a target URL")
	}
	if streams < 1 {
		streams = DefaultH2ConcurrentStreams
	}

	client, err := httpclient.NewH2Client(baseURL, timeout, insecure, DefaultH2MaxHeaderListSize)
	if err != nil {
		return err
	}
	e.H2Client = client
	e.h2StreamSem = make(chan struct{}, streams)
	return nil
}

func (e *Engine) BaseURL() string {
	e.targetLock.RLock()
	defer e.targetLock.RUnlock()
	return e.baseURL
}

func (e *Engine) Host() string {
	e.targetLock.RLock()
	defer e.targetLock.RUnlock()
	return e.host
}

// ─── Wordlist scanner ─────────────────────────────────────────────────────────

// Restart restarts the scanner with the current wordlist.
func (e *Engine) Restart() error {
	e.Config.RLock()
	path := e.Config.WordlistPath
	e.Config.RUnlock()
	if path == "" {
		return fmt.Errorf("no wordlist currently loaded to restart")
	}
	return e.ChangeWordlist(path)
}

// ChangeWordlist cancels the current scanner and starts a new one.
func (e *Engine) ChangeWordlist(path string) error {
	e.changeWordlistLock.Lock()
	defer e.changeWordlistLock.Unlock()

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("wordlist file does not exist: %s", path)
	}

	if oldCtx := e.scannerCtx.Load(); oldCtx != nil && oldCtx.cancel != nil {
		oldCtx.cancel()
		e.scannerWg.Wait() // Ensure old scanner has completely stopped before resetting state
	}

	e.shardedFilter = newShardedBloomFilter(bloomFilterShards, DefaultBloomFilterSize, DefaultBloomFilterFP)

	atomic.StoreInt64(&e.ProcessedLines, 0)
	atomic.StoreInt64(&e.TotalLines, 0)
	atomic.StoreInt64(&e.Count200, 0)
	atomic.StoreInt64(&e.Count403, 0)
	atomic.StoreInt64(&e.Count404, 0)
	atomic.StoreInt64(&e.Count429, 0)
	atomic.StoreInt64(&e.Count500, 0)
	atomic.StoreInt64(&e.CountConnErr, 0)
	atomic.StoreInt64(&e.CurrentRPS, 0)
	atomic.StoreInt32(&e.alreadyThrottled, 0)
	atomic.StoreInt64(&e.HarvestedPaths, 0)
	e.evasionAttempted = sync.Map{}
	e.EvasionScoreboard = NewEvasionScoreboard()
	e.headRejectedHosts.Range(func(k, _ interface{}) bool {
		e.headRejectedHosts.Delete(k)
		return true
	})

	e.fpMutex.Lock()
	e.fpCounts = make(map[string]int)
	e.fpMutex.Unlock()
	e.clearAutoFilterSizes()
	e.clearSimhashClusters()
	atomic.StoreInt64(&e.AutoFilterSuppressed, 0)
	atomic.StoreInt64(&e.SimhashSuppressed, 0)

	e.drainJobs()

	ctx, cancel := context.WithCancel(context.Background())
	e.scannerCtx.Store(&scannerContext{ctx: ctx, cancel: cancel})

	atomic.AddInt64(&e.RunID, 1)

	e.KickoffScanner(path, 0)
	return nil
}

// drainJobs safely drains all pending jobs from the jobs channel.
func (e *Engine) drainJobs() {
	for {
		select {
		case _, ok := <-e.jobs:
			if !ok {
				return
			}
			e.activeJobs.Done()
		default:
			return
		}
	}
}

// KickoffScanner starts the wordlist scanner.
//
// It is safe to call after Start from a coordinating goroutine; the scanner
// goroutine itself is owned by the engine and is drained by Shutdown.
func (e *Engine) KickoffScanner(path string, startLine int64) {
	e.AddScanner()
	sc := e.scannerCtx.Load()
	if sc != nil {
		go e.StartWordlistScanner(sc.ctx, atomic.LoadInt64(&e.RunID), path, startLine)
	}
}

func (e *Engine) AddScanner() { e.scannerWg.Add(1) }

// StartWordlistScanner reads from a wordlist and submits payloads to the engine
// in a SINGLE pass, updating TotalLines atomically as it goes.
func (e *Engine) StartWordlistScanner(ctx context.Context, runID int64, path string, startLine int64) {
	defer e.scannerWg.Done()
	e.Config.Lock()
	e.Config.WordlistPath = path
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()

	file, err := os.Open(path)
	if err != nil {
		res := Result{
			Path:         path,
			StatusCode:   0,
			IsAutoFilter: true,
			Headers:      map[string]string{"Msg": "Error opening wordlist: " + err.Error()},
		}
		e.handleResultWithContext(ctx, res)
		return
	}
	defer file.Close()

	lineNum := int64(0)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	// Load methods/smartAPI/extensions from the immutable snapshot once and
	// refresh only when the snapshot pointer changes. This avoids taking
	// the config RLock for every wordlist line.
	snap := e.configSnap.Load()
	var methods []string
	var smartAPI bool
	var exts []string
	if snap != nil {
		methods = snap.Methods
		smartAPI = snap.SmartAPI
		exts = make([]string, len(snap.Extensions))
		copy(exts, snap.Extensions)
	} else {
		e.Config.RLock()
		methods = e.Config.Methods
		smartAPI = e.Config.SmartAPI
		exts = make([]string, len(e.Config.Extensions))
		copy(exts, e.Config.Extensions)
		e.Config.RUnlock()
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			e.saveResumeState(path, lineNum, true)
			return
		default:
		}

		// Respect pause. Use the snapshot first; fall back to the lock if
		// the snapshot isn't available.
		var paused bool
		if s := e.configSnap.Load(); s != nil {
			paused = s.IsPaused
		} else {
			e.Config.RLock()
			paused = e.Config.IsPaused
			e.Config.RUnlock()
		}
		for paused {
			time.Sleep(100 * time.Millisecond)
			select {
			case <-ctx.Done():
				e.saveResumeState(path, lineNum, true)
				return
			default:
			}
			if s := e.configSnap.Load(); s != nil {
				paused = s.IsPaused
			} else {
				e.Config.RLock()
				paused = e.Config.IsPaused
				e.Config.RUnlock()
			}
		}

		line := strings.TrimRight(scanner.Text(), "\r")
		if line == "" {
			continue
		}
		lineNum++

		select {
		case <-ticker.C:
			e.saveResumeState(path, lineNum, false)
		default:
		}

		if lineNum <= startLine {
			continue
		}

		// Refresh locals if the global snapshot changed.
		if cur := e.configSnap.Load(); cur != snap && cur != nil {
			snap = cur
			methods = snap.Methods
			smartAPI = snap.SmartAPI
			exts = make([]string, len(snap.Extensions))
			copy(exts, snap.Extensions)
		}

		methodsToUse := resolveMethodsForPath(line, methods, smartAPI)
		for _, method := range methodsToUse {
			// Increment total for this base path.
			atomic.AddInt64(&e.TotalLines, 1)
			e.Submit(Job{Path: line, Depth: 0, Method: method, RunID: runID})
			for _, ext := range exts {
				cleanExt := strings.TrimSpace(ext)
				if !strings.HasPrefix(cleanExt, ".") {
					cleanExt = "." + cleanExt
				}
				atomic.AddInt64(&e.TotalLines, 1)
				e.Submit(Job{Path: line + cleanExt, Depth: 0, Method: method, RunID: runID})
			}
		}
	}

	if err := scanner.Err(); err != nil {
		res := Result{
			Path:         path,
			StatusCode:   0,
			IsAutoFilter: true,
			Headers:      map[string]string{"Msg": "Wordlist scan error: " + err.Error()},
		}
		e.handleResultWithContext(ctx, res)
	}
}

// resolveMethodsForPath returns the HTTP methods to use for a given path,
// taking into account SmartAPI mode.
func resolveMethodsForPath(line string, methods []string, smartAPI bool) []string {
	if len(methods) == 0 {
		return []string{""}
	}
	if !smartAPI || isAPIPath(line) {
		return methods
	}
	return []string{""}
}

type Estimate struct {
	BaseWords       int64
	Extensions      int
	Methods         int
	EstimatedJobs   int64
	Recursive       bool
	MaxDepth        int
	RecursiveWorst  int64
	RecursiveCapped bool
}

func (e *Engine) EstimateWordlist(path string, startLine int64) (Estimate, error) {
	e.Config.RLock()
	methods := append([]string(nil), e.Config.Methods...)
	smartAPI := e.Config.SmartAPI
	extensions := append([]string(nil), e.Config.Extensions...)
	recursive := e.Config.Recursive
	maxDepth := e.Config.MaxDepth
	e.Config.RUnlock()

	file, err := os.Open(path)
	if err != nil {
		return Estimate{}, err
	}
	defer file.Close()

	var jobs int64
	var words int64
	lineNum := int64(0)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		if line == "" {
			continue
		}
		lineNum++
		if lineNum <= startLine {
			continue
		}
		words++
		methodCount := int64(len(resolveMethodsForPath(line, methods, smartAPI)))
		jobs += methodCount * int64(1+len(extensions))
	}
	if err := scanner.Err(); err != nil {
		return Estimate{}, err
	}

	methodCount := len(methods)
	if methodCount == 0 {
		methodCount = 1
	}
	est := Estimate{
		BaseWords:      words,
		Extensions:     len(extensions),
		Methods:        methodCount,
		EstimatedJobs:  jobs,
		Recursive:      recursive,
		MaxDepth:       maxDepth,
		RecursiveWorst: jobs,
	}
	if recursive && maxDepth > 0 {
		worst := jobs
		level := jobs
		for depth := 1; depth <= maxDepth; depth++ {
			if level > 1_000_000_000/maxInt64(jobs, 1) {
				est.RecursiveCapped = true
				worst = 1_000_000_000
				break
			}
			level *= maxInt64(jobs, 1)
			worst += level
			if worst > 1_000_000_000 {
				est.RecursiveCapped = true
				worst = 1_000_000_000
				break
			}
		}
		est.RecursiveWorst = worst
	}
	return est, nil
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// isAPIPath returns true when the path segment looks like an API endpoint.
// Uses segment-boundary matching to avoid false positives like /overview1.
var apiPathRe = regexp.MustCompile(`(?i)(^|/)(v\d+|api|rest|graphql)(/|$)`)

func isAPIPath(line string) bool {
	return apiPathRe.MatchString(line)
}

// ─── Resume support ───────────────────────────────────────────────────────────

func (e *Engine) saveResumeState(wordlist string, lineNum int64, persistBloom bool) {
	if e.ResumeFile == "" {
		return
	}
	state := map[string]interface{}{
		"wordlist":  wordlist,
		"line":      lineNum,
		"processed": atomic.LoadInt64(&e.ProcessedLines),
		"total":     atomic.LoadInt64(&e.TotalLines),
		"target":    e.BaseURL(),
	}
	data, err := json.Marshal(state)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to marshal resume state: %v\n", err)
		return
	}
	if err := os.WriteFile(e.ResumeFile, data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to write resume file: %v\n", err)
	}
	if persistBloom {
		if err := e.saveBloomResumeState(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to write bloom resume state: %v\n", err)
		}
	}
}

func (e *Engine) bloomResumePath() string {
	if e.ResumeFile == "" {
		return ""
	}
	return e.ResumeFile + ".bloom"
}

func (e *Engine) saveBloomResumeState() error {
	path := e.bloomResumePath()
	if path == "" {
		return nil
	}
	data, err := e.shardedFilter.marshalBinary()
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func (e *Engine) loadBloomResumeState() error {
	path := e.bloomResumePath()
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return e.shardedFilter.unmarshalBinary(data)
}

func (e *Engine) LoadResumeState(path string) (string, int64, error) {
	if e.ResumeFile == "" {
		e.ResumeFile = path
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", 0, err
	}
	var state map[string]interface{}
	if err := json.Unmarshal(data, &state); err != nil {
		return "", 0, err
	}
	wordlist, _ := state["wordlist"].(string)
	lineF, _ := state["line"].(float64)
	if err := e.loadBloomResumeState(); err != nil {
		return "", 0, fmt.Errorf("loading bloom resume state: %w", err)
	}
	return wordlist, int64(lineF), nil
}

// ─── Calibration ─────────────────────────────────────────────────────────────

// AutoCalibrate detects wildcard responses using randomised paths.
// Body comparison uses a normalised hash so that path-reflecting wildcard
// pages (which vary in size) are still detected correctly.
func (e *Engine) AutoCalibrate() error {
	randoms := make([]string, CalibrationTestCount)
	for i := range randoms {
		randoms[i] = randomString(CalibrationRandomStringLen)
	}

	type sample struct {
		statusCode int
		bodyHash   [32]byte
		bodySize   int
	}

	var first *sample
	consistent := true

	for i := range randoms {
		word := randoms[i]
		currentBaseURL := e.BaseURL()
		fullURL := ""
		if strings.Contains(currentBaseURL, "{PAYLOAD}") {
			fullURL = strings.Replace(currentBaseURL, "{PAYLOAD}", word, 1)
		} else {
			fullURL = strings.TrimRight(currentBaseURL, "/") + "/" + word
		}

		parsedURL, errURL := url.Parse(fullURL)
		if errURL != nil {
			return fmt.Errorf("invalid calibration URL: %w", errURL)
		}
		reqPath := parsedURL.Path
		if parsedURL.RawQuery != "" {
			reqPath += "?" + parsedURL.RawQuery
		}
		if reqPath == "" {
			reqPath = "/"
		}

		var ua string
		if snapshot := e.configSnap.Load(); snapshot != nil {
			ua = snapshot.UserAgent
		} else {
			e.Config.RLock()
			ua = e.Config.UserAgent
			e.Config.RUnlock()
		}

		rawRequest := []byte(fmt.Sprintf(
			"GET %s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\nUser-Agent: %s\r\nAccept: */*\r\nAccept-Encoding: identity\r\n\r\n",
			reqPath, parsedURL.Host, ua,
		))

		var proxyAddr string
		if e.proxyDialer {
			proxyAddr = e.GetNextProxy()
		}

		sc := e.scannerCtx.Load()
		if sc == nil {
			return fmt.Errorf("scanner context not available")
		}

		resp, err := e.executeRequestWithRetry(sc.ctx, fullURL, rawRequest, CalibrationTimeout, proxyAddr)
		if err != nil {
			return fmt.Errorf("calibration request failed: %v", err)
		}

		// Normalise: replace the random string in the body before hashing so
		// that path-reflecting pages hash identically across requests.
		normBody := bytes.ReplaceAll(resp.Body, []byte(randoms[i]), []byte("FUZZ"))
		h := sha256.Sum256(normBody)

		s := &sample{
			statusCode: resp.StatusCode,
			bodyHash:   h,
			bodySize:   len(normBody),
		}

		if first == nil {
			first = s
		} else if s.statusCode != first.statusCode || s.bodyHash != first.bodyHash {
			consistent = false
			break
		}
	}

	if consistent && first != nil && first.statusCode > 0 {
		fmt.Printf("[+] Wildcard detected! Status: %d, normalised body hash consistent — filtering size: %d\n",
			first.statusCode, first.bodySize)
		e.AddFilterSize(first.bodySize)
	}

	return nil
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.IntN(len(letters))]
	}
	return string(b)
}

func (e *Engine) checkRecursiveWildcard(dirPath string) bool {
	e.Config.RLock()
	delay := e.Config.Delay
	e.Config.RUnlock()
	if delay > 0 {
		time.Sleep(delay)
	}

	randPath := strings.TrimSuffix(dirPath, "/") + "/" + randomString(RecursiveWildcardTestLen)

	var ua string
	if snapshot := e.configSnap.Load(); snapshot != nil {
		ua = snapshot.UserAgent
	} else {
		e.Config.RLock()
		ua = e.Config.UserAgent
		e.Config.RUnlock()
	}

	rawRequest := []byte(fmt.Sprintf(
		"GET %s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\nUser-Agent: %s\r\nAccept: */*\r\n\r\n",
		randPath, e.Host(), ua,
	))

	var proxyAddr string
	if e.proxyDialer {
		proxyAddr = e.GetNextProxy()
	}
	sc := e.scannerCtx.Load()
	if sc == nil {
		return false
	}
	resp, err := e.executeRequestWithRetry(sc.ctx, e.BaseURL(), rawRequest, RecursiveWildcardTimeout, proxyAddr)
	if err != nil {
		return false
	}
	// Treat 200, 403 and common redirect responses as wildcard indicators.
	// Some servers redirect unknown paths (e.g. /*) with 301/302 — these
	// should be treated as wildcard directories to avoid unbounded
	// recursive scanning.
	if resp.StatusCode == 200 || resp.StatusCode == 403 || resp.StatusCode == 301 || resp.StatusCode == 302 {
		return true
	}
	return false
}

// ─── Worker management ────────────────────────────────────────────────────────

func (e *Engine) QueueSize() int { return len(e.jobs) }

// NumWorkers returns the configured worker count for the engine.
func (e *Engine) NumWorkers() int {
	e.workerLock.Lock()
	defer e.workerLock.Unlock()
	return e.numWorkers
}

// Start launches the configured worker pool.
//
// Call Start once per engine instance before KickoffScanner. The method is
// concurrency-safe with Shutdown, but callers should not invoke it repeatedly
// on the same engine because it would spawn duplicate workers.
func (e *Engine) Start() {
	e.workerLock.Lock()
	defer e.workerLock.Unlock()
	now := time.Now().UTC().UnixNano()
	e.startedAtUnix.CompareAndSwap(0, now)
	e.isRunning.Store(true)
	for i := 0; i < e.numWorkers; i++ {
		e.wg.Add(1)
		e.activeWorkers.Add(1)
		e.emitLogEvent(LogLevelInfo, LogCategoryWorker, EventWorkerStarted, fmt.Sprintf("worker %d started", i), map[string]interface{}{"worker_id": i})
		go e.worker(i)
	}
}

func (e *Engine) SetWorkerCount(n int) {
	if n < MinWorkerCount {
		n = MinWorkerCount
	}
	e.Config.Lock()
	e.Config.MaxWorkers = n
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()

	e.workerLock.Lock()
	defer e.workerLock.Unlock()

	if n > e.numWorkers {
		// Grow the pool
		diff := n - e.numWorkers
		for i := 0; i < diff; i++ {
			e.wg.Add(1)
			e.activeWorkers.Add(1)
			workerID := e.numWorkers + i
			e.emitLogEvent(LogLevelInfo, LogCategoryWorker, EventWorkerStarted, fmt.Sprintf("worker %d started", workerID), map[string]interface{}{"worker_id": workerID, "new_size": n})
			go e.worker(workerID)
		}
	} else if n < e.numWorkers {
		// Shrink the pool
		diff := e.numWorkers - n
		for i := 0; i < diff; i++ {
			e.workerStopCh <- struct{}{}
		}
	}

	e.numWorkers = n
	e.UpdateRateLimiterFromDelay()
}

// autoThrottleCheck reduces workers/increases delay on repeated 429s.
// A guard prevents it from firing again once throttling is already applied.
func (e *Engine) autoThrottleCheck() {
	if !e.autoThrottle {
		return
	}
	count429 := atomic.LoadInt64(&e.Count429)
	if count429 > 0 && count429%AutoThrottleInterval == 0 {
		// Only fire once per AutoThrottleInterval batch.
		if !atomic.CompareAndSwapInt32(&e.alreadyThrottled, 0, 1) {
			return
		}
		// Reset so the next batch can trigger again.
		go func() {
			time.Sleep(5 * time.Second)
			atomic.StoreInt32(&e.alreadyThrottled, 0)
		}()

		e.Config.RLock()
		currentWorkers := e.Config.MaxWorkers
		currentDelay := e.Config.Delay
		e.Config.RUnlock()

		newWorkers := currentWorkers * ThrottleWorkerPercent / 100
		if newWorkers < MinThrottledWorkers {
			newWorkers = MinThrottledWorkers
		}
		newDelay := currentDelay + ThrottleDelayIncrease
		if newDelay > MaxThrottleDelay {
			newDelay = MaxThrottleDelay
		}

		e.SetWorkerCount(newWorkers)
		e.SetDelay(newDelay)
		e.emitLogEvent(LogLevelWarning, LogCategorySystem, EventRateLimitHit, fmt.Sprintf("auto-throttle applied: workers %d -> %d, delay %s", currentWorkers, newWorkers, newDelay), map[string]interface{}{
			"current_workers": currentWorkers,
			"new_workers":     newWorkers,
			"new_delay_ms":    newDelay.Milliseconds(),
		})

		res := Result{
			Path:         "AUTO-THROTTLE",
			StatusCode:   429,
			IsAutoFilter: true,
			Headers:      map[string]string{"Msg": fmt.Sprintf("429 spike! Workers: %d→%d, Delay: %s", currentWorkers, newWorkers, newDelay)},
		}
		e.handleResultNonBlocking(res)
	}
}

// ─── Redirect following ───────────────────────────────────────────────────────

func (e *Engine) followRedirectChain(
	ctx context.Context,
	initialResp *httpclient.RawResponse,
	targetURL, reqHost, ua string,
	headers map[string]string,
	maxRedirects int,
	proxyAddr string,
	timeout time.Duration,
) (*httpclient.RawResponse, string) {
	resp := initialResp
	finalURL := ""
	currentURL := targetURL
	ua = normalizeUserAgent(ua)
	if ua == "" {
		ua = "DirFuzz/2.0"
	}

	for i := 0; i < maxRedirects; i++ {
		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			break
		}
		location := resp.GetHeader("Location")
		if location == "" {
			break
		}

		baseURL, err := url.Parse(currentURL)
		if err == nil {
			if locURL, err := url.Parse(location); err == nil {
				location = baseURL.ResolveReference(locURL).String()
			}
		}

		parsedLoc, err := url.Parse(location)
		if err != nil {
			break
		}

		// SSRF guard on redirect destinations — allow override via config.
		e.Config.RLock()
		allow := e.Config.AllowPrivateTargets
		e.Config.RUnlock()
		if err := validateOutboundHostname(parsedLoc.Hostname(), allow); err != nil {
			break
		}

		reqPath := parsedLoc.Path
		if parsedLoc.RawQuery != "" {
			reqPath += "?" + parsedLoc.RawQuery
		}
		if reqPath == "" {
			reqPath = "/"
		}

		var headersStr strings.Builder
		for k, v := range headers {
			if strings.EqualFold(k, "User-Agent") {
				continue
			}
			headersStr.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
		}

		rawReq := []byte(fmt.Sprintf(
			"GET %s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\nUser-Agent: %s\r\n%sAccept: */*\r\n\r\n",
			reqPath, parsedLoc.Host, ua, headersStr.String(),
		))

		nextResp, err := e.executeRequestWithRetry(ctx, location, rawReq, timeout, proxyAddr)
		if err != nil {
			break
		}
		resp = nextResp
		finalURL = location
		currentURL = location
	}

	return resp, finalURL
}

// ─── RPS tracking ─────────────────────────────────────────────────────────────

func (e *Engine) UpdateRPS() {
	nowNano := time.Now().UnixNano()
	lastTick := atomic.LoadInt64(&e.lastTick)
	elapsed := float64(nowNano-lastTick) / 1e9
	if elapsed < 0.1 {
		return
	}
	current := atomic.LoadInt64(&e.ProcessedLines)
	lastProcessed := atomic.LoadInt64(&e.lastProcessed)
	delta := current - lastProcessed
	atomic.StoreInt64(&e.CurrentRPS, int64(float64(delta)/elapsed))
	atomic.StoreInt64(&e.lastProcessed, current)
	atomic.StoreInt64(&e.lastTick, nowNano)
}

// ─── HTTP request execution ───────────────────────────────────────────────────

func (e *Engine) executeRequestWithRetry(ctx context.Context, targetURL string, rawRequest []byte, timeout time.Duration, proxyAddr string) (*httpclient.RawResponse, error) {
	e.Config.RLock()
	retries := e.Config.MaxRetries
	insecure := e.Config.Insecure
	h2Mode := e.Config.H2Mode
	antiBotFallback := e.Config.AntiBotFallback
	e.Config.RUnlock()

	if ctx == nil {
		ctx = context.Background()
	}

	if h2Mode && e.H2Client != nil {
		return e.executeH2RequestWithRetry(ctx, targetURL, rawRequest, timeout)
	}

	backoff := 1 * time.Second
	var (
		resp *httpclient.RawResponse
		err  error
	)
	for attempt := 0; attempt <= retries; attempt++ {
		resp, err = e.executeRequestOnce(ctx, targetURL, rawRequest, timeout, proxyAddr, insecure, h2Mode, antiBotFallback)
		if err == nil {
			e.mergeResponseCookies(targetURL, resp)
			if retryResp, handled := e.handleAntiBotResponse(ctx, targetURL, rawRequest, timeout, proxyAddr, insecure, h2Mode, antiBotFallback, resp); handled {
				return retryResp, nil
			}
			return resp, nil
		}
		if isContextDoneError(ctx, err) {
			return nil, err
		}
		e.emitLogEvent(LogLevelWarning, LogCategoryNetwork, EventRetryAttempt, fmt.Sprintf("request attempt %d failed: %v", attempt+1, err), map[string]interface{}{
			"attempt":     attempt + 1,
			"max_retries": retries,
			"target":      targetURL,
			"proxy":       proxyAddr,
			"error":       err.Error(),
		})
		if attempt < retries {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
				backoff *= 2
			}
		}
	}
	if err != nil {
		e.emitLogEvent(LogLevelError, LogCategoryNetwork, EventNetworkError, fmt.Sprintf("request failed after %d attempt(s): %v", retries+1, err), map[string]interface{}{
			"attempts": retries + 1,
			"target":   targetURL,
			"proxy":    proxyAddr,
			"error":    err.Error(),
		})
	}
	return resp, err
}

func (e *Engine) executeH2RequestWithRetry(ctx context.Context, targetURL string, rawRequest []byte, timeout time.Duration) (*httpclient.RawResponse, error) {
	e.Config.RLock()
	retries := e.Config.MaxRetries
	e.Config.RUnlock()

	if ctx == nil {
		ctx = context.Background()
	}

	backoff := 1 * time.Second
	var (
		resp *httpclient.RawResponse
		err  error
	)
	for attempt := 0; attempt <= retries; attempt++ {
		resp, err = e.executeH2Request(ctx, targetURL, rawRequest, timeout)
		if err == nil {
			return resp, nil
		}
		if isContextDoneError(ctx, err) {
			return nil, err
		}
		e.emitLogEvent(LogLevelWarning, LogCategoryNetwork, EventRetryAttempt, fmt.Sprintf("h2 attempt %d failed: %v", attempt+1, err), map[string]interface{}{
			"attempt":     attempt + 1,
			"max_retries": retries,
			"target":      targetURL,
			"error":       err.Error(),
		})
		if attempt < retries {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
				backoff *= 2
			}
		}
	}
	if err != nil {
		e.emitLogEvent(LogLevelError, LogCategoryNetwork, EventNetworkError, fmt.Sprintf("h2 request failed after %d attempt(s): %v", retries+1, err), map[string]interface{}{
			"attempts": retries + 1,
			"target":   targetURL,
			"error":    err.Error(),
		})
	}
	return resp, err
}

func isContextDoneError(ctx context.Context, err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	return ctx != nil && ctx.Err() != nil && errors.Is(err, ctx.Err())
}

func (e *Engine) executeH2Request(ctx context.Context, targetURL string, rawRequest []byte, timeout time.Duration) (*httpclient.RawResponse, error) {
	if e.H2Client == nil {
		if err := e.RefreshH2Client(); err != nil {
			return nil, err
		}
	}
	if e.H2Client == nil {
		return nil, fmt.Errorf("HTTP/2 client is not initialized")
	}

	if sem := e.h2StreamSem; sem != nil {
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	req, err := buildH2HTTPRequest(ctx, targetURL, rawRequest)
	if err != nil {
		return nil, err
	}
	e.requestsDispatched.Add(1)
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
		req = req.WithContext(ctx)
	}

	start := time.Now()
	resp, err := e.H2Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return rawResponseFromHTTPResponse(resp, start)
}

func buildH2HTTPRequest(ctx context.Context, targetURL string, rawRequest []byte) (*http.Request, error) {
	parsedTarget, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(rawRequest)))
	if err != nil {
		return nil, fmt.Errorf("failed to parse raw request: %w", err)
	}
	defer req.Body.Close()

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read raw request body: %w", err)
	}

	reqURL := *parsedTarget
	reqURL.Path = req.URL.Path
	reqURL.RawPath = req.URL.RawPath
	reqURL.RawQuery = req.URL.RawQuery
	reqURL.Fragment = ""
	if reqURL.Path == "" {
		reqURL.Path = "/"
	}

	outReq, err := http.NewRequestWithContext(ctx, req.Method, reqURL.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to build H2 request: %w", err)
	}
	outReq.Host = req.Host
	if outReq.Host == "" {
		outReq.Host = parsedTarget.Host
	}
	outReq.Header = req.Header.Clone()
	for _, key := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Transfer-Encoding", "Upgrade", "HTTP2-Settings"} {
		outReq.Header.Del(key)
	}
	return outReq, nil
}

func rawResponseFromHTTPResponse(resp *http.Response, start time.Time) (*httpclient.RawResponse, error) {
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, httpclient.MaxBodySize))
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var headersStr bytes.Buffer
	headersStr.WriteString(fmt.Sprintf("%s %s\r\n", resp.Proto, resp.Status))
	headerMap := make(map[string]string, len(resp.Header))
	for k, vals := range resp.Header {
		if len(vals) == 0 {
			continue
		}
		headerMap[strings.ToLower(k)] = vals[0]
		for _, v := range vals {
			headersStr.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
		}
	}

	var raw bytes.Buffer
	raw.WriteString(headersStr.String())
	raw.WriteString("\r\n")
	raw.Write(respBody)

	return &httpclient.RawResponse{
		StatusCode:   resp.StatusCode,
		Headers:      headersStr.String(),
		HeaderMap:    headerMap,
		Body:         respBody,
		Raw:          raw.Bytes(),
		Duration:     time.Since(start),
		BodyComplete: true,
	}, nil
}

// ─── Worker ───────────────────────────────────────────────────────────────────

// buildRequest constructs a raw HTTP request byte slice.
func buildRequest(method, reqPath, reqHost, ua, headersStr, bodyContent string) []byte {
	// Prevent CRLF injection in the request line.
	reqPath = strings.ReplaceAll(reqPath, "\r", "")
	reqPath = strings.ReplaceAll(reqPath, "\n", "")

	reqHost = strings.ReplaceAll(reqHost, "\r", "")
	reqHost = strings.ReplaceAll(reqHost, "\n", "")

	ua = strings.ReplaceAll(ua, "\r", "")
	ua = strings.ReplaceAll(ua, "\n", "")

	// For headersStr, we shouldn't simply remove all CRLFs as headers are separated by CRLF.
	// We need to ensure that the injected payload in the header doesn't create NEW headers.
	// Since headersStr is constructed earlier using `{PAYLOAD}` replacements,
	// we should ensure that `headersStr` does not contain double CRLF `\r\n\r\n`
	// which would prematurely end the headers section. But actually, `headersStr`
	// is built properly in worker() before passing here.
	// It's safer to ensure that no `\n` without preceding `\r` and no `\r\n\r\n` exist.
	// However, `headersStr` may naturally contain `\r\n` separating valid headers.
	// Let's strip double CRLF to prevent premature body termination.
	for strings.Contains(headersStr, "\r\n\r\n") {
		headersStr = strings.ReplaceAll(headersStr, "\r\n\r\n", "\r\n")
	}

	if bodyContent != "" {
		return []byte(fmt.Sprintf(
			"%s %s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\nUser-Agent: %s\r\n%sAccept: */*\r\nAccept-Encoding: identity\r\n\r\n%s",
			method, reqPath, reqHost, ua, headersStr, bodyContent,
		))
	}
	return []byte(fmt.Sprintf(
		"%s %s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\nUser-Agent: %s\r\n%sAccept: */*\r\nAccept-Encoding: identity\r\n\r\n",
		method, reqPath, reqHost, ua, headersStr,
	))
}

func spiderChildJob(parent Job, newPath string) Job {
	return Job{
		Path:   newPath,
		Depth:  parent.Depth + 1,
		Method: "GET",
		RunID:  parent.RunID,
	}
}

func computeResponseMetrics(resp *httpclient.RawResponse, successfulMethod string) (bodySize, wordCount, lineCount int, contentType string, bodyHash uint64) {
	bodySize = len(resp.Body)
	wordCount = -1
	lineCount = -1

	if resp.BodyEncoded {
		bodySize = -1
	} else {
		if successfulMethod == "HEAD" {
			clVal := resp.GetHeader("Content-Length")
			if clVal != "" {
				if s, parseErr := strconv.Atoi(clVal); parseErr == nil {
					bodySize = s
				}
			}
		}

		if len(resp.Body) == 0 {
			wordCount = 0
			lineCount = 0
		} else {
			wordCount = 0
			lineCount = 0
			inWord := false
			for i := 0; i < len(resp.Body); {
				r, size := utf8.DecodeRune(resp.Body[i:])
				i += size
				if r == '\n' {
					lineCount++
				}
				if unicode.IsSpace(r) {
					if inWord {
						inWord = false
					}
				} else {
					if !inWord {
						wordCount++
						inWord = true
					}
				}
			}
			lineCount = lineCount + 1
		}
	}

	contentType = resp.GetHeader("Content-Type")
	if idx := strings.Index(contentType, ";"); idx != -1 {
		contentType = strings.TrimSpace(contentType[:idx])
	}
	bodyHash = simhashBody(resp.Body)
	return
}

func isSameSpiderScopeHost(baseHostname string, parsedLink *url.URL) bool {
	if !parsedLink.IsAbs() {
		return true
	}
	return strings.EqualFold(parsedLink.Hostname(), baseHostname)
}

// applyFilters returns true when the result should be kept (not filtered).
func (e *Engine) applyFilters(
	resp *httpclient.RawResponse,
	bodySize, wordCount, lineCount int,
	bodyHash uint64,
	contentType string,
	forceKeep bool,
	filterSizes map[int]bool,
	filterSizeRanges []SizeRange,
	matchCodes map[int]bool,
	filterWords, filterLines, matchWords, matchLines int,
	matchContentTypes, filterContentTypes []string,
	filterRTMin, filterRTMax time.Duration,
	skipRT bool,
) bool {
	if forceKeep {
		return true
	}
	// 1. Status code.
	if len(matchCodes) > 0 && !matchCodes[resp.StatusCode] {
		return false
	}
	// 2. Exact size filter.
	if len(filterSizes) > 0 && filterSizes[bodySize] {
		return false
	}
	// 3. Size range filter (NEW).
	for _, r := range filterSizeRanges {
		// If bodySize is unknown (-1) do not match any size ranges.
		if bodySize >= 0 && bodySize >= r.Min && bodySize <= r.Max {
			return false
		}
	}
	// 4. Word / line counts.
	if filterWords >= 0 && wordCount == filterWords {
		return false
	}
	if filterLines >= 0 && lineCount == filterLines {
		return false
	}
	if matchWords >= 0 && wordCount != matchWords {
		return false
	}
	if matchLines >= 0 && lineCount != matchLines {
		return false
	}
	// 5. Body regex.
	if mRe := e.matchRe.Load(); mRe != nil {
		if resp.BodyEncoded || !mRe.Match(resp.Body) {
			return false
		}
	}
	if fRe := e.filterRe.Load(); fRe != nil && !resp.BodyEncoded && fRe.Match(resp.Body) {
		return false
	}
	// 6. Response time.
	if !skipRT {
		if filterRTMin > 0 && resp.Duration < filterRTMin {
			return false
		}
		if filterRTMax > 0 && resp.Duration > filterRTMax {
			return false
		}
	}
	// 7. Content-type match (NEW).
	ctLower := strings.ToLower(contentType)
	if len(matchContentTypes) > 0 {
		matched := false
		for _, ct := range matchContentTypes {
			if strings.Contains(ctLower, strings.ToLower(ct)) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	// 8. Content-type filter (NEW).
	for _, ct := range filterContentTypes {
		if strings.Contains(ctLower, strings.ToLower(ct)) {
			return false
		}
	}
	// 9. SimHash soft-404 clustering.
	if e.isSimhashSoftFour(bodyHash) {
		atomic.AddInt64(&e.SimhashSuppressed, 1)
		e.emitLogEvent(LogLevelWarning, LogCategoryFilter, EventSimhashCluster, fmt.Sprintf("simhash cluster suppressed body hash %x", bodyHash), map[string]interface{}{
			"body_hash": bodyHash,
			"status":    resp.StatusCode,
			"size":      bodySize,
		})
		return false
	}
	return true
}

func (e *Engine) cleanupJob(shouldExit bool) bool {
	e.activeJobs.Done()
	return shouldExit
}

// invokeOnFindingHook calls the match plugin's optional on_finding(result) hook.
// Returns (dropped, labels, confidence). Dropped indicates the plugin requested
// the result not be emitted to the results channel.
func (e *Engine) invokeOnFindingHook(ctx context.Context, res *Result) (bool, []string, string) {
	if e.matchPlugin == nil {
		return false, nil, ""
	}
	// Build values to pass into the plugin.
	var timeout time.Duration
	var proxyOut string
	var insecure bool
	var allowPrivate bool

	if snap := e.configSnap.Load(); snap != nil {
		timeout = snap.Timeout
		proxyOut = snap.ProxyOut
	}
	e.Config.RLock()
	insecure = e.Config.Insecure
	allowPrivate = e.Config.AllowPrivateTargets
	e.Config.RUnlock()

	dropped, labels, confidence := e.matchPlugin.OnFinding(ctx, timeout, proxyOut, insecure, allowPrivate, res)
	return dropped, labels, confidence
}

// handleResultWithContext attempts to call any on_finding hook and send the
// result to the results channel. Returns true if the context was cancelled
// before the result could be emitted (caller should exit).
func (e *Engine) handleResultWithContext(ctx context.Context, res Result) bool {
	if dropped, labels, conf := e.invokeOnFindingHook(ctx, &res); dropped {
		// Plugin suppressed emission; treat as normal (not interrupted).
		return false
	} else {
		if len(labels) > 0 {
			res.Labels = append(res.Labels, labels...)
		}
		if conf != "" {
			res.Confidence = conf
		}
	}

	select {
	case e.Results <- res:
		e.resultsCollected.Add(1)
		return false
	case <-ctx.Done():
		return true
	}
}

// handleResultNonBlocking calls on_finding and attempts a non-blocking send.
// If the results channel is full the result is dropped and TUIDropped is incremented.
func (e *Engine) handleResultNonBlocking(res Result) {
	if dropped, labels, conf := e.invokeOnFindingHook(context.Background(), &res); dropped {
		return
	} else {
		if len(labels) > 0 {
			res.Labels = append(res.Labels, labels...)
		}
		if conf != "" {
			res.Confidence = conf
		}
	}

	select {
	case e.Results <- res:
		e.resultsCollected.Add(1)
	default:
		atomic.AddInt64(&e.TUIDropped, 1)
	}
}

// verbTamperHeaders returns method-override headers for non-GET/HEAD methods.
// GET and HEAD are excluded by design since overriding to those verbs has no
// access-control relevance.
func verbTamperHeaders(method string) map[string]string {
	switch strings.ToUpper(method) {
	case "GET", "HEAD":
		return nil
	}
	return map[string]string{
		"X-HTTP-Method-Override": method,
		"X-Forwarded-Method":     method,
		"X-Method-Override":      method,
	}
}

func (e *Engine) worker(id int) {
	defer func() {
		e.emitLogEvent(LogLevelInfo, LogCategoryWorker, EventWorkerStopped, fmt.Sprintf("worker %d stopped", id), map[string]interface{}{"worker_id": id})
		e.activeWorkers.Add(-1)
		e.wg.Done()
	}()

	for {
		select {
		case <-e.workerStopCh:
			return
		case job, ok := <-e.jobs:
			if !ok {
				return
			}

			if job.RunID != atomic.LoadInt64(&e.RunID) {
				e.activeJobs.Done()
				continue
			}

			// Load immutable snapshot for this job (cheap atomic pointer load).
			snap := e.configSnap.Load()
			if snap == nil {
				// Lazily initialize if not present.
				e.buildAndStoreConfigSnapshot()
				snap = e.configSnap.Load()
				if snap == nil {
					// Fallback to original locking behavior if snapshot still missing.
					e.Config.RLock()
					local := &configSnapshot{
						MaxWorkers:           e.Config.MaxWorkers,
						IsPaused:             e.Config.IsPaused,
						UserAgent:            e.Config.UserAgent,
						Headers:              make(map[string]string, len(e.Config.Headers)),
						MatchCodes:           make(map[int]bool, len(e.Config.MatchCodes)),
						FilterSizes:          make(map[int]bool, len(e.Config.FilterSizes)),
						FilterSizeRanges:     make([]SizeRange, len(e.Config.FilterSizeRanges)),
						MatchContentTypes:    make([]string, len(e.Config.MatchContentTypes)),
						FilterContentTypes:   make([]string, len(e.Config.FilterContentTypes)),
						FollowRedirects:      e.Config.FollowRedirects,
						MaxRedirects:         e.Config.MaxRedirects,
						RequestBody:          e.Config.RequestBody,
						FilterWords:          e.Config.FilterWords,
						FilterLines:          e.Config.FilterLines,
						MatchWords:           e.Config.MatchWords,
						MatchLines:           e.Config.MatchLines,
						FilterRTMin:          e.Config.FilterRTMin,
						FilterRTMax:          e.Config.FilterRTMax,
						ProxyOut:             e.Config.ProxyOut,
						Timeout:              e.Config.Timeout,
						SaveRaw:              e.Config.SaveRaw,
						AutoFilterThreshold:  e.Config.AutoFilterThreshold,
						SimhashThreshold:     e.Config.SimhashThreshold,
						SimhashClusterLimit:  e.Config.SimhashClusterLimit,
						H2Mode:               e.Config.H2Mode,
						H2ConcurrentStreams:  e.Config.H2ConcurrentStreams,
						TimingOracle:         e.Config.TimingOracle,
						TimeOracleK:          e.Config.TimeOracleK,
						TimeOracleN:          e.Config.TimeOracleN,
						TimeTrim:             e.Config.TimeTrim,
						Harvest:              e.Config.Harvest,
						HarvestJS:            e.Config.HarvestJS,
						HarvestAPI:           e.Config.HarvestAPI,
						HarvestResponse:      e.Config.HarvestResponse,
						HarvestResponseDepth: e.Config.HarvestResponseDepth,
						HarvestResponseFetch: e.Config.HarvestResponseFetch,
						ParamWordlist:        append([]string(nil), e.Config.ParamWordlist...),
						EvasionLimit:         e.Config.EvasionLimit,
						Mutate:               e.Config.Mutate,
						Recursive:            e.Config.Recursive,
						MaxDepth:             e.Config.MaxDepth,
						WordlistPath:         e.Config.WordlistPath,
						WAFEvasion:           e.Config.WAFEvasion,
						VerbTamper:           e.Config.VerbTamper,
						FourOhThreeBypass:    e.Config.FourOhThreeBypass,
						Spidering:            e.Config.Spidering,
						AuthMatrix:           make(map[string][]string, len(e.Config.AuthMatrix)),
					}
					ua := local.UserAgent
					for k, v := range e.Config.Headers {
						if strings.EqualFold(k, "User-Agent") {
							ua = normalizeUserAgent(v)
							continue
						}
						local.Headers[k] = v
					}
					local.UserAgent = ua
					for k, v := range e.Config.MatchCodes {
						local.MatchCodes[k] = v
					}
					for k, v := range e.Config.FilterSizes {
						local.FilterSizes[k] = v
					}
					copy(local.FilterSizeRanges, e.Config.FilterSizeRanges)
					copy(local.MatchContentTypes, e.Config.MatchContentTypes)
					copy(local.FilterContentTypes, e.Config.FilterContentTypes)
					for role, hdrs := range e.Config.AuthMatrix {
						local.AuthMatrix[role] = append([]string(nil), hdrs...)
					}
					e.Config.RUnlock()
					snap = local
				}
			}
			// Copy snapshot values into local variables used below.
			paused := snap.IsPaused
			ua := snap.UserAgent
			headers := snap.Headers
			matchCodes := snap.MatchCodes
			filterSizes := snap.FilterSizes
			filterSizeRanges := snap.FilterSizeRanges
			matchContentTypes := snap.MatchContentTypes
			filterContentTypes := snap.FilterContentTypes
			followRedirects := snap.FollowRedirects
			maxRedirects := snap.MaxRedirects
			requestBody := snap.RequestBody
			filterWords := snap.FilterWords
			filterLines := snap.FilterLines
			matchWords := snap.MatchWords
			matchLines := snap.MatchLines
			filterRTMin := snap.FilterRTMin
			filterRTMax := snap.FilterRTMax
			proxyOut := snap.ProxyOut
			requestTimeout := snap.Timeout
			if requestTimeout <= 0 {
				requestTimeout = DefaultHTTPTimeout
			}
			saveRaw := snap.SaveRaw
			authMatrix := snap.AuthMatrix
			autoFilterThreshold := snap.AutoFilterThreshold
			doMutate := snap.Mutate
			doRecurse := snap.Recursive
			maxDepth := snap.MaxDepth
			wordlistPath := snap.WordlistPath
			wafEvasion := snap.WAFEvasion
			verbTamper := snap.VerbTamper
			fourOhThreeBypass := snap.FourOhThreeBypass
			spidering := snap.Spidering

			shouldExit := id >= snap.MaxWorkers

			sc := e.scannerCtx.Load()
			if sc == nil {
				if e.cleanupJob(shouldExit) {
					return
				}
				continue
			}
			localCtx := sc.ctx

			// Pause loop — re-check the immutable snapshot to avoid frequent
			// locking on the hot path. Fall back to the config lock if the
			// snapshot is temporarily unavailable.
			for paused {
				select {
				case <-localCtx.Done():
					e.activeJobs.Done()
					return
				case <-time.After(100 * time.Millisecond):
				}
				if s := e.configSnap.Load(); s != nil {
					paused = s.IsPaused
				} else {
					e.Config.RLock()
					paused = e.Config.IsPaused
					e.Config.RUnlock()
				}
			}

			payload := job.Path
			depth := job.Depth

			e.targetLock.RLock()
			currentBaseURL := e.baseURL
			e.targetLock.RUnlock()

			// Build full URL.
			var fullURL string
			word := payload
			if strings.Contains(currentBaseURL, "{PAYLOAD}") {
				fullURL = strings.Replace(currentBaseURL, "{PAYLOAD}", word, 1)
			} else {
				if !strings.HasPrefix(word, "/") {
					word = "/" + word
				}
				fullURL = strings.TrimRight(currentBaseURL, "/") + word
			}

			parsedURL, errURL := url.Parse(fullURL)
			if errURL != nil {
				if e.cleanupJob(shouldExit) {
					return
				}
				continue
			}

			reqHost := parsedURL.Host
			reqHostname := parsedURL.Hostname()

			// Per-host rate limiter.
			limiter := e.getLimiter(reqHost)
			waitStart := time.Now()
			if err := limiter.Wait(localCtx); err != nil {
				if e.cleanupJob(shouldExit) {
					return
				}
				continue
			} else if waited := time.Since(waitStart); waited > time.Millisecond {
				e.emitLogEvent(LogLevelInfo, LogCategoryNetwork, EventRateLimitHit, fmt.Sprintf("rate limiter delayed request by %s", waited.Round(time.Millisecond)), map[string]interface{}{
					"host":    reqHost,
					"wait_ms": waited.Milliseconds(),
					"path":    job.Path,
					"method":  job.Method,
					"run_id":  job.RunID,
				})
			}

			reqPath := parsedURL.Path
			if parsedURL.RawQuery != "" {
				reqPath += "?" + parsedURL.RawQuery
			}
			if reqPath == "" {
				reqPath = "/"
			}

			// Inject payload into User-Agent.
			ua = normalizeUserAgent(strings.ReplaceAll(ua, "{PAYLOAD}", payload))
			if ua == "" {
				ua = "DirFuzz/2.0"
			}

			// Merge base + per-job headers into a local map, then render once.
			// Keep user-provided header precedence by only adding auto verb
			// tamper headers when they are not already present.
			reqHeaders := make(map[string]string, len(headers)+len(job.ExtraHeaders)+3)
			for k, v := range headers {
				reqHeaders[k] = v
			}
			for k, v := range job.ExtraHeaders {
				reqHeaders[k] = v
			}
			if verbTamper {
				if overrideHdrs := verbTamperHeaders(job.Method); overrideHdrs != nil {
					for k, v := range overrideHdrs {
						if _, exists := reqHeaders[k]; !exists {
							reqHeaders[k] = v
						}
					}
				}
			}

			headerSafePayload := sanitizeHeaderToken(payload)
			var reqHdrKeys []string
			for k := range reqHeaders {
				reqHdrKeys = append(reqHdrKeys, k)
			}
			sort.Strings(reqHdrKeys)
			var headersBuilder strings.Builder
			for _, k := range reqHdrKeys {
				safeK := sanitizeHeaderToken(k)
				safeV := sanitizeHeaderToken(strings.ReplaceAll(reqHeaders[k], "{PAYLOAD}", headerSafePayload))
				headersBuilder.WriteString(fmt.Sprintf("%s: %s\r\n", safeK, safeV))
			}
			headersStr := headersBuilder.String()
			headers = reqHeaders

			var proxyAddr string
			if e.proxyDialer {
				proxyAddr = e.GetNextProxy()
			}

			// ── Execute request ────────────────────────────────────────────────
			var resp *httpclient.RawResponse
			var err error
			var successfulMethod string
			var rawRequest []byte
			var authFinding *AuthMatrixFinding
			var bodyContent string
			var timingMedian time.Duration
			var timingOracleHit bool
			var timingOracleZ float64
			var samples []time.Duration
			var oracleErr error
			oracleEnabled := snap.TimingOracle && e.timingOracle != nil

			if job.Method == "" {
				bodyFilterActive := e.matchRe.Load() != nil || e.filterRe.Load() != nil ||
					filterWords >= 0 || filterLines >= 0 || matchWords >= 0 || matchLines >= 0 ||
					len(matchContentTypes) > 0 || len(filterContentTypes) > 0

				if len(authMatrix) > 0 {
					successfulMethod = "GET"
					resp, rawRequest, successfulMethod, authFinding, err = e.executeAuthMatrixRequests(
						localCtx,
						currentBaseURL,
						reqPath,
						reqHost,
						ua,
						reqHeaders,
						requestTimeout,
						proxyAddr,
						authMatrix,
					)
				} else {
					if bodyFilterActive || e.isHeadRejected(reqHost) || followRedirects || oracleEnabled {
						successfulMethod = "GET"
						rawRequest = buildRequest("GET", reqPath, reqHost, ua, headersStr, "")
					} else {
						successfulMethod = "HEAD"
						rawRequest = buildRequest("HEAD", reqPath, reqHost, ua, headersStr, "")
					}

					if oracleEnabled {
						resp, samples, oracleErr = e.executeTimingOracleRequests(localCtx, currentBaseURL, rawRequest, requestTimeout, proxyAddr)
						if oracleErr != nil {
							err = oracleErr
						} else if e.timingOracle != nil {
							timingMedian = e.timingOracle.Median(samples)
							timingOracleHit = e.timingOracle.IsAnomaly(timingMedian)
							timingOracleZ = e.timingOracle.ZScore(timingMedian)
						}
					} else {
						resp, err = e.executeRequestWithRetry(localCtx, currentBaseURL, rawRequest, requestTimeout, proxyAddr)
						if err == nil && successfulMethod == "HEAD" && (resp.StatusCode == 405 || resp.StatusCode == 501) {
							e.markHeadRejected(reqHost)
							successfulMethod = "GET"
							rawRequest = buildRequest("GET", reqPath, reqHost, ua, headersStr, "")
							if fbResp, fbErr := e.executeRequestWithRetry(localCtx, currentBaseURL, rawRequest, requestTimeout, proxyAddr); fbErr == nil {
								resp = fbResp
							} else {
								successfulMethod = "HEAD"
							}
						}
					}
				}
				atomic.AddInt64(&e.ProcessedLines, 1)
			} else {
				successfulMethod = job.Method
				bodyContent = ""
				var methodHdrBuf strings.Builder
				methodHdrBuf.WriteString(headersStr)

				hasContentType := false
				for k := range headers {
					if strings.EqualFold(k, "Content-Type") {
						hasContentType = true
						break
					}
				}

				if requestBody != "" && (job.Method == "POST" || job.Method == "PUT" || job.Method == "PATCH") {
					bodyContent = strings.ReplaceAll(requestBody, "{PAYLOAD}", payload)
					methodHdrBuf.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(bodyContent)))
					if !hasContentType {
						methodHdrBuf.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
					}
				} else if job.Method == "POST" || job.Method == "PUT" || job.Method == "PATCH" || job.Method == "DELETE" {
					methodHdrBuf.WriteString("Content-Length: 0\r\n")
				}
				rawRequest = buildRequest(job.Method, reqPath, reqHost, ua, methodHdrBuf.String(), bodyContent)
				if oracleEnabled {
					resp, samples, oracleErr = e.executeTimingOracleRequests(localCtx, currentBaseURL, rawRequest, requestTimeout, proxyAddr)
					if oracleErr != nil {
						err = oracleErr
					} else if e.timingOracle != nil {
						timingMedian = e.timingOracle.Median(samples)
						timingOracleHit = e.timingOracle.IsAnomaly(timingMedian)
						timingOracleZ = e.timingOracle.ZScore(timingMedian)
					}
				} else {
					resp, err = e.executeRequestWithRetry(localCtx, currentBaseURL, rawRequest, requestTimeout, proxyAddr)
				}
				atomic.AddInt64(&e.ProcessedLines, 1)
			}

			if err != nil {
				if !isContextDoneError(localCtx, err) {
					atomic.AddInt64(&e.CountConnErr, 1)
				}
				if e.cleanupJob(shouldExit) {
					return
				}
				continue
			}

			// Update stats counters.
			switch {
			case resp.StatusCode == 200:
				atomic.AddInt64(&e.Count200, 1)
			case resp.StatusCode == 403:
				atomic.AddInt64(&e.Count403, 1)
			case resp.StatusCode == 404:
				atomic.AddInt64(&e.Count404, 1)
			case resp.StatusCode == 429:
				atomic.AddInt64(&e.Count429, 1)
				e.autoThrottleCheck()
			case resp.StatusCode >= 500:
				atomic.AddInt64(&e.Count500, 1)
			}

			// Follow redirects.
			var finalRedirectURL string
			originalStatusCode := resp.StatusCode
			if followRedirects && resp.StatusCode >= 300 && resp.StatusCode < 400 {
				resp, finalRedirectURL = e.followRedirectChain(localCtx, resp, fullURL, reqHost, ua, headers, maxRedirects, proxyAddr, requestTimeout)
				if resp.StatusCode != originalStatusCode {
					switch {
					case resp.StatusCode == 200:
						atomic.AddInt64(&e.Count200, 1)
					case resp.StatusCode == 403:
						atomic.AddInt64(&e.Count403, 1)
					case resp.StatusCode == 404:
						atomic.AddInt64(&e.Count404, 1)
					}
				}
			}

			bodySize, wordCount, lineCount, contentType, bodyHash := computeResponseMetrics(resp, successfulMethod)
			skipRTFilters := timingOracleHit

			// Apply all filters.
			if !e.applyFilters(resp, bodySize, wordCount, lineCount, bodyHash, contentType,
				timingOracleHit,
				filterSizes, filterSizeRanges, matchCodes,
				filterWords, filterLines, matchWords, matchLines,
				matchContentTypes, filterContentTypes,
				filterRTMin, filterRTMax,
				skipRTFilters) {
				if e.cleanupJob(shouldExit) {
					return
				}
				continue
			}

			// 403 classification.
			forbidden403Type := ""
			var bypassTechniqueLabel string
			if resp.StatusCode == 403 {
				classifyBody := resp.Body
				classifyHeaders := resp.Headers
				if successfulMethod == "HEAD" {
					followupReq := buildRequest("GET", reqPath, reqHost, ua, headersStr, "")
					if followupResp, followupErr := e.executeRequestWithRetry(localCtx, currentBaseURL, followupReq, 3*time.Second, proxyAddr); followupErr == nil {
						classifyBody = followupResp.Body
						classifyHeaders = followupResp.Headers
					}
				}
				forbidden403Type = Classify403(classifyBody, classifyHeaders)

				if wafEvasion || fourOhThreeBypass {
					detectedWAFVendor := "unknown"
					wafRes := FingerprintWAF(classifyBody, classifyHeaders, resp.StatusCode, int64(resp.Duration.Milliseconds()))
					if wafRes.Detected {
						detectedWAFVendor = wafRes.Vendor
					}
					e.setWAFState(wafRes.Detected, detectedWAFVendor)

					evasionLimit := snap.EvasionLimit
					if evasionLimit < 1 {
						evasionLimit = DefaultEvasionLimit
					}

					techniques := EvasionStrategiesFor(detectedWAFVendor)
					if len(techniques) > 0 && e.EvasionScoreboard != nil {
						tried := 0
						for _, technique := range techniques {
							if tried >= evasionLimit {
								break
							}
							if e.evasionTechniqueSeen(payload, technique.Name) {
								continue
							}
							e.markEvasionTechnique(payload, technique.Name)
							tried++
							e.logWAFBypassAttempt(detectedWAFVendor, technique.Name, payload, tried)

							bypassPath, bypassHeaders := technique.ModifyRequest(payload, headers, successfulMethod)
							reqHeaders := make(map[string]string, len(headers)+len(bypassHeaders)+3)
							for k, v := range headers {
								reqHeaders[k] = v
							}
							for k, v := range bypassHeaders {
								reqHeaders[k] = v
							}
							var reqHdrKeys []string
							for k := range reqHeaders {
								reqHdrKeys = append(reqHdrKeys, k)
							}
							sort.Strings(reqHdrKeys)
							var bypassHdrBuf strings.Builder
							headerSafePayload := sanitizeHeaderToken(payload)
							for _, k := range reqHdrKeys {
								safeK := sanitizeHeaderToken(k)
								safeV := sanitizeHeaderToken(strings.ReplaceAll(reqHeaders[k], "{PAYLOAD}", headerSafePayload))
								bypassHdrBuf.WriteString(fmt.Sprintf("%s: %s\r\n", safeK, safeV))
							}
							bypassReq := buildRequest(successfulMethod, bypassPath, reqHost, ua, bypassHdrBuf.String(), bodyContent)
							bypassResp, bypassErr := e.executeRequestWithRetry(localCtx, currentBaseURL, bypassReq, requestTimeout, proxyAddr)
							if bypassErr != nil {
								e.EvasionScoreboard.Record(technique.Name, false)
								e.logWAFBypassOutcome(detectedWAFVendor, technique.Name, payload, false, 0)
								continue
							}
							if bypassResp.StatusCode == 403 || bypassResp.StatusCode == 429 || bypassResp.StatusCode == 444 {
								e.EvasionScoreboard.Record(technique.Name, false)
								e.logWAFBypassOutcome(detectedWAFVendor, technique.Name, payload, false, bypassResp.StatusCode)
								continue
							}

							e.EvasionScoreboard.Record(technique.Name, true)
							e.logWAFBypassOutcome(detectedWAFVendor, technique.Name, payload, true, bypassResp.StatusCode)
							resp = bypassResp
							rawRequest = bypassReq
							bodySize, wordCount, lineCount, contentType, bodyHash = computeResponseMetrics(resp, successfulMethod)
							if strings.Contains(currentBaseURL, "{PAYLOAD}") {
								fullURL = strings.Replace(currentBaseURL, "{PAYLOAD}", bypassPath, 1)
							} else {
								bypassURLPath := bypassPath
								if !strings.HasPrefix(bypassURLPath, "/") {
									bypassURLPath = "/" + bypassURLPath
								}
								fullURL = strings.TrimRight(currentBaseURL, "/") + bypassURLPath
							}
							bypassTechniqueLabel = "BYPASS:" + technique.Name
							break
						}
					}
				}
				if bypassTechniqueLabel != "" && resp.StatusCode != 403 {
					atomic.AddInt64(&e.Count403, -1)
					switch {
					case resp.StatusCode == 200:
						atomic.AddInt64(&e.Count200, 1)
					case resp.StatusCode == 404:
						atomic.AddInt64(&e.Count404, 1)
					case resp.StatusCode >= 500:
						atomic.AddInt64(&e.Count500, 1)
					}
				}
			}

			// Smart Filter.
			if bodySize != -1 && (resp.StatusCode == 200 || resp.StatusCode == 301 || resp.StatusCode == 302 || resp.StatusCode == 403) {
				fpKey := fmt.Sprintf("%d:%d", resp.StatusCode, bodySize)
				if resp.StatusCode == 403 {
					fpKey = fmt.Sprintf("403:%s:%d", forbidden403Type, bodySize)
				}

				e.fpMutex.Lock()
				e.fpCounts[fpKey]++
				count := e.fpCounts[fpKey]
				e.fpMutex.Unlock()

				threshold := autoFilterThreshold
				if threshold > 0 && count == threshold {
					e.AddAutoFilterSize(bodySize)
					e.emitLogEvent(LogLevelSuccess, LogCategoryFilter, EventAutoFilterTriggered, fmt.Sprintf("auto-filter triggered for size %d", bodySize), map[string]interface{}{
						"body_size": bodySize,
						"status":    resp.StatusCode,
						"count":     count,
						"threshold": threshold,
					})
					select {
					case e.Results <- Result{
						Path:         "AUTO-FILTER",
						Method:       successfulMethod,
						StatusCode:   resp.StatusCode,
						Size:         bodySize,
						Headers:      map[string]string{"Msg": fmt.Sprintf("Auto-filtered repetitive size: %d", bodySize)},
						IsAutoFilter: true,
					}:
						e.resultsCollected.Add(1)
					default:
					}
				}
				if threshold > 0 && count >= threshold {
					atomic.AddInt64(&e.AutoFilterSuppressed, 1)
					if e.cleanupJob(shouldExit) {
						return
					}
					continue
				}
			}

			// Capture interesting headers.
			capturedHeaders := make(map[string]string)
			for _, line := range strings.Split(strings.ReplaceAll(resp.Headers, "\r\n", "\n"), "\n") {
				if idx := strings.Index(line, ":"); idx != -1 {
					key := strings.TrimSpace(line[:idx])
					val := strings.TrimSpace(line[idx+1:])
					switch strings.ToLower(key) {
					case "server":
						capturedHeaders["Server"] = val
					case "x-powered-by":
						capturedHeaders["X-Powered-By"] = val
					case "cf-ray":
						capturedHeaders["Cf-Ray"] = val
					case "content-security-policy":
						capturedHeaders["Content-Security-Policy"] = val
					case "strict-transport-security":
						capturedHeaders["Strict-Transport-Security"] = val
					case "x-frame-options":
						capturedHeaders["X-Frame-Options"] = val
					case "x-content-type-options":
						capturedHeaders["X-Content-Type-Options"] = val
					case "referrer-policy":
						capturedHeaders["Referrer-Policy"] = val
					case "permissions-policy":
						capturedHeaders["Permissions-Policy"] = val
					case "access-control-allow-origin":
						capturedHeaders["Access-Control-Allow-Origin"] = val
					}
				}
			}

			result := Result{
				Path:        payload,
				Method:      successfulMethod,
				StatusCode:  resp.StatusCode,
				Size:        bodySize,
				Words:       wordCount,
				Lines:       lineCount,
				ContentType: contentType,
				Duration:    resp.Duration,
				Headers:     capturedHeaders,
				URL:         fullURL,
			}
			if timingOracleHit {
				result.Duration = timingMedian
			}

			// Only include raw request/response when SaveRaw is enabled.
			if saveRaw {
				result.Request = string(rawRequest)
				result.Response = string(resp.Raw)
				result.RequestBytes = append([]byte(nil), rawRequest...)
				result.ResponseBytes = append([]byte(nil), resp.Raw...)
			}

			if resp.StatusCode >= 300 && resp.StatusCode < 400 && !followRedirects {
				result.Redirect = resp.GetHeader("Location")
			}
			if finalRedirectURL != "" && resp.StatusCode >= 300 && resp.StatusCode < 400 {
				result.Redirect = finalRedirectURL
			}
			if resp.StatusCode == 403 {
				result.Forbidden403Type = forbidden403Type
			}
			if bypassTechniqueLabel != "" {
				result.Labels = append(result.Labels, bypassTechniqueLabel)
			}

			// Eagle Mode.
			e.eagleLock.RLock()
			if e.PreviousState != nil {
				if oldStatus, exists := e.PreviousState[payload]; exists && oldStatus != resp.StatusCode {
					result.IsEagleAlert = true
					result.OldStatusCode = oldStatus
				}
			}
			e.eagleLock.RUnlock()

			// Lua plugin match. Allocate the response body string only when a
			// match plugin is configured to avoid unnecessary large allocations.
			var bodyStr string
			if e.matchPlugin != nil && bypassTechniqueLabel == "" {
				bodyStr = string(resp.Body)
			}
			if e.matchPlugin != nil && bypassTechniqueLabel == "" {
				matched, labels, confidence := e.matchPlugin.Match(resp.StatusCode, bodySize, wordCount, lineCount, bodyStr, contentType)
				if !matched {
					if e.cleanupJob(shouldExit) {
						return
					}
					continue
				}
				// Enrich result with any metadata provided by the matcher plugin.
				if len(labels) > 0 {
					result.Labels = labels
				}
				if confidence != "" {
					result.Confidence = confidence
				}

				if e.cleanupJob(shouldExit) {
					return
				}
				continue
			}

			if timingOracleHit {
				result.Labels = append(result.Labels, "TIMING-ORACLE")
				oracleConfidence := fmt.Sprintf("z=%.1f", timingOracleZ)
				if result.Confidence == "" {
					result.Confidence = oracleConfidence
				} else {
					result.Confidence = result.Confidence + ";" + oracleConfidence
				}
			}

			if authFinding != nil {
				if result.Headers == nil {
					result.Headers = make(map[string]string)
				}
				result.Labels = append(result.Labels, authFinding.Labels...)
				if authFinding.Confidence != "" {
					if result.Confidence == "" {
						result.Confidence = authFinding.Confidence
					} else {
						result.Confidence = result.Confidence + ";" + authFinding.Confidence
					}
				}
				if authFinding.Summary != "" {
					result.Headers["Auth-Matrix"] = authFinding.Summary
				}
			}

			e.queueParamFuzzFromResult(result, bodySize, bodyHash)
			e.queueResponseHarvestFromResult(job, fullURL, finalRedirectURL, contentType, resp.Body)

			// Spidering / dynamic link extraction
			if spidering && len(resp.Body) > 0 && resp.StatusCode >= 200 && resp.StatusCode < 300 {
				matches := linkRegex.FindAllStringSubmatch(string(resp.Body), -1)
				for _, match := range matches {
					if len(match) < 2 {
						continue
					}
					link := strings.TrimSpace(match[1])
					lowerLink := strings.ToLower(link)
					if strings.HasPrefix(lowerLink, "javascript:") || strings.HasPrefix(lowerLink, "mailto:") || strings.HasPrefix(lowerLink, "data:") || strings.HasPrefix(lowerLink, "#") {
						continue
					}

					parsedLink, errL := url.Parse(link)
					if errL != nil {
						continue
					}

					if !isSameSpiderScopeHost(reqHostname, parsedLink) {
						continue
					}

					newPath := parsedLink.Path
					if parsedLink.RawQuery != "" {
						newPath += "?" + parsedLink.RawQuery
					}
					if newPath == "" {
						newPath = "/"
					}

					// Submit will run Bloom filter check
					e.Submit(spiderChildJob(job, newPath))
				}
			}

			if e.handleResultWithContext(localCtx, result) {
				e.activeJobs.Done()
				return
			}

			// Outbound proxy replay via bounded queue.
			if proxyOut != "" {
				select {
				case e.replayCh <- replayTask{
					proxyAddr:   proxyOut,
					fullURL:     fullURL,
					method:      successfulMethod,
					ua:          ua,
					headers:     headers,
					requestBody: requestBody,
					payload:     payload,
				}:
				default:
					// Drop if queue is full — don't block workers.
				}
			}

			// Smart Mutation — applies to ALL paths (not just dotted ones).
			if doMutate && (resp.StatusCode == 200 || resp.StatusCode == 403 || resp.StatusCode == 301) {
				go func(runID int64, basePath, method string) {
					mutations := []string{".bak", ".old", ".save", "~", ".swp", ".orig", ".tmp"}
					for _, m := range mutations {
						e.Submit(Job{Path: basePath + m, Depth: depth, Method: method, RunID: runID})
					}
				}(job.RunID, payload, job.Method)
			}

			// Recursive scanning with bounded concurrency.
			if doRecurse && depth < maxDepth {
				inScope := true
				if result.Redirect != "" {
					if parsedRedir, err := url.Parse(result.Redirect); err == nil && parsedRedir.Host != "" {
						e.targetLock.RLock()
						scopeDom := e.scopeDomain
						e.targetLock.RUnlock()
						redirHost := parsedRedir.Hostname()
						if redirHost != scopeDom && !strings.HasSuffix(redirHost, "."+scopeDom) {
							inScope = false
						}
					}
				}
				if inScope {
					// Perform the wildcard check asynchronously so the worker isn't
					// blocked performing network IO. If the path is not a
					// wildcard and a semaphore slot is available, spawn the
					// recursive scanner.
					go func(runID int64, basePath string, nextDepth int, wlPath string) {
						if e.checkRecursiveWildcard(basePath) {
							return
						}

						// Acquire semaphore slot (non-blocking to avoid stalling).
						select {
						case e.recursiveSem <- struct{}{}:
							e.AddScanner()
							go func(runID int64, basePath string, nextDepth int, wlPath string) {
								defer e.scannerWg.Done()
								defer func() { <-e.recursiveSem }()

								snap := e.configSnap.Load()
								if snap == nil {
									return
								}

								f, err := os.Open(wlPath)
								if err != nil {
									return
								}
								defer f.Close()

								scanner := bufio.NewScanner(f)
								for scanner.Scan() {
									word := scanner.Text()
									if word == "" {
										continue
									}
									newPath := strings.TrimSuffix(basePath, "/") + "/" + strings.TrimPrefix(word, "/")
									for _, method := range resolveMethodsForPath(newPath, snap.Methods, snap.SmartAPI) {
										atomic.AddInt64(&e.TotalLines, 1)
										e.Submit(Job{Path: newPath, Depth: nextDepth, Method: method, RunID: runID})
									}
								}
							}(runID, basePath, nextDepth, wlPath)
						default:
							// Semaphore full; skip recursive scan for this hit.
						}
					}(job.RunID, payload, depth+1, wordlistPath)
				}
			}

			e.activeJobs.Done()
			if shouldExit {
				return
			}

		case <-e.workerStopCh:
			return
		}
	}
}

// ─── Proxy replay (bounded) ───────────────────────────────────────────────────

// execReplay forwards a hit through an HTTP proxy (e.g. Burp Suite).
func (e *Engine) execReplay(task replayTask) {
	client := e.getReplayClient(task.proxyAddr)
	if client == nil {
		return
	}

	method := task.method
	if method == "" || method == "HEAD" {
		method = "GET"
	}

	var body io.Reader
	if task.requestBody != "" && (method == "POST" || method == "PUT" || method == "PATCH") {
		body = strings.NewReader(strings.ReplaceAll(task.requestBody, "{PAYLOAD}", task.payload))
	}

	req, err := http.NewRequest(method, task.fullURL, body)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", strings.ReplaceAll(task.ua, "{PAYLOAD}", task.payload))
	for k, v := range task.headers {
		req.Header.Set(k, strings.ReplaceAll(v, "{PAYLOAD}", task.payload))
	}

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

// getReplayClient returns a reusable *http.Client for the given proxy address.
// If the proxy address is invalid or empty this returns nil. Clients are
// cached in a sync.Map to avoid repeatedly allocating transports and to
// enable connection/TLS session reuse with the proxy.
func (e *Engine) getReplayClient(proxyAddr string) *http.Client {
	if proxyAddr == "" {
		return nil
	}
	if v, ok := e.replayClients.Load(proxyAddr); ok {
		return v.(*http.Client)
	}

	proxyURL, err := url.Parse(proxyAddr)
	if err != nil {
		return nil
	}

	transport := &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}

	actual, loaded := e.replayClients.LoadOrStore(proxyAddr, client)
	if loaded {
		// Another goroutine stored a client first; close our idle conns.
		if tr, ok := client.Transport.(*http.Transport); ok {
			tr.CloseIdleConnections()
		}
		return actual.(*http.Client)
	}
	return client
}

// ─── Job submission ───────────────────────────────────────────────────────────

// Submit adds a payload to the queue if it passes the Bloom filter check.
func (e *Engine) Submit(job Job) {
	if job.RunID != atomic.LoadInt64(&e.RunID) {
		return
	}

	filterKey := job.Path
	if job.Method != "" {
		filterKey = job.Method + ":" + job.Path
	}

	if e.shardedFilter.TestAndAddString(filterKey) {
		atomic.AddInt64(&e.ProcessedLines, 1)
		return
	}

	e.activeJobs.Add(1)
	sc := e.scannerCtx.Load()
	if sc == nil {
		e.activeJobs.Done()
		return
	}
	select {
	case e.jobs <- job:
	case <-sc.ctx.Done():
		e.activeJobs.Done()
	}
}

// SubmitHarvestPath adds a harvested path to the active scan and counts it in
// the progress metrics so harvested discoveries show up as part of the run.
func (e *Engine) SubmitHarvestPath(path string, runID int64, harvestDepth int) {
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}

	atomic.AddInt64(&e.TotalLines, 1)
	atomic.AddInt64(&e.HarvestedPaths, 1)
	e.Submit(Job{
		Path:         path,
		Depth:        0,
		HarvestDepth: harvestDepth,
		Method:       http.MethodGet,
		RunID:        runID,
	})
}

// ─── Lifecycle ────────────────────────────────────────────────────────────────

func (e *Engine) Wait() {
	e.scannerWg.Wait()
	e.activeJobs.Wait()
	e.paramTasksWg.Wait()
}

// Shutdown requests a graceful stop and closes the result/log channels.
//
// It is safe to call multiple times; only the first call performs teardown.
func (e *Engine) Shutdown() {
	e.shutdownOnce.Do(func() {
		e.isRunning.Store(false)
		// Signal scanners to stop producing new jobs.
		if sc := e.scannerCtx.Load(); sc != nil && sc.cancel != nil {
			sc.cancel()
		}

		// Wait for all scanner goroutines to finish. This ensures no more
		// jobs will be submitted.
		e.scannerWg.Wait()

		// Now that producers are stopped, it's safe to close the jobs channel.
		// This will signal the worker goroutines to exit their range loop
		// once they have finished processing all queued jobs.
		close(e.jobs)

		// Wait for all worker goroutines to finish.
		e.wg.Wait()

		// Drain and stop the hidden-parameter worker pool after the main
		// directory scan workers have finished submitting tasks.
		if e.paramTaskChan != nil {
			close(e.paramTaskChan)
			e.paramFuzzWg.Wait()
		}

		// Close replay channel, stopping replay workers.
		close(e.replayCh)

		// Close idle connections on cached replay transports so they don't
		// leak goroutines or hold resources after shutdown.
		e.replayClients.Range(func(k, v interface{}) bool {
			if client, ok := v.(*http.Client); ok {
				if tr, ok := client.Transport.(*http.Transport); ok {
					tr.CloseIdleConnections()
				}
			}
			return true
		})

		close(e.LogEvents)
		close(e.Results)
	})
}

// ─── Meta ─────────────────────────────────────────────────────────────────────

type EngineConfigDump struct {
	Target     string
	Wordlist   string
	OutputFile string
	SmartAPI   bool
}

type RuntimeConfigSnapshot struct {
	Timeout     time.Duration
	RequestBody string
	FilterWords int
	SaveRaw     bool
	ProxyOut    string
	Methods     []string
}

func (e *Engine) RuntimeSnapshot() RuntimeConfigSnapshot {
	s := e.configSnap.Load()
	if s == nil {
		e.buildAndStoreConfigSnapshot()
		s = e.configSnap.Load()
	}
	if s == nil {
		return RuntimeConfigSnapshot{}
	}
	return RuntimeConfigSnapshot{
		Timeout:     s.Timeout,
		RequestBody: s.RequestBody,
		FilterWords: s.FilterWords,
		SaveRaw:     s.SaveRaw,
		ProxyOut:    s.ProxyOut,
		Methods:     append([]string(nil), s.Methods...),
	}
}

func (e *Engine) DumpMeta() EngineConfigDump {
	e.Config.RLock()
	defer e.Config.RUnlock()
	return EngineConfigDump{
		Target:     e.BaseURL(),
		Wordlist:   e.Config.WordlistPath,
		OutputFile: e.Config.OutputFile,
		SmartAPI:   e.Config.SmartAPI,
	}
}

// SetTransformPlugin sets the Lua request transformer plugin.
func (e *Engine) SetTransformPlugin(pt *PluginRequestTransformer) {
	e.transformPlugin = pt
}
