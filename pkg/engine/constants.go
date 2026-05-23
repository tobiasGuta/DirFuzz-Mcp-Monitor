package engine

import "time"

// ─── Bloom Filter ─────────────────────────────────────────────────────────────
const (
	DefaultBloomFilterSize = 10_000_000
	DefaultBloomFilterFP   = 0.001
)

// ─── Auto-Filter ─────────────────────────────────────────────────────────────
const (
	DefaultAutoFilterThreshold = 15
)

// ─── SimHash Soft-404 Clustering ─────────────────────────────────────────────
const (
	DefaultSimhashThreshold    = 3
	DefaultSimhashClusterLimit = 5
)

// ─── WAF Evasion ─────────────────────────────────────────────────────────────
const (
	DefaultEvasionLimit = 4
)

// ─── HTTP/2 ──────────────────────────────────────────────────────────────────
const (
	DefaultH2ConcurrentStreams = 100
	DefaultH2MaxHeaderListSize = 1 << 20
)

// ─── HTTP Client ─────────────────────────────────────────────────────────────
const (
	DefaultHTTPTimeout     = 5 * time.Second
	DefaultConnTimeout     = 3 * time.Second
	DefaultReadTimeout     = 5 * time.Second
	DefaultMaxScanDuration = 0
)

// ─── Worker Pool ─────────────────────────────────────────────────────────────
const (
	DefaultWorkerCount  = 50
	DefaultJobQueueSize = DefaultWorkerCount * 10
	MinWorkerCount      = 1
	MinRateLimitBurst   = 10
)

// ─── Calibration ─────────────────────────────────────────────────────────────
const (
	CalibrationRandomStringLen = 16
	CalibrationTestCount       = 10
	CalibrationTimeout         = 5 * time.Second
)

// ─── Timing Oracle ──────────────────────────────────────────────────────────
const (
	TimingOracleBaselineSamples = 30
	TimingOracleMinDelta        = 50 * time.Millisecond
	TimingOracleDefaultK        = 2.5
	TimingOracleDefaultRepeatN  = 5
)

// ─── Recursion ────────────────────────────────────────────────────────────────
const (
	DefaultMaxDepth          = 3
	RecursiveWildcardTestLen = 12
	RecursiveWildcardTimeout = 3 * time.Second
	DefaultMaxRedirects      = 5

	// MaxConcurrentRecursions caps the number of simultaneously running
	// recursive wordlist scanners to avoid file-descriptor exhaustion.
	MaxConcurrentRecursions = 20
)

// ─── Auto-Throttle ────────────────────────────────────────────────────────────
const (
	AutoThrottleInterval  = 10
	MinThrottledWorkers   = 5
	ThrottleWorkerPercent = 50
	ThrottleDelayIncrease = 200 * time.Millisecond
	MaxThrottleDelay      = 5 * time.Second
)

// ─── Output ───────────────────────────────────────────────────────────────────
const (
	DefaultOutputFormat = "jsonl"
	ResultsChannelSize  = DefaultWorkerCount * 10
)

// ─── Harvesting ───────────────────────────────────────────────────────────────
const (
	DefaultHarvestResponseDepth = 2
	DefaultHarvestResponseFetch = 32
)

// ─── Mutation ─────────────────────────────────────────────────────────────────
const (
	DefaultMutations = ".bak,.old,.save,~,.swp"
)

// ─── Proxy Replay ─────────────────────────────────────────────────────────────
const (
	// ReplayWorkers is the fixed number of goroutines consuming the replay queue.
	ReplayWorkers = 8
	// ReplayQueueSize is the buffer for the outbound proxy replay channel.
	ReplayQueueSize = 256
)
