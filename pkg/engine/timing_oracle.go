package engine

import (
	"context"
	"fmt"
	"math"
	"net/url"
	"sort"
	"strings"
	"time"

	"dirfuzz/pkg/httpclient"
)

// TimingOracle holds the baseline timing distribution and detection settings.
type TimingOracle struct {
	baselineSamples []time.Duration
	baselineMedian  time.Duration
	baselineStddev  float64
	K               float64
	RepeatN         int
	Trim            bool
	threshold       time.Duration
}

func newTimingOracle(samples []time.Duration, k float64, repeatN int, trim bool) (*TimingOracle, error) {
	if len(samples) == 0 {
		return nil, fmt.Errorf("timing oracle requires at least one baseline sample")
	}
	if repeatN < 1 {
		repeatN = TimingOracleDefaultRepeatN
	}
	if k <= 0 {
		k = TimingOracleDefaultK
	}

	o := &TimingOracle{
		baselineSamples: append([]time.Duration(nil), samples...),
		K:               k,
		RepeatN:         repeatN,
		Trim:            trim,
	}
	o.recompute()
	return o, nil
}

func (o *TimingOracle) recompute() {
	samples := o.baselineSamples
	if len(samples) == 0 {
		o.baselineMedian = 0
		o.baselineStddev = 0
		o.threshold = TimingOracleMinDelta
		return
	}

	o.baselineMedian = medianDuration(samples, o.Trim)
	o.baselineStddev = stddevDuration(samples, o.Trim)

	deltaNs := float64(TimingOracleMinDelta)
	if candidate := o.K * o.baselineStddev; candidate > deltaNs {
		deltaNs = candidate
	}
	o.threshold = o.baselineMedian + time.Duration(deltaNs)
}

func (o *TimingOracle) Median(samples []time.Duration) time.Duration {
	return medianDuration(samples, o.Trim)
}

func (o *TimingOracle) ZScore(sample time.Duration) float64 {
	if o == nil {
		return 0
	}
	if o.baselineStddev <= 0 {
		if sample > o.threshold {
			return math.Inf(1)
		}
		return 0
	}
	return float64(sample-o.baselineMedian) / o.baselineStddev
}

func (o *TimingOracle) IsAnomaly(sample time.Duration) bool {
	if o == nil {
		return false
	}
	return sample > o.threshold
}

func (o *TimingOracle) BaselineMedian() time.Duration {
	if o == nil {
		return 0
	}
	return o.baselineMedian
}

func (o *TimingOracle) Threshold() time.Duration {
	if o == nil {
		return 0
	}
	return o.threshold
}

func trimDurations(samples []time.Duration) []time.Duration {
	if len(samples) < 3 {
		return append([]time.Duration(nil), samples...)
	}
	out := append([]time.Duration(nil), samples...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out[1 : len(out)-1]
}

func medianDuration(samples []time.Duration, trim bool) time.Duration {
	if len(samples) == 0 {
		return 0
	}
	work := append([]time.Duration(nil), samples...)
	if trim {
		work = trimDurations(work)
	}
	if len(work) == 0 {
		return 0
	}
	sort.Slice(work, func(i, j int) bool { return work[i] < work[j] })
	mid := len(work) / 2
	if len(work)%2 == 1 {
		return work[mid]
	}
	return (work[mid-1] + work[mid]) / 2
}

func stddevDuration(samples []time.Duration, trim bool) float64 {
	work := append([]time.Duration(nil), samples...)
	if trim {
		work = trimDurations(work)
	}
	if len(work) < 2 {
		return 0
	}

	var (
		mean float64
		m2   float64
		n    float64
	)
	for _, sample := range work {
		x := float64(sample)
		n++
		delta := x - mean
		mean += delta / n
		m2 += delta * (x - mean)
	}
	return math.Sqrt(m2 / (n - 1))
}

func (e *Engine) CalibrateTimingOracle() (*TimingOracle, error) {
	e.Config.RLock()
	enabled := e.Config.TimingOracle
	repeatN := e.Config.TimeOracleN
	k := e.Config.TimeOracleK
	trim := e.Config.TimeTrim
	timeout := CalibrationTimeout
	e.Config.RUnlock()

	if !enabled {
		e.timingOracle = nil
		return nil, nil
	}
	if repeatN < 1 {
		repeatN = TimingOracleDefaultRepeatN
	}
	if k <= 0 {
		k = TimingOracleDefaultK
	}

	e.emitLogEvent(LogLevelInfo, LogCategorySystem, EventTimingOracleStarted, "starting timing oracle calibration", map[string]interface{}{
		"baseline_samples": TimingOracleBaselineSamples,
		"repeat_n":         repeatN,
		"k":                k,
		"trim":             trim,
	})

	samples := make([]time.Duration, 0, TimingOracleBaselineSamples)
	for i := 0; i < TimingOracleBaselineSamples; i++ {
		word := randomString(CalibrationRandomStringLen)
		currentBaseURL := e.BaseURL()
		fullURL := ""
		if strings.Contains(currentBaseURL, "{PAYLOAD}") {
			fullURL = strings.Replace(currentBaseURL, "{PAYLOAD}", word, 1)
		} else {
			fullURL = strings.TrimRight(currentBaseURL, "/") + "/" + word
		}

		parsedURL, err := url.Parse(fullURL)
		if err != nil {
			return nil, fmt.Errorf("invalid timing oracle calibration URL: %w", err)
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
			return nil, fmt.Errorf("scanner context not available")
		}

		resp, err := e.executeRequestWithRetry(sc.ctx, fullURL, rawRequest, timeout, proxyAddr)
		if err != nil {
			return nil, fmt.Errorf("timing oracle calibration request failed: %w", err)
		}
		samples = append(samples, resp.Duration)
	}

	oracle, err := newTimingOracle(samples, k, repeatN, trim)
	if err != nil {
		return nil, err
	}
	e.timingOracle = oracle
	e.emitLogEvent(LogLevelSuccess, LogCategorySystem, EventTimingOracleCalibrated, fmt.Sprintf("timing oracle ready with threshold %s", oracle.Threshold().Round(time.Millisecond)), map[string]interface{}{
		"baseline_median_ms": oracle.BaselineMedian().Milliseconds(),
		"threshold_ms":       oracle.Threshold().Milliseconds(),
		"repeat_n":           oracle.RepeatN,
	})
	return oracle, nil
}

func (e *Engine) executeTimingOracleRequests(ctx context.Context, targetURL string, rawRequest []byte, timeout time.Duration, proxyAddr string) (*httpclient.RawResponse, []time.Duration, error) {
	e.Config.RLock()
	repeatN := e.Config.TimeOracleN
	e.Config.RUnlock()
	if repeatN < 1 {
		repeatN = TimingOracleDefaultRepeatN
	}

	samples := make([]time.Duration, 0, repeatN)
	var first *httpclient.RawResponse
	for i := 0; i < repeatN; i++ {
		resp, err := e.executeRequestWithRetry(ctx, targetURL, rawRequest, timeout, proxyAddr)
		if err != nil {
			return nil, nil, err
		}
		if first == nil {
			first = resp
		}
		samples = append(samples, resp.Duration)
	}
	return first, samples, nil
}
