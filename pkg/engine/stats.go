package engine

import "time"

// EngineStats is a concurrent snapshot of the live scan state.
type EngineStats struct {
	RequestsDispatched int64
	ResultsCollected   int
	WorkersActive      int
	StartedAt          time.Time
	IsRunning          bool
	WAFDetected        bool
	WAFVendorGuess     string
	EvasionScoreboard  []EvasionScoreboardRow
}

// Stats returns a safe, point-in-time snapshot of the engine counters.
func (e *Engine) Stats() EngineStats {
	if e == nil {
		return EngineStats{}
	}

	startedAt := time.Time{}
	if startedAtUnix := e.startedAtUnix.Load(); startedAtUnix != 0 {
		startedAt = time.Unix(0, startedAtUnix).UTC()
	}
	wafDetected, wafVendorGuess := e.wafState()

	return EngineStats{
		RequestsDispatched: e.requestsDispatched.Load(),
		ResultsCollected:   int(e.resultsCollected.Load()),
		WorkersActive:      int(e.activeWorkers.Load()),
		StartedAt:          startedAt,
		IsRunning:          e.isRunning.Load(),
		WAFDetected:        wafDetected,
		WAFVendorGuess:     wafVendorGuess,
		EvasionScoreboard:  e.EvasionSummaryRows(),
	}
}
