package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dirfuzz/pkg/engine"
	"dirfuzz/pkg/tui"

	tea "github.com/charmbracelet/bubbletea"
)

// tuiResultBufSize mirrors engine.ResultsChannelSize so the fanout goroutine
// is never the bottleneck between the engine and the TUI.
const tuiResultBufSize = engine.ResultsChannelSize

// run builds the engine from cfg, starts a scan, and hands off to either the
// Bubble Tea TUI (default) or a plain stdout loop (--no-tui).
func run(cfg cliConfig) error {
	if cfg.Swarm {
		return runSwarm(cfg)
	}

	// ── 1. Engine ─────────────────────────────────────────────────────────────
	eng := engine.NewEngine(cfg.Threads, engine.DefaultBloomFilterSize, engine.DefaultBloomFilterFP)
	eng.ResumeFile = cfg.ResumeFile

	// ── 2. Match / filter codes ───────────────────────────────────────────────
	matchCodes := mustCSVInts(cfg.MatchCodes, "-mc")
	filterSizes := mustCSVInts(cfg.FilterSizes, "-fs")
	eng.ConfigureFilters(matchCodes, filterSizes)

	// ── 3. Extensions ─────────────────────────────────────────────────────────
	for _, ext := range splitTrimmed(cfg.Extensions) {
		eng.AddExtension(strings.TrimPrefix(ext, "."))
	}

	// ── 4. HTTP settings ──────────────────────────────────────────────────────
	if cfg.UserAgent != "" {
		eng.UpdateUserAgent(cfg.UserAgent)
	}
	if cfg.Cookie != "" {
		eng.AddHeader("Cookie", cfg.Cookie)
	}
	for _, h := range cfg.Headers {
		if parts := strings.SplitN(h, ":", 2); len(parts) == 2 {
			eng.AddHeader(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}
	if cfg.Delay > 0 {
		eng.SetDelay(cfg.Delay)
	}
	if cfg.RPS > 0 {
		eng.SetRPS(cfg.RPS)
	}
	if cfg.Follow {
		eng.SetFollowRedirects(true)
	}
	if normalized, err := normalizeAuthMatrix(cfg.AuthMatrix); err != nil {
		return fmt.Errorf("invalid auth matrix: %w", err)
	} else {
		cfg.AuthMatrix = normalized
	}

	eng.UpdateConfig(func(c *engine.Config) {
		c.Timeout = cfg.Timeout
		c.Insecure = cfg.Insecure
		c.MaxRedirects = cfg.MaxRedirects
		c.RequestBody = cfg.Body
		c.SaveRaw = cfg.SaveRaw
		c.ExcludePathPatterns = append([]string(nil), cfg.ExcludePaths...)
		c.AuthMatrix = cfg.AuthMatrix
		c.Recursive = cfg.Recursive
		c.RecursivePrune = cfg.RecursivePrune
		c.MaxDepth = cfg.MaxDepth
		c.SmartAPI = cfg.SmartAPI
		c.Mutate = cfg.Mutate
		c.FilterWords = cfg.FilterWords
		c.FilterLines = cfg.FilterLines
		c.MatchWords = cfg.MatchWords
		c.MatchLines = cfg.MatchLines
		c.FilterRTMin = cfg.RTMin
		c.FilterRTMax = cfg.RTMax
		c.ProxyOut = cfg.ProxyOut
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
		c.HarvestResponse = cfg.HarvestResponse
		c.HarvestPassive = cfg.HarvestPassive
		c.HarvestSourceMaps = cfg.HarvestSourceMaps
		c.HarvestResponseDepth = cfg.HarvestResponseDepth
		c.HarvestResponseFetch = cfg.HarvestResponseFetch
		c.HarvestOTXKey = cfg.HarvestOTXKey
		c.ParamWordlist = append([]string(nil), cfg.ParamWords...)
		c.EvasionLimit = cfg.EvasionLimit
		c.MaxRetries = cfg.MaxRetries
		c.VerbTamper = cfg.VerbTamper
		c.FourOhThreeBypass = cfg.FourOhThreeBypass
		c.AntiBotFallback = cfg.AntiBotFallback
		c.AllowPrivateTargets = cfg.AllowPrivate
		if cfg.OutputFile != "" {
			c.OutputFile = cfg.OutputFile
			c.OutputFormat = cfg.OutputFormat
		}
		for _, m := range splitTrimmed(cfg.Methods) {
			c.Methods = append(c.Methods, strings.ToUpper(m))
		}
	})

	// ── 5. Regex filters ──────────────────────────────────────────────────────
	if cfg.MatchRegex != "" {
		if err := eng.SetMatchRegex(cfg.MatchRegex); err != nil {
			return fmt.Errorf("invalid -mr regex: %w", err)
		}
	}
	if cfg.FilterRegex != "" {
		if err := eng.SetFilterRegex(cfg.FilterRegex); err != nil {
			return fmt.Errorf("invalid -fr regex: %w", err)
		}
	}

	// ── 6. Lua plugins ────────────────────────────────────────────────────────
	if cfg.PluginMatch != "" {
		pm, err := engine.NewPluginMatcher(cfg.PluginMatch, cfg.Timeout)
		if err != nil {
			return fmt.Errorf("plugin-match: %w", err)
		}
		defer pm.Close()
		eng.SetMatchPlugin(pm)
	}
	if cfg.PluginMutate != "" {
		pm, err := engine.NewPluginMutator(cfg.PluginMutate, cfg.Timeout)
		if err != nil {
			return fmt.Errorf("plugin-mutate: %w", err)
		}
		defer pm.Close()
		eng.SetMutatePlugin(pm)
	}

	// ── 7. Proxy rotation ─────────────────────────────────────────────────────
	if cfg.ProxyFile != "" {
		if err := eng.LoadProxies(cfg.ProxyFile); err != nil {
			return fmt.Errorf("loading proxy list: %w", err)
		}
	}
	if cfg.OOB {
		eng.UpdateConfig(func(c *engine.Config) {
			c.OOBEnabled = true
			c.InteractshServer = cfg.OOBServer
			c.InteractshToken = cfg.OOBToken
		})
	}
	if cfg.ProxyOut != "" && cfg.Insecure {
		fmt.Fprintf(os.Stderr, "[!] Warning: --proxy-out is using insecure TLS verification because --insecure is enabled\n")
	}

	// ── 8. Eagle mode ─────────────────────────────────────────────────────────
	if cfg.EagleFile != "" {
		if err := eng.LoadPreviousScan(cfg.EagleFile); err != nil {
			return fmt.Errorf("loading eagle baseline: %w", err)
		}
	}

	if cfg.H2Mode && cfg.ProxyFile != "" {
		return fmt.Errorf("--h2 cannot be used together with --proxy")
	}

	// ── 9. Target ─────────────────────────────────────────────────────────────
	if err := eng.SetTarget(cfg.Target); err != nil {
		return fmt.Errorf("invalid target: %w", err)
	}
	if cfg.H2Mode {
		if err := eng.RefreshH2Client(); err != nil {
			return fmt.Errorf("initializing HTTP/2 client: %w", err)
		}
	}

	// ── 10. Auto-calibration ──────────────────────────────────────────────────
	if cfg.Calibrate {
		fmt.Fprintln(os.Stderr, "[*] Auto-calibrating…")
		if err := eng.AutoCalibrate(); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Calibration warning: %v\n", err)
		}
	}

	if cfg.TimingOracle {
		fmt.Fprintln(os.Stderr, "[*] Calibrating timing oracle…")
		oracle, err := eng.CalibrateTimingOracle()
		if err != nil {
			return fmt.Errorf("calibrating timing oracle: %w", err)
		}
		fmt.Fprintf(os.Stderr, "[*] Timing oracle ready: baseline=%s threshold=%s repeat=%d\n",
			oracle.BaselineMedian().Round(time.Millisecond), oracle.Threshold().Round(time.Millisecond), oracle.RepeatN)
	}

	// ── 11. Resume ────────────────────────────────────────────────────────────
	wordlistPath := cfg.Wordlist
	var startLine int64

	if cfg.Resume {
		wl, line, err := eng.LoadResumeState(cfg.ResumeFile)
		if err != nil {
			return fmt.Errorf("loading resume state from %s: %w", cfg.ResumeFile, err)
		}
		wordlistPath = wl
		startLine = line
		fmt.Fprintf(os.Stderr, "[*] Resuming %s from line %d\n", wordlistPath, startLine)
	}

	eng.Config.Lock()
	eng.Config.WordlistPath = wordlistPath
	eng.Config.Unlock()
	eng.RefreshConfigSnapshot()

	if cfg.DryRun {
		est, err := eng.EstimateWordlist(wordlistPath, startLine)
		if err != nil {
			return fmt.Errorf("estimating scan: %w", err)
		}
		printDryRunEstimate(cfg, est)
		return nil
	}

	var priorResults []engine.Result
	if cfg.HistoryMode == HistoryModeAppend && !cfg.NoTUI {
		results, err := loadPersistedResults(cfg.OutputFile)
		if err != nil {
			return fmt.Errorf("loading persisted scan history from %s: %w", cfg.OutputFile, err)
		}
		priorResults = results
	}

	// ── 12. Output file ───────────────────────────────────────────────────────
	var (
		outFile *os.File
		bufW    *bufio.Writer
		csvW    *csv.Writer
	)

	if cfg.OutputFile != "" {
		f, err := os.OpenFile(cfg.OutputFile, outputFileOpenFlags(cfg.HistoryMode), 0o600)
		if err != nil {
			return fmt.Errorf("creating output file %s: %w", cfg.OutputFile, err)
		}
		defer func() {
			if bufW != nil {
				bufW.Flush()
			}
			if csvW != nil {
				csvW.Flush()
			}
			f.Close()
		}()
		outFile = f

		if cfg.OutputFormat == "csv" {
			csvW = csv.NewWriter(outFile)
			engine.WriteCSVHeader(csvW)
		} else {
			bufW = bufio.NewWriter(outFile)
		}
	}

	// ── 13. Harvest endpoints ────────────────────────────────────────────────
	if cfg.Harvest || cfg.HarvestJS || cfg.HarvestAPI || cfg.HarvestResponse {
		paths, err := eng.HarvestEndpoints(context.Background())
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Harvest warning: %v\n", err)
		}
		runID := atomic.LoadInt64(&eng.RunID)
		for _, p := range paths {
			eng.SubmitHarvestPath(p, runID, 1)
		}
		fmt.Fprintf(os.Stderr, "[*] Harvested %d endpoint(s)\n", len(paths))
	}

	// writeResult writes one result to the output file. It is always called
	// from the fanout goroutine (never dropped) and never from the TUI path.
	var reportResults []engine.Result
	var reportMu sync.Mutex
	writeResult := func(r engine.Result) {
		if cfg.ReportFile != "" && !r.IsAutoFilter {
			reportMu.Lock()
			reportResults = append(reportResults, r)
			reportMu.Unlock()
		}
		if outFile == nil {
			return
		}
		switch cfg.OutputFormat {
		case "csv":
			_ = csvW.Write(r.ToCSV())
		case "url":
			u := r.URL
			if u == "" {
				u = r.Path
			}
			fmt.Fprintln(bufW, u)
		default: // jsonl
			b, _ := json.Marshal(r)
			_, _ = bufW.Write(b)
			_, _ = bufW.Write([]byte("\n"))
		}
	}

	// ── 14. Start engine ──────────────────────────────────────────────────────
	eng.Start()
	eng.KickoffScanner(wordlistPath, startLine)
	if cfg.MaxDuration > 0 {
		timeoutTimer := time.AfterFunc(cfg.MaxDuration, eng.Shutdown)
		defer timeoutTimer.Stop()
	}

	// ── 15. Display mode ──────────────────────────────────────────────────────
	if cfg.NoTUI {
		collectedResults, err := runPlain(eng, cfg, writeResult)
		if err != nil {
			return err
		}
		if cfg.HeaderAudit {
			PrintHeaderAuditSummary(RunHeaderAudit(collectedResults))
		}
		reportMu.Lock()
		defer reportMu.Unlock()
		return writeReportIfRequested(eng, cfg, reportResults)
	}
	if err := runTUI(eng, cfg, writeResult, priorResults); err != nil {
		return err
	}
	reportMu.Lock()
	defer reportMu.Unlock()
	return writeReportIfRequested(eng, cfg, reportResults)
}

// ── Plain / no-TUI mode ───────────────────────────────────────────────────────

func runPlain(eng *engine.Engine, cfg cliConfig, writeResult func(engine.Result)) ([]engine.Result, error) {
	go func() {
		eng.Wait()
		eng.Shutdown()
	}()

	var collectedResults []engine.Result

	for res := range eng.Results {
		if res.IsAutoFilter {
			if cfg.Verbose {
				msg := ""
				if res.Headers != nil {
					msg = res.Headers["Msg"]
				}
				if msg != "" {
					fmt.Fprintf(os.Stderr, "[AF] %s: %s\n", res.Path, msg)
				}
			}
			continue
		}
		collectedResults = append(collectedResults, res)
		if res.IsEagleAlert {
			line := fmt.Sprintf("[EAGLE] %s  %d → %d", res.Path, res.OldStatusCode, res.StatusCode)
			fmt.Println(line)
		} else {
			fmt.Println(res.String())
		}
		writeResult(res)
	}

	dropped := atomic.LoadInt64(&eng.TUIDropped)
	if dropped > 0 {
		fmt.Fprintf(os.Stderr,
			"[!] %d result(s) were dropped from display (TUI backpressure — file output unaffected)\n",
			dropped,
		)
	}

	return collectedResults, nil
}

// ── TUI mode (default) ────────────────────────────────────────────────────────

// runTUI launches the Bubble Tea TUI. It creates a fanout goroutine between
// the engine's Results channel and the TUI so that:
//
//   - File output always receives every result (never dropped).
//   - The TUI channel is fed with a non-blocking send; if full, the result is
//     counted in eng.TUIDropped and shown in the TUI header as ⚠ TUI-dropped:N.
func runTUI(eng *engine.Engine, cfg cliConfig, writeResult func(engine.Result), priorResults []engine.Result) error {
	tuiCh := make(chan engine.Result, tuiResultBufSize)
	logEventCh := make(chan engine.LogEvent, 5000)

	// Fanout goroutine to pass results and log events to the TUI channels.
	var fanoutWg sync.WaitGroup
	fanoutWg.Add(1)
	go func() {
		defer fanoutWg.Done()
		resultsCh := eng.Results
		logsCh := eng.LogEvents
		for resultsCh != nil || logsCh != nil {
			select {
			case res, ok := <-resultsCh:
				if !ok {
					resultsCh = nil
					continue
				}
				// File write is guaranteed.
				if !res.IsAutoFilter {
					writeResult(res)
				}

				// TUI receive is best-effort.
				select {
				case tuiCh <- res:
				default:
					atomic.AddInt64(&eng.TUIDropped, 1)
				}
			case ev, ok := <-logsCh:
				if !ok {
					logsCh = nil
					continue
				}
				select {
				case logEventCh <- ev:
				default:
					eng.LogEventsDropped.Add(1)
				}
			}
		}
		// When eng.Results is closed, unblock the TUI so it can exit.
		close(tuiCh)
		close(logEventCh)
	}()

	model := tui.NewModel(eng, tuiCh, logEventCh)
	model.ConfigureHistoryPersistence(cfg.OutputFile, cfg.HistoryMode)
	if len(priorResults) > 0 {
		model.LoadPersistedResults(priorResults)
	}
	if err := model.LoadPersistedUIState(); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Warning: failed to load UI state: %v\n", err)
	}
	p := tea.NewProgram(&model, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		return fmt.Errorf("TUI error: %w", err)
	}
	if err := model.FlushPersistedUIState(); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Warning: failed to save UI state: %v\n", err)
	}

	// TUI has exited, now gracefully shut down the engine.
	eng.Shutdown()
	fanoutWg.Wait() // Wait for file/report writing to finish.

	// Post-scan warning printed after the terminal is restored.
	dropped := atomic.LoadInt64(&eng.TUIDropped)
	if dropped > 0 {
		fmt.Fprintf(os.Stderr,
			"\n[!] Warning: %d result(s) were dropped from the TUI display due to backpressure.\n"+
				"    All hits were written to the output file (if -o was specified).\n",
			dropped,
		)
	}

	return nil
}
