package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"dirfuzz/pkg/engine"
)

// ─── Defaults ────────────────────────────────────────────────────────────────

const (
	defaultStateFile      = "/data/state.jsonl"
	defaultScanInterval   = time.Hour
	defaultMatchCodes     = "200,301,302,403"
	maxWriteRetries       = 5
	maxWebhookAttempts    = 3
	webhookInitialBackoff = 5 * time.Second
	webhookMaxBackoff     = time.Minute

	minScanInterval = 5 * time.Minute
	// sizeChangeTolerance is the minimum byte delta to consider a body size
	// change interesting. Tuneable via code for operator preference.
	sizeChangeTolerance = 100
)

// ─── Config ──────────────────────────────────────────────────────────────────

type monitorConfig struct {
	Target              string
	Wordlist            string
	DiscordWebhook      string
	StateFile           string
	ScanInterval        time.Duration
	Jitter              time.Duration
	Workers             int
	MatchCodes          []int
	Methods             []string
	Headers             map[string]string
	Extensions          []string
	AllowPrivateTargets bool
	SaveRaw             bool
	NormalizeRegex      string
	LogLevel            slog.Level
}

func main() {
	cfg, err := loadConfigFromEnv()
	if err != nil {
		fmt.Fprintf(os.Stderr, "configuration error: %v\n", err)
		os.Exit(1)
	}

	logger := newLogger(cfg.LogLevel)
	rand.Seed(time.Now().UnixNano())
	if err := ensureStateDir(cfg.StateFile); err != nil {
		logger.Error("failed to prepare state directory", "state_file", cfg.StateFile, "error", err)
		os.Exit(1)
	}
	if cfg.DiscordWebhook == "" {
		logger.Info("DISCORD_WEBHOOK not set; findings will be logged but not sent to Discord")
	}

	logger.Info("monitor started",
		"target", cfg.Target,
		"wordlist", cfg.Wordlist,
		"state_file", cfg.StateFile,
		"scan_interval", cfg.ScanInterval.String(),
		"jitter", cfg.Jitter.String(),
		"workers", cfg.Workers,
		"match_codes", cfg.MatchCodes,
	)
	if len(cfg.Headers) > 0 {
		logger.Info("custom headers configured", "keys", sortedHeaderKeys(cfg.Headers))
	}
	if len(cfg.Extensions) > 0 {
		logger.Info("extensions configured", "extensions", cfg.Extensions)
	}
	if len(cfg.Methods) > 0 {
		logger.Info("http methods configured", "methods", cfg.Methods)
	}

	var (
		shutdownRequested atomic.Bool
		engineMu          sync.Mutex
		currentEngine     *engine.Engine
	)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	go func() {
		sig := <-sigCh
		logger.Info("shutdown signal received; finishing current scan state write before exit", "signal", sig.String())
		shutdownRequested.Store(true)
		engineMu.Lock()
		if currentEngine != nil {
			currentEngine.Shutdown()
		}
		engineMu.Unlock()
	}()

	for {
		if shutdownRequested.Load() {
			logger.Info("shutdown requested; exiting monitor loop")
			return
		}

		cycleStart := time.Now()
		interestingCount, err := runScanCycle(cfg, logger, &engineMu, &currentEngine, shutdownRequested.Load)
		if err != nil {
			logger.Error("scan cycle failed", "error", err)
		} else {
			logger.Info("scan cycle completed", "interesting_findings", interestingCount, "duration", time.Since(cycleStart).Round(time.Millisecond).String())
		}

		if shutdownRequested.Load() {
			logger.Info("shutdown completed after current cycle")
			return
		}

		logger.Info("sleeping before next scan", "interval", cfg.ScanInterval.String())

		// Apply jitter before the main scan interval to stagger runs across
		// multiple monitor instances.
		if cfg.Jitter > 0 {
			jitterDuration := time.Duration(rand.Int63n(int64(cfg.Jitter)))
			logger.Info("applying scan jitter", "jitter", cfg.Jitter.String(), "delay", jitterDuration.String())
			jitterTimer := time.NewTimer(jitterDuration)
			select {
			case <-jitterTimer.C:
			case sig := <-sigCh:
				if !jitterTimer.Stop() {
					<-jitterTimer.C
				}
				logger.Info("shutdown signal received while applying jitter; exiting", "signal", sig.String())
				shutdownRequested.Store(true)
				return
			}
		}

		timer := time.NewTimer(cfg.ScanInterval)
		select {
		case <-timer.C:
		case sig := <-sigCh:
			if !timer.Stop() {
				<-timer.C
			}
			logger.Info("shutdown signal received while sleeping; exiting", "signal", sig.String())
			shutdownRequested.Store(true)
			return
		}
	}
}

// ─── Scan cycle ──────────────────────────────────────────────────────────────

func runScanCycle(
	cfg monitorConfig,
	logger *slog.Logger,
	engineMu *sync.Mutex,
	currentEngine **engine.Engine,
	shutdownRequested func() bool,
) (int, error) {
	logger.Info("starting scan cycle")

	if _, err := os.Stat(cfg.Wordlist); err != nil {
		return 0, fmt.Errorf("wordlist is not readable: %w", err)
	}

	eng := engine.NewEngine(cfg.Workers, engine.DefaultBloomFilterSize, engine.DefaultBloomFilterFP)
	if len(cfg.Methods) > 0 {
		eng.UpdateConfig(func(c *engine.Config) {
			c.Methods = append([]string(nil), cfg.Methods...)
		})
	}
	eng.ConfigureFilters(cfg.MatchCodes, nil)
	if len(cfg.Headers) > 0 {
		for key, val := range cfg.Headers {
			eng.AddHeader(key, val)
		}
	}
	if len(cfg.Extensions) > 0 {
		for _, ext := range cfg.Extensions {
			eng.AddExtension(ext)
		}
	}

	if cfg.AllowPrivateTargets {
		eng.UpdateConfig(func(c *engine.Config) {
			c.AllowPrivateTargets = true
		})
		logger.Debug("enabled private target allowance", "target", cfg.Target)
	}

	if err := eng.SetTarget(cfg.Target); err != nil {
		return 0, fmt.Errorf("engine target setup failed: %w", err)
	}

	// Compile normalization regex for body hashing.
	normPattern := cfg.NormalizeRegex
	if normPattern == "" {
		normPattern = `(?i)(csrf[_-]?token|authenticity[_-]?token|nonce|timestamp|ts|session[_-]?id)["'=:\s>]+[A-Za-z0-9\-\._~%]+`
	}
	var normalizeRe *regexp.Regexp
	if normPattern != "" {
		if re, err := regexp.Compile(normPattern); err != nil {
			logger.Warn("invalid MONITOR_NORMALIZE_RE; content hashing disabled", "error", err)
		} else {
			normalizeRe = re
		}
	}

	// Ensure engine stores raw responses when requested so the monitor can compute hashes.
	if cfg.SaveRaw {
		eng.UpdateConfig(func(c *engine.Config) {
			c.SaveRaw = true
		})
	}

	stateExists, err := fileExists(cfg.StateFile)
	if err != nil {
		return 0, fmt.Errorf("failed checking state file: %w", err)
	}
	if stateExists {
		if err := eng.LoadPreviousScan(cfg.StateFile); err != nil {
			logger.Error("failed to load previous scan; continuing without baseline", "state_file", cfg.StateFile, "error", err)
			eng.PreviousState = nil
		} else {
			logger.Info("loaded previous state", "entries", len(eng.PreviousState), "state_file", cfg.StateFile)
		}
	}

	// Build previous state map with status, size and body hash from the previous JSONL state file.
	previous := make(map[string]prevInfo)
	if stateExists {
		f, err := os.Open(cfg.StateFile)
		if err != nil {
			logger.Error("failed to open previous state file; continuing without baseline", "state_file", cfg.StateFile, "error", err)
		} else {
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				var row struct {
					engine.Result
					BodyHash string `json:"body_hash,omitempty"`
				}
				if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
					continue
				}
				previous[row.Path] = prevInfo{Status: row.StatusCode, Size: row.Size, Hash: row.BodyHash}
			}
			f.Close()
		}
	}

	engineMu.Lock()
	*currentEngine = eng
	engineMu.Unlock()

	eng.Start()
	eng.KickoffScanner(cfg.Wordlist, 0)

	go func() {
		eng.Wait()
		eng.Shutdown()
	}()

	results := make([]engine.Result, 0, 128)
	for res := range eng.Results {
		if !res.IsAutoFilter {
			results = append(results, res)
		}
	}

	engineMu.Lock()
	if *currentEngine == eng {
		*currentEngine = nil
	}
	engineMu.Unlock()

	if err := ensureStateDir(cfg.StateFile); err != nil {
		return 0, fmt.Errorf("failed to ensure state directory: %w", err)
	}

	// Compute current body hashes for this run (requires engine.SaveRaw=true).
	curHashes := make(map[string]string, len(results))
	for _, res := range results {
		var h string
		if res.Response != "" {
			raw := []byte(res.Response)
			if idx := bytes.Index(raw, []byte("\r\n\r\n")); idx >= 0 {
				rawBody := raw[idx+4:]
				if normalizeRe != nil {
					rawBody = normalizeRe.ReplaceAll(rawBody, []byte(""))
				}
				sum := sha256.Sum256(rawBody)
				h = hex.EncodeToString(sum[:])
			} else {
				body := raw
				if normalizeRe != nil {
					body = normalizeRe.ReplaceAll(body, []byte(""))
				}
				sum := sha256.Sum256(body)
				h = hex.EncodeToString(sum[:])
			}
		}
		curHashes[res.Path] = h
	}

	if err := persistState(cfg.StateFile, results, logger, normalizeRe, curHashes, shutdownRequested()); err != nil {
		return 0, err
	}

	// Baseline behavior: if the state file did not exist prior to this cycle,
	// or the operator explicitly requests a baseline via BASELINE_RUN, persist
	// the current results but do not send Discord notifications.
	baselineEnv := strings.ToLower(strings.TrimSpace(os.Getenv("BASELINE_RUN")))
	forceBaseline := baselineEnv == "1" || baselineEnv == "true" || baselineEnv == "yes"
	if !stateExists || forceBaseline {
		logger.Info("first run complete. State baselined. Future runs will report changes.", "state_file", cfg.StateFile, "results", len(results))
		return 0, nil
	}

	interesting := findInteresting(results, previous, curHashes)
	logFindings(logger, interesting)

	if len(interesting) > 0 && cfg.DiscordWebhook != "" {
		if err := postDiscordWebhook(context.Background(), logger, cfg.DiscordWebhook, cfg.Target, cfg.ScanInterval, interesting); err != nil {
			logger.Error("failed to send discord webhook", "error", err)
		}
	}

	return len(interesting), nil
}

// ─── Findings ────────────────────────────────────────────────────────────────

type findingType string

const (
	findingStatusChange   findingType = "status_change"
	findingNewEndpoint    findingType = "new_endpoint"
	findingBodySizeChange findingType = "body_size_change"
	findingContentChange  findingType = "content_change"
)

type finding struct {
	Type      findingType
	Path      string
	OldStatus int
	NewStatus int
	OldSize   int
	NewSize   int
	OldHash   string
	NewHash   string
}

// prevInfo stores status, size and hash from the previous run for a given path.
type prevInfo struct {
	Status int
	Size   int
	Hash   string
}

func findInteresting(results []engine.Result, previous map[string]prevInfo, curHashes map[string]string) []finding {
	findings := make([]finding, 0)
	statusSeen := make(map[string]struct{})
	newSeen := make(map[string]struct{})
	sizeSeen := make(map[string]struct{})
	hashSeen := make(map[string]struct{})

	for _, res := range results {
		if res.IsAutoFilter {
			continue
		}

		prev, existed := previous[res.Path]
		curHash := curHashes[res.Path]

		if existed {
			// Status change
			if prev.Status != res.StatusCode {
				key := fmt.Sprintf("%s|%d|%d", res.Path, prev.Status, res.StatusCode)
				if _, exists := statusSeen[key]; !exists {
					statusSeen[key] = struct{}{}
					findings = append(findings, finding{
						Type:      findingStatusChange,
						Path:      res.Path,
						OldStatus: prev.Status,
						NewStatus: res.StatusCode,
					})
				}
			}

			// Content hash change
			if prev.Hash != "" && curHash != "" && prev.Hash != curHash {
				key := fmt.Sprintf("%s|hash|%s|%s", res.Path, prev.Hash, curHash)
				if _, exists := hashSeen[key]; !exists {
					hashSeen[key] = struct{}{}
					findings = append(findings, finding{
						Type:    findingContentChange,
						Path:    res.Path,
						OldHash: prev.Hash,
						NewHash: curHash,
					})
				}
			}

			// Body size change
			if prev.Size >= 0 && res.Size >= 0 {
				delta := res.Size - prev.Size
				if delta < 0 {
					delta = -delta
				}

				// Calculate percentage change to avoid false positives on large files
				percentChange := 0.0
				if prev.Size > 0 {
					percentChange = (float64(delta) / float64(prev.Size)) * 100.0
				}

				// Trigger if change is > 1.5% OR if the raw byte difference is huge (> 2000 bytes).
				// (Keeps the 100 byte tolerance for extremely tiny files under ~7KB)
				if percentChange >= 1.5 || (delta > 2000) || (delta > sizeChangeTolerance && prev.Size < 500) {
					key := fmt.Sprintf("%s|size|%d|%d", res.Path, prev.Size, res.Size)
					if _, exists := sizeSeen[key]; !exists {
						sizeSeen[key] = struct{}{}
						findings = append(findings, finding{
							Type:    findingBodySizeChange,
							Path:    res.Path,
							OldSize: prev.Size,
							NewSize: res.Size,
						})
					}
				}
			}
		} else {
			key := fmt.Sprintf("%s|%d", res.Path, res.StatusCode)
			if _, exists := newSeen[key]; !exists {
				newSeen[key] = struct{}{}
				findings = append(findings, finding{
					Type:      findingNewEndpoint,
					Path:      res.Path,
					NewStatus: res.StatusCode,
				})
			}
		}
	}

	return findings
}

func logFindings(logger *slog.Logger, findings []finding) {
	if len(findings) == 0 {
		logger.Info("no interesting findings in this cycle")
		return
	}

	for _, f := range findings {
		switch f.Type {
		case findingStatusChange:
			logger.Info("finding", "type", "status_change", "path", f.Path, "old_status", f.OldStatus, "new_status", f.NewStatus)
		case findingContentChange:
			oldShort, newShort := f.OldHash, f.NewHash
			if len(oldShort) > 8 {
				oldShort = oldShort[:8]
			}
			if len(newShort) > 8 {
				newShort = newShort[:8]
			}
			logger.Info("finding", "type", "content_change", "path", f.Path, "old_hash", oldShort, "new_hash", newShort)
		case findingBodySizeChange:
			logger.Info("finding", "type", "body_size_change", "path", f.Path, "old_size", f.OldSize, "new_size", f.NewSize)
		case findingNewEndpoint:
			logger.Info("finding", "type", "new_endpoint", "path", f.Path, "status", f.NewStatus)
		}
	}
}

// ─── Discord ─────────────────────────────────────────────────────────────────

type discordField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

type discordFooter struct {
	Text string `json:"text"`
}

type discordEmbed struct {
	Title       string         `json:"title"`
	Description string         `json:"description,omitempty"`
	Color       int            `json:"color"`
	Fields      []discordField `json:"fields"`
	Footer      discordFooter  `json:"footer"`
}

type discordPayload struct {
	Embeds []discordEmbed `json:"embeds"`
}

func postDiscordWebhook(ctx context.Context, logger *slog.Logger, webhook, target string, interval time.Duration, findings []finding) error {
	if len(findings) == 0 {
		return nil
	}

	color := 16776960
	for _, f := range findings {
		if f.NewStatus == http.StatusOK {
			color = 15158332
			break
		}
	}

	fields := make([]discordField, 0, min(25, len(findings)+2))
	fields = append(fields, discordField{
		Name:   "📋 Target",
		Value:  target,
		Inline: false,
	})
	maxDetailFields := len(findings)
	if len(findings) > 24 {
		maxDetailFields = 23
	}

	ordered := make([]finding, 0, len(findings))
	for _, f := range findings {
		if f.Type == findingStatusChange {
			ordered = append(ordered, f)
		}
	}
	for _, f := range findings {
		if f.Type == findingContentChange {
			ordered = append(ordered, f)
		}
	}
	for _, f := range findings {
		if f.Type == findingBodySizeChange {
			ordered = append(ordered, f)
		}
	}
	for _, f := range findings {
		if f.Type == findingNewEndpoint {
			ordered = append(ordered, f)
		}
	}

	for _, f := range ordered[:maxDetailFields] {
		switch f.Type {
		case findingStatusChange:
			fields = append(fields, discordField{
				Name:   "⚡ Status Change",
				Value:  fmt.Sprintf("`%s` was `%d` → now `%d`", f.Path, f.OldStatus, f.NewStatus),
				Inline: false,
			})
		case findingContentChange:
			oldShort := f.OldHash
			if len(oldShort) > 8 {
				oldShort = oldShort[:8]
			}
			newShort := f.NewHash
			if len(newShort) > 8 {
				newShort = newShort[:8]
			}
			fields = append(fields, discordField{
				Name:   "⚠️ Content Change",
				Value:  fmt.Sprintf("`%s` changed (hash `%s` → `%s`)", f.Path, oldShort, newShort),
				Inline: false,
			})
		case findingBodySizeChange:
			fields = append(fields, discordField{
				Name:   "🔀 Body Size Change",
				Value:  fmt.Sprintf("`%s` size `%d` → `%d`", f.Path, f.OldSize, f.NewSize),
				Inline: false,
			})
		case findingNewEndpoint:
			fields = append(fields, discordField{
				Name:   "🆕 New Endpoint",
				Value:  fmt.Sprintf("`%s` returned `%d`", f.Path, f.NewStatus),
				Inline: false,
			})
		}
	}

	if len(findings) > 24 {
		fields = append(fields, discordField{
			Name:   fmt.Sprintf("+ %d more findings", len(findings)-23),
			Value:  "check STATE_FILE",
			Inline: false,
		})
	}

	payload := discordPayload{
		Embeds: []discordEmbed{
			{
				Title:       "🔍 DirFuzz Monitor — Changes Detected",
				Description: fmt.Sprintf("🎯 Target: %s", target),
				Color:       color,
				Fields:      fields,
				Footer: discordFooter{
					Text: fmt.Sprintf("Scan completed at %s | Next scan in %s", time.Now().Format(time.RFC3339), interval.String()),
				},
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal discord payload: %w", err)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	backoff := webhookInitialBackoff

	for attempt := 1; attempt <= maxWebhookAttempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhook, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("build discord request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return nil
			}
			err = fmt.Errorf("discord webhook returned status %d", resp.StatusCode)
		}

		if attempt == maxWebhookAttempts {
			return fmt.Errorf("discord webhook delivery failed after %d attempt(s): %w", maxWebhookAttempts, err)
		}

		logger.Error("discord webhook delivery failed; retrying",
			"attempt", attempt,
			"max_attempts", maxWebhookAttempts,
			"error", err,
			"retry_in", backoff.String(),
		)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}

		if backoff < webhookMaxBackoff {
			backoff *= 2
			if backoff > webhookMaxBackoff {
				backoff = webhookMaxBackoff
			}
		}
	}
	return fmt.Errorf("discord webhook delivery failed")
}

// ─── State persistence ───────────────────────────────────────────────────────

func persistState(path string, results []engine.Result, logger *slog.Logger, normalizeRe *regexp.Regexp, precomputedHashes map[string]string, isShutdown bool) error {
	var err error
	if isShutdown {
		err = writeStateWithRetry(path, results, logger, normalizeRe, precomputedHashes)
	} else {
		err = writeStateAtomic(path, results, normalizeRe, precomputedHashes)
	}
	if err != nil {
		logger.Error("failed to persist state", "state_file", path, "entries", len(results), "error", err)
		return fmt.Errorf("failed to persist state: %w", err)
	}
	logger.Info("persisted current state", "state_file", path, "entries", len(results))
	return nil
}

func writeStateWithRetry(path string, results []engine.Result, logger *slog.Logger, normalizeRe *regexp.Regexp, precomputedHashes map[string]string) error {
	for attempt := 1; attempt <= maxWriteRetries; attempt++ {
		err := writeStateAtomic(path, results, normalizeRe, precomputedHashes)
		if err == nil {
			return nil
		}
		logger.Error("state write failed during shutdown; retrying", "attempt", attempt, "error", err)
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("state write failed after %d attempts", maxWriteRetries)
}

func writeStateAtomic(path string, results []engine.Result, normalizeRe *regexp.Regexp, precomputedHashes map[string]string) error {
	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		dir = "."
	}

	file, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("create temp state file: %w", err)
	}
	tmpPath := file.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()

	bufw := bufio.NewWriter(file)
	encoder := json.NewEncoder(bufw)

	for _, res := range results {
		bodyHash := precomputedHashes[res.Path]
		row := struct {
			engine.Result
			BodyHash string `json:"body_hash,omitempty"`
		}{
			Result:   res,
			BodyHash: bodyHash,
		}
		if err := encoder.Encode(row); err != nil {
			_ = file.Close()
			return fmt.Errorf("encode state row: %w", err)
		}
	}

	if err := bufw.Flush(); err != nil {
		_ = file.Close()
		return fmt.Errorf("flush temp state file: %w", err)
	}

	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync temp state file: %w", err)
	}

	if err := file.Close(); err != nil {
		return fmt.Errorf("close temp state file: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		if copyErr := replaceFileContents(tmpPath, path); copyErr != nil {
			return fmt.Errorf("replace state file (rename: %v, copy fallback: %w)", err, copyErr)
		}
		return nil
	}

	return nil
}

func replaceFileContents(srcPath, dstPath string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("open temp state file: %w", err)
	}
	defer src.Close()

	dst, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("open destination state file: %w", err)
	}

	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		return fmt.Errorf("copy temp state file: %w", err)
	}

	if err := dst.Sync(); err != nil {
		_ = dst.Close()
		return fmt.Errorf("sync destination state file: %w", err)
	}

	if err := dst.Close(); err != nil {
		return fmt.Errorf("close destination state file: %w", err)
	}

	return nil
}

func ensureStateDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		return nil
	}
	return os.MkdirAll(dir, 0o755)
}

// ─── Environment ─────────────────────────────────────────────────────────────

func loadConfigFromEnv() (monitorConfig, error) {
	cfg := monitorConfig{
		StateFile:    getenvDefault("STATE_FILE", defaultStateFile),
		ScanInterval: defaultScanInterval,
		Workers:      engine.DefaultWorkerCount,
		LogLevel:     slog.LevelInfo,
	}

	cfg.Target = strings.TrimSpace(os.Getenv("TARGET"))
	cfg.Wordlist = strings.TrimSpace(os.Getenv("WORDLIST"))
	cfg.DiscordWebhook = strings.TrimSpace(os.Getenv("DISCORD_WEBHOOK"))

	if cfg.Target == "" {
		return monitorConfig{}, errors.New("TARGET is required")
	}
	if cfg.Wordlist == "" {
		return monitorConfig{}, errors.New("WORDLIST is required")
	}

	intervalRaw := strings.TrimSpace(os.Getenv("SCAN_INTERVAL"))
	if intervalRaw != "" {
		d, err := time.ParseDuration(intervalRaw)
		if err != nil {
			return monitorConfig{}, fmt.Errorf("invalid SCAN_INTERVAL: %w", err)
		}
		if d <= 0 {
			return monitorConfig{}, errors.New("SCAN_INTERVAL must be > 0")
		}
		if d < minScanInterval {
			slog.Warn("SCAN_INTERVAL is very short; clamping to minimum",
				"requested", d.String(), "minimum", minScanInterval.String())
			d = minScanInterval
		}
		cfg.ScanInterval = d
	}

	// Optional jitter to randomise schedule and avoid synchronized scans.
	jitterRaw := strings.TrimSpace(os.Getenv("SCAN_JITTER"))
	if jitterRaw != "" {
		j, err := time.ParseDuration(jitterRaw)
		if err != nil {
			return monitorConfig{}, fmt.Errorf("invalid SCAN_JITTER: %w", err)
		}
		if j < 0 {
			return monitorConfig{}, errors.New("SCAN_JITTER must be >= 0")
		}
		cfg.Jitter = j
	}

	workersRaw := strings.TrimSpace(os.Getenv("WORKERS"))
	if workersRaw != "" {
		workers, err := strconv.Atoi(workersRaw)
		if err != nil {
			return monitorConfig{}, fmt.Errorf("invalid WORKERS: %w", err)
		}
		if workers <= 0 {
			return monitorConfig{}, errors.New("WORKERS must be > 0")
		}
		cfg.Workers = workers
	}

	matchRaw := strings.TrimSpace(os.Getenv("MATCH_CODES"))
	if matchRaw == "" {
		matchRaw = defaultMatchCodes
	}
	matchCodes, err := parseStatusCodes(matchRaw)
	if err != nil {
		return monitorConfig{}, fmt.Errorf("invalid MATCH_CODES: %w", err)
	}
	cfg.MatchCodes = matchCodes
	cfg.Methods = parseMethods(strings.TrimSpace(os.Getenv("METHOD")))
	cfg.Headers = parseHeaders(strings.TrimSpace(os.Getenv("HEADERS")))
	cfg.Extensions = parseExtensions(strings.TrimSpace(os.Getenv("EXTENSIONS")))

	logLevelRaw := strings.ToLower(strings.TrimSpace(getenvDefault("LOG_LEVEL", "info")))
	switch logLevelRaw {
	case "info":
		cfg.LogLevel = slog.LevelInfo
	case "debug":
		cfg.LogLevel = slog.LevelDebug
	default:
		return monitorConfig{}, fmt.Errorf("invalid LOG_LEVEL %q, expected info or debug", logLevelRaw)
	}

	// Allow operator to explicitly enable private target scanning
	allowPrivateRaw := strings.ToLower(strings.TrimSpace(os.Getenv("ALLOW_PRIVATE_TARGETS")))
	if allowPrivateRaw != "" {
		switch allowPrivateRaw {
		case "1", "true", "yes":
			cfg.AllowPrivateTargets = true
		case "0", "false", "no":
			cfg.AllowPrivateTargets = false
		default:
			return monitorConfig{}, fmt.Errorf("invalid ALLOW_PRIVATE_TARGETS value %q, expected true/false/1/0/yes/no", allowPrivateRaw)
		}
	}

	return cfg, nil
}

func parseStatusCodes(raw string) ([]int, error) {
	parts := strings.Split(raw, ",")
	codes := make([]int, 0, len(parts))

	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" {
			continue
		}
		code, err := strconv.Atoi(trimmed)
		if err != nil {
			return nil, fmt.Errorf("bad status code %q: %w", trimmed, err)
		}
		if code < 100 || code > 599 {
			return nil, fmt.Errorf("status code out of range: %d", code)
		}
		codes = append(codes, code)
	}

	if len(codes) == 0 {
		return nil, errors.New("at least one status code is required")
	}

	return codes, nil
}

func parseHeaders(raw string) map[string]string {
	if raw == "" {
		return nil
	}

	headers := make(map[string]string)
	for i, pair := range strings.Split(raw, ";") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		sep := strings.Index(pair, ":")
		if sep <= 0 {
			slog.Warn("skipping malformed HEADERS pair", "position", i, "reason", "missing key:value separator")
			continue
		}

		key := strings.TrimSpace(pair[:sep])
		value := strings.TrimSpace(pair[sep+1:])
		if key == "" {
			slog.Warn("skipping malformed HEADERS pair", "position", i, "reason", "empty header key")
			continue
		}

		headers[key] = value
	}

	if len(headers) == 0 {
		return nil
	}
	return headers
}

func parseExtensions(raw string) []string {
	if raw == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	extensions := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))

	for _, part := range parts {
		ext := strings.TrimSpace(part)
		ext = strings.TrimPrefix(ext, ".")
		if ext == "" {
			continue
		}
		if _, exists := seen[ext]; exists {
			continue
		}
		seen[ext] = struct{}{}
		extensions = append(extensions, ext)
	}

	if len(extensions) == 0 {
		return nil
	}
	return extensions
}

func parseMethods(raw string) []string {
	if raw == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	methods := make([]string, 0, len(parts))
	for _, part := range parts {
		method := strings.ToUpper(strings.TrimSpace(part))
		if method == "" {
			continue
		}
		switch method {
		case "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH":
			methods = append(methods, method)
		default:
			slog.Warn("skipping invalid METHOD entry", "method", method)
		}
	}

	if len(methods) == 0 {
		return nil
	}
	return methods
}

func sortedHeaderKeys(headers map[string]string) []string {
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func getenvDefault(key, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}

func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

// ─── Target checks ───────────────────────────────────────────────────────────

// ─── Logging ─────────────────────────────────────────────────────────────────

func newLogger(level slog.Level) *slog.Logger {
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	return slog.New(handler)
}
