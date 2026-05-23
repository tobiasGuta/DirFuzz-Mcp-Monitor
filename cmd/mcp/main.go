// DirFuzz MCP server.
//
// Exposes read-only MCP resources for wordlists and loaded scope, plus tools
// for launching and analyzing directory-fuzzing scans. Before starting any
// scan the server validates the target against live H1-Scope-Watcher JSON
// files so the AI cannot accidentally fuzz out-of-scope assets.
//
// Required environment variables:
//
//	DIRFUZZ_WORDLIST_DIR   directory that contains wordlist .txt files
//	DIRFUZZ_SCOPE_DIR      directory that contains H1-Scope-Watcher .json files
//	DIRFUZZ_OUTPUT_DIR     directory that contains scan output files for analysis
//
// Optional environment variables:
//
//	DIRFUZZ_MAX_THREADS    max concurrent workers per scan      (default 15)
//	DIRFUZZ_MAX_RESULTS    max results returned to the AI       (default 200)
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dirfuzz/pkg/engine"
	"dirfuzz/pkg/scope"

	"github.com/google/uuid"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// ── startup constants & defaults ─────────────────────────────────────────────

const (
	defaultMaxThreads      = 15
	defaultMaxResults      = 200
	defaultRateLimitWindow = 10 * time.Minute
	defaultToolLimit       = 60
	defaultScanToolLimit   = 20

	serverName    = "DirFuzz"
	serverVersion = "2.3.0"
	toolName      = "dirfuzz_scan"
)

// ── server config (loaded once at startup) ───────────────────────────────────

type mcpConfig struct {
	wordlistDir        string
	scopeDir           string
	outputDir          string
	auditLogPath       string
	maxThreads         int
	maxResults         int
	maxConcurrentScans int
	rateLimitWindow    time.Duration
	defaultToolLimit   int
	scanToolLimit      int
}

type rateLimitRule struct {
	Limit  int
	Window time.Duration
}

type toolRateLimiter struct {
	mu    sync.Mutex
	calls map[string][]time.Time
}

type auditLogger struct {
	mu   sync.Mutex
	file *os.File
	path string
}

type auditEntry struct {
	Timestamp    string `json:"timestamp"`
	Tool         string `json:"tool"`
	Arguments    any    `json:"arguments,omitempty"`
	Outcome      string `json:"outcome"`
	DurationMS   int64  `json:"duration_ms"`
	RetryAfterMS int64  `json:"retry_after_ms,omitempty"`
}

var bearerTokenPattern = regexp.MustCompile(`(?i)(bearer\s+)[^\s,;]+`)

func newToolRateLimiter() *toolRateLimiter {
	return &toolRateLimiter{calls: make(map[string][]time.Time)}
}

func (rl *toolRateLimiter) allow(tool string, rule rateLimitRule, now time.Time) (time.Duration, bool) {
	if rl == nil || rule.Limit <= 0 || rule.Window <= 0 {
		return 0, true
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	calls := rl.calls[tool]
	cutoff := now.Add(-rule.Window)
	pruned := calls[:0]
	for _, ts := range calls {
		if ts.After(cutoff) {
			pruned = append(pruned, ts)
		}
	}
	calls = pruned
	if len(calls) >= rule.Limit {
		oldest := calls[0]
		retryAfter := oldest.Add(rule.Window).Sub(now)
		if retryAfter < 0 {
			retryAfter = 0
		}
		rl.calls[tool] = calls
		return retryAfter, false
	}
	rl.calls[tool] = append(calls, now)
	return 0, true
}

func newAuditLogger(path string) (*auditLogger, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("audit log path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create audit log directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log %q: %w", path, err)
	}
	return &auditLogger{file: f, path: path}, nil
}

func (l *auditLogger) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.file.Close()
}

func (l *auditLogger) Log(entry auditEntry) error {
	if l == nil || l.file == nil {
		return nil
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.file.Write(append(raw, '\n')); err != nil {
		return err
	}
	return l.file.Sync()
}

type scanRegistry struct {
	mu    sync.RWMutex
	scans map[string]*scanState
}

type scanState struct {
	mu               sync.RWMutex
	scanID           string
	target           string
	startedAt        time.Time
	finishedAt       time.Time
	running          bool
	canceled         bool
	capped           bool
	resultsFile      string
	resultsPath      string
	engine           *engine.Engine
	cancel           context.CancelFunc
	resultsCollected int64
}

func newScanRegistry() *scanRegistry {
	return &scanRegistry{scans: make(map[string]*scanState)}
}

func (r *scanRegistry) register(state *scanState, limit int) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	activeIDs := make([]string, 0, len(r.scans))
	for _, scan := range r.scans {
		scan.mu.RLock()
		running := scan.running
		scanID := scan.scanID
		scan.mu.RUnlock()
		if running {
			activeIDs = append(activeIDs, scanID)
		}
	}
	if limit > 0 && len(activeIDs) >= limit {
		sort.Strings(activeIDs)
		return activeIDs, fmt.Errorf("scan limit reached")
	}
	r.scans[state.scanID] = state
	return nil, nil
}

func (r *scanRegistry) get(scanID string) (*scanState, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	state, ok := r.scans[scanID]
	return state, ok
}

func (s *scanState) attachEngine(e *engine.Engine) {
	s.mu.Lock()
	s.engine = e
	s.running = true
	s.mu.Unlock()
}

func (s *scanState) attachCancel(cancel context.CancelFunc) {
	s.mu.Lock()
	s.cancel = cancel
	s.mu.Unlock()
}

func (s *scanState) finish(resultsFile, resultsPath string, capped bool) {
	s.mu.Lock()
	s.running = false
	s.finishedAt = time.Now().UTC()
	s.resultsFile = resultsFile
	s.resultsPath = resultsPath
	s.capped = capped
	s.mu.Unlock()
}

func (s *scanState) cancelRunning() bool {
	s.mu.RLock()
	cancel := s.cancel
	running := s.running
	s.mu.RUnlock()
	if cancel == nil {
		return false
	}
	if running {
		cancel()
		s.mu.Lock()
		s.canceled = true
		s.mu.Unlock()
		return true
	}
	return false
}

func (s *scanState) addCollected(n int64) {
	atomic.AddInt64(&s.resultsCollected, n)
}

func (s *scanState) snapshot() scanStatusOutput {
	s.mu.RLock()
	scanID := s.scanID
	target := s.target
	startedAt := s.startedAt
	finishedAt := s.finishedAt
	running := s.running
	capped := s.capped
	resultsFile := s.resultsFile
	resultsPath := s.resultsPath
	eng := s.engine
	s.mu.RUnlock()

	elapsed := time.Since(startedAt)
	if !finishedAt.IsZero() {
		elapsed = finishedAt.Sub(startedAt)
	}

	status := scanStatusOutput{
		ScanID:             scanID,
		Target:             target,
		StartedAt:          startedAt.Format(time.RFC3339Nano),
		ElapsedMS:          elapsed.Milliseconds(),
		RequestsDispatched: 0,
		ResultsCollected:   atomic.LoadInt64(&s.resultsCollected),
		CurrentWorkerCount: 0,
		CurrentRPS:         0,
		Running:            running,
		Canceled:           s.canceled,
		Capped:             capped,
		ResultsFile:        resultsFile,
		ResultsPath:        resultsPath,
	}

	if eng != nil {
		stats := eng.Stats()
		status.RequestsDispatched = stats.RequestsDispatched
		status.ResultsCollected = int64(stats.ResultsCollected)
		status.CurrentWorkerCount = int64(stats.WorkersActive)
		status.CurrentRPS = atomic.LoadInt64(&eng.CurrentRPS)
		status.WAFDetected = stats.WAFDetected
		status.WAFVendorGuess = stats.WAFVendorGuess
		status.WAFScoreboard = convertEvasionSummary(stats.EvasionScoreboard)
		status.QueueDepth = eng.QueueSize()
		if !stats.StartedAt.IsZero() {
			status.StartedAt = stats.StartedAt.Format(time.RFC3339Nano)
		}
		status.Running = stats.IsRunning
	}
	return status
}

type toolHandler func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error)

func wrapToolHandler(
	toolName string,
	rule rateLimitRule,
	limiter *toolRateLimiter,
	audit *auditLogger,
	handler toolHandler,
) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, req mcp.CallToolRequest) (result *mcp.CallToolResult, err error) {
		start := time.Now().UTC()
		outcome := "ok"
		var retryAfter time.Duration

		defer func() {
			if rec := recover(); rec != nil {
				outcome = "panic"
				result = mcp.NewToolResultError(fmt.Sprintf("internal error: %v", rec))
				err = nil
			}
			if audit != nil {
				_ = audit.Log(auditEntry{
					Timestamp:    start.Format(time.RFC3339Nano),
					Tool:         toolName,
					Arguments:    sanitizeAuditArguments(req.GetRawArguments()),
					Outcome:      outcome,
					DurationMS:   time.Since(start).Milliseconds(),
					RetryAfterMS: retryAfter.Milliseconds(),
				})
			}
		}()

		if limiter != nil {
			if wait, allowed := limiter.allow(toolName, rule, start); !allowed {
				retryAfter = wait
				outcome = "rate_limited"
				msg := fmt.Sprintf("%s rate limit exceeded (%d per %s); retry after %s", toolName, rule.Limit, rule.Window, wait.Round(time.Second))
				result = mcp.NewToolResultError(msg)
				return result, nil
			}
		}

		result, err = handler(ctx, req)
		if err != nil {
			outcome = "handler_error"
			return result, err
		}
		if result != nil && result.IsError {
			outcome = "tool_error"
		}
		return result, nil
	}
}

func loadConfig(exePath string) (mcpConfig, error) {
	cfg := mcpConfig{
		maxThreads:         defaultMaxThreads,
		maxResults:         defaultMaxResults,
		maxConcurrentScans: 5,
		rateLimitWindow:    defaultRateLimitWindow,
		defaultToolLimit:   defaultToolLimit,
		scanToolLimit:      defaultScanToolLimit,
	}

	cfg.wordlistDir = strings.TrimSpace(os.Getenv("DIRFUZZ_WORDLIST_DIR"))
	if cfg.wordlistDir == "" {
		return mcpConfig{}, fmt.Errorf("DIRFUZZ_WORDLIST_DIR is required")
	}
	if info, err := os.Stat(cfg.wordlistDir); err != nil || !info.IsDir() {
		return mcpConfig{}, fmt.Errorf("DIRFUZZ_WORDLIST_DIR %q is not a readable directory", cfg.wordlistDir)
	}

	cfg.scopeDir = strings.TrimSpace(os.Getenv("DIRFUZZ_SCOPE_DIR"))
	if cfg.scopeDir == "" {
		return mcpConfig{}, fmt.Errorf("DIRFUZZ_SCOPE_DIR is required — set it to the directory containing H1-Scope-Watcher JSON files")
	}
	if info, err := os.Stat(cfg.scopeDir); err != nil || !info.IsDir() {
		return mcpConfig{}, fmt.Errorf("DIRFUZZ_SCOPE_DIR %q is not a readable directory", cfg.scopeDir)
	}

	cfg.outputDir = strings.TrimSpace(os.Getenv("DIRFUZZ_OUTPUT_DIR"))
	if cfg.outputDir == "" {
		return mcpConfig{}, fmt.Errorf("DIRFUZZ_OUTPUT_DIR is required.\n\nPaste this Claude Desktop stanza and set the output path:\n%s", formatClaudeDesktopConfigStanza(exePath, cfg.wordlistDir, cfg.scopeDir))
	}
	if info, err := os.Stat(cfg.outputDir); err != nil || !info.IsDir() {
		return mcpConfig{}, fmt.Errorf("DIRFUZZ_OUTPUT_DIR %q is not a readable directory", cfg.outputDir)
	}

	if raw := strings.TrimSpace(os.Getenv("DIRFUZZ_MAX_THREADS")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			return mcpConfig{}, fmt.Errorf("DIRFUZZ_MAX_THREADS must be a positive integer, got %q", raw)
		}
		cfg.maxThreads = n
	}

	if raw := strings.TrimSpace(os.Getenv("DIRFUZZ_MAX_RESULTS")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			return mcpConfig{}, fmt.Errorf("DIRFUZZ_MAX_RESULTS must be a positive integer, got %q", raw)
		}
		cfg.maxResults = n
	}

	if raw := strings.TrimSpace(os.Getenv("DIRFUZZ_MAX_CONCURRENT_SCANS")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			return mcpConfig{}, fmt.Errorf("DIRFUZZ_MAX_CONCURRENT_SCANS must be a positive integer, got %q", raw)
		}
		cfg.maxConcurrentScans = n
	}

	if raw := strings.TrimSpace(os.Getenv("DIRFUZZ_RATE_LIMIT_WINDOW_SECONDS")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			return mcpConfig{}, fmt.Errorf("DIRFUZZ_RATE_LIMIT_WINDOW_SECONDS must be a positive integer, got %q", raw)
		}
		cfg.rateLimitWindow = time.Duration(n) * time.Second
	}

	if raw := strings.TrimSpace(os.Getenv("DIRFUZZ_TOOL_RATE_LIMIT")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			return mcpConfig{}, fmt.Errorf("DIRFUZZ_TOOL_RATE_LIMIT must be a positive integer, got %q", raw)
		}
		cfg.defaultToolLimit = n
	}

	if raw := strings.TrimSpace(os.Getenv("DIRFUZZ_SCAN_RATE_LIMIT")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			return mcpConfig{}, fmt.Errorf("DIRFUZZ_SCAN_RATE_LIMIT must be a positive integer, got %q", raw)
		}
		cfg.scanToolLimit = n
	}

	if raw := strings.TrimSpace(os.Getenv("DIRFUZZ_AUDIT_LOG")); raw != "" {
		cfg.auditLogPath = raw
	} else {
		cfg.auditLogPath = filepath.Join(cfg.outputDir, "dirfuzz-audit.jsonl")
	}

	return cfg, nil
}

// ── main ─────────────────────────────────────────────────────────────────────

func main() {
	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("dirfuzz-mcp: failed to resolve executable path: %v", err)
	}
	if absExe, absErr := filepath.Abs(exePath); absErr == nil {
		exePath = absExe
	}

	cfg, err := loadConfig(exePath)
	if err != nil {
		log.Fatalf("dirfuzz-mcp: configuration error: %v", err)
	}
	if _, warnings, err := scope.LoadDir(cfg.scopeDir); err != nil {
		log.Printf("dirfuzz-mcp: scope preload error: %v", err)
	} else {
		for _, warning := range warnings {
			log.Printf("dirfuzz-mcp: %s", warning)
		}
	}

	s := server.NewMCPServer(serverName, serverVersion)
	registry := newScanRegistry()
	limiter := newToolRateLimiter()
	auditLogger, err := newAuditLogger(cfg.auditLogPath)
	if err != nil {
		log.Fatalf("dirfuzz-mcp: audit logger error: %v", err)
	}
	defer func() {
		if err := auditLogger.Close(); err != nil {
			log.Printf("dirfuzz-mcp: audit log close error: %v", err)
		}
	}()

	wordlistResource := mcp.NewResource(
		"dirfuzz://wordlists",
		"DirFuzz Wordlist Inventory",
		mcp.WithResourceDescription("Lists all available .txt wordlists in DIRFUZZ_WORDLIST_DIR with line counts and short semantic descriptions."),
		mcp.WithMIMEType("application/json"),
	)
	s.AddResource(wordlistResource, func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		inventory, err := loadWordlistInventory(cfg.wordlistDir)
		if err != nil {
			return nil, err
		}
		payload, err := json.MarshalIndent(inventory, "", "  ")
		if err != nil {
			return nil, err
		}
		return []mcp.ResourceContents{
			mcp.TextResourceContents{
				URI:      "dirfuzz://wordlists",
				MIMEType: "application/json",
				Text:     string(payload),
			},
		}, nil
	})

	scopeResource := mcp.NewResource(
		"dirfuzz://scope",
		"DirFuzz Scope Snapshot",
		mcp.WithResourceDescription("Returns the currently loaded H1-Scope-Watcher scope as structured JSON, grouped by source file."),
		mcp.WithMIMEType("application/json"),
	)
	s.AddResource(scopeResource, func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		snapshot, err := loadScopeSnapshot(cfg.scopeDir)
		if err != nil {
			return nil, err
		}
		payload, err := json.MarshalIndent(snapshot, "", "  ")
		if err != nil {
			return nil, err
		}
		return []mcp.ResourceContents{
			mcp.TextResourceContents{
				URI:      "dirfuzz://scope",
				MIMEType: "application/json",
				Text:     string(payload),
			},
		}, nil
	})

	reconPrompt := mcp.NewPrompt(
		"recon_workflow",
		mcp.WithPromptDescription("Structured recon workflow for a target domain: enumerate scope, select a wordlist, scan, expand, and analyze."),
		mcp.WithArgument(
			"target_domain",
			mcp.ArgumentDescription("Target domain or base URL to assess, e.g. example.com or https://example.com"),
			mcp.RequiredArgument(),
		),
	)
	s.AddPrompt(reconPrompt, func(ctx context.Context, request mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		targetDomain := strings.TrimSpace(request.Params.Arguments["target_domain"])
		if targetDomain == "" {
			return nil, fmt.Errorf("target_domain is required")
		}
		return buildReconWorkflowPrompt(targetDomain), nil
	})

	bypassPrompt := mcp.NewPrompt(
		"403_bypass_workflow",
		mcp.WithPromptDescription("Structured workflow for blocked paths that return 403 or similar denial responses."),
		mcp.WithArgument(
			"blocked_path",
			mcp.ArgumentDescription("The blocked path or endpoint to investigate, e.g. /admin or /api/internal"),
			mcp.RequiredArgument(),
		),
		mcp.WithArgument(
			"target_domain",
			mcp.ArgumentDescription("Target domain or base URL containing the blocked path, e.g. example.com or https://example.com"),
		),
	)
	s.AddPrompt(bypassPrompt, func(ctx context.Context, request mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		blockedPath := strings.TrimSpace(request.Params.Arguments["blocked_path"])
		if blockedPath == "" {
			return nil, fmt.Errorf("blocked_path is required")
		}
		targetDomain := strings.TrimSpace(request.Params.Arguments["target_domain"])
		return build403BypassWorkflowPrompt(targetDomain, blockedPath), nil
	})

	apiPrompt := mcp.NewPrompt(
		"api_surface_mapping",
		mcp.WithPromptDescription("Structured workflow for mapping REST or JSON API surfaces."),
		mcp.WithArgument(
			"target_domain",
			mcp.ArgumentDescription("Target API host or base URL, e.g. api.example.com or https://api.example.com"),
			mcp.RequiredArgument(),
		),
		mcp.WithArgument(
			"api_hint",
			mcp.ArgumentDescription("Optional API hint such as REST, GraphQL, /api, /v1, or /v2"),
		),
	)
	s.AddPrompt(apiPrompt, func(ctx context.Context, request mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		targetDomain := strings.TrimSpace(request.Params.Arguments["target_domain"])
		if targetDomain == "" {
			return nil, fmt.Errorf("target_domain is required")
		}
		apiHint := strings.TrimSpace(request.Params.Arguments["api_hint"])
		return buildAPISurfaceMappingPrompt(targetDomain, apiHint), nil
	})

	statusTool := mcp.NewTool("dirfuzz_scan_status",
		mcp.WithDescription("Return a live status snapshot for an in-flight or completed DirFuzz scan identified by scan_id."),
		mcp.WithString("scan_id",
			mcp.Required(),
			mcp.Description("Scan identifier returned by dirfuzz_scan."),
		),
	)
	s.AddTool(statusTool, wrapToolHandler("dirfuzz_scan_status", rateLimitRule{Limit: cfg.defaultToolLimit, Window: cfg.rateLimitWindow}, limiter, auditLogger, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return handleScanStatus(ctx, req, registry)
	}))

	cancelTool := mcp.NewTool("dirfuzz_cancel",
		mcp.WithDescription("Cancel a running DirFuzz scan by scan_id."),
		mcp.WithString("scan_id",
			mcp.Required(),
			mcp.Description("Scan identifier returned by dirfuzz_scan."),
		),
	)
	s.AddTool(cancelTool, wrapToolHandler("dirfuzz_cancel", rateLimitRule{Limit: cfg.defaultToolLimit, Window: cfg.rateLimitWindow}, limiter, auditLogger, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return handleCancelScan(ctx, req, registry)
	}))

	listScopeTool := mcp.NewTool("dirfuzz_list_scope",
		mcp.WithDescription("Return the fully parsed current scope snapshot as structured JSON."),
	)
	s.AddTool(listScopeTool, wrapToolHandler("dirfuzz_list_scope", rateLimitRule{Limit: cfg.defaultToolLimit, Window: cfg.rateLimitWindow}, limiter, auditLogger, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return handleListScope(ctx, req, cfg)
	}))

	wafTool := mcp.NewTool("dirfuzz_waf_probe",
		mcp.WithDescription("Probe a discovered path with WAF evasion techniques and return the evasion scoreboard."),
		mcp.WithString("scan_id", mcp.Required(), mcp.Description("Scan identifier returned by dirfuzz_scan.")),
		mcp.WithString("path", mcp.Required(), mcp.Description("Discovered path or full URL to probe.")),
		mcp.WithString("method", mcp.Description("HTTP method to use for probing (default GET).")),
		mcp.WithArray("headers", mcp.Description("Optional extra headers as 'Key: Value' strings."), mcp.WithStringItems()),
	)
	s.AddTool(wafTool, wrapToolHandler("dirfuzz_waf_probe", rateLimitRule{Limit: cfg.defaultToolLimit, Window: cfg.rateLimitWindow}, limiter, auditLogger, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return handleWAFProbe(ctx, req, registry)
	}))

	paramTool := mcp.NewTool("dirfuzz_param_fuzz",
		mcp.WithDescription("Discover hidden GET/POST parameters on a discovered endpoint using the scan target as context."),
		mcp.WithString("scan_id", mcp.Required(), mcp.Description("Scan identifier returned by dirfuzz_scan.")),
		mcp.WithString("path", mcp.Required(), mcp.Description("Discovered endpoint path or full URL to fuzz.")),
		mcp.WithString("method", mcp.Description("HTTP method to use for the baseline request (default GET).")),
		mcp.WithArray("wordlist", mcp.Description("Optional custom parameter names to probe instead of the built-in list."), mcp.WithStringItems()),
		mcp.WithArray("headers", mcp.Description("Optional extra headers as 'Key: Value' strings."), mcp.WithStringItems()),
	)
	s.AddTool(paramTool, wrapToolHandler("dirfuzz_param_fuzz", rateLimitRule{Limit: cfg.defaultToolLimit, Window: cfg.rateLimitWindow}, limiter, auditLogger, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return handleParamFuzz(ctx, req, registry)
	}))

	authTool := mcp.NewTool("dirfuzz_auth_test",
		mcp.WithDescription("Replay discovered paths across multiple auth token sets to detect access-control mismatches."),
		mcp.WithString("scan_id", mcp.Required(), mcp.Description("Scan identifier returned by dirfuzz_scan.")),
		mcp.WithArray("paths", mcp.Required(), mcp.Description("Discovered paths or full URLs to test."), mcp.WithStringItems()),
		mcp.WithString("auth_matrix_json", mcp.Required(), mcp.Description("JSON object mapping auth roles to arrays of header strings.")),
		mcp.WithArray("headers", mcp.Description("Optional extra headers as 'Key: Value' strings."), mcp.WithStringItems()),
	)
	s.AddTool(authTool, wrapToolHandler("dirfuzz_auth_test", rateLimitRule{Limit: cfg.defaultToolLimit, Window: cfg.rateLimitWindow}, limiter, auditLogger, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return handleAuthTest(ctx, req, registry)
	}))

	scanTool := mcp.NewTool(toolName,
		mcp.WithDescription(
			"Run a DirFuzz directory-fuzzing scan against a target URL. "+
				"The target must be in the live H1 scope and bounty-eligible; "+
				"the server will block scans that fall outside the loaded scope files.",
		),
		mcp.WithString("target",
			mcp.Required(),
			mcp.Description("Full target URL to fuzz, e.g. https://api.example.com"),
		),
		mcp.WithString("wordlist",
			mcp.Required(),
			mcp.Description("Wordlist filename (without path) from the server's wordlist directory, e.g. common.txt"),
		),
		mcp.WithString("extensions",
			mcp.Description("Comma-separated extensions to append to every path, e.g. php,html,js (optional)"),
		),
		mcp.WithString("match_codes",
			mcp.Description("Comma-separated HTTP status codes to report, e.g. 200,301,403 (default: 200,204,301,302,401,403)"),
		),
		mcp.WithString("methods",
			mcp.Description("Comma-separated HTTP methods, e.g. GET,POST,PUT (optional)"),
		),
		mcp.WithString("body",
			mcp.Description("Request body for POST/PUT/PATCH; {PAYLOAD} is substituted (optional)"),
		),
		mcp.WithArray("headers",
			mcp.Description("Custom headers as 'Key: Value' strings (optional)"),
			mcp.WithStringItems(),
		),
		mcp.WithNumber("rps",
			mcp.Description("Global requests-per-second cap; 0 means unlimited (optional)"),
		),
		mcp.WithNumber("timeout_seconds",
			mcp.Description("Per-request timeout in seconds (optional, default 5)"),
		),
		mcp.WithNumber("max_duration_seconds",
			mcp.Description("Maximum scan runtime in seconds before cancellation (optional, default 60)"),
		),
	)

	s.AddTool(scanTool, wrapToolHandler(toolName, rateLimitRule{Limit: cfg.scanToolLimit, Window: cfg.rateLimitWindow}, limiter, auditLogger, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return handleScan(ctx, req, cfg, registry)
	}))

	analyzeTool := mcp.NewTool("dirfuzz_analyze",
		mcp.WithDescription("Analyze a DirFuzz JSONL results file or scan_id. Groups findings by severity, identifies high-value targets, and flags blocked paths worth bypassing."),
		mcp.WithString("results_file",
			mcp.Description("Path to the JSONL results file under DIRFUZZ_OUTPUT_DIR. Optional when scan_id is provided."),
		),
		mcp.WithString("scan_id",
			mcp.Description("Scan identifier returned by dirfuzz_scan. If provided, the server resolves scan-<id>.jsonl automatically."),
		),
		mcp.WithString("target", mcp.Description("The base URL that was scanned (for context).")),
	)
	s.AddTool(analyzeTool, wrapToolHandler("dirfuzz_analyze", rateLimitRule{Limit: cfg.defaultToolLimit, Window: cfg.rateLimitWindow}, limiter, auditLogger, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return handleAnalyze(ctx, req, cfg)
	}))

	buildTool := mcp.NewTool("dirfuzz_build_scan",
		mcp.WithDescription("Translate a natural language scan request into optimal DirFuzz parameters."),
		mcp.WithString("description", mcp.Required(), mcp.Description("Natural language description of the scan goal.")),
		mcp.WithString("target", mcp.Required(), mcp.Description("The target URL.")),
	)
	s.AddTool(buildTool, wrapToolHandler("dirfuzz_build_scan", rateLimitRule{Limit: cfg.defaultToolLimit, Window: cfg.rateLimitWindow}, limiter, auditLogger, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return handleBuildScan(ctx, req, cfg)
	}))

	expandTool := mcp.NewTool("dirfuzz_expand",
		mcp.WithDescription("Autonomously expand discovered endpoints with recursive sub-scans."),
		mcp.WithString("base_target", mcp.Required(), mcp.Description("The original base URL.")),
		mcp.WithString("hits_jsonl", mcp.Required(), mcp.Description("Path to JSONL results file.")),
		mcp.WithNumber("max_depth", mcp.Description("Maximum expansion depth (default 2, max 4).")),
		mcp.WithNumber("max_targets", mcp.Description("Maximum sub-paths to expand (default 10).")),
		mcp.WithString("wordlist", mcp.Description("Wordlist path for sub-scans.")),
	)
	s.AddTool(expandTool, wrapToolHandler("dirfuzz_expand", rateLimitRule{Limit: cfg.defaultToolLimit, Window: cfg.rateLimitWindow}, limiter, auditLogger, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return handleExpand(ctx, req, cfg)
	}))

	log.Printf("dirfuzz-mcp: starting (wordlist_dir=%s scope_dir=%s output_dir=%s audit_log=%s max_threads=%d max_results=%d max_concurrent_scans=%d scan_limit=%d/%s tool_limit=%d/%s)",
		cfg.wordlistDir, cfg.scopeDir, cfg.outputDir, cfg.auditLogPath, cfg.maxThreads, cfg.maxResults, cfg.maxConcurrentScans, cfg.scanToolLimit, cfg.rateLimitWindow, cfg.defaultToolLimit, cfg.rateLimitWindow)

	if err := server.ServeStdio(s); err != nil {
		log.Fatalf("dirfuzz-mcp: stdio server error: %v", err)
	}
}

// ── tool handler ─────────────────────────────────────────────────────────────

func handleScan(ctx context.Context, req mcp.CallToolRequest, cfg mcpConfig, registry *scanRegistry) (*mcp.CallToolResult, error) {
	// ── 1. Parse arguments ────────────────────────────────────────────────────
	// Use req.GetString (mcp-go v0.47.1) which safely handles type assertion
	// from the Arguments map and returns the default on any miss.

	target, err := requireStringArg(req, "target")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	wordlistName, err := requireStringArg(req, "wordlist")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// ── 2. Dynamic scope validation ───────────────────────────────────────────
	//
	// Reload scope files on every request so that additions/removals made by
	// H1-Scope-Watcher are picked up without restarting the MCP server.

	assets, warnings, err := scope.LoadDir(cfg.scopeDir)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to read scope directory: %v", err)), nil
	}

	for _, warning := range warnings {
		log.Printf("dirfuzz-mcp: %s", warning)
	}

	allowed, reason := scope.IsAllowed(target, assets)
	if !allowed {
		return mcp.NewToolResultError(
			fmt.Sprintf("Error: target blocked by scope validator: %s", reason),
		), nil
	}

	// ── 3. Resolve & sanitise wordlist path ───────────────────────────────────
	//
	// Reject any path-traversal attempt in the wordlist name before filepath.Join.
	// The AI must only be able to reach files inside DIRFUZZ_WORDLIST_DIR.

	resolvedWordlist, err := resolvePathInAllowedDir(cfg.wordlistDir, wordlistName)
	if err != nil {
		if errors.Is(err, errPathEscapesAllowedDir) {
			return mcp.NewToolResultError("wordlist path escapes the allowed directory"), nil
		}
		return mcp.NewToolResultError(fmt.Sprintf("wordlist %q not found in wordlist directory", wordlistName)), nil
	}

	// ── 4. Parse optional parameters ─────────────────────────────────────────

	matchCodesRaw := "200,204,301,302,401,403"
	if raw := strings.TrimSpace(req.GetString("match_codes", "")); raw != "" {
		matchCodesRaw = raw
	}
	matchCodes, err := parseMatchCodes(matchCodesRaw)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("invalid match_codes: %v", err)), nil
	}

	var extensions []string
	if raw := strings.TrimSpace(req.GetString("extensions", "")); raw != "" {
		extensions = parseExtensions(raw)
	}

	// ── 5. Run the scan ───────────────────────────────────────────────────────

	methods, err := parseMethods(req.GetString("methods", ""))
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("invalid methods: %v", err)), nil
	}
	headers, err := parseOptionalHeaderArgs(req)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("invalid headers: %v", err)), nil
	}

	opts := scanOptions{
		Methods:     methods,
		Body:        req.GetString("body", ""),
		Headers:     headers,
		RPS:         req.GetInt("rps", 0),
		Timeout:     secondsDuration(req.GetFloat("timeout_seconds", 0), engine.DefaultHTTPTimeout),
		MaxDuration: secondsDuration(req.GetFloat("max_duration_seconds", 0), engine.DefaultMaxScanDuration),
	}
	scanID := uuid.NewString()
	startedAt := time.Now().UTC()
	state := &scanState{
		scanID:    scanID,
		target:    target,
		startedAt: startedAt,
		running:   true,
	}
	activeIDs, err := registry.register(state, cfg.maxConcurrentScans)
	if err != nil {
		if len(activeIDs) == 0 {
			return mcp.NewToolResultError(fmt.Sprintf("scan limit reached (max %d). No active scan IDs available.", cfg.maxConcurrentScans)), nil
		}
		return mcp.NewToolResultError(fmt.Sprintf("scan limit reached (max %d). Active scan IDs: %s", cfg.maxConcurrentScans, strings.Join(activeIDs, ", "))), nil
	}
	defer func() {
		state.mu.Lock()
		if state.finishedAt.IsZero() {
			state.finishedAt = time.Now().UTC()
		}
		state.running = false
		state.mu.Unlock()
	}()

	scanCtx, scanCancel := context.WithCancel(ctx)
	state.attachCancel(scanCancel)
	defer scanCancel()

	results, err := runScan(scanCtx, target, resolvedWordlist, cfg.maxThreads, cfg.maxResults, matchCodes, extensions, opts, state)
	if err != nil {
		state.finish("", "", len(results) >= cfg.maxResults)
		return mcp.NewToolResultError(fmt.Sprintf("scan failed: %v", err)), nil
	}

	outputName := fmt.Sprintf("scan-%s.jsonl", scanID)
	outputPath := filepath.Join(cfg.outputDir, outputName)
	if err := writeScanJSONL(outputPath, results); err != nil {
		state.finish("", "", len(results) >= cfg.maxResults)
		return mcp.NewToolResultError(fmt.Sprintf("scan completed but failed to persist results: %v", err)), nil
	}
	state.finish(outputName, outputPath, len(results) >= cfg.maxResults)

	payload := buildScanOutput(target, scanID, startedAt, results, cfg.maxResults, outputName, warnings)
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("scan completed but failed to encode JSON: %v", err)), nil
	}
	return mcp.NewToolResultText(string(raw)), nil
}

// ── scan runner ───────────────────────────────────────────────────────────────

type scanOptions struct {
	Methods     []string
	Body        string
	Headers     map[string]string
	RPS         int
	Timeout     time.Duration
	MaxDuration time.Duration
}

func runScan(
	ctx context.Context,
	target, wordlistPath string,
	threads, maxResults int,
	matchCodes []int,
	extensions []string,
	opts scanOptions,
	state *scanState,
) ([]engine.Result, error) {
	eng := engine.NewEngine(threads, engine.DefaultBloomFilterSize, engine.DefaultBloomFilterFP)
	if state != nil {
		state.attachEngine(eng)
	}
	eng.ConfigureFilters(matchCodes, nil)

	for _, ext := range extensions {
		eng.AddExtension(ext)
	}
	for key, val := range opts.Headers {
		eng.AddHeader(key, val)
	}
	if opts.RPS > 0 {
		eng.SetRPS(opts.RPS)
	}
	eng.UpdateConfig(func(c *engine.Config) {
		c.Methods = append([]string(nil), opts.Methods...)
		c.RequestBody = opts.Body
		if opts.Timeout > 0 {
			c.Timeout = opts.Timeout
		}
	})

	if err := eng.SetTarget(target); err != nil {
		return nil, fmt.Errorf("invalid target: %w", err)
	}
	if opts.MaxDuration <= 0 {
		opts.MaxDuration = engine.DefaultMaxScanDuration
	}
	var (
		scanCtx context.Context
		cancel  context.CancelFunc
	)
	if opts.MaxDuration > 0 {
		scanCtx, cancel = context.WithTimeout(ctx, opts.MaxDuration)
	} else {
		scanCtx, cancel = context.WithCancel(ctx)
	}
	defer cancel()

	eng.Start()
	eng.KickoffScanner(wordlistPath, 0)

	go func() {
		eng.Wait()
		cancel() // signal context too so cap-check stops
		eng.Shutdown()
	}()

	// On context expiry (max_duration), cancel the engine.
	go func() {
		<-scanCtx.Done()
		eng.Shutdown()
	}()

	collected := make([]engine.Result, 0, 64)
	for res := range eng.Results {
		if res.IsAutoFilter {
			continue
		}
		collected = append(collected, res)
		if state != nil {
			state.addCollected(1)
		}
		if len(collected) >= maxResults {
			// Cap reached — shut the engine down and drain so workers don't leak.
			if state != nil {
				state.mu.Lock()
				state.capped = true
				state.mu.Unlock()
			}
			eng.Shutdown()
			for range eng.Results { //nolint:revive // intentional drain
			}
			break
		}
	}
	if err := scanCtx.Err(); err != nil && err != context.Canceled {
		return collected, err
	}

	return collected, nil
}

type scanOutput struct {
	Target        string           `json:"target"`
	ScanID        string           `json:"scan_id"`
	StartedAt     string           `json:"started_at"`
	DurationMS    int64            `json:"duration_ms"`
	TotalHits     int              `json:"total_hits"`
	Capped        bool             `json:"capped"`
	ResultsFile   string           `json:"results_file"`
	ScopeWarnings []string         `json:"scope_warnings,omitempty"`
	Results       []scanOutputItem `json:"results"`
}

type scanOutputItem struct {
	URL         string   `json:"url"`
	StatusCode  int      `json:"status_code"`
	Method      string   `json:"method"`
	SizeBytes   int      `json:"size_bytes"`
	ContentType string   `json:"content_type,omitempty"`
	Severity    string   `json:"severity"`
	Labels      []string `json:"labels,omitempty"`
}

func buildScanOutput(target, scanID string, startedAt time.Time, results []engine.Result, maxResults int, resultsFileName string, scopeWarnings []string) scanOutput {
	items := make([]scanOutputItem, 0, len(results))
	for _, r := range results {
		items = append(items, scanOutputItem{
			URL:         resultURL(r),
			StatusCode:  r.StatusCode,
			Method:      resultMethod(r),
			SizeBytes:   r.Size,
			ContentType: r.ContentType,
			Severity:    resultSeverity(r),
			Labels:      resultLabels(r),
		})
	}
	return scanOutput{
		Target:        target,
		ScanID:        scanID,
		StartedAt:     startedAt.Format(time.RFC3339Nano),
		DurationMS:    time.Since(startedAt).Milliseconds(),
		TotalHits:     len(items),
		Capped:        len(results) >= maxResults,
		ResultsFile:   resultsFileName,
		ScopeWarnings: append([]string(nil), scopeWarnings...),
		Results:       items,
	}
}

func writeScanJSONL(path string, results []engine.Result) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, r := range results {
		b, err := json.Marshal(r)
		if err != nil {
			return err
		}
		if _, err := w.Write(b); err != nil {
			return err
		}
		if err := w.WriteByte('\n'); err != nil {
			return err
		}
	}
	return w.Flush()
}

func resultURL(r engine.Result) string {
	if r.URL != "" {
		return r.URL
	}
	return r.Path
}

func resultMethod(r engine.Result) string {
	if r.Method != "" {
		return r.Method
	}
	return "GET"
}

func resultSeverity(r engine.Result) string {
	switch {
	case r.StatusCode == 200 && isCriticalResultPath(r.Path):
		return "critical"
	case r.StatusCode == 200 && isHighSeverityResultPath(r.Path):
		return "high"
	case r.StatusCode == 403 || r.StatusCode == 401 || r.StatusCode == 500:
		return "medium"
	default:
		return "info"
	}
}

func resultLabels(r engine.Result) []string {
	labels := make([]string, 0, 8)
	labels = append(labels, fmt.Sprintf("status_%d", r.StatusCode))
	if r.ContentType != "" {
		labels = append(labels, "content_type_"+sanitizeLabel(r.ContentType))
	}
	segments := pathSegments(r.Path)
	if len(segments) > 0 {
		if pathContainsAnySegment(segments, map[string]struct{}{
			"admin": {}, "panel": {}, "dashboard": {}, "management": {}, "console": {},
		}) {
			labels = append(labels, "surface_admin")
		}
		if pathContainsAnySegment(segments, map[string]struct{}{
			"api": {}, "v1": {}, "v2": {}, "v3": {}, "internal": {},
		}) {
			labels = append(labels, "surface_api")
		}
	}
	if r.Forbidden403Type != "" {
		labels = append(labels, "forbidden_"+sanitizeLabel(r.Forbidden403Type))
	}
	if r.IsEagleAlert {
		labels = append(labels, "eagle_alert")
	}
	if r.ContentDrift {
		labels = append(labels, "content_drift")
	}
	return labels
}

func sanitizeLabel(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return "unknown"
	}
	replacer := strings.NewReplacer(" ", "_", "/", "_", "\\", "_", ":", "_", ";", "_", ",", "_", ".", "_", "-", "_")
	return replacer.Replace(raw)
}

func isCriticalResultPath(rawPath string) bool {
	segments := pathSegments(rawPath)
	criticalSegments := map[string]struct{}{
		".git":          {},
		"backup":        {},
		".env":          {},
		"config":        {},
		"database":      {},
		"dump":          {},
		"phpinfo":       {},
		"server-status": {},
		"actuator":      {},
		".aws":          {},
		".ssh":          {},
	}
	return pathContainsAnySegment(segments, criticalSegments)
}

func isHighSeverityResultPath(rawPath string) bool {
	segments := pathSegments(rawPath)
	highSegments := map[string]struct{}{
		"admin":      {},
		"panel":      {},
		"dashboard":  {},
		"management": {},
		"console":    {},
	}
	return isHighSeverityPath(segments, highSegments)
}

type scanStatusOutput struct {
	ScanID             string                  `json:"scan_id"`
	Target             string                  `json:"target"`
	StartedAt          string                  `json:"started_at"`
	ElapsedMS          int64                   `json:"elapsed_ms"`
	RequestsDispatched int64                   `json:"requests_dispatched"`
	ResultsCollected   int64                   `json:"results_collected"`
	CurrentWorkerCount int64                   `json:"current_worker_count"`
	CurrentRPS         int64                   `json:"current_rps"`
	Running            bool                    `json:"running"`
	Canceled           bool                    `json:"canceled"`
	Capped             bool                    `json:"capped"`
	ResultsFile        string                  `json:"results_file,omitempty"`
	ResultsPath        string                  `json:"results_path,omitempty"`
	QueueDepth         int                     `json:"queue_depth"`
	WAFDetected        bool                    `json:"waf_detected,omitempty"`
	WAFVendorGuess     string                  `json:"waf_vendor_guess,omitempty"`
	WAFScoreboard      []evasionScoreboardJSON `json:"waf_evasion_scoreboard,omitempty"`
}

type evasionScoreboardJSON struct {
	Technique string  `json:"technique"`
	Attempts  int     `json:"attempts"`
	Bypasses  int     `json:"bypasses"`
	Rate      float64 `json:"rate"`
}

func convertEvasionSummary(rows []engine.EvasionScoreboardRow) []evasionScoreboardJSON {
	if len(rows) == 0 {
		return nil
	}
	out := make([]evasionScoreboardJSON, 0, len(rows))
	for _, row := range rows {
		out = append(out, evasionScoreboardJSON{
			Technique: row.Technique,
			Attempts:  row.Attempts,
			Bypasses:  row.Bypasses,
			Rate:      row.Rate,
		})
	}
	return out
}

func handleScanStatus(ctx context.Context, req mcp.CallToolRequest, registry *scanRegistry) (*mcp.CallToolResult, error) {
	scanID, err := requireStringArg(req, "scan_id")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	if scanID == "" {
		return mcp.NewToolResultError("scan_id is required"), nil
	}
	state, ok := registry.get(scanID)
	if !ok {
		return mcp.NewToolResultError(fmt.Sprintf("unknown scan_id %q", scanID)), nil
	}
	payload := state.snapshot()
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to encode scan status: %v", err)), nil
	}
	return mcp.NewToolResultText(string(raw)), nil
}

func handleCancelScan(ctx context.Context, req mcp.CallToolRequest, registry *scanRegistry) (*mcp.CallToolResult, error) {
	scanID, err := requireStringArg(req, "scan_id")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	if scanID == "" {
		return mcp.NewToolResultError("scan_id is required"), nil
	}
	state, ok := registry.get(scanID)
	if !ok {
		return mcp.NewToolResultError(fmt.Sprintf("unknown scan_id %q", scanID)), nil
	}
	if state.cancelRunning() {
		payload := map[string]any{
			"scan_id":  scanID,
			"canceled": true,
			"message":  "cancel signal sent",
		}
		raw, _ := json.MarshalIndent(payload, "", "  ")
		return mcp.NewToolResultText(string(raw)), nil
	}
	payload := map[string]any{
		"scan_id":  scanID,
		"canceled": false,
		"message":  "scan is not running",
	}
	raw, _ := json.MarshalIndent(payload, "", "  ")
	return mcp.NewToolResultText(string(raw)), nil
}

func handleListScope(ctx context.Context, req mcp.CallToolRequest, cfg mcpConfig) (*mcp.CallToolResult, error) {
	snapshot, err := loadScopeSnapshot(cfg.scopeDir)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to load scope snapshot: %v", err)), nil
	}
	raw, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to encode scope snapshot: %v", err)), nil
	}
	return mcp.NewToolResultText(string(raw)), nil
}

func requireStringArg(req mcp.CallToolRequest, key string) (string, error) {
	value, err := req.RequireString(key)
	if err != nil {
		return "", err
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("argument %q is required and must be a non-empty string", key)
	}
	return value, nil
}

func optionalStringArg(req mcp.CallToolRequest, key string) (string, error) {
	args := req.GetArguments()
	if args == nil {
		return "", nil
	}
	if _, ok := args[key]; !ok {
		return "", nil
	}
	return requireStringArg(req, key)
}

func optionalStringSliceArg(req mcp.CallToolRequest, key string) ([]string, error) {
	args := req.GetArguments()
	if args == nil {
		return nil, nil
	}
	if _, ok := args[key]; !ok {
		return nil, nil
	}
	values, err := req.RequireStringSlice(key)
	if err != nil {
		return nil, err
	}
	return values, nil
}

func parseOptionalHeaderArgs(req mcp.CallToolRequest) (map[string]string, error) {
	args := req.GetArguments()
	if args == nil {
		return nil, nil
	}
	if _, ok := args["headers"]; !ok {
		return nil, nil
	}
	rawHeaders, err := req.RequireStringSlice("headers")
	if err != nil {
		return nil, err
	}
	return parseHeaders(rawHeaders)
}

func sanitizeAuditArguments(raw any) any {
	switch v := raw.(type) {
	case nil:
		return nil
	case string:
		return redactBearerTokens(v)
	case []any:
		out := make([]any, 0, len(v))
		for _, item := range v {
			out = append(out, sanitizeAuditArguments(item))
		}
		return out
	case []string:
		out := make([]string, 0, len(v))
		for _, item := range v {
			out = append(out, redactBearerTokens(item))
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, value := range v {
			out[key] = sanitizeAuditArguments(value)
		}
		return out
	case map[string]string:
		out := make(map[string]string, len(v))
		for key, value := range v {
			out[key] = redactBearerTokens(value)
		}
		return out
	default:
		return v
	}
}

func redactBearerTokens(raw string) string {
	if raw == "" {
		return raw
	}
	return bearerTokenPattern.ReplaceAllString(raw, "${1}[REDACTED]")
}

func formatClaudeDesktopConfigStanza(commandPath, wordlistDir, scopeDir string) string {
	commandPath = strings.ReplaceAll(commandPath, `\`, `\\`)
	wordlistDir = strings.ReplaceAll(wordlistDir, `\`, `\\`)
	scopeDir = strings.ReplaceAll(scopeDir, `\`, `\\`)
	outputDir := "/absolute/path/to/DirFuzz/output"
	return fmt.Sprintf(`{
  "mcpServers": {
    "dirfuzz": {
      "command": "%s",
      "env": {
        "DIRFUZZ_WORDLIST_DIR": "%s",
        "DIRFUZZ_SCOPE_DIR": "%s",
        "DIRFUZZ_OUTPUT_DIR": "%s"
      }
    }
  }
}`, commandPath, wordlistDir, scopeDir, outputDir)
}

func handleWAFProbe(ctx context.Context, req mcp.CallToolRequest, registry *scanRegistry) (*mcp.CallToolResult, error) {
	scanID, err := requireStringArg(req, "scan_id")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	state, ok := registry.get(scanID)
	if !ok {
		return mcp.NewToolResultError(fmt.Sprintf("unknown scan_id %q", scanID)), nil
	}
	state.mu.RLock()
	eng := state.engine
	target := state.target
	state.mu.RUnlock()
	if eng == nil {
		return mcp.NewToolResultError("scan engine is unavailable"), nil
	}
	rawPath, err := requireStringArg(req, "path")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	method, err := optionalStringArg(req, "method")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("invalid method: %v", err)), nil
	}
	method = strings.ToUpper(method)
	if method == "" {
		method = "GET"
	}
	headers, err := parseOptionalHeaderArgs(req)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("invalid headers: %v", err)), nil
	}
	targetURL := resolveProbeTarget(target, rawPath)
	report, err := eng.ProbeWAF(ctx, targetURL, rawPath, method, headers, 0, "")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("waf probe failed: %v", err)), nil
	}
	payload := map[string]any{
		"scan_id": scanID,
		"report":  report,
	}
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to encode waf probe: %v", err)), nil
	}
	return mcp.NewToolResultText(string(raw)), nil
}

func handleParamFuzz(ctx context.Context, req mcp.CallToolRequest, registry *scanRegistry) (*mcp.CallToolResult, error) {
	scanID, err := requireStringArg(req, "scan_id")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	state, ok := registry.get(scanID)
	if !ok {
		return mcp.NewToolResultError(fmt.Sprintf("unknown scan_id %q", scanID)), nil
	}
	state.mu.RLock()
	eng := state.engine
	target := state.target
	state.mu.RUnlock()
	if eng == nil {
		return mcp.NewToolResultError("scan engine is unavailable"), nil
	}
	rawPath, err := requireStringArg(req, "path")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	method, err := optionalStringArg(req, "method")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("invalid method: %v", err)), nil
	}
	method = strings.ToUpper(method)
	if method == "" {
		method = "GET"
	}
	customWordlist, err := optionalStringSliceArg(req, "wordlist")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("invalid wordlist: %v", err)), nil
	}
	headers, err := parseOptionalHeaderArgs(req)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("invalid headers: %v", err)), nil
	}
	targetURL := resolveProbeTarget(target, rawPath)
	report := engine.ParamProbeReport{Target: targetURL, Path: rawPath, Method: method}
	if len(customWordlist) > 0 {
		hits, err := eng.FuzzParams(ctx, engine.ParamTask{URL: targetURL, Method: method}, customWordlist)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("param fuzz failed: %v", err)), nil
		}
		for _, hit := range hits {
			report.Findings = append(report.Findings, engine.ParamProbeFinding{
				Params:      append([]string(nil), hit.Params...),
				ProbeURL:    hit.ProbeURL,
				StatusCode:  hit.StatusCode,
				SizeBytes:   hit.Size,
				Words:       hit.Words,
				Lines:       hit.Lines,
				ContentType: hit.ContentType,
				DurationMS:  hit.Duration.Milliseconds(),
				Headers:     hit.Headers,
			})
		}
	} else {
		var err error
		report, err = eng.ProbeHiddenParams(ctx, targetURL, rawPath, method, headers)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("param fuzz failed: %v", err)), nil
		}
	}
	payload := map[string]any{
		"scan_id": scanID,
		"report":  report,
	}
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to encode param fuzz: %v", err)), nil
	}
	return mcp.NewToolResultText(string(raw)), nil
}

func handleAuthTest(ctx context.Context, req mcp.CallToolRequest, registry *scanRegistry) (*mcp.CallToolResult, error) {
	scanID, err := requireStringArg(req, "scan_id")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	state, ok := registry.get(scanID)
	if !ok {
		return mcp.NewToolResultError(fmt.Sprintf("unknown scan_id %q", scanID)), nil
	}
	state.mu.RLock()
	eng := state.engine
	target := state.target
	state.mu.RUnlock()
	if eng == nil {
		return mcp.NewToolResultError("scan engine is unavailable"), nil
	}
	rawPaths, err := req.RequireStringSlice("paths")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("invalid paths: %v", err)), nil
	}
	if len(rawPaths) == 0 {
		return mcp.NewToolResultError("paths is required"), nil
	}
	matrixRaw, err := requireStringArg(req, "auth_matrix_json")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	authMatrix := make(map[string][]string)
	if err := json.Unmarshal([]byte(matrixRaw), &authMatrix); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("invalid auth_matrix_json: %v", err)), nil
	}
	fullPaths := make([]string, 0, len(rawPaths))
	for _, rawPath := range rawPaths {
		rawPath = strings.TrimSpace(rawPath)
		if rawPath == "" {
			continue
		}
		fullPaths = append(fullPaths, resolveProbeTarget(target, rawPath))
	}
	findings, err := eng.TestAuthMatrix(ctx, fullPaths, authMatrix)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("auth matrix failed: %v", err)), nil
	}
	payload := map[string]any{
		"scan_id":  scanID,
		"findings": findings,
	}
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to encode auth test: %v", err)), nil
	}
	return mcp.NewToolResultText(string(raw)), nil
}

func resolveProbeTarget(baseTarget, rawPath string) string {
	rawPath = strings.TrimSpace(rawPath)
	if rawPath == "" {
		return baseTarget
	}
	if strings.HasPrefix(rawPath, "http://") || strings.HasPrefix(rawPath, "https://") {
		return rawPath
	}
	if baseTarget == "" {
		return rawPath
	}
	u, err := url.Parse(baseTarget)
	if err != nil {
		return strings.TrimRight(baseTarget, "/") + "/" + strings.TrimLeft(rawPath, "/")
	}
	if !strings.HasPrefix(rawPath, "/") {
		rawPath = "/" + rawPath
	}
	u.Path = strings.TrimRight(u.Path, "/") + rawPath
	if u.Path == "" {
		u.Path = rawPath
	}
	return u.String()
}

// ── parameter parsers ─────────────────────────────────────────────────────────

// parseMatchCodes parses a comma-separated status code list into []int.
func parseMatchCodes(raw string) ([]int, error) {
	parts := strings.Split(raw, ",")
	codes := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid code %q", p)
		}
		if n < 100 || n > 599 {
			return nil, fmt.Errorf("code %d out of range 100-599", n)
		}
		codes = append(codes, n)
	}
	if len(codes) == 0 {
		return nil, fmt.Errorf("at least one status code is required")
	}
	return codes, nil
}

// parseExtensions splits a comma-separated extension list, stripping leading
// dots and deduplicating entries.
func parseExtensions(raw string) []string {
	parts := strings.Split(raw, ",")
	exts := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		ext := strings.TrimPrefix(strings.TrimSpace(p), ".")
		if ext == "" {
			continue
		}
		if _, exists := seen[ext]; exists {
			continue
		}
		seen[ext] = struct{}{}
		exts = append(exts, ext)
	}
	return exts
}

func parseMethods(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	methods := make([]string, 0, len(parts))
	for _, p := range parts {
		method := strings.ToUpper(strings.TrimSpace(p))
		if method == "" {
			continue
		}
		switch method {
		case "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH":
			methods = append(methods, method)
		default:
			return nil, fmt.Errorf("unsupported method %q", method)
		}
	}
	return methods, nil
}

func parseHeaders(raw []string) (map[string]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	headers := make(map[string]string, len(raw))
	for _, h := range raw {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
			return nil, fmt.Errorf("header %q must be 'Key: Value'", h)
		}
		headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
	return headers, nil
}

var errPathEscapesAllowedDir = errors.New("path escapes allowed directory")

func resolvePathInAllowedDir(allowedDir, requestedPath string) (string, error) {
	joinedPath := filepath.Join(allowedDir, requestedPath)
	absPath, err := filepath.Abs(joinedPath)
	if err != nil {
		return "", err
	}
	absAllowedDir, err := filepath.Abs(allowedDir)
	if err != nil {
		return "", err
	}

	// Evaluate symlinks so a symlink inside allowedDir pointing outside is caught.
	resolvedPath, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		return "", err
	}
	resolvedAllowedDir, err := filepath.EvalSymlinks(absAllowedDir)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(resolvedPath, resolvedAllowedDir+string(filepath.Separator)) {
		return "", errPathEscapesAllowedDir
	}
	return resolvedPath, nil
}

func secondsDuration(seconds float64, fallback time.Duration) time.Duration {
	if seconds <= 0 {
		return fallback
	}
	return time.Duration(seconds * float64(time.Second))
}

func pathSegments(rawPath string) []string {
	rawPath = strings.TrimSpace(rawPath)
	if rawPath == "" {
		return nil
	}

	if parsed, err := url.Parse(rawPath); err == nil && parsed.Path != "" {
		rawPath = parsed.Path
	}
	rawPath = strings.Trim(rawPath, "/")
	if rawPath == "" {
		return nil
	}

	parts := strings.Split(strings.ToLower(rawPath), "/")
	segments := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			segments = append(segments, part)
		}
	}
	return segments
}

func pathContainsAnySegment(segments []string, keywords map[string]struct{}) bool {
	for _, segment := range segments {
		if _, ok := keywords[segment]; ok {
			return true
		}
	}
	return false
}

func isHighSeverityPath(segments []string, highSegments map[string]struct{}) bool {
	if pathContainsAnySegment(segments, highSegments) {
		return true
	}
	for i := 0; i < len(segments)-1; i++ {
		if segments[i] == "api" && segments[i+1] == "internal" {
			return true
		}
	}
	return false
}

// ── MCP Tool: dirfuzz_analyze ─────────────────────────────────────────────────

func handleAnalyze(ctx context.Context, req mcp.CallToolRequest, cfg mcpConfig) (*mcp.CallToolResult, error) {
	resultsFile, resultsErr := optionalStringArg(req, "results_file")
	if resultsErr != nil {
		return mcp.NewToolResultError(fmt.Sprintf("invalid results_file: %v", resultsErr)), nil
	}
	scanID, scanErr := optionalStringArg(req, "scan_id")
	if scanErr != nil {
		return mcp.NewToolResultError(fmt.Sprintf("invalid scan_id: %v", scanErr)), nil
	}
	target, targetErr := optionalStringArg(req, "target")
	if targetErr != nil {
		return mcp.NewToolResultError(fmt.Sprintf("invalid target: %v", targetErr)), nil
	}

	if resultsFile == "" && scanID == "" {
		return mcp.NewToolResultError("either results_file or scan_id is required"), nil
	}
	if resultsFile == "" && scanID != "" {
		resultsFile = fmt.Sprintf("scan-%s.jsonl", scanID)
	}

	resolvedResultsFile, err := resolvePathInAllowedDir(cfg.outputDir, resultsFile)
	if err != nil {
		if errors.Is(err, errPathEscapesAllowedDir) {
			return mcp.NewToolResultError("results_file path escapes DIRFUZZ_OUTPUT_DIR"), nil
		}
		return mcp.NewToolResultError("results_file not found in DIRFUZZ_OUTPUT_DIR"), nil
	}

	f, err := os.Open(resolvedResultsFile)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("error opening results file: %v", err)), nil
	}
	defer f.Close()

	var findings analysisFindings
	total := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var r engine.Result
		if err := json.Unmarshal(line, &r); err != nil {
			continue
		}
		total++
		finding := resultFindingFromEngine(r)
		switch finding.Severity {
		case "critical":
			findings.Critical = append(findings.Critical, finding)
		case "high":
			findings.High = append(findings.High, finding)
		case "medium":
			findings.Medium = append(findings.Medium, finding)
		default:
			findings.Info = append(findings.Info, finding)
		}
	}
	if err := scanner.Err(); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("error reading results file: %v", err)), nil
	}

	payload := analysisOutput{
		Target:               target,
		ScanID:               scanID,
		ResultsFile:          resultsFile,
		TotalHits:            total,
		Findings:             findings,
		RecommendedNextSteps: buildAnalysisNextSteps(findings),
	}
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("analysis failed to encode JSON: %v", err)), nil
	}
	return mcp.NewToolResultText(string(raw)), nil
}

type analysisOutput struct {
	Target               string           `json:"target"`
	ScanID               string           `json:"scan_id,omitempty"`
	ResultsFile          string           `json:"results_file"`
	TotalHits            int              `json:"total_hits"`
	Findings             analysisFindings `json:"findings"`
	RecommendedNextSteps []string         `json:"recommended_next_steps"`
}

type analysisFindings struct {
	Critical []analysisFinding `json:"critical"`
	High     []analysisFinding `json:"high"`
	Medium   []analysisFinding `json:"medium"`
	Info     []analysisFinding `json:"info"`
}

type analysisFinding struct {
	URL              string   `json:"url"`
	StatusCode       int      `json:"status_code"`
	Method           string   `json:"method"`
	SizeBytes        int      `json:"size_bytes"`
	ContentType      string   `json:"content_type,omitempty"`
	Forbidden403Type string   `json:"forbidden_403_type,omitempty"`
	Severity         string   `json:"severity"`
	Labels           []string `json:"labels,omitempty"`
}

func resultFindingFromEngine(r engine.Result) analysisFinding {
	return analysisFinding{
		URL:              resultURL(r),
		StatusCode:       r.StatusCode,
		Method:           resultMethod(r),
		SizeBytes:        r.Size,
		ContentType:      r.ContentType,
		Forbidden403Type: r.Forbidden403Type,
		Severity:         resultSeverity(r),
		Labels:           resultLabels(r),
	}
}

func buildAnalysisNextSteps(findings analysisFindings) []string {
	steps := make([]string, 0, 4)
	if len(findings.Critical) > 0 {
		steps = append(steps, fmt.Sprintf("Investigate %d critical findings immediately.", len(findings.Critical)))
	}
	if len(findings.High) > 0 {
		steps = append(steps, fmt.Sprintf("Review %d high-severity paths for authentication, admin, or panel exposure.", len(findings.High)))
	}
	if len(findings.Medium) > 0 {
		steps = append(steps, fmt.Sprintf("Run focused bypass attempts on %d blocked or erroring paths.", len(findings.Medium)))
	}
	if len(findings.Info) > 0 {
		steps = append(steps, fmt.Sprintf("Use %d informational hits to guide the next expansion pass.", len(findings.Info)))
	}
	if len(steps) == 0 {
		steps = append(steps, "No findings were classified; consider a narrower wordlist or a different target path surface.")
	}
	return steps
}

// ── MCP Tool: dirfuzz_build_scan ──────────────────────────────────────────────

func handleBuildScan(ctx context.Context, req mcp.CallToolRequest, cfg mcpConfig) (*mcp.CallToolResult, error) {
	desc, err := requireStringArg(req, "description")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	target, err := requireStringArg(req, "target")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	descLower := strings.ToLower(desc)

	wordlist := "common.txt"
	extensions := make([]string, 0, 8)
	matchCodes := "200,204,301,302,401,403"
	threads := 20
	recursive := false
	mutate := false
	smartAPI := false
	var reasoning []string

	// Framework → wordlist + extensions
	switch {
	case contains(descLower, "laravel", "php"):
		wordlist = bestWordlist(cfg.wordlistDir, []string{"php-common.txt", "common.txt"})
		extensions = append(extensions, "php", "env", "blade.php")
		reasoning = append(reasoning, "Detected Laravel/PHP target.")
	case contains(descLower, "django", "python", "flask"):
		wordlist = bestWordlist(cfg.wordlistDir, []string{"common.txt"})
		extensions = append(extensions, "py", "pyc", "cfg")
		reasoning = append(reasoning, "Detected Python/Django/Flask target.")
	case contains(descLower, "rails", "ruby"):
		wordlist = bestWordlist(cfg.wordlistDir, []string{"common.txt"})
		extensions = append(extensions, "rb", "erb")
		reasoning = append(reasoning, "Detected Rails/Ruby target.")
	case contains(descLower, "node", "express", "javascript"):
		wordlist = bestWordlist(cfg.wordlistDir, []string{"common.txt"})
		extensions = append(extensions, "js", "json", "env", "ts")
		reasoning = append(reasoning, "Detected Node.js/Express target.")
	case contains(descLower, "spring", "java", "tomcat"):
		wordlist = bestWordlist(cfg.wordlistDir, []string{"common.txt"})
		extensions = append(extensions, "java", "class", "war", "jsp")
		reasoning = append(reasoning, "Detected Java/Spring/Tomcat target.")
	case contains(descLower, "wordpress", "wp"):
		wordlist = bestWordlist(cfg.wordlistDir, []string{"wordpress.txt", "common.txt"})
		extensions = append(extensions, "php")
		reasoning = append(reasoning, "Detected WordPress target.")
	case contains(descLower, "api", "rest", "graphql"):
		wordlist = bestWordlist(cfg.wordlistDir, []string{"api-endpoints.txt", "common.txt"})
		smartAPI = true
		reasoning = append(reasoning, "API/REST/GraphQL target. Enabled smart_api mode.")
	}

	// Goal keywords
	if contains(descLower, "admin", "panel", "dashboard") {
		matchCodes = "200,204,301,302,403"
		reasoning = append(reasoning, "Admin panel search — including 403 in match codes.")
	}
	if contains(descLower, "backup", "git", "config", "env") {
		extensions = append(extensions, "bak", "old", "git", "env", "config", "sql", "zip")
		mutate = true
		reasoning = append(reasoning, "Looking for backup/config files — enabled mutation.")
	}
	if contains(descLower, "recursive", "deep", "all") {
		recursive = true
		reasoning = append(reasoning, "Deep scan requested — enabled recursive mode.")
	}

	wordlistPath := filepath.Join(cfg.wordlistDir, wordlist)

	result := map[string]interface{}{
		"recommended_params": map[string]interface{}{
			"target":      target,
			"wordlist":    wordlistPath,
			"extensions":  strings.Join(extensions, ","),
			"threads":     threads,
			"match_codes": matchCodes,
			"recursive":   recursive,
			"mutate":      mutate,
			"smart_api":   smartAPI,
		},
		"reasoning": strings.Join(reasoning, " "),
	}

	out, _ := json.Marshal(result)
	return mcp.NewToolResultText(string(out)), nil
}

func buildReconWorkflowPrompt(targetDomain string) *mcp.GetPromptResult {
	return mcp.NewGetPromptResult(
		"Recon workflow",
		[]mcp.PromptMessage{
			mcp.NewPromptMessage(
				mcp.RoleUser,
				mcp.NewTextContent(formatWorkflowPrompt(
					"Recon Workflow",
					"Target domain: "+targetDomain,
					[]string{
						"Enumerate scope first using `dirfuzz://scope` so every scan stays bounded by the live allowlist.",
						"Inspect `dirfuzz://wordlists` and choose a wordlist that matches the target surface area, such as `common.txt`, `api-endpoints.txt`, or a framework-specific list if present.",
						"Run `dirfuzz_build_scan` when you want the server to turn the target description into a concrete scan plan.",
						"Execute the initial scan with `dirfuzz_scan` using the selected wordlist and the narrowest useful status-code filter.",
						"Feed notable hits into `dirfuzz_expand` to recursively probe high-value paths.",
						"Finish with `dirfuzz_analyze` to cluster findings and identify the next best follow-up.",
					},
					[]string{
						"Start with the resources before any scan tool call so the model has live context about scope and dictionary coverage.",
						"Prefer a small initial scan over a broad one; expansion is more efficient after you have evidence of interesting paths.",
						"Use the analyzer last so the output is shaped by the actual hits rather than assumptions.",
					},
				)),
			),
		},
	)
}

func build403BypassWorkflowPrompt(targetDomain, blockedPath string) *mcp.GetPromptResult {
	contextLine := "Blocked path: " + blockedPath
	if targetDomain != "" {
		contextLine += "\nTarget domain: " + targetDomain
	}
	return mcp.NewGetPromptResult(
		"403 bypass workflow",
		[]mcp.PromptMessage{
			mcp.NewPromptMessage(
				mcp.RoleUser,
				mcp.NewTextContent(formatWorkflowPrompt(
					"403 Bypass Workflow",
					contextLine,
					[]string{
						"Confirm the blocked path is in scope by checking `dirfuzz://scope` before spending effort on retries.",
						"Use `dirfuzz://wordlists` to pick a focused list that emphasizes the blocked area instead of a large generic corpus.",
						"Build a bypass-oriented scan plan with `dirfuzz_build_scan`, then override the generated parameters only when the blocked route requires a tighter or broader match-code set.",
						"Re-run the scan against the exact blocked path and then call `dirfuzz_expand` on any nearby positive responses.",
						"Use `dirfuzz_analyze` to separate true blocked-path candidates from incidental noise and to decide whether follow-up probing is worthwhile.",
					},
					[]string{
						"Treat the 403 as a signal to refine the request shape, not as a reason to expand indiscriminately.",
						"Prefer targeted retries that keep the same scope boundary and only vary the minimum number of request dimensions needed for diagnosis.",
						"Analyze before widening the search again so you can tell whether the block is structural or path-specific.",
					},
				)),
			),
		},
	)
}

func buildAPISurfaceMappingPrompt(targetDomain, apiHint string) *mcp.GetPromptResult {
	contextLine := "Target API: " + targetDomain
	if apiHint != "" {
		contextLine += "\nAPI hint: " + apiHint
	}
	return mcp.NewGetPromptResult(
		"API surface mapping",
		[]mcp.PromptMessage{
			mcp.NewPromptMessage(
				mcp.RoleUser,
				mcp.NewTextContent(formatWorkflowPrompt(
					"API Surface Mapping",
					contextLine,
					[]string{
						"Check `dirfuzz://scope` first so API discovery is anchored to the current allowlist.",
						"Review `dirfuzz://wordlists` and prefer API-focused or endpoint-heavy lists if they exist; otherwise fall back to `common.txt`.",
						"Start with `dirfuzz_build_scan` so the server can translate the API description into scan parameters that fit the target.",
						"Run a first pass against obvious API prefixes such as `/api`, `/v1`, `/v2`, or other versioned roots that match the target's naming style.",
						"Expand high-value hits with `dirfuzz_expand`, then map the response patterns and content types with `dirfuzz_analyze`.",
					},
					[]string{
						"APIs benefit from version-aware discovery, so start narrow and let expansion reveal the rest of the surface.",
						"Response codes and content types are usually more informative than raw hit counts for API targets.",
						"Keep the workflow explicit so the host application can show each stage to the user before the agent proceeds.",
					},
				)),
			),
		},
	)
}

func formatWorkflowPrompt(title, contextLine string, steps []string, rationale []string) string {
	var sb strings.Builder
	sb.WriteString("## ")
	sb.WriteString(title)
	sb.WriteString("\n\n")
	sb.WriteString("### Context\n")
	sb.WriteString(contextLine)
	sb.WriteString("\n\n")
	sb.WriteString("### Recommended Steps\n")
	for i, step := range steps {
		fmt.Fprintf(&sb, "%d. %s\n", i+1, step)
	}
	sb.WriteString("\n### Tool Call Recommendations\n")
	sb.WriteString("- Read `dirfuzz://scope` before any scan.\n")
	sb.WriteString("- Read `dirfuzz://wordlists` before selecting a wordlist.\n")
	sb.WriteString("- Use `dirfuzz_build_scan` to turn the target into concrete scan parameters.\n")
	sb.WriteString("- Use `dirfuzz_scan` for the initial pass.\n")
	sb.WriteString("- Use `dirfuzz_expand` on promising hits.\n")
	sb.WriteString("- Use `dirfuzz_analyze` to summarize the results.\n")
	sb.WriteString("\n### Rationale\n")
	for _, item := range rationale {
		sb.WriteString("- ")
		sb.WriteString(item)
		sb.WriteString("\n")
	}
	return sb.String()
}

type wordlistInventory struct {
	GeneratedAt string            `json:"generated_at"`
	Directory   string            `json:"directory"`
	TotalFiles  int               `json:"total_files"`
	Wordlists   []wordlistSummary `json:"wordlists"`
}

type wordlistSummary struct {
	Name        string `json:"name"`
	File        string `json:"file"`
	LineCount   int    `json:"line_count"`
	Description string `json:"description"`
}

func loadWordlistInventory(dir string) (wordlistInventory, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return wordlistInventory{}, fmt.Errorf("wordlist inventory: list %q: %w", dir, err)
	}

	summaries := make([]wordlistSummary, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".txt") {
			continue
		}
		fullPath := filepath.Join(dir, entry.Name())
		lineCount, err := countLines(fullPath)
		if err != nil {
			return wordlistInventory{}, fmt.Errorf("wordlist inventory: count %q: %w", fullPath, err)
		}
		summaries = append(summaries, wordlistSummary{
			Name:        strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name())),
			File:        entry.Name(),
			LineCount:   lineCount,
			Description: describeWordlist(entry.Name()),
		})
	}

	sort.SliceStable(summaries, func(i, j int) bool {
		return strings.ToLower(summaries[i].File) < strings.ToLower(summaries[j].File)
	})

	return wordlistInventory{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Directory:   dir,
		TotalFiles:  len(summaries),
		Wordlists:   summaries,
	}, nil
}

func describeWordlist(name string) string {
	base := strings.ToLower(strings.TrimSuffix(name, filepath.Ext(name)))
	switch base {
	case "common":
		return "General-purpose path fragments for broad scans."
	case "actions":
		return "Action-oriented route fragments and verbs."
	case "big":
		return "Large exhaustive corpus for deeper coverage."
	case "sample":
		return "Small sample set for quick smoke tests."
	case "api-endpoints":
		return "API route fragments and endpoint names."
	case "wordpress":
		return "WordPress-specific paths, files, and endpoints."
	default:
		return "Wordlist for " + humanizeWordlistName(base) + "."
	}
}

func humanizeWordlistName(raw string) string {
	raw = strings.ReplaceAll(raw, "_", " ")
	raw = strings.ReplaceAll(raw, "-", " ")
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "general path fragments"
	}
	return raw
}

func countLines(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		count++
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return count, nil
}

type scopeSnapshot struct {
	GeneratedAt string          `json:"generated_at"`
	Directory   string          `json:"directory"`
	TotalFiles  int             `json:"total_files"`
	TotalAssets int             `json:"total_assets"`
	Warnings    []string        `json:"warnings,omitempty"`
	Files       []scopeFileView `json:"files"`
}

type scopeFileView struct {
	File              string        `json:"file"`
	AssetCount        int           `json:"asset_count"`
	BountyEligible    int           `json:"bounty_eligible"`
	URLAssets         int           `json:"url_assets"`
	WildcardAssets    int           `json:"wildcard_assets"`
	CIDRAssets        int           `json:"cidr_assets"`
	IPAddressAssets   int           `json:"ip_address_assets"`
	SourceCodeAssets  int           `json:"source_code_assets"`
	ExecutableAssets  int           `json:"executable_assets"`
	UnsupportedAssets int           `json:"unsupported_assets"`
	Assets            []scope.Asset `json:"assets"`
}

func loadScopeSnapshot(dir string) (scopeSnapshot, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return scopeSnapshot{}, fmt.Errorf("scope snapshot: list %q: %w", dir, err)
	}

	files := make([]scopeFileView, 0, len(entries))
	warnings := make([]string, 0)
	totalAssets := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
			continue
		}
		fullPath := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(fullPath)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("scope snapshot: skipping %s (read error): %v", fullPath, err))
			continue
		}
		var assets []scope.Asset
		if err := json.Unmarshal(data, &assets); err != nil {
			warnings = append(warnings, fmt.Sprintf("scope snapshot: skipping %s (parse error): %v", fullPath, err))
			continue
		}

		view := scopeFileView{
			File:   entry.Name(),
			Assets: assets,
		}
		for _, asset := range assets {
			view.AssetCount++
			if asset.EligibleForBounty {
				view.BountyEligible++
			}
			switch strings.ToUpper(strings.TrimSpace(asset.AssetType)) {
			case "URL":
				view.URLAssets++
			case "WILDCARD":
				view.WildcardAssets++
			case "CIDR":
				view.CIDRAssets++
			case "IP_ADDRESS":
				view.IPAddressAssets++
			case "SOURCE_CODE":
				view.SourceCodeAssets++
			case "EXECUTABLE":
				view.ExecutableAssets++
			default:
				view.UnsupportedAssets++
			}
		}
		totalAssets += view.AssetCount
		files = append(files, view)
	}

	sort.SliceStable(files, func(i, j int) bool {
		return strings.ToLower(files[i].File) < strings.ToLower(files[j].File)
	})

	return scopeSnapshot{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Directory:   dir,
		TotalFiles:  len(files),
		TotalAssets: totalAssets,
		Warnings:    warnings,
		Files:       files,
	}, nil
}

func bestWordlist(dir string, candidates []string) string {
	for _, c := range candidates {
		if _, err := os.Stat(filepath.Join(dir, c)); err == nil {
			return c
		}
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".txt") {
			return e.Name()
		}
	}
	return "common.txt"
}

func contains(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// ── MCP Tool: dirfuzz_expand ──────────────────────────────────────────────────

func handleExpand(ctx context.Context, req mcp.CallToolRequest, cfg mcpConfig) (*mcp.CallToolResult, error) {
	baseTarget, err := requireStringArg(req, "base_target")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	hitsJSONL, err := requireStringArg(req, "hits_jsonl")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	wordlistArg, err := optionalStringArg(req, "wordlist")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("invalid wordlist: %v", err)), nil
	}
	maxDepth := 2
	maxTargets := 10

	if v := req.GetFloat("max_depth", 0); v > 0 {
		maxDepth = int(v)
	}
	if maxDepth > 4 {
		maxDepth = 4
	}
	if v := req.GetFloat("max_targets", 0); v > 0 {
		maxTargets = int(v)
	}
	if maxTargets > 20 {
		maxTargets = 20
	}

	resolvedHits, err := resolvePathInAllowedDir(cfg.outputDir, hitsJSONL)
	if err != nil {
		if errors.Is(err, errPathEscapesAllowedDir) {
			return mcp.NewToolResultError("hits_jsonl path escapes DIRFUZZ_OUTPUT_DIR"), nil
		}
		return mcp.NewToolResultError("hits_jsonl not found in DIRFUZZ_OUTPUT_DIR"), nil
	}
	f, err := os.Open(resolvedHits)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("error: %v", err)), nil
	}
	defer f.Close()

	type candidate struct {
		result engine.Result
		score  int
	}

	var candidates []candidate
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var r engine.Result
		if err := json.Unmarshal(scanner.Bytes(), &r); err != nil {
			continue
		}
		if r.StatusCode != 200 && r.StatusCode != 301 && r.StatusCode != 302 {
			continue
		}
		ext := filepath.Ext(r.Path)
		if ext != "" && ext != "/" {
			continue
		}
		score := 0
		for _, kw := range []string{"/api/", "/v1/", "/v2/", "/v3/", "/admin/", "/internal/"} {
			if strings.Contains(r.Path, kw) {
				score += 10
			}
		}
		if r.StatusCode == 200 {
			score += 5
		}
		if r.Size > 1000 {
			score += 3
		}
		slashCount := strings.Count(r.Path, "/")
		if slashCount > 4 {
			score -= 5
		}
		candidates = append(candidates, candidate{result: r, score: score})
	}
	if err := scanner.Err(); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("error reading hits file: %v", err)), nil
	}

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].score > candidates[j].score
	})
	if len(candidates) > maxTargets {
		candidates = candidates[:maxTargets]
	}

	wlName := strings.TrimSpace(wordlistArg)
	if wlName == "" {
		wlName = bestWordlist(cfg.wordlistDir, []string{"common.txt"})
	}
	wl, err := resolvePathInAllowedDir(cfg.wordlistDir, wlName)
	if err != nil {
		if errors.Is(err, errPathEscapesAllowedDir) {
			return mcp.NewToolResultError("wordlist path escapes DIRFUZZ_WORDLIST_DIR"), nil
		}
		return mcp.NewToolResultError("wordlist not found in DIRFUZZ_WORDLIST_DIR"), nil
	}

	expansions := make([]expansionOutputItem, 0, len(candidates))
	for _, c := range candidates {
		subTarget := strings.TrimRight(baseTarget, "/") + c.result.Path
		subResults, err := func() ([]engine.Result, error) {
			subCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()

			eng := engine.NewEngine(cfg.maxThreads, 1_000_000, 0.001)
			defer eng.Shutdown()
			eng.Config.Lock()
			eng.Config.MaxWorkers = cfg.maxThreads
			eng.Config.MatchCodes = map[int]bool{200: true, 301: true, 302: true, 403: true}
			eng.Config.MaxDepth = maxDepth
			eng.Config.Timeout = 5 * time.Second
			eng.Config.Unlock()

			if err := eng.SetTarget(subTarget); err != nil {
				return nil, fmt.Errorf("invalid expansion target %q: %w", subTarget, err)
			}

			eng.Start()
			eng.KickoffScanner(wl, 0)

			go func() {
				eng.Wait()
				cancel()
				eng.Shutdown()
			}()
			go func() {
				<-subCtx.Done()
				eng.Shutdown()
			}()

			subResults := make([]engine.Result, 0, 16)
			done := make(chan struct{})
			go func() {
				defer close(done)
				for r := range eng.Results {
					if len(subResults) >= 50 {
						continue
					}
					subResults = append(subResults, r)
				}
			}()
			<-done

			if err := subCtx.Err(); err != nil && err != context.Canceled && err != context.DeadlineExceeded {
				return subResults, err
			}
			return subResults, nil
		}()
		item := expansionOutputItem{
			SourcePath:  c.result.Path,
			Target:      subTarget,
			Score:       c.score,
			Wordlist:    wlName,
			SubResults:  make([]scanOutputItem, 0, len(subResults)),
			ResultCount: len(subResults),
		}
		if err != nil {
			item.Error = err.Error()
			expansions = append(expansions, item)
			continue
		}
		for _, sr := range subResults {
			item.SubResults = append(item.SubResults, scanOutputItem{
				URL:         resultURL(sr),
				StatusCode:  sr.StatusCode,
				Method:      resultMethod(sr),
				SizeBytes:   sr.Size,
				ContentType: sr.ContentType,
				Severity:    resultSeverity(sr),
				Labels:      resultLabels(sr),
			})
		}
		expansions = append(expansions, item)
	}

	payload := expansionOutput{
		BaseTarget: baseTarget,
		HitsJSONL:  hitsJSONL,
		Wordlist:   wlName,
		MaxDepth:   maxDepth,
		MaxTargets: maxTargets,
		Expansions: expansions,
	}
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("expansion failed to encode JSON: %v", err)), nil
	}
	return mcp.NewToolResultText(string(raw)), nil
}

type expansionOutput struct {
	BaseTarget string                `json:"base_target"`
	HitsJSONL  string                `json:"hits_jsonl"`
	Wordlist   string                `json:"wordlist"`
	MaxDepth   int                   `json:"max_depth"`
	MaxTargets int                   `json:"max_targets"`
	Expansions []expansionOutputItem `json:"expansions"`
}

type expansionOutputItem struct {
	SourcePath  string           `json:"source_path"`
	Target      string           `json:"target"`
	Score       int              `json:"score"`
	Wordlist    string           `json:"wordlist"`
	ResultCount int              `json:"result_count"`
	Error       string           `json:"error,omitempty"`
	SubResults  []scanOutputItem `json:"sub_results,omitempty"`
}
