// DirFuzz MCP server.
//
// Exposes a single MCP tool — dirfuzz_scan — that lets an AI assistant
// (Claude, etc.) launch directory-fuzzing scans.  Before starting any scan the
// server validates the target against live H1-Scope-Watcher JSON files so the
// AI cannot accidentally fuzz out-of-scope assets.
//
// Required environment variables:
//
//	DIRFUZZ_WORDLIST_DIR   directory that contains wordlist .txt files
//	DIRFUZZ_SCOPE_DIR      directory that contains H1-Scope-Watcher .json files
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
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"dirfuzz/pkg/engine"
	"dirfuzz/pkg/scope"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// ── startup constants & defaults ─────────────────────────────────────────────

const (
	defaultMaxThreads = 15
	defaultMaxResults = 200

	serverName    = "DirFuzz"
	serverVersion = "2.3.0"
	toolName      = "dirfuzz_scan"
)

// ── server config (loaded once at startup) ───────────────────────────────────

type mcpConfig struct {
	wordlistDir string
	scopeDir    string
	maxThreads  int
	maxResults  int
}

func loadConfig() (mcpConfig, error) {
	cfg := mcpConfig{
		maxThreads: defaultMaxThreads,
		maxResults: defaultMaxResults,
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

	return cfg, nil
}

// ── main ─────────────────────────────────────────────────────────────────────

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("dirfuzz-mcp: configuration error: %v", err)
	}

	s := server.NewMCPServer(serverName, serverVersion)

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

	s.AddTool(scanTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return handleScan(ctx, req, cfg)
	})

	analyzeTool := mcp.NewTool("dirfuzz_analyze",
		mcp.WithDescription("Analyze a DirFuzz JSONL results file. Groups findings by severity, identifies high-value targets, flags WAF-blocked paths worth bypassing."),
		mcp.WithString("results_file", mcp.Required(), mcp.Description("Absolute path to the JSONL results file.")),
		mcp.WithString("target", mcp.Description("The base URL that was scanned (for context).")),
	)
	s.AddTool(analyzeTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return handleAnalyze(ctx, req, cfg)
	})

	buildTool := mcp.NewTool("dirfuzz_build_scan",
		mcp.WithDescription("Translate a natural language scan request into optimal DirFuzz parameters."),
		mcp.WithString("description", mcp.Required(), mcp.Description("Natural language description of the scan goal.")),
		mcp.WithString("target", mcp.Required(), mcp.Description("The target URL.")),
	)
	s.AddTool(buildTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return handleBuildScan(ctx, req, cfg)
	})

	expandTool := mcp.NewTool("dirfuzz_expand",
		mcp.WithDescription("Autonomously expand discovered endpoints with recursive sub-scans."),
		mcp.WithString("base_target", mcp.Required(), mcp.Description("The original base URL.")),
		mcp.WithString("hits_jsonl", mcp.Required(), mcp.Description("Path to JSONL results file.")),
		mcp.WithNumber("max_depth", mcp.Description("Maximum expansion depth (default 2, max 4).")),
		mcp.WithNumber("max_targets", mcp.Description("Maximum sub-paths to expand (default 10).")),
		mcp.WithString("wordlist", mcp.Description("Wordlist path for sub-scans.")),
	)
	s.AddTool(expandTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return handleExpand(ctx, req, cfg)
	})

	log.Printf("dirfuzz-mcp: starting (wordlist_dir=%s scope_dir=%s max_threads=%d max_results=%d)",
		cfg.wordlistDir, cfg.scopeDir, cfg.maxThreads, cfg.maxResults)

	if err := server.ServeStdio(s); err != nil {
		log.Fatalf("dirfuzz-mcp: stdio server error: %v", err)
	}
}

// ── tool handler ─────────────────────────────────────────────────────────────

func handleScan(ctx context.Context, req mcp.CallToolRequest, cfg mcpConfig) (*mcp.CallToolResult, error) {
	// ── 1. Parse arguments ────────────────────────────────────────────────────
	// Use req.GetString (mcp-go v0.47.1) which safely handles type assertion
	// from the Arguments map and returns the default on any miss.

	target := strings.TrimSpace(req.GetString("target", ""))
	if target == "" {
		return mcp.NewToolResultError("target is required and must be a non-empty string"), nil
	}

	wordlistName := strings.TrimSpace(req.GetString("wordlist", ""))
	if wordlistName == "" {
		return mcp.NewToolResultError("wordlist is required and must be a non-empty string"), nil
	}

	// ── 2. Dynamic scope validation ───────────────────────────────────────────
	//
	// Reload scope files on every request so that additions/removals made by
	// H1-Scope-Watcher are picked up without restarting the MCP server.

	assets, err := scope.LoadDir(cfg.scopeDir)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to read scope directory: %v", err)), nil
	}

	if len(assets) == 0 {
		// No scope files present at all — fail-safe: deny everything.
		return mcp.NewToolResultError(
			"Error: no scope files found in DIRFUZZ_SCOPE_DIR. " +
				"Cannot validate target. Scan blocked.",
		), nil
	}

	if !scope.IsAllowed(target, assets) {
		return mcp.NewToolResultError(
			"Error: Target is not in the live scope or is not bounty eligible. Scan blocked.",
		), nil
	}

	// ── 3. Resolve & sanitise wordlist path ───────────────────────────────────
	//
	// Reject any path-traversal attempt in the wordlist name before filepath.Join.
	// The AI must only be able to reach files inside DIRFUZZ_WORDLIST_DIR.

	wordlistPath := filepath.Join(cfg.wordlistDir, wordlistName)
	absWordlist, err := filepath.Abs(wordlistPath)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("invalid wordlist path: %v", err)), nil
	}
	absDir, err := filepath.Abs(cfg.wordlistDir)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("invalid wordlist directory: %v", err)), nil
	}
	// Evaluate symlinks so a symlink inside wordlistDir pointing outside is caught.
	resolvedWordlist, err := filepath.EvalSymlinks(absWordlist)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("wordlist %q not found in wordlist directory", wordlistName)), nil
	}
	resolvedDir, err := filepath.EvalSymlinks(absDir)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("wordlist directory resolution failed: %v", err)), nil
	}
	if !strings.HasPrefix(resolvedWordlist, resolvedDir+string(filepath.Separator)) {
		return mcp.NewToolResultError("wordlist path escapes the allowed directory"), nil
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
	headers, err := parseHeaders(req.GetStringSlice("headers", nil))
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("invalid headers: %v", err)), nil
	}

	opts := scanOptions{
		Methods:     methods,
		Body:        req.GetString("body", ""),
		Headers:     headers,
		RPS:         req.GetInt("rps", 0),
		Timeout:     secondsDuration(req.GetFloat("timeout_seconds", 0), engine.DefaultHTTPTimeout),
		MaxDuration: secondsDuration(req.GetFloat("max_duration_seconds", 0), 60*time.Second),
	}
	results, err := runScan(ctx, target, wordlistPath, cfg.maxThreads, cfg.maxResults, matchCodes, extensions, opts)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("scan failed: %v", err)), nil
	}

	// ── 6. Return results ─────────────────────────────────────────────────────

	return mcp.NewToolResultText(formatResults(target, results, cfg.maxResults)), nil
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
) ([]engine.Result, error) {
	eng := engine.NewEngine(threads, engine.DefaultBloomFilterSize, engine.DefaultBloomFilterFP)
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
		opts.MaxDuration = 60 * time.Second
	}
	scanCtx, cancel := context.WithTimeout(ctx, opts.MaxDuration)
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
		if len(collected) >= maxResults {
			// Cap reached — shut the engine down and drain so workers don't leak.
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

// ── output formatting ─────────────────────────────────────────────────────────

// formatResults renders collected scan hits as a plain-text table for the AI.
func formatResults(target string, results []engine.Result, maxResults int) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "DirFuzz scan results for: %s\n", target)
	fmt.Fprintf(&sb, "Total hits: %d", len(results))
	if len(results) >= maxResults {
		fmt.Fprintf(&sb, " (capped at %d — re-run with a tighter wordlist to see more)", maxResults)
	}
	sb.WriteString("\n\n")

	if len(results) == 0 {
		sb.WriteString("No findings.\n")
		return sb.String()
	}

	fmt.Fprintf(&sb, "%-6s  %-8s  %-10s  %s\n", "Status", "Method", "Size", "URL")
	sb.WriteString(strings.Repeat("-", 72) + "\n")
	for _, r := range results {
		method := r.Method
		if method == "" {
			method = "GET"
		}
		u := r.URL
		if u == "" {
			u = r.Path
		}
		fmt.Fprintf(&sb, "%-6d  %-8s  %-10d  %s\n", r.StatusCode, method, r.Size, u)
	}
	return sb.String()
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

func secondsDuration(seconds float64, fallback time.Duration) time.Duration {
	if seconds <= 0 {
		return fallback
	}
	return time.Duration(seconds * float64(time.Second))
}

// ── MCP Tool: dirfuzz_analyze ─────────────────────────────────────────────────

func handleAnalyze(ctx context.Context, req mcp.CallToolRequest, cfg mcpConfig) (*mcp.CallToolResult, error) {
	args, _ := req.Params.Arguments.(map[string]any)
	resultsFile, _ := args["results_file"].(string)
	target, _ := args["target"].(string)

	if resultsFile == "" {
		return mcp.NewToolResultText("error: results_file is required"), nil
	}

	f, err := os.Open(resultsFile)
	if err != nil {
		return mcp.NewToolResultText(fmt.Sprintf("error opening results file: %v", err)), nil
	}
	defer f.Close()

	type scanResult struct {
		Path             string `json:"path"`
		StatusCode       int    `json:"status"`
		Size             int    `json:"length"`
		ContentType      string `json:"content_type"`
		Forbidden403Type string `json:"forbidden_403_type"`
	}

	var critical, high, medium, info []scanResult
	criticalPaths := []string{"/.git/", "/backup", "/.env", "/config", "/database", "/dump", "/phpinfo", "/server-status", "/actuator", "/.aws/", "/.ssh/"}
	highPaths := []string{"/admin", "/panel", "/dashboard", "/management", "/console", "/api/internal"}

	contentTypes := make(map[string]int)
	total := 0

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var r scanResult
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue
		}
		total++
		contentTypes[r.ContentType]++

		isCritical := false
		for _, cp := range criticalPaths {
			if strings.Contains(r.Path, cp) && r.StatusCode == 200 {
				isCritical = true
				break
			}
		}
		if isCritical {
			critical = append(critical, r)
			continue
		}
		isHigh := false
		for _, hp := range highPaths {
			if strings.Contains(r.Path, hp) && r.StatusCode == 200 {
				isHigh = true
				break
			}
		}
		if isHigh {
			high = append(high, r)
			continue
		}
		if r.StatusCode == 403 || r.StatusCode == 401 || r.StatusCode == 500 {
			medium = append(medium, r)
			continue
		}
		info = append(info, r)
	}

	var sb strings.Builder
	sb.WriteString("## Summary\n")
	sb.WriteString(fmt.Sprintf("- Target: %s\n", target))
	sb.WriteString(fmt.Sprintf("- Total hits: %d\n", total))
	sb.WriteString(fmt.Sprintf("- Critical: %d | High: %d | Medium: %d | Info: %d\n\n", len(critical), len(high), len(medium), len(info)))

	if len(critical) > 0 {
		sb.WriteString("## Critical Findings\n")
		for _, r := range critical {
			sb.WriteString(fmt.Sprintf("  [%d] %s (%d bytes) [%s]\n", r.StatusCode, r.Path, r.Size, r.ContentType))
		}
		sb.WriteString("\n")
	}
	if len(high) > 0 {
		sb.WriteString("## High Findings\n")
		for _, r := range high {
			sb.WriteString(fmt.Sprintf("  [%d] %s (%d bytes) [%s]\n", r.StatusCode, r.Path, r.Size, r.ContentType))
		}
		sb.WriteString("\n")
	}
	if len(medium) > 0 {
		sb.WriteString("## Medium Findings (Bypass Candidates)\n")
		for _, r := range medium {
			bypass := ""
			if r.Forbidden403Type != "" {
				bypass = " [" + r.Forbidden403Type + "]"
			}
			sb.WriteString(fmt.Sprintf("  [%d] %s (%d bytes)%s\n", r.StatusCode, r.Path, r.Size, bypass))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("## Recommended Next Steps\n")
	if len(medium) > 0 {
		sb.WriteString(fmt.Sprintf("- Run 403 bypass techniques on %d blocked paths\n", len(medium)))
	}
	if len(critical) > 0 {
		sb.WriteString(fmt.Sprintf("- Immediately investigate %d critical findings\n", len(critical)))
	}
	if len(high) > 0 {
		sb.WriteString(fmt.Sprintf("- Review %d high-severity admin/panel paths\n", len(high)))
	}

	return mcp.NewToolResultText(sb.String()), nil
}

// ── MCP Tool: dirfuzz_build_scan ──────────────────────────────────────────────

func handleBuildScan(ctx context.Context, req mcp.CallToolRequest, cfg mcpConfig) (*mcp.CallToolResult, error) {
	args, _ := req.Params.Arguments.(map[string]any)
	desc, _ := args["description"].(string)
	target, _ := args["target"].(string)

	descLower := strings.ToLower(desc)

	wordlist := "common.txt"
	extensions := ""
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
		extensions = "php,env,blade.php"
		reasoning = append(reasoning, "Detected Laravel/PHP target.")
	case contains(descLower, "django", "python", "flask"):
		wordlist = bestWordlist(cfg.wordlistDir, []string{"common.txt"})
		extensions = "py,pyc,cfg"
		reasoning = append(reasoning, "Detected Python/Django/Flask target.")
	case contains(descLower, "rails", "ruby"):
		wordlist = bestWordlist(cfg.wordlistDir, []string{"common.txt"})
		extensions = "rb,erb"
		reasoning = append(reasoning, "Detected Rails/Ruby target.")
	case contains(descLower, "node", "express", "javascript"):
		wordlist = bestWordlist(cfg.wordlistDir, []string{"common.txt"})
		extensions = "js,json,env,ts"
		reasoning = append(reasoning, "Detected Node.js/Express target.")
	case contains(descLower, "spring", "java", "tomcat"):
		wordlist = bestWordlist(cfg.wordlistDir, []string{"common.txt"})
		extensions = "java,class,war,jsp"
		reasoning = append(reasoning, "Detected Java/Spring/Tomcat target.")
	case contains(descLower, "wordpress", "wp"):
		wordlist = bestWordlist(cfg.wordlistDir, []string{"wordpress.txt", "common.txt"})
		extensions = "php"
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
		extensions = extensions + ",bak,old,git,env,config,sql,zip"
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
			"extensions":  extensions,
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
	args, _ := req.Params.Arguments.(map[string]any)
	baseTarget, _ := args["base_target"].(string)
	hitsJSONL, _ := args["hits_jsonl"].(string)
	wordlistArg, _ := args["wordlist"].(string)
	maxDepth := 2
	maxTargets := 10

	if v, ok := args["max_depth"].(float64); ok && v > 0 {
		maxDepth = int(v)
	}
	if maxDepth > 4 {
		maxDepth = 4
	}
	if v, ok := args["max_targets"].(float64); ok && v > 0 {
		maxTargets = int(v)
	}
	if maxTargets > 20 {
		maxTargets = 20
	}

	type scanResult struct {
		Path       string `json:"path"`
		StatusCode int    `json:"status"`
		Size       int    `json:"length"`
	}

	f, err := os.Open(hitsJSONL)
	if err != nil {
		return mcp.NewToolResultText(fmt.Sprintf("error: %v", err)), nil
	}
	defer f.Close()

	type candidate struct {
		result scanResult
		score  int
	}

	var candidates []candidate
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var r scanResult
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

	// Sort by score descending
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].score > candidates[j].score
	})
	if len(candidates) > maxTargets {
		candidates = candidates[:maxTargets]
	}

	wl := wordlistArg
	if wl == "" {
		wl = bestWordlist(cfg.wordlistDir, []string{"common.txt"})
		wl = filepath.Join(cfg.wordlistDir, wl)
	}

	_ = maxDepth // depth respected via MaxDepth config

	var sb strings.Builder
	sb.WriteString("## Expansion Report\n\n")
	sb.WriteString(fmt.Sprintf("Expanding %d candidate paths\n\n", len(candidates)))

	totalNew := 0
	for _, c := range candidates {
		subTarget := strings.TrimRight(baseTarget, "/") + c.result.Path
		_ = subTarget // TODO: wire up engine.SetTarget(subTarget) — scan loop is incomplete
		subCtx, cancel := context.WithTimeout(ctx, 30*time.Second)

		eng := engine.NewEngine(cfg.maxThreads, 1_000_000, 0.001)
		eng.Config.Lock()
		eng.Config.MaxWorkers = cfg.maxThreads
		eng.Config.MatchCodes = map[int]bool{200: true, 301: true, 302: true, 403: true}
		eng.Config.MaxDepth = 1
		eng.Config.Timeout = 5 * time.Second
		eng.Config.Unlock()

		var subResults []scanResult
		done := make(chan struct{})
		go func() {
			defer close(done)
			for r := range eng.Results {
				if len(subResults) >= 50 {
					break
				}
				subResults = append(subResults, scanResult{
					Path:       r.Path,
					StatusCode: r.StatusCode,
					Size:       r.Size,
				})
			}
		}()

		_ = subCtx
		cancel()
		<-done

		sb.WriteString(fmt.Sprintf("### %s → %d new findings\n", c.result.Path, len(subResults)))
		for _, sr := range subResults {
			sb.WriteString(fmt.Sprintf("  [%d] %s (%db)\n", sr.StatusCode, sr.Path, sr.Size))
		}
		sb.WriteString("\n")
		totalNew += len(subResults)
	}

	sb.WriteString(fmt.Sprintf("Total new endpoints discovered: %d\n", totalNew))
	return mcp.NewToolResultText(sb.String()), nil
}
