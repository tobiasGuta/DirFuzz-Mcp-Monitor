package engine

import (
	"bufio"
	"bytes"
	"context"
	"dirfuzz/pkg/httpclient"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	interactclient "github.com/projectdiscovery/interactsh/pkg/client"
	lua "github.com/yuin/gopher-lua"
)

const defaultLuaExecutionTimeout = 5 * time.Second

func defaultVMPoolSize() int {
	n := runtime.NumCPU()
	if n < 4 {
		n = 4
	}
	if n > 16 {
		n = 16
	}
	return n
}

func luaExecutionTimeout(timeout time.Duration) time.Duration {
	if timeout > 0 {
		return timeout
	}
	return defaultLuaExecutionTimeout
}

func runLuaWithTimeout(L *lua.LState, parent context.Context, timeout time.Duration, fn func() error) error {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, luaExecutionTimeout(timeout))
	defer cancel()
	L.SetContext(ctx)
	return fn()
}

func newRestrictedLuaState() *lua.LState {
	// Create a VM with the standard libraries skipped and open only a
	// minimal, safe subset to avoid exposing filesystem/OS operations.
	L := lua.NewState(lua.Options{SkipOpenLibs: true})
	// Open safe libraries only.
	lua.OpenBase(L)
	lua.OpenTable(L)
	lua.OpenString(L)
	lua.OpenMath(L)
	return L
}

// PluginMatcher wraps a pool of Lua VMs running the same matcher script.
// Previously this used a single VM with a mutex, serialising all 50 workers.
// The pool lets multiple workers execute Lua callbacks in parallel.
type PluginMatcher struct {
	pool     chan *lua.LState
	file     string
	compiled []byte
	timeout  time.Duration
}

func NewPluginMatcher(scriptPath string, timeout time.Duration) (*PluginMatcher, error) {
	compiled, err := os.ReadFile(scriptPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read plugin file: %w", err)
	}

	size := defaultVMPoolSize()
	pool := make(chan *lua.LState, size)

	for i := 0; i < size; i++ {
		L := newRestrictedLuaState()
		if err := runLuaWithTimeout(L, context.Background(), timeout, func() error {
			return L.DoString(string(compiled))
		}); err != nil {
			L.Close()
			for len(pool) > 0 {
				(<-pool).Close()
			}
			return nil, fmt.Errorf("failed to load plugin: %w", err)
		}
		if L.GetGlobal("match") == lua.LNil {
			L.Close()
			for len(pool) > 0 {
				(<-pool).Close()
			}
			return nil, fmt.Errorf("plugin must define a 'match' function")
		}
		pool <- L
	}
	return &PluginMatcher{pool: pool, file: scriptPath, compiled: compiled, timeout: timeout}, nil
}

func (pm *PluginMatcher) evalMatch(L *lua.LState, timeout time.Duration, statusCode, size, words, lines int, body, contentType string) (bool, []string, string) {
	matchFunc := L.GetGlobal("match")
	if matchFunc == lua.LNil {
		return false, nil, ""
	}
	t := L.NewTable()
	L.SetField(t, "status_code", lua.LNumber(statusCode))
	L.SetField(t, "size", lua.LNumber(size))
	L.SetField(t, "words", lua.LNumber(words))
	L.SetField(t, "lines", lua.LNumber(lines))
	L.SetField(t, "body", lua.LString(body))
	L.SetField(t, "content_type", lua.LString(contentType))

	if err := runLuaWithTimeout(L, context.Background(), timeout, func() error {
		return L.CallByParam(lua.P{Fn: matchFunc, NRet: 1, Protect: true}, t)
	}); err != nil {
		return false, nil, ""
	}
	res := L.Get(-1)
	L.Pop(1)

	// If the plugin returned a table, allow it to provide metadata like
	// { match = true, label = "SQLi", confidence = "high" }.
	if tbl, ok := res.(*lua.LTable); ok {
		// Determine whether the table indicates a match. If the explicit
		// "match" field is present use it; otherwise treat the table as a
		// truthy match indicator.
		matchField := L.GetField(tbl, "match")
		matched := true
		if matchField != lua.LNil {
			matched = lua.LVAsBool(matchField)
		}
		if !matched {
			return false, nil, ""
		}

		// Collect labels. Support either a single "label" string or a
		// "labels" table of strings.
		var labels []string
		if lf := L.GetField(tbl, "label"); lf != lua.LNil {
			if s, ok := lf.(lua.LString); ok {
				labels = append(labels, string(s))
			}
		}
		if lts := L.GetField(tbl, "labels"); lts != lua.LNil {
			if lt, ok := lts.(*lua.LTable); ok {
				lt.ForEach(func(_ lua.LValue, v lua.LValue) {
					if s, ok := v.(lua.LString); ok {
						labels = append(labels, string(s))
					}
				})
			} else if s, ok := lts.(lua.LString); ok {
				labels = append(labels, string(s))
			}
		}

		// Confidence string (optional)
		var confidence string
		if cf := L.GetField(tbl, "confidence"); cf != lua.LNil {
			confidence = lua.LVAsString(cf)
		}

		return true, labels, confidence
	}

	// Fallback: treat any non-table Lua value by its truthiness.
	return lua.LVAsBool(res), nil, ""
}

func (pm *PluginMatcher) Match(statusCode, size, words, lines int, body, contentType string, timeout time.Duration) (bool, []string, string) {
	if timeout <= 0 {
		timeout = pm.timeout
	}
	select {
	case L := <-pm.pool:
		defer func() { pm.pool <- L }()
		return pm.evalMatch(L, timeout, statusCode, size, words, lines, body, contentType)
	default:
		// Pool saturated: run the matcher in a short-lived VM so workers
		// don't block behind the fixed-size pool.
		L := newRestrictedLuaState()
		defer L.Close()
		if err := runLuaWithTimeout(L, context.Background(), timeout, func() error {
			return L.DoString(string(pm.compiled))
		}); err != nil {
			return false, nil, ""
		}
		return pm.evalMatch(L, timeout, statusCode, size, words, lines, body, contentType)
	}
}

func (pm *PluginMatcher) Close() {
	n := cap(pm.pool)
	for i := 0; i < n; i++ {
		(<-pm.pool).Close()
	}
	close(pm.pool)
}

// evalOnFinding invokes the optional on_finding(result) hook. It builds a
// Lua table representation of the Result and calls the hook. The hook may
// modify the table in-place. Returns (dropped, labels, confidence).
func (pm *PluginMatcher) evalOnFinding(L *lua.LState, timeout time.Duration, r *Result) (bool, []string, string) {
	onFunc := L.GetGlobal("on_finding")
	if onFunc == lua.LNil {
		return false, nil, ""
	}

	t := L.NewTable()
	L.SetField(t, "path", lua.LString(r.Path))
	L.SetField(t, "url", lua.LString(r.URL))
	L.SetField(t, "method", lua.LString(r.Method))
	L.SetField(t, "status_code", lua.LNumber(r.StatusCode))
	L.SetField(t, "size", lua.LNumber(r.Size))
	L.SetField(t, "words", lua.LNumber(r.Words))
	L.SetField(t, "lines", lua.LNumber(r.Lines))
	L.SetField(t, "content_type", lua.LString(r.ContentType))
	L.SetField(t, "duration_ms", lua.LNumber(r.Duration.Milliseconds()))

	hdrTbl := L.NewTable()
	for k, v := range r.Headers {
		L.SetField(hdrTbl, k, lua.LString(v))
	}
	L.SetField(t, "headers", hdrTbl)

	if err := runLuaWithTimeout(L, context.Background(), timeout, func() error {
		return L.CallByParam(lua.P{Fn: onFunc, NRet: 0, Protect: true}, t)
	}); err != nil {
		return false, nil, ""
	}

	// Check for suppress flag in the table.
	if sup := L.GetField(t, "suppress"); sup != lua.LNil {
		if lua.LVAsBool(sup) {
			return true, nil, ""
		}
	}

	var labels []string
	if lf := L.GetField(t, "label"); lf != lua.LNil {
		if s, ok := lf.(lua.LString); ok {
			labels = append(labels, string(s))
		}
	}
	if lts := L.GetField(t, "labels"); lts != lua.LNil {
		if lt, ok := lts.(*lua.LTable); ok {
			lt.ForEach(func(_ lua.LValue, v lua.LValue) {
				if s, ok := v.(lua.LString); ok {
					labels = append(labels, string(s))
				}
			})
		} else if s, ok := lts.(lua.LString); ok {
			labels = append(labels, string(s))
		}
	}

	var confidence string
	if cf := L.GetField(t, "confidence"); cf != lua.LNil {
		confidence = lua.LVAsString(cf)
	}

	return false, labels, confidence
}

// OnFinding calls the optional on_finding hook using a VM from the pool if
// available, otherwise a short-lived VM is created. registerHTTPLib is
// invoked so plugins can use http_send from within on_finding.
func (pm *PluginMatcher) OnFinding(reqCtx context.Context, timeout time.Duration, proxyAddr string, insecure bool, allowPrivate bool, r *Result) (bool, []string, string) {
	if timeout <= 0 {
		timeout = pm.timeout
	}
	select {
	case L := <-pm.pool:
		defer func() { pm.pool <- L }()
		// Ensure http_send is available in the VM for outbound notifications.
		registerHTTPLib(L, reqCtx, timeout, proxyAddr, insecure, allowPrivate)
		return pm.evalOnFinding(L, timeout, r)
	default:
		L := newRestrictedLuaState()
		defer L.Close()
		if err := runLuaWithTimeout(L, reqCtx, timeout, func() error {
			return L.DoString(string(pm.compiled))
		}); err != nil {
			return false, nil, ""
		}
		registerHTTPLib(L, reqCtx, timeout, proxyAddr, insecure, allowPrivate)
		return pm.evalOnFinding(L, timeout, r)
	}
}

// PluginMutator wraps a pool of Lua VMs running the same mutator script.
type PluginMutator struct {
	pool    chan *lua.LState
	file    string
	timeout time.Duration
}

func NewPluginMutator(scriptPath string, timeout time.Duration) (*PluginMutator, error) {
	size := defaultVMPoolSize()
	pool := make(chan *lua.LState, size)

	for i := 0; i < size; i++ {
		L := newRestrictedLuaState()
		if err := runLuaWithTimeout(L, context.Background(), timeout, func() error {
			return L.DoFile(scriptPath)
		}); err != nil {
			L.Close()
			for len(pool) > 0 {
				(<-pool).Close()
			}
			return nil, fmt.Errorf("failed to load plugin: %w", err)
		}
		if L.GetGlobal("mutate") == lua.LNil {
			L.Close()
			for len(pool) > 0 {
				(<-pool).Close()
			}
			return nil, fmt.Errorf("plugin must define a 'mutate' function")
		}
		pool <- L
	}
	return &PluginMutator{pool: pool, file: scriptPath, timeout: timeout}, nil
}

func (pm *PluginMutator) Mutate(original, targetURL string, depth int) []string {
	timeout := pm.timeout
	select {
	case L := <-pm.pool:
		defer func() { pm.pool <- L }()
		return pm.doMutate(L, timeout, original, targetURL, depth)
	default:
		// Pool saturated: run the mutator in a short-lived VM so workers
		// don't block behind the fixed-size pool.
		L := newRestrictedLuaState()
		defer L.Close()
		if err := runLuaWithTimeout(L, context.Background(), timeout, func() error {
			return L.DoFile(pm.file)
		}); err != nil {
			return []string{original}
		}
		return pm.doMutate(L, timeout, original, targetURL, depth)
	}
}

func (pm *PluginMutator) doMutate(L *lua.LState, timeout time.Duration, original, targetURL string, depth int) []string {
	mutateFunc := L.GetGlobal("mutate")
	if mutateFunc == lua.LNil {
		return []string{original}
	}

	// Provide a context table to the plugin so it can make target-aware
	// mutation decisions.
	ctx := L.NewTable()
	L.SetField(ctx, "target", lua.LString(targetURL))
	L.SetField(ctx, "depth", lua.LNumber(depth))

	if err := runLuaWithTimeout(L, context.Background(), timeout, func() error {
		return L.CallByParam(lua.P{Fn: mutateFunc, NRet: 1, Protect: true}, lua.LString(original), ctx)
	}); err != nil {
		return []string{original}
	}
	res := L.Get(-1)
	L.Pop(1)

	if table, ok := res.(*lua.LTable); ok {
		var variants []string
		table.ForEach(func(_ lua.LValue, val lua.LValue) {
			if s, ok := val.(lua.LString); ok {
				variants = append(variants, string(s))
			}
		})
		if len(variants) > 0 {
			return variants
		}
	}
	return []string{original}
}

func (pm *PluginMutator) Close() {
	n := cap(pm.pool)
	for i := 0; i < n; i++ {
		(<-pm.pool).Close()
	}
	close(pm.pool)
}

// registerHTTPLib registers http.send global function in Lua VM
func registerHTTPLib(L *lua.LState, reqCtx context.Context, timeout time.Duration, proxyAddr string, insecure bool, allowPrivate bool) {
	if reqCtx == nil {
		reqCtx = context.Background()
	}
	L.SetGlobal("http_send", L.NewFunction(func(L *lua.LState) int {
		req := L.CheckTable(1)
		method := "GET"
		if m := L.GetField(req, "method"); m != lua.LNil {
			method = strings.ToUpper(lua.LVAsString(m))
		}
		targetURL := lua.LVAsString(L.GetField(req, "url"))
		body := lua.LVAsString(L.GetField(req, "body"))
		headers := L.GetField(req, "headers")

		u, err := url.Parse(targetURL)
		if err != nil {
			result := L.NewTable()
			L.SetField(result, "error", lua.LString("invalid url: "+err.Error()))
			L.Push(result)
			return 1
		}
		if u.Scheme == "" || u.Host == "" {
			result := L.NewTable()
			L.SetField(result, "error", lua.LString("invalid url: missing scheme or host"))
			L.Push(result)
			return 1
		}
		if err := validateOutboundHostname(u.Hostname(), allowPrivate); err != nil {
			result := L.NewTable()
			L.SetField(result, "error", lua.LString(err.Error()))
			L.Push(result)
			return 1
		}

		pathQuery := u.Path
		if pathQuery == "" {
			pathQuery = "/"
		}
		if u.RawQuery != "" {
			pathQuery += "?" + u.RawQuery
		}

		var rawReq bytes.Buffer
		rawReq.WriteString(method + " " + pathQuery + " HTTP/1.1\r\n")
		rawReq.WriteString("Host: " + u.Host + "\r\n")
		if tbl, ok := headers.(*lua.LTable); ok {
			tbl.ForEach(func(k, v lua.LValue) {
				safeKey := strings.NewReplacer("\r", "", "\n", "").Replace(lua.LVAsString(k))
				safeVal := strings.NewReplacer("\r", "", "\n", "").Replace(lua.LVAsString(v))
				rawReq.WriteString(safeKey + ": " + safeVal + "\r\n")
			})
		}
		if body != "" {
			rawReq.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
		}
		rawReq.WriteString("\r\n")
		rawReq.WriteString(body)

		start := time.Now()
		resp, err := httpclient.SendRawRequestWithContext(reqCtx, targetURL, rawReq.Bytes(), timeout, proxyAddr, insecure)
		if err != nil {
			result := L.NewTable()
			L.SetField(result, "error", lua.LString(err.Error()))
			L.Push(result)
			return 1
		}

		result := L.NewTable()
		L.SetField(result, "status_code", lua.LNumber(resp.StatusCode))
		L.SetField(result, "body", lua.LString(string(resp.Body)))

		// Build a headers table keyed by lowercased header name for convenient
		// access from Lua (resp.headers["content-type"]). Preserve the raw
		// header block under headers_raw for compatibility.
		headerTable := L.NewTable()
		if resp.HeaderMap != nil {
			for k, v := range resp.HeaderMap {
				L.SetField(headerTable, k, lua.LString(v))
			}
		}
		L.SetField(result, "headers", headerTable)
		L.SetField(result, "headers_raw", lua.LString(resp.Headers))
		L.SetField(result, "response_time", lua.LNumber(time.Since(start).Milliseconds()))
		L.Push(result)
		return 1
	}))
}

// PluginPoC manages a pool of Lua VMs for Active PoC execution.
type PluginPoC struct {
	pool             chan *lua.LState
	timeout          time.Duration
	interactshClient *interactclient.Client
	scriptPath       string
}

// NewPluginPoC initializes a pool of Lua VMs configured for Active PoCs.
func NewPluginPoC(ctx context.Context, luaPath string, timeout time.Duration, proxyAddr string, insecure bool, targetURL string, allowPrivate bool, interactshClient *interactclient.Client) (*PluginPoC, error) {
	// Create a modest pool size to prevent overloading CPU/memory during high finding counts.
	poolSize := 4
	p := &PluginPoC{
		pool:             make(chan *lua.LState, poolSize),
		timeout:          timeout,
		interactshClient: interactshClient,
		scriptPath:       luaPath,
	}

	for i := 0; i < poolSize; i++ {
		L := newRestrictedLuaState()
		registerHTTPLib(L, ctx, timeout, proxyAddr, insecure, allowPrivate)
		registerStandardLibraries(L, ctx, interactshClient)

		if err := runLuaWithTimeout(L, ctx, timeout, func() error {
			return L.DoFile(luaPath)
		}); err != nil {
			L.Close()
			return nil, fmt.Errorf("failed to load script: %w", err)
		}

		p.pool <- L
	}
	return p, nil
}

// Close shuts down the pool.
func (p *PluginPoC) Close() {
	close(p.pool)
	for L := range p.pool {
		L.Close()
	}
}

// Execute runs the PoC against a specific finding and returns any generated results.
func (p *PluginPoC) Execute(ctx context.Context, res *Result) []Result {
	L := <-p.pool
	defer func() { p.pool <- L }()

	// Create context table
	ctxTable := L.NewTable()
	L.SetField(ctxTable, "matched_path", lua.LString(res.Path))
	L.SetField(ctxTable, "matched_url", lua.LString(res.URL))
	L.SetField(ctxTable, "matched_status", lua.LNumber(res.StatusCode))
	L.SetField(ctxTable, "matched_request", lua.LString(res.RequestBytes))
	L.SetField(ctxTable, "matched_response", lua.LString(res.ResponseBytes))

	// Pre-Flight check: is_target
	if isTargetFunc := L.GetGlobal("is_target"); isTargetFunc.Type() == lua.LTFunction {
		err := runLuaWithTimeout(L, ctx, p.timeout, func() error {
			return L.CallByParam(lua.P{Fn: isTargetFunc, NRet: 1, Protect: true}, ctxTable)
		})
		if err != nil {
			return nil // error evaluating is_target, skip
		}
		ret := L.Get(-1)
		L.Pop(1)
		if !lua.LVAsBool(ret) {
			return nil // skipping based on filter
		}
	}

	// pre_scan check
	if preScanFunc := L.GetGlobal("pre_scan"); preScanFunc.Type() == lua.LTFunction {
		_ = runLuaWithTimeout(L, ctx, p.timeout, func() error {
			return L.CallByParam(lua.P{Fn: preScanFunc, NRet: 0, Protect: true}, ctxTable)
		})
	}

	runFunc := L.GetGlobal("run")
	if runFunc == lua.LNil {
		return nil
	}

	if err := runLuaWithTimeout(L, ctx, p.timeout, func() error {
		return L.CallByParam(lua.P{Fn: runFunc, NRet: 1, Protect: true}, ctxTable)
	}); err != nil {
		return nil
	}

	var results []Result
	ret := L.Get(-1)
	L.Pop(1)
	if tbl, ok := ret.(*lua.LTable); ok {
		if first := tbl.RawGetInt(1); first.Type() != lua.LTNil {
			tbl.ForEach(func(_ lua.LValue, v lua.LValue) {
				if rTbl, isTbl := v.(*lua.LTable); isTbl {
					if r := parseResultTable(rTbl); r != nil {
						r.Labels = append(r.Labels, "ACTIVE-POC")
						results = append(results, *r)
					}
				}
			})
		} else {
			if r := parseResultTable(tbl); r != nil {
				r.Labels = append(r.Labels, "ACTIVE-POC")
				results = append(results, *r)
			}
		}
	}

	// post_scan check
	if postScanFunc := L.GetGlobal("post_scan"); postScanFunc.Type() == lua.LTFunction {
		_ = runLuaWithTimeout(L, ctx, p.timeout, func() error {
			return L.CallByParam(lua.P{Fn: postScanFunc, NRet: 0, Protect: true}, ctxTable)
		})
	}

	return results
}

// OnOOBHit runs the on_oob_hit Lua hook if defined, passing a generic map of the interaction.
func (p *PluginPoC) OnOOBHit(ctx context.Context, interactionData map[string]interface{}) []Result {
	L := <-p.pool
	defer func() { p.pool <- L }()

	fn := L.GetGlobal("on_oob_hit")
	if fn.Type() != lua.LTFunction {
		return nil
	}

	tbl := L.NewTable()
	for k, v := range interactionData {
		L.SetField(tbl, k, lua.LString(fmt.Sprint(v)))
	}

	if err := runLuaWithTimeout(L, ctx, p.timeout, func() error {
		return L.CallByParam(lua.P{Fn: fn, NRet: 1, Protect: true}, tbl)
	}); err != nil {
		return nil
	}

	var results []Result
	ret := L.Get(-1)
	L.Pop(1)
	if rTbl, ok := ret.(*lua.LTable); ok {
		if first := rTbl.RawGetInt(1); first.Type() != lua.LTNil {
			rTbl.ForEach(func(_ lua.LValue, v lua.LValue) {
				if t, isTbl := v.(*lua.LTable); isTbl {
					if r := parseResultTable(t); r != nil {
						r.Labels = append(r.Labels, "OOB-POC")
						results = append(results, *r)
					}
				}
			})
		} else {
			if r := parseResultTable(rTbl); r != nil {
				r.Labels = append(r.Labels, "OOB-POC")
				results = append(results, *r)
			}
		}
	}
	return results
}

// PreScan runs the optional `pre_scan(target)` hook.
func (p *PluginPoC) PreScan(ctx context.Context, target string, baseURL string, wordlist string) (bool, []string) {
	L := <-p.pool
	defer func() { p.pool <- L }()

	fn := L.GetGlobal("pre_scan")
	if fn.Type() != lua.LTFunction {
		return false, nil // Default: do not skip if no hook defined
	}

	tbl := L.NewTable()
	L.SetField(tbl, "target", lua.LString(target))
	L.SetField(tbl, "base_url", lua.LString(baseURL))
	L.SetField(tbl, "wordlist", lua.LString(wordlist))

	if err := runLuaWithTimeout(L, ctx, p.timeout, func() error {
		return L.CallByParam(lua.P{Fn: fn, NRet: 1, Protect: true}, tbl)
	}); err != nil {
		return true, nil // disable plugin if error
	}

	ret := L.Get(-1)
	L.Pop(1)
	
	skip := false
	var extraPaths []string
	
	if tbl, isTbl := ret.(*lua.LTable); isTbl {
		if skipVal := tbl.RawGetString("skip"); skipVal.Type() == lua.LTBool {
			skip = lua.LVAsBool(skipVal)
		}
		if pathsVal := tbl.RawGetString("extra_paths"); pathsVal.Type() == lua.LTTable {
			pathsVal.(*lua.LTable).ForEach(func(_ lua.LValue, v lua.LValue) {
				if v.Type() == lua.LTString {
					extraPaths = append(extraPaths, v.String())
				}
			})
		}
	} else if ret.Type() == lua.LTBool {
		skip = lua.LVAsBool(ret) // Fallback for backward compatibility
	}
	
	return skip, extraPaths
}

// PostScan runs the optional `post_scan(summary)` hook for deduplication and reporting.
func (p *PluginPoC) PostScan(ctx context.Context, findings []Result, totalFound int, durationMs int64) []Result {
	L := <-p.pool
	defer func() { p.pool <- L }()

	fn := L.GetGlobal("post_scan")
	if fn.Type() != lua.LTFunction {
		return nil // No hook defined, engine will retain original findings
	}

	summaryTable := L.NewTable()
	L.SetField(summaryTable, "total_found", lua.LNumber(totalFound))
	L.SetField(summaryTable, "duration_ms", lua.LNumber(durationMs))

	findingsTable := L.NewTable()
	for i, f := range findings {
		findingsTable.RawSetInt(i+1, resultToLuaTable(L, &f))
	}
	L.SetField(summaryTable, "results", findingsTable)

	if err := runLuaWithTimeout(L, ctx, p.timeout, func() error {
		return L.CallByParam(lua.P{Fn: fn, NRet: 1, Protect: true}, summaryTable)
	}); err != nil {
		return nil
	}

	ret := L.Get(-1)
	L.Pop(1)
	if ret.Type() == lua.LTTable {
		var deduplicated []Result
		ret.(*lua.LTable).ForEach(func(_ lua.LValue, v lua.LValue) {
			if t, isTbl := v.(*lua.LTable); isTbl {
				if r := parseResultTable(t); r != nil {
					deduplicated = append(deduplicated, *r)
				}
			}
		})
		return deduplicated
	}
	return nil
}

// TemplateMetadata holds information parsed from a template's `info` block
type TemplateMetadata struct {
	Name     string   `json:"name"`
	Author   string   `json:"author"`
	Severity string   `json:"severity"`
	CVE      string   `json:"cve"`
	Tags     []string `json:"tags"`
}

// ParseTemplateMetadata reads the first 30 lines of a script and extracts its `-- @field value` block.
func ParseTemplateMetadata(scriptPath string) (TemplateMetadata, error) {
	meta := TemplateMetadata{}
	
	f, err := os.Open(scriptPath)
	if err != nil {
		return meta, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineCount := 0
	for scanner.Scan() {
		lineCount++
		if lineCount > 30 {
			break
		}
		
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "--") {
			continue
		}
		
		line = strings.TrimPrefix(line, "--")
		line = strings.TrimSpace(line)
		
		if !strings.HasPrefix(line, "@") {
			continue
		}
		
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			continue
		}
		
		field := strings.ToLower(strings.TrimPrefix(parts[0], "@"))
		value := strings.TrimSpace(parts[1])
		
		switch field {
		case "name":
			meta.Name = value
		case "severity":
			meta.Severity = value
		case "cve":
			meta.CVE = value
		case "author":
			meta.Author = value
		case "tags":
			tags := strings.Split(value, ",")
			for _, t := range tags {
				t = strings.TrimSpace(t)
				if t != "" {
					meta.Tags = append(meta.Tags, t)
				}
			}
		}
	}
	return meta, scanner.Err()
}

func resultToLuaTable(L *lua.LState, res *Result) *lua.LTable {
	tbl := L.NewTable()
	L.SetField(tbl, "path", lua.LString(res.Path))
	L.SetField(tbl, "url", lua.LString(res.URL))
	L.SetField(tbl, "method", lua.LString(res.Method))
	L.SetField(tbl, "status_code", lua.LNumber(res.StatusCode))
	L.SetField(tbl, "size", lua.LNumber(res.Size))
	if len(res.Labels) > 0 {
		labels := L.NewTable()
		for i, l := range res.Labels {
			labels.RawSetInt(i+1, lua.LString(l))
		}
		L.SetField(tbl, "labels", labels)
	}
	L.SetField(tbl, "confidence", lua.LString(res.Confidence))
	L.SetField(tbl, "request", lua.LString(res.RequestBytes))
	L.SetField(tbl, "response", lua.LString(res.ResponseBytes))
	return tbl
}

func parseResultTable(t *lua.LTable) *Result {
	if match := t.RawGetString("match"); match.Type() == lua.LTBool && !lua.LVAsBool(match) {
		return nil
	}

	res := &Result{}
	if p := t.RawGetString("path"); p.Type() == lua.LTString {
		res.Path = p.String()
	}
	if u := t.RawGetString("url"); u.Type() == lua.LTString {
		res.URL = u.String()
	}
	if m := t.RawGetString("method"); m.Type() == lua.LTString {
		res.Method = m.String()
	}
	if s := t.RawGetString("status_code"); s.Type() == lua.LTNumber {
		res.StatusCode = int(lua.LVAsNumber(s))
	}
	if sz := t.RawGetString("size"); sz.Type() == lua.LTNumber {
		res.Size = int(lua.LVAsNumber(sz))
	}
	if lbl := t.RawGetString("label"); lbl.Type() == lua.LTString {
		res.Labels = append(res.Labels, lbl.String())
	}
	if lbls := t.RawGetString("labels"); lbls.Type() == lua.LTTable {
		lbls.(*lua.LTable).ForEach(func(_ lua.LValue, v lua.LValue) {
			if v.Type() == lua.LTString {
				res.Labels = append(res.Labels, v.String())
			}
		})
	}
	if c := t.RawGetString("confidence"); c.Type() == lua.LTString {
		res.Confidence = c.String()
	}
	if req := t.RawGetString("request"); req.Type() == lua.LTString {
		res.Request = req.String()
	}
	if rTbl := t.RawGetString("response"); rTbl.Type() == lua.LTString {
		res.Response = rTbl.String()
	}
	if hdrs := t.RawGetString("headers"); hdrs.Type() == lua.LTTable {
		res.Headers = make(map[string]string)
		hdrs.(*lua.LTable).ForEach(func(k lua.LValue, v lua.LValue) {
			if k.Type() == lua.LTString && v.Type() == lua.LTString {
				res.Headers[k.String()] = v.String()
			}
		})
	}
	return res
}

// FilterPlugin evaluates a plugin's metadata against Nuclei-style tag and severity requirements.
func FilterPlugin(meta TemplateMetadata, userTags, userSeverity string) bool {
	if userTags == "" && userSeverity == "" {
		return true
	}

	if userSeverity != "" {
		sevs := strings.Split(userSeverity, ",")
		matchedSev := false
		for _, s := range sevs {
			if strings.EqualFold(strings.TrimSpace(s), meta.Severity) {
				matchedSev = true
				break
			}
		}
		if !matchedSev {
			return false
		}
	}

	if userTags != "" {
		reqTags := strings.Split(userTags, ",")
		matchedTag := false
		for _, req := range reqTags {
			req = strings.TrimSpace(req)
			for _, t := range meta.Tags {
				if strings.EqualFold(req, t) {
					matchedTag = true
					break
				}
			}
			if matchedTag {
				break
			}
		}
		if !matchedTag {
			return false
		}
	}

	return true
}

// LoadPoCPlugins walks a directory or parses a single file, filtering by metadata.
func LoadPoCPlugins(ctx context.Context, path string, userTags, userSeverity string, timeout time.Duration, proxyAddr string, insecure bool, targetURL string, allowPrivate bool, interactshClient *interactclient.Client) ([]*PluginPoC, error) {
	var plugins []*PluginPoC
	var files []string

	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if info.IsDir() {
		filepath.Walk(path, func(p string, fi os.FileInfo, err error) error {
			if err == nil && !fi.IsDir() && strings.HasSuffix(p, ".lua") {
				files = append(files, p)
			}
			return nil
		})
	} else {
		files = append(files, path)
	}

	for _, f := range files {
		meta, err := ParseTemplateMetadata(f)
		if err != nil {
			continue // Log invalid templates?
		}

		if FilterPlugin(meta, userTags, userSeverity) {
			p, err := NewPluginPoC(ctx, f, timeout, proxyAddr, insecure, targetURL, allowPrivate, interactshClient)
			if err != nil {
				continue
			}
			plugins = append(plugins, p)
		}
	}
	return plugins, nil
}
