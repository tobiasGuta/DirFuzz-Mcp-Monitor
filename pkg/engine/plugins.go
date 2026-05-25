package engine

import (
	"bytes"
	"context"
	"dirfuzz/pkg/httpclient"
	"fmt"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

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

// RunActiveTemplate loads and executes a Lua PoC script with http.send available
func RunActiveTemplate(ctx context.Context, luaPath string, timeout time.Duration, proxyAddr string, insecure bool, targetURL string, allowPrivate bool) error {
	L := newRestrictedLuaState()
	defer L.Close()

	registerHTTPLib(L, ctx, timeout, proxyAddr, insecure, allowPrivate)

	if err := runLuaWithTimeout(L, ctx, timeout, func() error {
		return L.DoFile(luaPath)
	}); err != nil {
		return fmt.Errorf("failed to load script: %w", err)
	}

	runFunc := L.GetGlobal("run")
	if runFunc == lua.LNil {
		return fmt.Errorf("script must define a 'run' function")
	}

	// Create context table
	ctxTable := L.NewTable()
	L.SetField(ctxTable, "url", lua.LString(targetURL))

	baseURL := targetURL
	if strings.HasSuffix(baseURL, "/") {
		baseURL = strings.TrimSuffix(baseURL, "/")
	}
	L.SetField(ctxTable, "base_url", lua.LString(baseURL))

	if err := runLuaWithTimeout(L, ctx, timeout, func() error {
		return L.CallByParam(lua.P{Fn: runFunc, NRet: 0, Protect: true}, ctxTable)
	}); err != nil {
		return fmt.Errorf("run function failed: %w", err)
	}

	return nil
}
