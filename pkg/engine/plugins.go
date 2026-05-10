package engine

import (
	"bytes"
	"context"
	"dirfuzz/pkg/httpclient"
	"fmt"
	"net/url"
	"runtime"
	"strings"
	"time"

	lua "github.com/yuin/gopher-lua"
)

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

// PluginMatcher wraps a pool of Lua VMs running the same matcher script.
// Previously this used a single VM with a mutex, serialising all 50 workers.
// The pool lets multiple workers execute Lua callbacks in parallel.
type PluginMatcher struct {
	pool chan *lua.LState
	file string
}

func NewPluginMatcher(scriptPath string) (*PluginMatcher, error) {
	size := defaultVMPoolSize()
	pool := make(chan *lua.LState, size)

	for i := 0; i < size; i++ {
		L := lua.NewState()
		if err := L.DoFile(scriptPath); err != nil {
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
	return &PluginMatcher{pool: pool, file: scriptPath}, nil
}

func (pm *PluginMatcher) Match(statusCode, size, words, lines int, body, contentType string) bool {
	L := <-pm.pool
	defer func() { pm.pool <- L }()

	matchFunc := L.GetGlobal("match")
	if matchFunc == lua.LNil {
		return false
	}
	t := L.NewTable()
	L.SetField(t, "status_code", lua.LNumber(statusCode))
	L.SetField(t, "size", lua.LNumber(size))
	L.SetField(t, "words", lua.LNumber(words))
	L.SetField(t, "lines", lua.LNumber(lines))
	L.SetField(t, "body", lua.LString(body))
	L.SetField(t, "content_type", lua.LString(contentType))

	if err := L.CallByParam(lua.P{Fn: matchFunc, NRet: 1, Protect: true}, t); err != nil {
		return false
	}
	res := L.Get(-1)
	L.Pop(1)
	return lua.LVAsBool(res)
}

func (pm *PluginMatcher) Close() {
	n := cap(pm.pool)
	for i := 0; i < n; i++ {
		(<-pm.pool).Close()
	}
	close(pm.pool)
}

// PluginMutator wraps a pool of Lua VMs running the same mutator script.
type PluginMutator struct {
	pool chan *lua.LState
	file string
}

func NewPluginMutator(scriptPath string) (*PluginMutator, error) {
	size := defaultVMPoolSize()
	pool := make(chan *lua.LState, size)

	for i := 0; i < size; i++ {
		L := lua.NewState()
		if err := L.DoFile(scriptPath); err != nil {
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
	return &PluginMutator{pool: pool, file: scriptPath}, nil
}

func (pm *PluginMutator) Mutate(original string) []string {
	L := <-pm.pool
	defer func() { pm.pool <- L }()

	mutateFunc := L.GetGlobal("mutate")
	if mutateFunc == lua.LNil {
		return []string{original}
	}
	if err := L.CallByParam(lua.P{Fn: mutateFunc, NRet: 1, Protect: true}, lua.LString(original)); err != nil {
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
func registerHTTPLib(L *lua.LState, timeout time.Duration, proxyAddr string, insecure bool) {
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
			L.SetField(result, "error", lua.LString("invalid url: " + err.Error()))
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
				rawReq.WriteString(lua.LVAsString(k) + ": " + lua.LVAsString(v) + "\r\n")
			})
		}
		if body != "" {
			rawReq.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
		}
		rawReq.WriteString("\r\n")
		rawReq.WriteString(body)

		start := time.Now()
		resp, err := httpclient.SendRawRequestWithContext(context.Background(), targetURL, rawReq.Bytes(), timeout, proxyAddr, insecure)
		if err != nil {
			result := L.NewTable()
			L.SetField(result, "error", lua.LString(err.Error()))
			L.Push(result)
			return 1
		}

		result := L.NewTable()
		L.SetField(result, "status_code", lua.LNumber(resp.StatusCode))
		L.SetField(result, "body", lua.LString(string(resp.Body)))
		L.SetField(result, "headers", lua.LString(resp.Headers))
		L.SetField(result, "response_time", lua.LNumber(time.Since(start).Milliseconds()))
		L.Push(result)
		return 1
	}))
}

// RunActiveTemplate loads and executes a Lua PoC script with http.send available
func RunActiveTemplate(luaPath string, timeout time.Duration, proxyAddr string, insecure bool, targetURL string) error {
	L := lua.NewState()
	defer L.Close()

	registerHTTPLib(L, timeout, proxyAddr, insecure)

	if err := L.DoFile(luaPath); err != nil {
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

	if err := L.CallByParam(lua.P{Fn: runFunc, NRet: 0, Protect: true}, ctxTable); err != nil {
		return fmt.Errorf("run function failed: %w", err)
	}

	return nil
}
