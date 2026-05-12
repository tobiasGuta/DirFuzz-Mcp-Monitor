package engine

import (
	"fmt"

	lua "github.com/yuin/gopher-lua"
)

// PluginRequestTransformer wraps a pool of Lua VMs for request transformation.
type PluginRequestTransformer struct {
	pool chan *lua.LState
	file string
}

// RequestTransformInput holds the request fields available to the Lua hook.
type RequestTransformInput struct {
	Method  string
	Path    string
	Headers map[string]string
	Body    string
}

// RequestTransformOutput holds the transformed request fields.
type RequestTransformOutput struct {
	Method  string
	Path    string
	Headers map[string]string
	Body    string
}

// NewPluginRequestTransformer loads a Lua script that must define transform_request(req).
func NewPluginRequestTransformer(scriptPath string) (*PluginRequestTransformer, error) {
	size := defaultVMPoolSize()
	pool := make(chan *lua.LState, size)

	for i := 0; i < size; i++ {
		L := newRestrictedLuaState()
		if err := L.DoFile(scriptPath); err != nil {
			L.Close()
			for len(pool) > 0 {
				(<-pool).Close()
			}
			return nil, fmt.Errorf("failed to load transform plugin: %w", err)
		}
		if L.GetGlobal("transform_request") == lua.LNil {
			L.Close()
			for len(pool) > 0 {
				(<-pool).Close()
			}
			return nil, fmt.Errorf("transform plugin must define a 'transform_request' function")
		}
		pool <- L
	}
	return &PluginRequestTransformer{pool: pool, file: scriptPath}, nil
}

// Transform runs the Lua transform_request hook and returns the modified request.
// On any error, it returns the input unchanged (fail-open).
func (pt *PluginRequestTransformer) Transform(input RequestTransformInput) RequestTransformOutput {
	select {
	case L := <-pt.pool:
		defer func() { pt.pool <- L }()
		return pt.doTransform(L, input)
	default:
		// Pool saturated: run the transformer in a short-lived VM so workers
		// don't block behind the fixed-size pool.
		L := lua.NewState()
		defer L.Close()
		if err := L.DoFile(pt.file); err != nil {
			return outputFrom(input)
		}
		return pt.doTransform(L, input)
	}
}

func (pt *PluginRequestTransformer) doTransform(L *lua.LState, input RequestTransformInput) RequestTransformOutput {
	fn := L.GetGlobal("transform_request")
	if fn == lua.LNil {
		return outputFrom(input)
	}

	// Build the Lua table
	req := L.NewTable()
	L.SetField(req, "method", lua.LString(input.Method))
	L.SetField(req, "path", lua.LString(input.Path))
	L.SetField(req, "body", lua.LString(input.Body))
	headers := L.NewTable()
	for k, v := range input.Headers {
		L.SetField(headers, k, lua.LString(v))
	}
	L.SetField(req, "headers", headers)

	if err := L.CallByParam(lua.P{Fn: fn, NRet: 1, Protect: true}, req); err != nil {
		return outputFrom(input)
	}

	ret := L.Get(-1)
	L.Pop(1)

	table, ok := ret.(*lua.LTable)
	if !ok {
		return outputFrom(input)
	}

	out := RequestTransformOutput{
		Method:  getString(L, table, "method", input.Method),
		Path:    getString(L, table, "path", input.Path),
		Body:    getString(L, table, "body", input.Body),
		Headers: make(map[string]string),
	}

	// Copy headers back
	for k, v := range input.Headers {
		out.Headers[k] = v
	}
	if hTable, ok := L.GetField(table, "headers").(*lua.LTable); ok {
		hTable.ForEach(func(k lua.LValue, v lua.LValue) {
			if ks, ok2 := k.(lua.LString); ok2 {
				if vs, ok3 := v.(lua.LString); ok3 {
					out.Headers[string(ks)] = string(vs)
				}
			}
		})
	}

	return out
}

// Close drains and closes all Lua VMs in the pool.
func (pt *PluginRequestTransformer) Close() {
	n := cap(pt.pool)
	for i := 0; i < n; i++ {
		(<-pt.pool).Close()
	}
	close(pt.pool)
}

func getString(L *lua.LState, t *lua.LTable, key, fallback string) string {
	v := L.GetField(t, key)
	if s, ok := v.(lua.LString); ok {
		return string(s)
	}
	return fallback
}

func outputFrom(input RequestTransformInput) RequestTransformOutput {
	h := make(map[string]string, len(input.Headers))
	for k, v := range input.Headers {
		h[k] = v
	}
	return RequestTransformOutput{
		Method:  input.Method,
		Path:    input.Path,
		Headers: h,
		Body:    input.Body,
	}
}
