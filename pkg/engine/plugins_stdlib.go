package engine

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"time"

	interactclient "github.com/projectdiscovery/interactsh/pkg/client"
	lua "github.com/yuin/gopher-lua"
)

// registerStandardLibraries registers modern bug bounty built-ins for Lua scripts.
func registerStandardLibraries(L *lua.LState, ctx context.Context, interactshClient *interactclient.Client) {
	// sleep_ms(ms)
	L.SetGlobal("sleep_ms", L.NewFunction(func(L *lua.LState) int {
		ms := L.CheckInt(1)
		select {
		case <-time.After(time.Duration(ms) * time.Millisecond):
		case <-ctx.Done():
			L.RaiseError("context canceled during sleep")
		}
		return 0
	}))

	// base64_encode(str)
	L.SetGlobal("base64_encode", L.NewFunction(func(L *lua.LState) int {
		str := L.CheckString(1)
		encoded := base64.StdEncoding.EncodeToString([]byte(str))
		L.Push(lua.LString(encoded))
		return 1
	}))

	// base64_decode(str)
	L.SetGlobal("base64_decode", L.NewFunction(func(L *lua.LState) int {
		str := L.CheckString(1)
		decoded, err := base64.StdEncoding.DecodeString(str)
		if err != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(err.Error()))
			return 2
		}
		L.Push(lua.LString(decoded))
		return 1
	}))

	// url_encode(str)
	L.SetGlobal("url_encode", L.NewFunction(func(L *lua.LState) int {
		str := L.CheckString(1)
		L.Push(lua.LString(url.QueryEscape(str)))
		return 1
	}))

	// url_decode(str)
	L.SetGlobal("url_decode", L.NewFunction(func(L *lua.LState) int {
		str := L.CheckString(1)
		decoded, err := url.QueryUnescape(str)
		if err != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(err.Error()))
			return 2
		}
		L.Push(lua.LString(decoded))
		return 1
	}))

	// regex_match(pattern, str) -> bool, []matches
	L.SetGlobal("regex_match", L.NewFunction(func(L *lua.LState) int {
		pattern := L.CheckString(1)
		str := L.CheckString(2)
		re, err := regexp.Compile(pattern)
		if err != nil {
			L.RaiseError("invalid regex: %s", err)
			return 0
		}
		matches := re.FindStringSubmatch(str)
		if matches == nil {
			L.Push(lua.LBool(false))
			return 1
		}
		L.Push(lua.LBool(true))
		matchTable := L.NewTable()
		for i, m := range matches {
			L.RawSetInt(matchTable, i+1, lua.LString(m))
		}
		L.Push(matchTable)
		return 2
	}))

	// json_parse(str)
	L.SetGlobal("json_parse", L.NewFunction(func(L *lua.LState) int {
		str := L.CheckString(1)
		var v interface{}
		if err := json.Unmarshal([]byte(str), &v); err != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(err.Error()))
			return 2
		}
		L.Push(goValueToLua(L, v))
		return 1
	}))

	// json_encode(tbl)
	L.SetGlobal("json_encode", L.NewFunction(func(L *lua.LState) int {
		val := L.CheckAny(1)
		goVal := luaValueToGo(val)
		b, err := json.Marshal(goVal)
		if err != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(err.Error()))
			return 2
		}
		L.Push(lua.LString(string(b)))
		return 1
	}))

	// interactsh_url()
	L.SetGlobal("interactsh_url", L.NewFunction(func(L *lua.LState) int {
		if interactshClient == nil {
			L.Push(lua.LNil)
			L.Push(lua.LString("interactsh is not initialized"))
			return 2
		}
		u := interactshClient.URL()
		L.Push(lua.LString(u))
		return 1
	}))

	// hmac_sha256(key, data)
	L.SetGlobal("hmac_sha256", L.NewFunction(func(L *lua.LState) int {
		key := L.CheckString(1)
		data := L.CheckString(2)
		h := hmac.New(sha256.New, []byte(key))
		h.Write([]byte(data))
		signature := hex.EncodeToString(h.Sum(nil))
		L.Push(lua.LString(signature))
		return 1
	}))
}

// goValueToLua recursively converts a Go interface{} to a lua.LValue
func goValueToLua(L *lua.LState, val interface{}) lua.LValue {
	if val == nil {
		return lua.LNil
	}
	switch v := val.(type) {
	case string:
		return lua.LString(v)
	case float64:
		return lua.LNumber(v)
	case bool:
		return lua.LBool(v)
	case []interface{}:
		t := L.NewTable()
		for i, item := range v {
			L.RawSetInt(t, i+1, goValueToLua(L, item))
		}
		return t
	case map[string]interface{}:
		t := L.NewTable()
		for key, item := range v {
			L.SetField(t, key, goValueToLua(L, item))
		}
		return t
	default:
		return lua.LString(fmt.Sprintf("%v", v))
	}
}

// luaValueToGo recursively converts a lua.LValue to a Go interface{}
func luaValueToGo(val lua.LValue) interface{} {
	switch val.Type() {
	case lua.LTNil:
		return nil
	case lua.LTBool:
		return lua.LVAsBool(val)
	case lua.LTNumber:
		return float64(lua.LVAsNumber(val))
	case lua.LTString:
		return lua.LVAsString(val)
	case lua.LTTable:
		t := val.(*lua.LTable)
		// Check if it's an array-like table or a dictionary-like table
		isDict := false
		maxIndex := 0
		t.ForEach(func(k lua.LValue, v lua.LValue) {
			if k.Type() != lua.LTNumber {
				isDict = true
			} else {
				idx := int(lua.LVAsNumber(k))
				if idx > maxIndex {
					maxIndex = idx
				}
			}
		})
		if isDict || maxIndex == 0 {
			m := make(map[string]interface{})
			t.ForEach(func(k lua.LValue, v lua.LValue) {
				m[lua.LVAsString(k)] = luaValueToGo(v)
			})
			return m
		} else {
			a := make([]interface{}, maxIndex)
			t.ForEach(func(k lua.LValue, v lua.LValue) {
				idx := int(lua.LVAsNumber(k))
				if idx >= 1 && idx <= maxIndex {
					a[idx-1] = luaValueToGo(v)
				}
			})
			return a
		}
	default:
		return val.String()
	}
}
