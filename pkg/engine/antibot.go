package engine

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"dirfuzz/pkg/httpclient"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
)

type antiBotManager struct {
	jar    http.CookieJar
	mu     sync.Mutex
	states map[string]*antiBotHostState
}

type antiBotHostState struct {
	mu      sync.Mutex
	cond    *sync.Cond
	solving bool
	lastErr error
}

func newAntiBotManager() *antiBotManager {
	jar, _ := cookiejar.New(nil)
	return &antiBotManager{
		jar:    jar,
		states: make(map[string]*antiBotHostState),
	}
}

func (m *antiBotManager) hostState(host string) *antiBotHostState {
	if m == nil || host == "" {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if state, ok := m.states[host]; ok {
		return state
	}

	state := &antiBotHostState{}
	state.cond = sync.NewCond(&state.mu)
	m.states[host] = state
	return state
}

func (m *antiBotManager) cookieHeaderValue(targetURL string) string {
	if m == nil || m.jar == nil || targetURL == "" {
		return ""
	}

	u, err := url.Parse(targetURL)
	if err != nil {
		return ""
	}

	cookies := m.jar.Cookies(u)
	if len(cookies) == 0 {
		return ""
	}

	pairs := make([]string, 0, len(cookies))
	for _, c := range cookies {
		if c == nil || c.Name == "" {
			continue
		}
		pairs = append(pairs, c.Name+"="+c.Value)
	}
	return strings.Join(pairs, "; ")
}

func (m *antiBotManager) storeCookies(targetURL string, cookies []*http.Cookie) {
	if m == nil || m.jar == nil || targetURL == "" || len(cookies) == 0 {
		return
	}

	u, err := url.Parse(targetURL)
	if err != nil {
		return
	}
	m.jar.SetCookies(u, cookies)
}

func (m *antiBotManager) storeProtoCookies(targetURL string, cookies []*proto.NetworkCookie) {
	if m == nil || m.jar == nil || targetURL == "" || len(cookies) == 0 {
		return
	}

	u, err := url.Parse(targetURL)
	if err != nil {
		return
	}

	converted := make([]*http.Cookie, 0, len(cookies))
	for _, c := range cookies {
		if c == nil || c.Name == "" {
			continue
		}
		if !cookieAppliesToHost(c.Domain, u.Hostname()) {
			continue
		}

		hc := &http.Cookie{
			Name:     c.Name,
			Value:    c.Value,
			Domain:   c.Domain,
			Path:     c.Path,
			Secure:   c.Secure,
			HttpOnly: c.HTTPOnly,
		}
		if c.Expires > 0 {
			hc.Expires = c.Expires.Time()
		}
		converted = append(converted, hc)
	}

	if len(converted) > 0 {
		m.jar.SetCookies(u, converted)
	}
}

func cookieAppliesToHost(cookieDomain, host string) bool {
	if host == "" {
		return false
	}
	cookieDomain = strings.TrimSpace(strings.ToLower(cookieDomain))
	host = strings.ToLower(host)
	if cookieDomain == "" {
		return true
	}
	cookieDomain = strings.TrimPrefix(cookieDomain, ".")
	return host == cookieDomain || strings.HasSuffix(host, "."+cookieDomain)
}

func (e *Engine) injectCookiesIntoRawRequest(targetURL string, rawRequest []byte) []byte {
	if e == nil || e.antiBot == nil {
		return rawRequest
	}

	cookieValue := e.antiBot.cookieHeaderValue(targetURL)
	if cookieValue == "" {
		return rawRequest
	}

	headerEnd, sep := findHeaderSeparator(rawRequest)
	if headerEnd == -1 {
		return rawRequest
	}

	headerBlock := string(rawRequest[:headerEnd])
	body := rawRequest[headerEnd+len(sep):]
	normalized := strings.ReplaceAll(headerBlock, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	lines := strings.Split(normalized, "\n")

	hasCookie := false
	out := make([]string, 0, len(lines)+1)
	for i, line := range lines {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		if i == 0 {
			out = append(out, line)
			continue
		}
		idx := strings.Index(line, ":")
		if idx != -1 && strings.EqualFold(strings.TrimSpace(line[:idx]), "Cookie") {
			hasCookie = true
			existing := strings.TrimSpace(line[idx+1:])
			if existing == "" {
				out = append(out, "Cookie: "+cookieValue)
			} else {
				out = append(out, "Cookie: "+existing+"; "+cookieValue)
			}
			continue
		}
		out = append(out, line)
	}
	if !hasCookie {
		out = append(out, "Cookie: "+cookieValue)
	}

	var buf bytes.Buffer
	for _, line := range out {
		buf.WriteString(line)
		buf.WriteString("\r\n")
	}
	buf.WriteString("\r\n")
	buf.Write(body)
	return buf.Bytes()
}

func findHeaderSeparator(rawRequest []byte) (int, []byte) {
	if idx := bytes.Index(rawRequest, []byte("\r\n\r\n")); idx != -1 {
		return idx, []byte("\r\n\r\n")
	}
	if idx := bytes.Index(rawRequest, []byte("\n\n")); idx != -1 {
		return idx, []byte("\n\n")
	}
	return -1, nil
}

func (e *Engine) executeRequestOnce(ctx context.Context, targetURL string, rawRequest []byte, timeout time.Duration, proxyAddr string, insecure bool, h2Mode bool, antiBotFallback bool) (*httpclient.RawResponse, error) {
	rawRequest = e.injectCookiesIntoRawRequest(targetURL, rawRequest)

	if h2Mode && e.H2Client != nil {
		return e.executeH2RequestWithRetry(ctx, targetURL, rawRequest, timeout)
	}
	e.requestsDispatched.Add(1)
	return httpclient.SendRawRequestWithContext(ctx, targetURL, rawRequest, timeout, proxyAddr, insecure)
}

func (e *Engine) mergeResponseCookies(targetURL string, resp *httpclient.RawResponse) {
	if e == nil || e.antiBot == nil || resp == nil {
		return
	}
	e.antiBot.storeCookies(targetURL, httpclient.ParseSetCookies(resp.Headers))
}

func (e *Engine) handleAntiBotResponse(
	ctx context.Context,
	targetURL string,
	rawRequest []byte,
	timeout time.Duration,
	proxyAddr string,
	insecure bool,
	h2Mode bool,
	antiBotFallback bool,
	resp *httpclient.RawResponse,
) (*httpclient.RawResponse, bool) {
	if e == nil || e.antiBot == nil || resp == nil || !antiBotFallback {
		return nil, false
	}

	signal := httpclient.InspectAntiBotResponse(resp)
	if !signal.Blocked {
		return nil, false
	}

	solved, err := e.antiBot.solve(ctx, targetURL)
	if err != nil || !solved {
		return nil, false
	}

	retryResp, retryErr := e.executeRequestOnce(ctx, targetURL, rawRequest, timeout, proxyAddr, insecure, h2Mode, antiBotFallback)
	if retryErr != nil || retryResp == nil {
		return nil, false
	}
	e.mergeResponseCookies(targetURL, retryResp)
	return retryResp, true
}

func (m *antiBotManager) solve(ctx context.Context, targetURL string) (bool, error) {
	if m == nil || targetURL == "" {
		return false, fmt.Errorf("anti-bot manager is not configured")
	}

	u, err := url.Parse(targetURL)
	if err != nil {
		return false, fmt.Errorf("invalid anti-bot target URL: %w", err)
	}

	host := strings.ToLower(u.Hostname())
	if host == "" {
		return false, fmt.Errorf("anti-bot target host is empty")
	}

	state := m.hostState(host)
	if state == nil {
		return false, fmt.Errorf("anti-bot host state unavailable")
	}

	state.mu.Lock()
	if state.solving {
		for state.solving {
			state.cond.Wait()
		}
		solved := state.lastErr == nil
		err := state.lastErr
		state.mu.Unlock()
		return solved, err
	}
	state.solving = true
	state.lastErr = nil
	state.mu.Unlock()

	defer func() {
		state.mu.Lock()
		state.solving = false
		state.cond.Broadcast()
		state.mu.Unlock()
	}()

	solveCtx := ctx
	cancel := func() {}
	if solveCtx == nil {
		solveCtx = context.Background()
	}
	solveCtx, cancel = context.WithTimeout(solveCtx, 60*time.Second)
	defer cancel()

	launcher := launcher.New().Headless(true).NoSandbox(true)
	controlURL, err := launcher.Launch()
	if err != nil {
		state.mu.Lock()
		state.lastErr = err
		state.mu.Unlock()
		return false, err
	}
	defer launcher.Cleanup()

	browser := rod.New().ControlURL(controlURL)
	if err := browser.Connect(); err != nil {
		state.mu.Lock()
		state.lastErr = err
		state.mu.Unlock()
		return false, err
	}
	defer browser.MustClose()

	page, err := browser.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		state.mu.Lock()
		state.lastErr = err
		state.mu.Unlock()
		return false, err
	}
	waitNav := page.MustWaitNavigation()
	if err := page.Navigate(targetURL); err != nil {
		state.mu.Lock()
		state.lastErr = err
		state.mu.Unlock()
		return false, err
	}
	waitNav()

	// Give the browser a moment to settle, then poll the body text until the
	// challenge markers disappear or we recover clearance cookies.
	_ = page.WaitStable(2 * time.Second)

	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		if err := solveCtx.Err(); err != nil {
			state.mu.Lock()
			state.lastErr = err
			state.mu.Unlock()
			return false, err
		}

		if cookies, err := page.Cookies([]string{targetURL}); err == nil {
			m.storeProtoCookies(targetURL, cookies)
		}

		bodyText := ""
		if res, err := page.Eval(`() => {
			const root = document.body || document.documentElement;
			return root ? (root.innerText || root.textContent || "") : "";
		}`); err == nil && res != nil {
			bodyText = strings.ToLower(res.String())
		}

		if bodyText != "" && !challengeLooksActive(bodyText) {
			if cookies, err := page.Cookies([]string{targetURL}); err == nil {
				m.storeProtoCookies(targetURL, cookies)
			}
			return true, nil
		}

		time.Sleep(1 * time.Second)
	}

	err = fmt.Errorf("anti-bot challenge did not clear for %s", targetURL)
	state.mu.Lock()
	state.lastErr = err
	state.mu.Unlock()
	return false, err
}

func challengeLooksActive(bodyText string) bool {
	if bodyText == "" {
		return false
	}

	markers := []string{
		"just a moment",
		"checking your browser",
		"verify you are human",
		"enable javascript and cookies",
		"security check",
		"captcha",
		"turnstile",
		"cloudflare",
		"attention required",
		"one moment please",
		"pardon our interruption",
		"sorry, you have been blocked",
		"request blocked",
		"incapsula incident id",
		"datadome",
		"modsecurity",
		"sucuri website firewall",
		"barracuda web application firewall",
		"the requested url was rejected",
	}
	for _, marker := range markers {
		if strings.Contains(bodyText, marker) {
			return true
		}
	}
	return false
}
