package rod

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-rod/rod/lib/proto"
	"golang.org/x/net/websocket"
)

type Browser struct {
	controlURL string
	pages      []*Page
	mu         sync.Mutex
}

func New() *Browser {
	return &Browser{}
}

func (b *Browser) ControlURL(url string) *Browser {
	b.controlURL = url
	return b
}

func (b *Browser) Connect() error {
	if b == nil {
		return fmt.Errorf("browser is nil")
	}
	if b.controlURL == "" {
		return fmt.Errorf("control URL is empty")
	}
	return nil
}

func (b *Browser) MustConnect() *Browser {
	if err := b.Connect(); err != nil {
		panic(err)
	}
	return b
}

func (b *Browser) Page(opts proto.TargetCreateTarget) (*Page, error) {
	if b == nil {
		return nil, fmt.Errorf("browser is nil")
	}
	baseURL, err := browserHTTPBase(b.controlURL)
	if err != nil {
		return nil, err
	}

	targetURL := strings.TrimSpace(opts.URL)
	if targetURL == "" {
		targetURL = "about:blank"
	}

	wsURL, err := createNewPageWS(baseURL, targetURL)
	if err != nil {
		return nil, err
	}
	page, err := newPage(wsURL)
	if err != nil {
		return nil, err
	}

	b.mu.Lock()
	b.pages = append(b.pages, page)
	b.mu.Unlock()
	return page, nil
}

func (b *Browser) MustPage(urls ...string) *Page {
	target := "about:blank"
	if len(urls) > 0 && strings.TrimSpace(urls[0]) != "" {
		target = strings.TrimSpace(urls[0])
	}
	p, err := b.Page(proto.TargetCreateTarget{URL: target})
	if err != nil {
		panic(err)
	}
	return p
}

func (b *Browser) Close() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, p := range b.pages {
		_ = p.Close()
	}
	b.pages = nil
	return nil
}

func (b *Browser) MustClose() {
	_ = b.Close()
}

type Page struct {
	wsURL string
	conn  *cdpConn
}

func newPage(wsURL string) (*Page, error) {
	conn, err := dialCDP(wsURL)
	if err != nil {
		return nil, err
	}
	return &Page{wsURL: wsURL, conn: conn}, nil
}

func (p *Page) Close() error {
	if p == nil || p.conn == nil {
		return nil
	}
	return p.conn.Close()
}

func (p *Page) Navigate(targetURL string) error {
	if p == nil || p.conn == nil {
		return fmt.Errorf("page is not connected")
	}
	_, err := p.conn.Call("Page.navigate", map[string]string{"url": targetURL})
	return err
}

func (p *Page) MustNavigate(targetURL string) *Page {
	if err := p.Navigate(targetURL); err != nil {
		panic(err)
	}
	return p
}

func (p *Page) Eval(js string, params ...interface{}) (*proto.RuntimeRemoteObject, error) {
	if p == nil || p.conn == nil {
		return nil, fmt.Errorf("page is not connected")
	}
	req := map[string]any{
		"expression":     js,
		"returnByValue":  true,
		"awaitPromise":   true,
		"userGesture":    true,
		"includeCommandLineAPI": true,
	}
	if len(params) > 0 {
		req["arguments"] = params
	}

	raw, err := p.conn.Call("Runtime.evaluate", req)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Result struct {
			Result proto.RuntimeRemoteObject `json:"result"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, err
	}
	return &resp.Result.Result, nil
}

func (p *Page) MustEval(js string, params ...interface{}) *proto.RuntimeRemoteObject {
	res, err := p.Eval(js, params...)
	if err != nil {
		panic(err)
	}
	return res
}

func (p *Page) WaitNavigation(name proto.PageLifecycleEventName) func() {
	return func() {
		// Minimal compatibility helper. The caller still performs DOM polling.
		time.Sleep(250 * time.Millisecond)
	}
}

func (p *Page) MustWaitNavigation() func() {
	return p.WaitNavigation(proto.PageLifecycleEventNameNetworkAlmostIdle)
}

func (p *Page) WaitStable(d time.Duration) error {
	time.Sleep(d)
	return nil
}

func (p *Page) MustWaitStable(d time.Duration) *Page {
	_ = p.WaitStable(d)
	return p
}

func (p *Page) Cookies(urls []string) ([]*proto.NetworkCookie, error) {
	if p == nil || p.conn == nil {
		return nil, fmt.Errorf("page is not connected")
	}
	raw, err := p.conn.Call("Network.getAllCookies", nil)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Result struct {
			Cookies []*proto.NetworkCookie `json:"cookies"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, err
	}
	if len(urls) == 0 {
		return resp.Result.Cookies, nil
	}

	filtered := make([]*proto.NetworkCookie, 0, len(resp.Result.Cookies))
	for _, cookie := range resp.Result.Cookies {
		if cookie == nil {
			continue
		}
		if cookieMatchesURLs(cookie, urls) {
			filtered = append(filtered, cookie)
		}
	}
	return filtered, nil
}

func (p *Page) MustCookies(urls []string) []*proto.NetworkCookie {
	cookies, err := p.Cookies(urls)
	if err != nil {
		panic(err)
	}
	return cookies
}

type cdpConn struct {
	ws      *websocket.Conn
	mu      sync.Mutex
	nextID  int64
	pending map[int64]chan []byte
	closed  chan struct{}
}

func dialCDP(wsURL string) (*cdpConn, error) {
	if wsURL == "" {
		return nil, fmt.Errorf("websocket URL is empty")
	}
	origin, err := websocketOrigin(wsURL)
	if err != nil {
		return nil, err
	}
	cfg, err := websocket.NewConfig(wsURL, origin)
	if err != nil {
		return nil, err
	}
	ws, err := websocket.DialConfig(cfg)
	if err != nil {
		return nil, err
	}

	c := &cdpConn{
		ws:      ws,
		pending: make(map[int64]chan []byte),
		closed:  make(chan struct{}),
	}
	go c.readLoop()
	return c, nil
}

func (c *cdpConn) Close() error {
	if c == nil {
		return nil
	}
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	if c.ws != nil {
		return c.ws.Close()
	}
	return nil
}

func (c *cdpConn) Call(method string, params any) (json.RawMessage, error) {
	if c == nil || c.ws == nil {
		return nil, fmt.Errorf("CDP connection is closed")
	}

	id := atomic.AddInt64(&c.nextID, 1)
	ch := make(chan []byte, 1)

	c.mu.Lock()
	c.pending[id] = ch
	c.mu.Unlock()

	req := map[string]any{
		"id":     id,
		"method": method,
	}
	if params != nil {
		req["params"] = params
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	if err := websocket.Message.Send(c.ws, body); err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, err
	}

	select {
	case raw := <-ch:
		var envelope struct {
			ID     int64           `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  *struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(raw, &envelope); err != nil {
			return nil, err
		}
		if envelope.Error != nil {
			return nil, fmt.Errorf("cdp %s failed: %s", method, envelope.Error.Message)
		}
		return envelope.Result, nil
	case <-time.After(30 * time.Second):
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, fmt.Errorf("cdp call timed out: %s", method)
	case <-c.closed:
		return nil, fmt.Errorf("cdp connection closed")
	}
}

func (c *cdpConn) readLoop() {
	for {
		var raw []byte
		if err := websocket.Message.Receive(c.ws, &raw); err != nil {
			return
		}
		var envelope struct {
			ID int64 `json:"id"`
		}
		if err := json.Unmarshal(raw, &envelope); err != nil {
			continue
		}
		if envelope.ID == 0 {
			continue
		}

		c.mu.Lock()
		ch, ok := c.pending[envelope.ID]
		if ok {
			delete(c.pending, envelope.ID)
		}
		c.mu.Unlock()
		if ok {
			ch <- raw
		}
	}
}

func websocketOrigin(wsURL string) (string, error) {
	u, err := url.Parse(wsURL)
	if err != nil {
		return "", err
	}
	if u.Scheme == "ws" {
		u.Scheme = "http"
	} else if u.Scheme == "wss" {
		u.Scheme = "https"
	}
	u.Path = ""
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

func browserHTTPBase(controlURL string) (string, error) {
	u, err := url.Parse(controlURL)
	if err != nil {
		return "", err
	}
	host := u.Host
	if host == "" {
		return "", fmt.Errorf("control URL missing host")
	}
	return "http://" + host, nil
}

func createNewPageWS(baseURL, pageURL string) (string, error) {
	endpoints := []string{
		baseURL + "/json/new?" + url.QueryEscape(pageURL),
		baseURL + "/json/new?url=" + url.QueryEscape(pageURL),
	}
	var lastErr error
	for _, endpoint := range endpoints {
		resp, err := http.Get(endpoint)
		if err != nil {
			lastErr = err
			continue
		}
		body, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		var payload struct {
			WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			lastErr = err
			continue
		}
		if payload.WebSocketDebuggerURL != "" {
			return payload.WebSocketDebuggerURL, nil
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("browser did not return a page websocket URL")
	}
	return "", lastErr
}

func cookieMatchesURLs(cookie *proto.NetworkCookie, urls []string) bool {
	if cookie == nil {
		return false
	}
	for _, rawURL := range urls {
		u, err := url.Parse(rawURL)
		if err != nil {
			continue
		}
		host := strings.ToLower(u.Hostname())
		if host == "" {
			continue
		}
		cookieDomain := strings.TrimPrefix(strings.ToLower(cookie.Domain), ".")
		if cookieDomain != "" && host != cookieDomain && !strings.HasSuffix(host, "."+cookieDomain) {
			continue
		}
		if cookie.Path != "" && !strings.HasPrefix(u.Path, cookie.Path) {
			continue
		}
		return true
	}
	return false
}
