package httpclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/http2"
)

// NewH2Client builds an HTTP client that speaks HTTP/2 to a fixed target
// scheme. HTTPS targets negotiate h2 over TLS, while HTTP targets use h2c
// cleartext via the http2 transport's AllowHTTP path.
func NewH2Client(targetURL string, timeout time.Duration, insecure bool, maxHeaderListSize uint32) (*http.Client, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid H2 target URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported H2 target scheme %q", u.Scheme)
	}

	allowHTTP := u.Scheme == "http"
	transport := &http2.Transport{
		AllowHTTP:         allowHTTP,
		MaxHeaderListSize: maxHeaderListSize,
	}

	dialer := &net.Dialer{Timeout: timeout}
	if allowHTTP {
		transport.DialTLSContext = func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		}
	} else {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: insecure,
			NextProtos:         []string{http2.NextProtoTLS},
		}
		transport.DialTLSContext = func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			if cfg == nil {
				cfg = &tls.Config{}
			}
			cfg = cfg.Clone()
			if len(cfg.NextProtos) == 0 {
				cfg.NextProtos = []string{http2.NextProtoTLS}
			}
			return tls.DialWithDialer(dialer, network, addr, cfg)
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return client, nil
}
