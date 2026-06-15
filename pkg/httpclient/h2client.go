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
	return NewH2ClientWithPrivatePolicy(targetURL, timeout, insecure, maxHeaderListSize, true)
}

// NewH2ClientWithPrivatePolicy builds an HTTP/2 client with explicit
// private-network enforcement at dial time.
func NewH2ClientWithPrivatePolicy(targetURL string, timeout time.Duration, insecure bool, maxHeaderListSize uint32, allowPrivateTargets bool) (*http.Client, error) {
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

	if allowHTTP {
		transport.DialTLSContext = func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return dialContextResolved(ctx, network, addr, timeout, allowPrivateTargets, nil)
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
			rawConn, err := dialContextResolved(ctx, network, addr, timeout, allowPrivateTargets, nil)
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(rawConn, cfg)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				rawConn.Close()
				return nil, err
			}
			return tlsConn, nil
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
