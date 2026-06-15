package httpclient

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestEngine_DNSRebinding(t *testing.T) {
	oldLookup := lookupIPAddrContext
	lookupIPAddrContext = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		if host != "rebind.test" {
			t.Fatalf("unexpected lookup host %q", host)
		}
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}
	t.Cleanup(func() {
		lookupIPAddrContext = oldLookup
	})

	raw := []byte("GET / HTTP/1.1\r\nHost: rebind.test\r\nConnection: close\r\n\r\n")
	_, err := SendRawRequestWithContextPolicy(context.Background(), "http://rebind.test/", raw, time.Second, "", false, false)
	if err == nil {
		t.Fatal("expected private rebinding address to be rejected")
	}
	if !strings.Contains(err.Error(), "SSRF protection") {
		t.Fatalf("unexpected error: %v", err)
	}
}
