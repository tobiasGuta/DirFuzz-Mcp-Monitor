package netutil

import (
	"context"
	"net"
	"strings"
	"time"
)

// IsPrivateHost returns true when host is a loopback/private IP, or resolves
// to one via DNS.
func IsPrivateHost(host string) bool {
	lower := strings.ToLower(host)
	if lower == "" {
		return false
	}
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") {
		return true
	}

	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = append(ips, ip)
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		addrs, err := net.DefaultResolver.LookupHost(ctx, host)
		if err != nil || len(addrs) == 0 {
			// Fail closed: refuse targets we can't resolve, since the engine
			// will resolve at request time and may pick up a private address.
			return true
		}
		for _, addr := range addrs {
			if parsed := net.ParseIP(addr); parsed != nil {
				ips = append(ips, parsed)
			}
		}
	}

	if len(ips) == 0 {
		return true
	}

	for _, testIP := range ips {
		if IsPrivateIP(testIP) {
			return true
		}
	}
	return false
}

// IsPrivateIP reports whether ip is loopback, private, link-local, or otherwise
// local-only for DirFuzz outbound safety checks.
func IsPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, cidr := range []string{
		"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
	} {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
