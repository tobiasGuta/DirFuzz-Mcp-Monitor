package scope

import (
	"testing"
)

func TestIsAllowed(t *testing.T) {
	assets := []Asset{
		{AssetIdentifier: "api.example.com", AssetType: "URL", EligibleForBounty: true},
		{AssetIdentifier: "*.example.com", AssetType: "WILDCARD", EligibleForBounty: true},
		{AssetIdentifier: "192.168.1.1", AssetType: "IP_ADDRESS", EligibleForBounty: true},
		{AssetIdentifier: "2001:db8::1", AssetType: "IP_ADDRESS", EligibleForBounty: true},
		{AssetIdentifier: "10.0.0.0/8", AssetType: "CIDR", EligibleForBounty: true},
	}

	tests := []struct {
		name     string
		target   string
		expected bool
	}{
		{"Direct URL match", "api.example.com", true},
		{"Subdomain wildcard match", "test.example.com", true},
		{"Multi-level subdomain wildcard match", "a.b.c.example.com", true},
		{"Apex domain no match", "example.com", false},
		{"IPv4 match", "192.168.1.1", false}, // Currently unsupported
		{"IPv6 match", "2001:db8::1", false}, // Currently unsupported
		{"CIDR match", "10.0.0.1", false},    // Currently unsupported
		{"No match", "another.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsAllowed(tt.target, assets); got != tt.expected {
				t.Errorf("IsAllowed() = %v, want %v", got, tt.expected)
			}
		})
	}
}
