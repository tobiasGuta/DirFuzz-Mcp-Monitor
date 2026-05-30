package engine

import "testing"

func TestEvasionScoreboardRanking(t *testing.T) {
	scoreboard := NewEvasionScoreboard()

	base := EvasionStrategiesFor("cloudflare")
	if len(base) < 2 {
		t.Fatalf("expected at least two cloudflare techniques, got %d", len(base))
	}

	// Below the floor, ranking should remain in the static default order.
	scoreboard.Record(base[0].Name, true)
	scoreboard.Record(base[0].Name, false)
	scoreboard.Record(base[0].Name, false)
	scoreboard.Record(base[1].Name, false)
	got := scoreboard.RankedTechniques("cloudflare")
	if got[0].Name != base[0].Name || got[1].Name != base[1].Name {
		t.Fatalf("expected default order below floor, got %q then %q", got[0].Name, got[1].Name)
	}

	// Once the floor is reached, higher bypass rate should sort first.
	scoreboard.Record(base[1].Name, true)
	got = scoreboard.RankedTechniques("cloudflare")
	if got[0].Name != base[1].Name {
		t.Fatalf("expected %q to rank first, got %q", base[1].Name, got[0].Name)
	}
}

func TestMutatePathOnly(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		strategy string
	}{
		{
			input:    "/api/user?id=1",
			expected: "/api/user/?id=1",
			strategy: "trailing-slash",
		},
		{
			input:    "/api/user",
			expected: "/api/user/",
			strategy: "trailing-slash",
		},
		{
			input:    "/api/user?id=1",
			expected: "/api/user/./?id=1",
			strategy: "dot-slash",
		},
		{
			input:    "/api/user?id=1",
			expected: "/%2e/api/user?id=1",
			strategy: "path-dotslash",
		},
	}

	for _, tc := range tests {
		var strategies []EvasionTechnique
		if tc.strategy == "path-dotslash" {
			strategies = EvasionStrategiesFor("cloudflare")
		} else {
			strategies = EvasionStrategiesFor("")
		}

		var matched EvasionTechnique
		found := false
		for _, s := range strategies {
			if s.Name == tc.strategy {
				matched = s
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("strategy %q not found", tc.strategy)
		}

		got, _ := matched.ModifyRequest(tc.input, nil, "GET")
		if got != tc.expected {
			t.Errorf("strategy %q: expected %q, got %q for input %q", tc.strategy, tc.expected, got, tc.input)
		}
	}
}
