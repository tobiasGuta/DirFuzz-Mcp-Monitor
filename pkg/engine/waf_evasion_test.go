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
