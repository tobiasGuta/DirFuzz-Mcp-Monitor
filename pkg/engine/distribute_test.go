package engine

import "testing"

func TestAggregateSwarmResultsKeepsDistinctPathsWithSameShape(t *testing.T) {
	results := []Result{
		{
			Path:        "/admin",
			URL:         "https://example.test/admin",
			Method:      "GET",
			StatusCode:  200,
			Size:        128,
			Words:       12,
			Lines:       3,
			ContentType: "text/html",
		},
		{
			Path:        "/login",
			URL:         "https://example.test/login",
			Method:      "GET",
			StatusCode:  200,
			Size:        128,
			Words:       12,
			Lines:       3,
			ContentType: "text/html",
		},
	}

	got := AggregateSwarmResults(results, -1, 0)
	if len(got) != 2 {
		t.Fatalf("AggregateSwarmResults() returned %d result(s), want 2", len(got))
	}
}
