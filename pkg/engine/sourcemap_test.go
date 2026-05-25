package engine

import "testing"

func TestExtractSourceMapURL(t *testing.T) {
	headers := map[string]string{
		"X-SourceMap": "app.min.js.map",
	}
	if got := ExtractSourceMapURL(headers, nil); got != "app.min.js.map" {
		t.Fatalf("header source map: got %q", got)
	}

	body := []byte("const a = 1;\n//# sourceMappingURL=/assets/app.min.js.map\n")
	if got := ExtractSourceMapURL(nil, body); got != "/assets/app.min.js.map" {
		t.Fatalf("body source map: got %q", got)
	}
}

func TestExtractSourceMapRoutes(t *testing.T) {
	content := `
		const routes = [
			"/api/v1/users",
			"/v1/admin/export",
			"/settings/profile",
			"/api/v1/users",
		];
	`
	got := extractSourceMapRoutes(content)
	if len(got) == 0 {
		t.Fatal("expected source map routes")
	}
}
