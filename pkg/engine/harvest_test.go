package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHarvestEndpointsFull(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><head><script src="/assets/app.js"></script></head><body>{"endpoints":["/api/user","/api/jobs","/api/applications"]}</body></html>`))
		case "/assets/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(`
				const apiBase = "/v2";
				fetch("/api/v1/users");
				axios.get("/admin/panel");
				const chunks = {0:"reports/list"};
			`))
		case "/openapi.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"paths": {"/users": {}, "/orders": {}},
				"servers": [{"url": "https://example.test/api"}]
			}`))
		case "/graphql":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"data": {
					"__schema": {
						"types": [{
							"name": "OrderHistory",
							"fields": [{"name": "createdAt"}, {"name": "userProfile"}]
						}]
					}
				}
			}`))
		case "/api/graphql", "/v1/graphql":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"__schema":{"types":[]}}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	got := HarvestEndpoints(context.Background(), srv.URL, client)

	want := []string{
		"/admin/panel",
		"/api",
		"/api/applications",
		"/api/jobs",
		"/api/user",
		"/api/v1/users",
		"/orders",
		"/reports/list",
		"/users",
		"/v2",
		"OrderHistory",
		"created-at",
		"created_at",
		"createdAt",
		"order-history",
		"order_history",
		"user-profile",
		"user_profile",
		"userProfile",
	}

	for _, wantItem := range want {
		if !containsString(got, wantItem) {
			t.Fatalf("HarvestEndpoints() missing %q in %v", wantItem, got)
		}
	}
}

func TestHarvestEndpointsModes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><head><script src="/bundle.js"></script></head><body>{"endpoints":["/api/from-response"]}</body></html>`))
		case "/bundle.js":
			_, _ = w.Write([]byte(`fetch("/api/from-js")`))
		case "/openapi.json":
			_, _ = w.Write([]byte(`{"paths":{"/api/from-spec":{}}}`))
		case "/graphql":
			_, _ = w.Write([]byte(`{"data":{"__schema":{"types":[{"name":"GraphUser","fields":[{"name":"userToken"}]}]}}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 5 * time.Second}

	jsOnly := harvestEndpointsWithOptions(nil, context.Background(), srv.URL, client, harvestOptions{js: true})
	if !containsString(jsOnly, "/api/from-js") {
		t.Fatalf("js-only harvest missing JS endpoint: %v", jsOnly)
	}
	if containsString(jsOnly, "/api/from-spec") || containsString(jsOnly, "GraphUser") {
		t.Fatalf("js-only harvest leaked API candidates: %v", jsOnly)
	}

	apiOnly := harvestEndpointsWithOptions(nil, context.Background(), srv.URL, client, harvestOptions{api: true})
	if !containsString(apiOnly, "/api/from-spec") || !containsString(apiOnly, "GraphUser") {
		t.Fatalf("api-only harvest missing API candidates: %v", apiOnly)
	}
	if containsString(apiOnly, "/api/from-js") {
		t.Fatalf("api-only harvest leaked JS candidates: %v", apiOnly)
	}

	responseOnly := harvestEndpointsWithOptions(nil, context.Background(), srv.URL, client, harvestOptions{
		response:           true,
		responseMaxDepth:   DefaultHarvestResponseDepth,
		responseMaxFetches: DefaultHarvestResponseFetch,
	})
	if !containsString(responseOnly, "/api/from-response") {
		t.Fatalf("response-only harvest missing JSON response endpoint: %v", responseOnly)
	}
	if containsString(responseOnly, "/api/from-js") || containsString(responseOnly, "/api/from-spec") || containsString(responseOnly, "GraphUser") {
		t.Fatalf("response-only harvest leaked non-response candidates: %v", responseOnly)
	}
}

func TestHarvestResponseFollowsDiscoveredAPIEndpoints(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"endpoints":["/api/jobs"]}`))
		case "/api/jobs":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"endpoints":["/api/applications"]}`))
		case "/api/applications":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"endpoints":["/api/applications/detail"]}`))
		case "/api/applications/detail":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	got := harvestEndpointsWithOptions(nil, context.Background(), srv.URL, client, harvestOptions{
		response:           true,
		responseMaxDepth:   DefaultHarvestResponseDepth,
		responseMaxFetches: DefaultHarvestResponseFetch,
	})

	for _, want := range []string{"/api/jobs", "/api/applications", "/api/applications/detail"} {
		if !containsString(got, want) {
			t.Fatalf("response follow-up harvest missing %q in %v", want, got)
		}
	}
}

func TestHarvestResponseHonorsDepthLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"endpoints":["/api/jobs"]}`))
		case "/api/jobs":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"endpoints":["/api/applications"]}`))
		case "/api/applications":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"endpoints":["/api/applications/detail"]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	got := harvestEndpointsWithOptions(nil, context.Background(), srv.URL, client, harvestOptions{
		response:           true,
		responseMaxDepth:   1,
		responseMaxFetches: DefaultHarvestResponseFetch,
	})

	if !containsString(got, "/api/jobs") {
		t.Fatalf("depth-limited harvest missing first hop endpoint: %v", got)
	}
	if !containsString(got, "/api/applications") {
		t.Fatalf("depth-limited harvest missing endpoint discovered from first follow-up: %v", got)
	}
	if containsString(got, "/api/applications/detail") {
		t.Fatalf("depth-limited harvest exceeded configured depth: %v", got)
	}
}

func containsString(values []string, want string) bool {
	for _, v := range values {
		if strings.EqualFold(v, want) || v == want {
			return true
		}
	}
	return false
}
