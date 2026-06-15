package main

import (
	"testing"
	"time"

	"dirfuzz/pkg/engine"
)

func TestMonitor_HangingScanTimeout(t *testing.T) {
	resultsCh := make(chan engine.Result)
	aborted := make(chan struct{})

	results, timedOut := collectScanCycleResults(resultsCh, 10*time.Millisecond, func() {
		close(aborted)
	}, nil)
	if !timedOut {
		t.Fatal("expected hanging result stream to time out")
	}
	if len(results) != 0 {
		t.Fatalf("expected no results, got %d", len(results))
	}
	select {
	case <-aborted:
	default:
		t.Fatal("expected timeout to abort the scan")
	}
}

func TestMonitorMaxScanDurationDefaultsToNinetyPercentInterval(t *testing.T) {
	setRequiredMonitorEnv(t)
	t.Setenv("SCAN_INTERVAL", "10m")
	t.Setenv("MAX_SCAN_DURATION", "")

	cfg, err := loadConfigFromEnv()
	if err != nil {
		t.Fatalf("loadConfigFromEnv: %v", err)
	}
	if cfg.MaxScanDuration != 9*time.Minute {
		t.Fatalf("MaxScanDuration = %s, want 9m", cfg.MaxScanDuration)
	}
}

func TestMonitorMaxScanDurationFromEnv(t *testing.T) {
	setRequiredMonitorEnv(t)
	t.Setenv("SCAN_INTERVAL", "10m")
	t.Setenv("MAX_SCAN_DURATION", "5s")

	cfg, err := loadConfigFromEnv()
	if err != nil {
		t.Fatalf("loadConfigFromEnv: %v", err)
	}
	if cfg.MaxScanDuration != 5*time.Second {
		t.Fatalf("MaxScanDuration = %s, want 5s", cfg.MaxScanDuration)
	}
}

func setRequiredMonitorEnv(t *testing.T) {
	t.Helper()
	t.Setenv("TARGET", "https://example.com")
	t.Setenv("WORDLIST", "wordlists/common.txt")
	t.Setenv("DISCORD_WEBHOOK", "")
	t.Setenv("NOTIFY_PROVIDER_CONFIG", "")
	t.Setenv("STATE_FILE", "state.jsonl")
	t.Setenv("SCAN_JITTER", "")
	t.Setenv("WORKERS", "")
	t.Setenv("MATCH_CODES", "")
	t.Setenv("METHOD", "")
	t.Setenv("HEADERS", "")
	t.Setenv("EXTENSIONS", "")
	t.Setenv("LOG_LEVEL", "info")
	t.Setenv("ALLOW_PRIVATE_TARGETS", "")
	t.Setenv("HARVEST_PASSIVE", "")
	t.Setenv("OTX_API_KEY", "")
	t.Setenv("OOB", "")
	t.Setenv("INTERACTSH_SERVER", "")
	t.Setenv("INTERACTSH_TOKEN", "")
}
