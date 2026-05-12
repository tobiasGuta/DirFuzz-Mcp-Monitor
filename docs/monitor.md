# DirFuzz Monitor

## Overview

The Monitor is a lightweight, standalone runner that periodically exercises a target web application using the DirFuzz engine and records a compact state snapshot of responses. It's intended for continuous, scheduled checks to detect configuration changes, content drift, regressions, or newly exposed paths.

## Key features

- Periodic scans of a target using the same fuzzing engine used by DirFuzz.
- Configurable scan interval and jitter to stagger runs across instances.
- JSONL state persistence (atomic writes) so each run produces a durable snapshot.
- Detection of content drift and size/duration changes; keeps previous state for comparison.
- Optional Discord webhook alerting for interesting findings (optional, not required).
- Configurable HTTP methods, headers, extensions and match status codes.
- Safe defaults and operator controls (e.g., private target scanning guarded by env var).

## How it works

1. The monitor reads configuration from environment variables.
2. On each cycle it instantiates an Engine configured with the provided wordlist/target.
3. It runs a scan over the wordlist and collects `Result` records for matches (status, size, headers, timing, etc.).
4. A SHA256 body hash is computed per-path (if raw bodies are available) to detect content changes reliably.
5. Results are written atomically to the configured state file in JSONL format.
6. If a finding is considered "interesting" (status code, content or size drift), it is logged and — if configured — sent to the Discord webhook.

## Output / State file

The monitor writes a JSONL file (one JSON object per line) containing a snapshot of `engine.Result` plus a `body_hash` field. Example fields you may see:

- `path` — the fuzzed path (relative path)
- `status` — HTTP status code
- `length` — response body size in bytes
- `words`, `lines` — simple content metrics
- `content_type` — detected Content-Type header
- `duration` — request duration
- `url` — full URL (if available)
- `request`, `response` — raw request/response (present only when the engine is configured to save raw data)
- `content_drift`, `old_size`, `old_words`, `drift_delta_bytes`, `old_status` — fields used to indicate changes compared to the previous snapshot
- `body_hash` — SHA256 (hex) of the normalized response body used for robust content-change detection

Because the file is JSONL and written atomically, it can be ingested by other tools, archived, or diffed by operator scripts.

## Configuration (environment variables)

The monitor is configured exclusively via environment variables. Important ones:

- `TARGET` (required): base target URL, e.g. `https://example.com`.
- `WORDLIST` (required): path to the wordlist used for fuzzing.
- `DISCORD_WEBHOOK` (optional): if set, monitors will POST findings to this webhook; otherwise findings are logged only.
- `STATE_FILE` (optional): path for the JSONL snapshot. Defaults to `/data/state.jsonl`.
- `SCAN_INTERVAL` (optional): e.g. `1h`, `30m`. Defaults to `1h`. Very short intervals are clamped to a safe minimum.
- `SCAN_JITTER` (optional): add random jitter (e.g. `10m`) to stagger multiple monitors.
- `WORKERS` (optional): number of concurrent workers used by the internal engine.
- `MATCH_CODES` (optional): comma-separated status codes considered hits (default `200,301,302,403`).
- `METHOD` (optional): specific HTTP method to use.
- `HEADERS` (optional): semicolon-separated `Key:Value` pairs for custom headers.
- `EXTENSIONS` (optional): comma-separated file extensions to append during fuzzing.
- `LOG_LEVEL` (optional): `info` or `debug`.
- `ALLOW_PRIVATE_TARGETS` (optional): `true|false` to allow scanning private IPs/hosts (use with caution).

For full control of the engine there are additional configuration knobs exposed in code; use environment variables and the engine API for advanced use cases.

## Benefits of using the Monitor

- Continuous visibility: detects regressions and unexpected content changes quickly.
- Low operational overhead: runs the same engine used for one-off scans, so results are consistent with your local runs.
- Alerting-ready: add `DISCORD_WEBHOOK` to receive near-real-time notifications when new findings are discovered.
- Durable, auditable state snapshots via JSONL make it easy to track changes over time or feed into downstream automation.

## Best practices

- Run the monitor from a small, dedicated host or container with a stable schedule (cron/kubernetes CronJob, systemd timer, etc.).
- Configure `SCAN_JITTER` when running multiple monitors to avoid thundering herds.
- Keep `SCAN_INTERVAL` at a reasonable cadence for the target (hourly/daily), and avoid very tight intervals unless you understand the load impact.
- Use `DISCORD_WEBHOOK` or other alerting connectors only for confirmed, high-confidence findings to avoid noise.
- Store `STATE_FILE` on persistent storage (or object storage) if you want long-term history.

## Example run

Populate environment and run the binary (example):

```bash
export TARGET=https://example.com
export WORDLIST=./wordlists/common.txt
export STATE_FILE=./monitor_state.jsonl
export SCAN_INTERVAL=1h
# optional: export DISCORD_WEBHOOK="https://discordapp.com/api/webhooks/..."
./cmd/monitor/monitor
```

(Replace the binary path with your preferred run method, e.g. `go run ./cmd/monitor` or a packaged container.)

## Troubleshooting & notes

- If you rely on raw request/response storage for reliable content hashing, make sure the engine is configured to retain raw data; otherwise `body_hash` may be empty.
- The monitor is conservative about private/internal IP targets; enabling `ALLOW_PRIVATE_TARGETS` bypasses the guard and should be done intentionally.
- The JSONL state is intended as a compact, machine-friendly snapshot. If you need richer change history, archive snapshots externally (timestamped files) and diff them.


