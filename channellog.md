# DirFuzz MCP Monitor Change Log

This file is the single place for update notes and changelog entries.

## Security and Reliability Fixes

### MCP scan approval and scope enforcement

- Added approval-token enforcement to `dirfuzz_expand`.
- Added scope validation for `dirfuzz_expand` using the configured scope directory.
- Changed `dirfuzz_expand` to use the stricter scan rate limit.
- Added `approval_token` as a documented `dirfuzz_expand` argument.
- Updated the tool description so expansion is described as approved and scope-checked.

### MCP probe target validation

- Updated WAF probe, parameter fuzzing, and auth-test target resolution.
- Absolute probe URLs are now rejected unless their hostname matches the original scan target hostname.
- Relative probe paths continue to resolve against the original scan target.

### MCP token and scan-state safety

- Replaced direct approval-token string comparison with constant-time comparison.
- Cleared completed scan engine pointers so finished scans can release engine memory.
- Moved `scanState.canceled` reads under the existing scan-state lock to avoid a data race.

### Dial-time private IP filtering

- Added reusable private-IP checking in `pkg/netutil`.
- Added dial-time DNS resolution and private-IP rejection in the raw HTTP client.
- Direct dials now resolve once, reject private or loopback IPs when private targets are disabled, and dial the validated IP.
- Added HTTP/2 client support for the same private-target policy.
- Threaded `AllowPrivateTargets` through engine raw requests, HTTP/2 client refresh, and harvest clients.

### Monitor scan timeout

- Added `MAX_SCAN_DURATION` support for the monitor.
- Default monitor max scan duration is now 90% of `SCAN_INTERVAL`.
- Monitor scan result collection now aborts the current engine when the max duration is exceeded.
- Timed-out scan cycles return an explicit timeout error so the scheduler can continue.

### Configuration and audit-log hygiene

- Added `DIRFUZZ_SCAN_ENABLED=false` to `dirfuzz-mcp.env.example`.
- Added a commented `DIRFUZZ_SCAN_APPROVAL_TOKEN` example with a safety note.
- Added local `dirfuzz-audit.jsonl` paths to `.gitignore`.

## Tests Added or Updated

- Added MCP tests for `dirfuzz_expand` rejecting disabled scans, missing approval tokens, and out-of-scope targets.
- Added MCP tests for rejecting different-host absolute probe URLs and allowing same-host absolute probe URLs.
- Added MCP test to verify completed scan states clear their engine pointer.
- Added DNS rebinding regression coverage in `pkg/httpclient`.
- Added monitor timeout and `MAX_SCAN_DURATION` config tests.

## Verification Run

The focused packages touched by these changes passed:

```powershell
go test ./pkg/netutil
go test ./pkg/httpclient
go test ./cmd/mcp
go test ./cmd/monitor
```

`go test ./pkg/engine` was also attempted, but the package timed out in the existing `TestChangeWordlistConcurrency` test.

## Historical Updates

### 2026-05-27

- Added a native Nuclei Orchestrator Subprocess. When `--nuclei` is passed, DirFuzz streams discovered URLs directly into Nuclei's `stdin` via a dedicated subprocess.
- Parsed Nuclei's JSONL `stdout` in real-time, mapping the template findings natively into DirFuzz's TUI and output log with the `NUCLEI` label.
- Implemented concurrent deduplication (`sync.Map`) so Nuclei never double-scans the same endpoint.

### 2026-05-26

- Added anomaly-only TUI filtering with `a` and `:anomalies [on|off|toggle]` so the visible hit list can collapse down to eagle alerts, drift, discovered params, bypasses, auth-matrix findings, timing-oracle hits, and manual marks.
- Added in-TUI triage marking so selected hits can be toggled as interesting with `t`, surfaced visually in the list/detail views, and restored from append-mode UI state on reopen.
- Added repeatable `--exclude-path` regex support so authenticated, recursive, and harvested scan work can skip unsafe routes such as logout, delete, destroy, or reset endpoints before they ever hit the queue.
- Added repeater clipboard/export actions so requests and responses can be copied without relying on terminal text selection: `Ctrl+Y` copies the request, `Alt+Y` copies the response, `Alt+B` copies both, `Alt+C` copies a generated `curl` command, and `Alt+W` exports the request to a temporary `.http` file.
- Added repeater command-palette actions `:copy-request`, `:copy-response`, `:copy-both`, `:copy-curl`, and `:export-request [file]`.
- Added `--history-mode overwrite|append` so `-o` can either start fresh or keep an append-only JSONL results journal.
- Added persistent TUI restore for append mode, including loading prior hits into the visible list when reopening the same `-o` file.
- Added repeater session persistence in a sidecar file such as `results.jsonl.ui.json`, including restored tabs, per-session history, and saved replay state.
- Made append-mode TUI history merge repeated findings by endpoint identity so the visible list updates to the latest snapshot instead of duplicating every rediscovery.
- Made `:restart` preserve visible history and repeater sessions in append mode while continuing to add or update findings from the new run.
- Extended saved JSONL results with optional raw request/response byte fields so restored hits can keep working with hex, diff, and replay workflows when `--save-raw` is enabled.
- Replaced the markdown-looking dashboard tables with modern card sections using bordered panels.
- Improved the selected row styling in lists to use a left accent bar (`>`) and colorful text instead of a full purple background.
- Redesigned the footer into a compact layout with colored minimalist key chips and muted labels.
- Upgraded the command panel to a full "Command Palette" featuring descriptions for each command and streamlined selected-item styling.
- Added a blinking live status indicator (`SCANNING` or `PAUSED`) to the right side of the footer.
- Fixed an issue where the Repeater's text area rendered an opaque background that obscured transparent terminal backgrounds.

### 2026-05-25

- Added bounded asynchronous 401/403 bypass micro-tasks that try standard path normalization and IP-spoofing headers, and emit labeled `[BYPASS: ...]` findings when a permutation returns a successful response.
- Added JavaScript source map harvesting so `.js` responses can discover hidden routes from `SourceMap` / `X-SourceMap` headers or `sourceMappingURL` directives and feed them back into the fuzzing queue.
- Replaced the monitor's hardcoded Slack/Discord webhook formatter with ProjectDiscovery-style notify provider config loading, so alerts can go through Slack, Discord, Telegram, Pushover, Teams, Gotify, Google Chat, SMTP, or custom webhooks from a standard `provider-config.yaml`.
- Added passive route harvesting from the Wayback Machine, Common Crawl, and AlienVault OTX with per-source timeouts so slow archives cannot hang the scan loop.
- Added optional Interactsh-based OOB payload generation with `--oob`, plus monitor-side polling and webhook alerts for blind SSRF/command-injection style hits.
- Removed `403` from the recursive wildcard shortcut so access-controlled directories are not silently pruned during recursion.
- Fixed recursive scanning noise where child routes such as `api/api`, `api/api/user`, and `api/user/api` could be reported when they returned the same response fingerprint as an already-seen parent or canonical route.
- Added default-on recursive pruning through `--recursive-prune` to report low-value static/resource branches once, then avoid spending recursive depth under paths like `includes/fonts`.
- Made recursive pruning conservative for pentest workflows: static-looking branches are still recursively scanned when their listings expose interesting names such as `config`, `.bak`, `.old`, `.env`, `secret`, `admin`, `api`, or `upload`.

### 2026-05-23

- Removed the built-in hidden-parameter brute-force list and made parameter fuzzing opt-in through `--param-wordlist` / `--param-wordlists`.
- Disabled automatic parameter fuzzing when no parameter wordlist is provided.
- Added smart parameter hint extraction from response text, error messages, HTML forms, and links to augment configured parameter wordlists.
- Deduplicated hidden-parameter probes across repeated URLs that differ only by query values, such as multiple `jobs.php?id=*` findings.
- Fixed redirect-followed parameter fuzzing to probe the final canonical URL instead of the pre-redirect URL, reducing `301` false positives on paths like `/api`.
- Added neutral control probes for hidden-parameter fuzzing to suppress pages that change generically for any query string.
- Added `--harvest-response` for generic response-driven endpoint discovery, including JSON API bodies that list child endpoints.
- Added `--harvest-response-depth` and `--harvest-response-fetch` to tune bounded follow-up crawling for response-driven harvesting.
- Made live scan responses feed response-harvest discoveries back into the active queue, so paths revealed by endpoints like `/api/` are scanned during the same run.
- Fixed harvest progress accounting so harvested jobs count toward total progress instead of pushing scans past 100%.
- Fixed raw request/response capture for hidden-parameter fuzzing when `--save-raw` is enabled.
- Prevented canceled requests from being counted as network failures or retry noise.
- Removed the default 60-second scan cap so normal scans run until completion unless `--max-duration` is set.
- Made the TUI exit cleanly when the engine result stream closes instead of freezing on partial progress.
- Stopped auto param-fuzz from triggering on redirect-only responses.
