# DirFuzz v4.0

DirFuzz is a memory-efficient, high-performance web security testing and directory fuzzing engine. It is built for fast local scans, interactive manual follow-up, raw request/response inspection, authorized distributed execution, and automated monitoring.

## What’s Included

- `cmd/dirfuzz`: the main CLI scanner with the interactive TUI.
- `cmd/monitor`: the scheduled monitoring runner.
- `cmd/mcp`: the MCP server for AI-assisted workflows.
- `pkg/engine`: the reusable scanning engine.

## Key Capabilities

- Fast HTTP/1.1 and HTTP/2 scanning with connection pooling, proxy support, and request mutation.
- Smart filtering with status, size, word/line, regex, response-time, AutoFilter, and SimHash suppression.
- WAF and anti-bot handling, including optional headless fallback when challenge responses are detected.
- Recursive scanning, wildcard calibration, timing-oracle enumeration, and route harvesting from JS/OpenAPI/GraphQL.
- Hidden parameter fuzzing with chunked probes and bisection to isolate interesting parameters.
- Harvesting from JavaScript, OpenAPI, GraphQL, and generic response bodies such as JSON endpoint lists.
- Role-based auth matrix execution for comparing the same path across multiple header/cookie states.
- Raw request/response capture with hex inspection and split-screen replay/diff workflows in the TUI.
- Live system logs, a multi-tab metrics dashboard, log search/filter/export, and context-aware related logs in the TUI.
- Lua plugins for transformers, matchers, mutators, and active proof-of-concept flows.
- Swarm mode for authorized distributed execution. It is opt-in only and stays disabled unless `--swarm` is provided.
- Eagle mode, resume support, and continuous monitoring with webhook alerts.
- MCP integration for scoped AI workflows.

## Build

Requirements: Go 1.24.2 or newer.

```bash
go build -o dirfuzz ./cmd/dirfuzz
go build -o dirfuzz-monitor ./cmd/monitor
go build -o dirfuzz-mcp ./cmd/mcp
```

## Quick Start

### Basic local scan

```bash
./dirfuzz -u https://example.com -w wordlists/common.txt
```

This is the default behavior. No distributed mode is used unless you explicitly pass `--swarm`.

### Headless JSONL output

```bash
./dirfuzz -u https://example.com -w wordlists/common.txt --no-tui -o results.jsonl
```

### Save raw request and response bytes

```bash
./dirfuzz -u https://example.com -w wordlists/common.txt --save-raw
```

`--save-raw` unlocks the raw hex viewer, replay diff workflow, and raw-request replay in the TUI.

### Anti-bot fallback

```bash
./dirfuzz -u https://example.com -w wordlists/common.txt --anti-bot-fallback
```

The fallback is enabled by default. You can disable it with `--anti-bot-fallback=false`.

### Harvest routes before scanning

```bash
./dirfuzz -u https://app.example.com -w wordlists/common.txt --harvest
```

### Harvest endpoints from JSON API responses

```bash
./dirfuzz -u https://api.example.com/api/ -w wordlists/common.txt \
  --harvest-response \
  --harvest-response-depth 3 \
  --harvest-response-fetch 100
```

This is useful for APIs that advertise child routes in ordinary responses, for example:

```json
{
  "endpoints": [
    "/api/user",
    "/api/jobs",
    "/api/applications"
  ]
}
```

`--harvest-response-depth` controls how many follow-up layers DirFuzz will inspect after the initial response, and `--harvest-response-fetch` caps how many follow-up API responses it will fetch during harvesting.

### Blind enumeration with the timing oracle

```bash
./dirfuzz -u https://example.com -w wordlists/common.txt --time-oracle --time-n 5 --time-k 2.5 --time-trim
```

### WAF bypass attempts

```bash
./dirfuzz -u https://example.com -w wordlists/common.txt --bypass-403 --evasion-limit 4
```

### Role-based auth matrix

```bash
./dirfuzz -u https://example.com -w wordlists/common.txt \
  --auth admin="Cookie: session=A" \
  --auth user="Cookie: session=B"
```

You can also define this in a profile with `auth_matrix`.

### Swarm mode

```bash
./dirfuzz -u https://example.com -w wordlists/common.txt --swarm --swarm-nodes 8 --swarm-chunk-size 5000
./dirfuzz -u https://example.com -w wordlists/common.txt --swarm --swarm-provider lambda
```

Swarm mode is completely opt-in. Without `--swarm`, DirFuzz stays local and single-node.

### Lua active PoC

```bash
./dirfuzz -u https://target.com -active-poc plugins/spring4shell.lua
```

### Eagle mode

```bash
./dirfuzz -u https://api.example.com -w wordlists/common.txt --eagle previous_scan.jsonl
```

## TUI Workflow

The TUI is where the new inspection features shine.

- `Enter` on a hit opens the detail view.
- `h` opens the raw request hex view.
- `H` opens the raw response hex view.
- `Tab` toggles request and response inside the hex view.
- `R` saves the selected response as the diff reference.
- `d` opens the split diff view against the saved reference.
- `D` opens the replay diff view from the repeater.
- `r` sends a selected request to the repeater.
- `L` toggles the live log panel.
- `m` cycles the main view between the list, dashboard, and log panel modes.
- `1` to `5` switch between the dashboard analytics tabs.
- `f` cycles the dashboard time range.
- `e` exports the current metrics snapshot to JSON.
- `x` expands or collapses detail rows in the system log panel.
- `Esc` or `q` returns to the previous screen.

The list, dashboard, detail, hex, repeater, and log views all advertise their own shortcut hints in the footer, so the controls stay discoverable without opening a separate help screen.

## Diff and Replay Workflow

1. Run a scan with `--save-raw`.
2. Open a hit in the TUI with `Enter`.
3. Press `R` to save the current response as your reference.
4. Select another hit and press `d` to compare them.
5. Or press `r` to send a request to the repeater, then use `D` to diff the replayed response against the saved reference.

The diff view highlights deleted text in red on the left and added text in green on the right.

## Feature Notes

- `--save-raw` is what enables the hex viewer, replay comparison, and diff screens.
- The TUI includes a live system log stream, a bounded log buffer, log search/filter/export commands, and a split layout that can show logs under the main results list.
- The dashboard includes performance, error, discovery, network, and timeline views with rolling histories.
- `--auth` is repeatable and accepts `role=Header: Value||Header2: Value2`.
- `--swarm-provider lambda` expects a Lambda function name in `DIRFUZZ_SWARM_LAMBDA_FUNCTION`, `SWARM_LAMBDA_FUNCTION`, or `AWS_LAMBDA_FUNCTION_NAME`.
- `--harvest-js` and `--harvest-api` let you narrow route harvesting to one source family.
- `--harvest-response` narrows harvesting to generic HTTP response bodies, which is useful for JSON APIs that advertise child endpoints.
- `--harvest-response-depth` and `--harvest-response-fetch` control how far response-driven harvesting follows discovered API endpoints and how many follow-up fetches it may spend.
- Hidden parameter fuzzing is now opt-in through `--param-wordlist` (or `--param-wordlists`); when no parameter wordlist is provided, automatic param fuzzing stays off.
- `--no-tui` is the best choice when you want machine-readable JSONL output.
- `-e` accepts a comma-separated extension list such as `-e php,html,js`.

## Suggested Workflow

1. Start with `--calibrate` and `-af` to suppress wildcard and soft-404 noise.
2. Add `--harvest` to seed the queue with app-specific routes.
3. Use `--save-raw` when you want hex, replay, or diff inspection.
4. Add `--param-wordlist path/to/params.txt` when you want hidden parameter fuzzing during a scan.
5. Enable `--anti-bot-fallback` on targets that present WAF or challenge behavior.
6. Use `--auth` when you want to compare the same path across multiple roles.
7. Turn on `--swarm` only for authorized distributed execution.
8. Export with `--no-tui -o results.jsonl` when you want a clean JSONL stream.

## Monitoring and MCP

- `cmd/monitor` runs recurring scans and can alert on new findings.
- `cmd/mcp` exposes the scanner through MCP for scoped AI workflows.

## Docker / Compose

The included `docker-compose.yml` can build and run the monitoring workflow.

1. Copy `.env.example` to `.env` and configure your targets.
2. Place wordlists in `./wordlists`.
3. Run `docker compose up --build -d`.

## Final Notes

- Normal scans are local and single-node by default.
- Distributed execution only happens when `--swarm` is explicitly provided.
- The TUI, raw capture, auth matrix, and replay/diff features work without extra setup; hidden parameter fuzzing requires `--param-wordlist`.
