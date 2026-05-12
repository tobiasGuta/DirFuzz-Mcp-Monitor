# 🦇 DirFuzz v3.0

DirFuzz is a memory-efficient, high-performance web security testing and directory fuzzing engine. It is designed for a wide range of use cases, from large-scale automated scans and continuous monitoring to detailed manual vulnerability hunting and safe, AI-driven automation.

This repository contains:
- The core high-performance fuzzing **engine** (`pkg/engine`), which can be embedded in other Go applications.
- A powerful **CLI runner** (`cmd/dirfuzz`) with a rich TUI for interactive fuzzing.
- A **continuous monitoring** runner (`cmd/monitor`) for scheduled, automated security checks.
- An **MCP (Model Context Protocol) Server** (`cmd/mcp`) for secure integration with AI assistants.

* * * * *

## Key Capabilities & Features

DirFuzz transcends a simple directory enumerator, acting as a complete protocol fuzzing suite tightly integrated with both AI environments and manual bug bounty workflows.

-   **High-Performance HTTP Engine:** Built on a custom raw HTTP/1.1 and **HTTP/2** client with state-of-the-art connection pooling. It features **chunked transfer encoding** support, TLS cipher randomization, persistent connection recycling, and **SOCKS5/HTTP Proxy Rotation**.
-   **WAF Fingerprinting & Evasion:** Automatically fingerprints responses against major Web Application Firewalls (AWS WAF, Cloudflare, Akamai, Barracuda, F5). 
-   **Suite Bridge & Interactive TUI:** An interactive Terminal UI featuring real-time logging, response insights, and a **Suite Bridge**. With a single keystroke, you can send any discovered endpoint straight to **Burp Suite Repeater (`r`)** or **Intruder (`i`)**.
-   **Lua Plugin Ecosystem:** Write custom fuzzing logic using the built-in parallel Lua VM pool:
    -   **Transformers:** Manipulate requests raw on-the-fly (`transform_plugin.go`).
    -   **Matchers & Mutators:** Define custom payload generation and match signatures.
    -   **Active PoC:** Enables dynamic, multi-stage exploitation (e.g. `Spring4Shell`) directly from Lua using the exposed `http_send()` function. 
-   **Smart Target & Recursion Tracking:** Configurable `MaxDepth` recursion, intelligent wildcard calibration (`--calibrate`) to baseline soft-404s, and `SmartAPI` mode to heavily restrict method-fuzzing permutations uniquely to fuzzy path patterns (`/api/`, `/v1/`).
-   **Advanced Filtering & Deduplication:** Filter by HTTP codes, response sizes, payload content boundaries, regex body matches, word/line counts, or strict response time thresholds. Employs a low-contention Bloom filter for instant memory-efficient deduplication, alongside an **AutoFilter threshold** (`-af`) to silently suppress recurring spam sizes.
-   **WebSocket Frame Tracking:** Configurable WebSocket frame extraction and logging constraint (`--max-ws-frames`) extending scope across WS endpoints.
-   **Eagle Mode & State Monitoring:** Conduct differential scans (`--eagle`) against previous baseline JSONL persistence files. A `cmd/monitor` binary orchestrates continuous execution hooks and **Discord webhook alerting** upon discovering new endpoints.
-   **Safe AI Tooling (MCP):** A completely isolated Model Context Protocol (MCP) server that exposes fuzzing APIs `dirfuzz_scan` & `dirfuzz_list_wordlists` to Claude or Copilot—fortified by strict SSRF prevention, H1-Scope JSON validator, and path-traversal resistant wordlist selection.

* * * * *

## Provided Binaries & Runners

-   `cmd/dirfuzz`: The CLI runner encompassing the complete platform including the TUI, proxy forwarding (`--proxy-out`), reports, plugins, resume capabilities, and eagle mode.
-   `cmd/monitor`: A continuous monitor executing background loops over environment-driven configs to deliver JSONL differential alerting securely over Webhooks.
-   `cmd/mcp`: The Model Context Protocol abstraction layer exposing secure capabilities to underlying LLMs.

* * * * *

## Build & Deploy

Requirements: Go 1.22+

**Build the Go Binaries:**
```bash
go build -o dirfuzz ./cmd/dirfuzz
go build -o dirfuzz-monitor ./cmd/monitor
go build -o dirfuzz-mcp ./cmd/mcp
```

**Docker / Compose:**
The included `docker-compose.yml` can build and run the monitor image and mount your wordlists and state files.
1.  Copy `.env.example` to `.env` and configure your deployment targets.
2.  Ensure your wordlists are located in the `./wordlists` directory.
3.  Run `docker compose up --build -d` to start the monitor.

* * * * *

## Example Usage

**CLI Fuzzing (With TUI and Proxying):**
```bash
# Fuzz deeply, send through local Burp proxy out-of-the-box
./dirfuzz -u https://api.example.com -w wordlists/common.txt -t 50 -r -depth 3 --proxy-out http://127.0.0.1:8080
```

**CLI Headless Fuzzing (Save to JSONL):**
```bash
# Great for continuous baselining or piping into analysis workflows
./dirfuzz --no-tui -u https://example.com -w wordlists/common.txt -o results.jsonl -v
```

**Lua Active PoC Bridge:**
```bash
./dirfuzz -u https://target.com -active-poc plugins/spring4shell.lua
```

**Eagle Mode (Differential Scan against Baseline):**
```bash
./dirfuzz -u https://api.example.com -w wordlists/common.txt --eagle previous_scan.jsonl
```

**Continuous Monitor (Env-driven):**
```bash
export TARGET=https://target.example.com
export WORDLIST=/data/wordlists/common.txt
export DISCORD_WEBHOOK=https://discordapp/api/webhooks/...
export STATE_FILE=/data/state.jsonl
export SCAN_INTERVAL=1h
./dirfuzz-monitor
```

* * * * *

## Engine & Embedding

The scanning engine is implemented in `pkg/engine` and fully accommodates dependency embedding into other Go solutions.

It offers a robust `Config` struct that natively drives logic across:
- Connection pooling & HTTP/2 transports.
- Outbound forwarding via `proxy-out`.
- Recursive depth scanning and bounding concurrency.
- Built-in persistence for checkpoint resumption (`LoadPreviousScan`).

* * * * *

## Advanced Integrations

### Lua Plugin Handlers
Place Lua scripts inside the `plugins/` directory or inject statically via CLI arguments (`--plugin-match` / `--plugin-mutate` / `--active-poc`).
A pool of Lua VMs will execute handlers in parallel with high-performance CGO boundaries isolating custom behaviors securely from core concurrency blocks.

### TUI Suite Bridge Integrations
Upon launching the binary (without `--no-tui`), users navigate fuzzing results concurrently. The selection pane intercepts native commands:
- **`r`** pipes current endpoint and session attributes directly to the Repeater.
- **`i`** intercepts and injects parameters straight into Intruder deployments.

* * * * *

## Output Exports

By default, DirFuzz employs `jsonl` representing resilient, parseable representations of scanning artifacts. You can toggle across tabular `csv` outputs globally, clean `url` extractions (ideal for stdout piping), or generate complex vulnerability summaries over standalone `--report-format html|markdown`.

* * * * *

## DirFuzz

https://github.com/user-attachments/assets/ec012ec6-6230-423c-8564-9df753e4c5a7

## Contributing
Contributions and community bug reports are openly accepted. The project is managed with clear separation across plugins, engines, UI, and external integrations. Please log issues and open discussion threads before large refactors.

* * * * *

## License
MIT
