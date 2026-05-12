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

### Flag notes that trip people up

- `-e` takes one comma-separated list of extensions. Use `-e php,html,js`, not multiple `-e` flags.
- `-o` writes surfaced results to a file. It does not save every request the scanner sends.
- `--save-raw` stores the raw request/response inside each saved hit when `-o` is enabled.
- `--no-tui` is the cleanest mode when you want a plain JSONL file for piping or later analysis.

Here is a strategic workflow for how to use DirFuzz effectively in a real-world engagement:

* * * * *

1\. The Recon Phase: "Deep & Quiet"
-----------------------------------

Before going loud, you want to map the hidden structure without being blocked. Use `--calibrate` to handle those annoying custom "soft-404" pages and `-af` (Auto-filter) to ignore junk.

Bash

```
# Calibrate against wildcards, use recursion, and output to JSONL for your logs
dirfuzz -u https://api.target.com -w common.txt --calibrate -r -depth 2 -o initial_recon.jsonl

```

-   **Why:** `--calibrate` baselines the server's behavior. If everything returns a 200 with 1243 bytes, DirFuzz will stop bothering you with those results.

2\. The Manual Bridge: "The Burp Workflow"
------------------------------------------

This is the "Killer Feature." Instead of copy-pasting URLs into Burp Suite, let DirFuzz act as your scout while you sit in the Repeater.

Bash

```
dirfuzz -u https://target.com -w big.txt -t 60 --proxy-out http://127.0.0.1:8080

```

-   **Tactical Tip:** Launch with the **TUI enabled**. When you see a suspicious `403 Forbidden` or a `500 Internal Server Error`, hit **`r`**. It instantly fires that exact request into **Burp Repeater**, allowing you to test for bypasses (like `X-Forwarded-For` or path normalization) immediately.

3\. Targeting APIs: "Method Swapping"
-------------------------------------

Many hunters miss vulnerabilities because they only use `GET`. The `--smart-api` flag is high-signal for API bug hunting.

Bash

```
dirfuzz -u https://target.com/api/v2/ -w api_endpoints.txt --smart-api -m GET,POST,PUT,DELETE,PATCH

```

-   **Why:** `--smart-api` is intelligent. It won't try `DELETE` on a standard image directory, but it *will* cycle methods on paths that look like REST endpoints, potentially uncovering unauthorized data modification.

4\. The "Eagle Mode" for Continuous Income
------------------------------------------

If you are on a long-term private program, "New" is your best friend. New endpoints often lack the hardened security of the old ones.

Bash

```
# Day 1: Establish baseline
dirfuzz -u https://target.com -w discovery.txt -o baseline.jsonl

# Day 7: Run Eagle Mode
dirfuzz -u https://target.com -w discovery.txt --eagle baseline.jsonl

```

-   **Why:** `--eagle` filters out everything you've already seen. It highlights **only what changed**. If a developer pushes a `/dev/` or `/backup/` folder on a Friday night, Eagle mode surfaces it instantly.

5\. Hunting for Hidden Treasures: "The Mutator"
-----------------------------------------------

Backups and swap files are gold mines for source code disclosure.

Bash

```
dirfuzz -u https://target.com -w files.txt -e php,asp,aspx --mutate

```

-   **Why:** The `--mutate` flag will automatically check for `config.php.bak`, `index.php~`, or `.DS_Store`. These often contain hardcoded credentials or logic that the main app hides.

6\. Advanced: The "Active PoC" (Lua)
------------------------------------

When a new CVE drops (like a Log4Shell or Spring4Shell), you can use the Lua engine to test for it at scale without needing a separate tool.

Bash

```
dirfuzz -u https://target.com -w subdomains.txt -active-poc plugins/cve-2024-xxxx.lua

```

-   **Why:** This allows for multi-stage fuzzing. Your Lua script can see a `403`, try a specific bypass header, and if it gets a `200`, log it as a critical hit.

* * * * *

### Pro-Tip: The "Bug Hunter's Stealth" Combo

If you suspect a WAF (Cloudflare/Akamai) is tracking you:

1.  **`-delay 200ms`**: Slow down to stay under the radar.

2.  **`--proxy proxy_list.txt`**: Rotate your IP address through a list of SOCKS5 proxies to avoid IP-based rate limiting.

3.  **`-ua "Custom User Agent"`**: Mimic a common browser or a known crawler.

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

When `-o` is set, DirFuzz writes the results it surfaces as hits. The default format is `jsonl`, which is the most useful option for baselining, diffing, and later analysis. You can switch to `csv` for spreadsheet workflows or `url` for a clean list of paths suitable for piping. If you want a file that is easy to inspect line-by-line, pair `-o` with `--no-tui`.

`--save-raw` adds the raw HTTP request/response bytes to each saved hit. It does not create a full request log by itself, and it only affects results that are actually written.

For standalone summaries, use `--report` with `--report-format html|markdown`.

* * * * *

## DirFuzz

https://github.com/user-attachments/assets/ec012ec6-6230-423c-8564-9df753e4c5a7

## Contributing
Contributions and community bug reports are openly accepted. The project is managed with clear separation across plugins, engines, UI, and external integrations. Please log issues and open discussion threads before large refactors.

* * * * *

## License
MIT
