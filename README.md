# 🦇 DirFuzz v3.0

DirFuzz is a memory-efficient, high-performance web security testing and directory fuzzing engine. It is designed for a wide range of use cases, from large-scale automated scans and continuous monitoring to detailed manual vulnerability hunting and safe, AI-driven automation.

This repository contains:
- The core high-performance fuzzing **engine** (`pkg/engine`), which can be embedded in other Go applications.
- A powerful **CLI runner** (`cmd/dirfuzz`) with an optional TUI for interactive fuzzing.
- A **continuous monitoring** runner (`cmd/monitor`) for scheduled, automated security checks.
- An **MCP (Model Context Protocol) server** (`cmd/mcp`) for secure integration with AI assistants.

* * * * *

## Recent Updates

-   **Security Hardening:**
    -   **SSRF & DNS Rebinding:** Patched critical Time-of-Check to Time-of-Use (TOCTOU) vulnerabilities in target validation.
    -   **Path Traversal:** Secured the MCP server against wordlist path traversal attacks.
    -   **Origin Validation:** Locked down WebSocket and CORS origins to prevent cross-origin hijacking.
-   **State & Concurrency:**
    -   Rewrote the JSONL persistence layer (`pkg/store`) to prevent data loss and panics during high-speed I/O.
    -   Reduced Bloom filter lock contention for faster concurrent scanning.
-   **Protocol & Performance Fixes:**
    -   Solved data races in regex filtering.
    -   Improved HTTP/1.0 keep-alive discarding.
    -   Added robust support for Brotli compression.
    -   Mitigated CRLF injection risks in raw request building.
-   **Active PoC Bridge:** Lua scripts can now perform active HTTP requests using the `http_send()` function, enabling more dynamic and powerful proof-of-concept testing.

* * * * *

## Highlights

-   **Advanced Engine:** High-performance raw HTTP/1.1 client with connection pooling, TLS cipher randomization, and SOCKS5/HTTP proxy support.
-   **Memory Efficiency:** Deduplication using a Bloom filter, per-host rate limiting, and safe concurrent state persistence.
-   **Rich Filtering:** Status codes, content-type, response sizes, regex body matching, word/line counts, and response time ranges.
-   **Eagle Mode & Resume:** Differential scans against previous JSONL baselines to easily spot new or modified endpoints.
-   **Lua Plugin System:** Parallel VM pool for writing custom matchers and mutators.
-   **Safe AI Tooling:** MCP server that exposes a `dirfuzz_scan` tool to AI assistants, with targets strictly validated against live H1-style JSON scope files.

* * * * *

## Provided Binaries / Runners

-   `cmd/dirfuzz`: The CLI runner with an optional TUI. Exposes the full engine surface (methods, filters, proxies, plugins, resume, eagle mode).
-   `cmd/monitor`: The continuous monitor runner. Executes scheduled scans, persists state as JSONL, compares against previous states, and sends Discord webhooks for new endpoints.
-   `cmd/mcp`: The MCP server for AI assistants. Validates targets against scope JSON files and constrains wordlist selection securely.

* * * * *

## Build

Requirements: Go 1.22+

**Build the Go Binaries:**
```bash
go build -o dirfuzz ./cmd/dirfuzz
go build -o dirfuzz-monitor ./cmd/monitor
go build -o dirfuzz-mcp ./cmd/mcp
```

**Docker / Compose:**
The included `docker-compose.yml` can build and run the monitor image and mount your wordlists and state files.
1.  Copy `.env.example` to `.env` and fill in your variables.
2.  Ensure your wordlists are located in the `./wordlists` directory.
3.  Run `docker compose up --build -d` to start the monitor in the background.

* * * * *

## Example Usage

**CLI (TUI Fuzzing):**
```bash
./dirfuzz -u https://api.example.com -w wordlists/common.txt -t 50 -r -depth 3
```

**CLI (Headless, save to JSONL):**
```bash
./dirfuzz --no-tui -u https://example.com -w wordlists/common.txt -o results.jsonl
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

**MCP Server (AI Integration):**
```bash
export DIRFUZZ_WORDLIST_DIR=/srv/dirfuzz/wordlists
export DIRFUZZ_SCOPE_DIR=/srv/dirfuzz/scopes
./dirfuzz-mcp
```

* * * * *

## Engine & Embedding

The scanning engine is implemented in `pkg/engine`. It is designed to be embedded by other programs and exposes a `Config` struct that controls runtime behavior. Notable capabilities:
-   Multi-method fuzzing and `SmartAPI` mode for intelligent API path handling.
-   Recursive scanning with `MaxDepth`, bounded concurrency, and wildcard detection.
-   Proxy rotation (HTTP & SOCKS5) and an outbound `proxy-out` mode for forwarding hits.
-   Resume support and `LoadPreviousScan` for differential comparisons.
-   Extensible `PluginMatcher` and `PluginMutator` pools via Lua.

* * * * *

## Lua Plugins

Place Lua scripts in the `plugins/` directory or point the CLI at a plugin file using `--plugin-match` / `--plugin-mutate`.
-   Matchers expose a `match(tbl)` function receiving `status_code`, `size`, `words`, `lines`, `body`, and `content_type` returning a boolean.
-   Mutators expose a `mutate(original)` function returning an array of payload variants.
Plugins are executed inside a pool of Lua VMs, allowing parallel execution without serializing workers.

* * * * *

## Safety & Scope Validation

When running as an MCP tool, the server strictly validates targets against loopback/private IP restrictions (SSRF prevention) and a live directory of H1-style scope JSON files (`pkg/scope`). Out-of-scope scans are automatically denied.

* * * * *

## Output Formats & Eagle Mode

-   `jsonl`: One JSON result per line. Excellent for resumes and diffs.
-   `csv`: Standard tabular export.
-   `url`: Prints only matching URLs for easy piping into other terminal tools.

Eagle Mode loads a previous JSONL state file and highlights changed or newly discovered endpoints when comparing scan results.

* * * * *

## Contributing

Contributions are welcome. Please open issues for bugs or feature requests before sending PRs. The project follows small, focused changes—avoid big refactors without prior discussion.

* * * * *

## License

MIT