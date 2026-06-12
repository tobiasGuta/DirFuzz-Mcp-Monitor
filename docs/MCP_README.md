# DirFuzz MCP Server

DirFuzz features an embedded **MCP (Model Context Protocol)** server binary (`cmd/mcp`). This server exposes two read-only resources, `dirfuzz://wordlists` and `dirfuzz://scope`, three workflow prompts, and ten tools (`dirfuzz_scan`, `dirfuzz_scan_status`, `dirfuzz_cancel`, `dirfuzz_list_scope`, `dirfuzz_waf_probe`, `dirfuzz_param_fuzz`, `dirfuzz_auth_test`, `dirfuzz_analyze`, `dirfuzz_build_scan`, and `dirfuzz_expand`) so AI assistants (Claude, Copilot) can plan scans with live context before they act.

The MCP server wraps DirFuzz's high-performance engine in an iron-clad vulnerability sandboxing model, strictly validating target definitions and restricting AI path traversal capabilities to secure your environment.

---

## Security Model

The MCP layer is built for authorized use only and applies layered guardrails:
- **Scope enforcement**: `dirfuzz_scan` reloads the live scope files from `DIRFUZZ_SCOPE_DIR` and blocks any target that does not match an in-scope asset.
- **Path traversal prevention**: wordlist, results, and scope file paths are resolved inside their allowed directories before any file is read.
- **Rate limiting**: each tool call is checked against a sliding-window limiter, and scan concurrency is capped by the MCP registry.
- **Audit logging**: every tool invocation is appended to a JSONL audit log at `DIRFUZZ_AUDIT_LOG` with bearer tokens redacted from header-like arguments.
- **Output bounding**: scan results are capped by `DIRFUZZ_MAX_RESULTS`, and large follow-on operations are exposed as separate tools so agents can make smaller, deliberate steps.

---

## Resources

### `dirfuzz://wordlists`

Read-only JSON inventory of the `.txt` files in `DIRFUZZ_WORDLIST_DIR`, including line counts and a short semantic description for each entry.

### `dirfuzz://scope`

Read-only JSON snapshot of the currently loaded H1-Scope-Watcher assets, grouped by source file and annotated with summary counts.

---

## Prompts

### `recon_workflow`

Structured multi-step planning prompt for a target domain. It walks through scope review, wordlist selection, initial scanning, expansion, and analysis.

### `403_bypass_workflow`

Structured prompt for blocked paths that need a focused retry plan and follow-up analysis.

### `api_surface_mapping`

Structured prompt for REST or JSON API targets that emphasizes API-prefix discovery, expansion, and analysis.

---

## MCP Tools

### `dirfuzz_scan`

Run a directory-fuzzing scan against a scoped target and write the structured results to `DIRFUZZ_OUTPUT_DIR`.

Server-side safety gate:
- `DIRFUZZ_SCAN_ENABLED` must be set to exactly `true`; by default scans are disabled.
- When `DIRFUZZ_SCAN_APPROVAL_TOKEN` is configured, the tool call must include a matching `approval_token`.
- Failed approval checks happen before scope validation, wordlist resolution, engine setup, or network activity.
- `approval_token` is redacted from audit logs.

Parameters:
- `target` `string` required: full target URL to fuzz.
- `wordlist` `string` required: wordlist filename from `DIRFUZZ_WORDLIST_DIR`.
- `approval_token` `string` required when `DIRFUZZ_SCAN_APPROVAL_TOKEN` is configured.
- `extensions` `string` optional: comma-separated extensions to append to every path.
- `match_codes` `string` optional: comma-separated HTTP status codes to keep.
- `methods` `string` optional: comma-separated HTTP methods to try.
- `body` `string` optional: request body with `{PAYLOAD}` substitution. If the target URL has no `{PAYLOAD}`, body fuzzing keeps the URL fixed and inserts each wordlist entry only in the body.
- `headers` `string[]` optional: extra headers as `Key: Value` strings.
- `rps` `number` optional: global requests-per-second cap.
- `timeout_seconds` `number` optional: per-request timeout in seconds.
- `max_duration_seconds` `number` optional: maximum scan runtime in seconds.

### `dirfuzz_scan_status`

Return a live status snapshot for a running or completed scan.

Parameters:
- `scan_id` `string` required: scan identifier returned by `dirfuzz_scan`.

### `dirfuzz_cancel`

Cancel a running scan.

Parameters:
- `scan_id` `string` required: scan identifier returned by `dirfuzz_scan`.

### `dirfuzz_list_scope`

Return the fully parsed current scope as structured JSON.

Parameters:
- none.

### `dirfuzz_waf_probe`

Probe a discovered path with WAF evasion techniques and return the evasion scoreboard.

Parameters:
- `scan_id` `string` required: scan identifier returned by `dirfuzz_scan`.
- `path` `string` required: discovered path or full URL to probe.
- `method` `string` optional: HTTP method for probing.
- `headers` `string[]` optional: extra headers as `Key: Value` strings.

### `dirfuzz_param_fuzz`

Discover hidden GET/POST parameters on a discovered endpoint.

Parameters:
- `scan_id` `string` required: scan identifier returned by `dirfuzz_scan`.
- `path` `string` required: discovered endpoint path or full URL.
- `method` `string` optional: HTTP method for the baseline request.
- `wordlist` `string[]` optional: custom parameter names to probe instead of the built-in list.
- `headers` `string[]` optional: extra headers as `Key: Value` strings.

### `dirfuzz_auth_test`

Replay discovered paths across multiple auth token sets to detect access-control mismatches.

Parameters:
- `scan_id` `string` required: scan identifier returned by `dirfuzz_scan`.
- `paths` `string[]` required: discovered paths or full URLs to test.
- `auth_matrix_json` `string` required: JSON object mapping auth roles to arrays of header strings.
- `headers` `string[]` optional: extra headers as `Key: Value` strings.

### `dirfuzz_analyze`

Analyze a JSONL results file or `scan_id` and classify findings by severity.

Parameters:
- `results_file` `string` optional: path to a JSONL results file in `DIRFUZZ_OUTPUT_DIR`.
- `scan_id` `string` optional: scan identifier returned by `dirfuzz_scan`.
- `target` `string` optional: target URL used for context in the response.

### `dirfuzz_build_scan`

Translate a natural-language scan goal into recommended DirFuzz parameters.

Parameters:
- `description` `string` required: natural-language scan goal.
- `target` `string` required: full target URL.

### `dirfuzz_expand`

Recursively expand high-value hits with focused sub-scans.

Parameters:
- `base_target` `string` required: original base URL.
- `hits_jsonl` `string` required: JSONL results file to expand from.
- `max_depth` `number` optional: maximum expansion depth.
- `max_targets` `number` optional: maximum sub-paths to expand.
- `wordlist` `string` optional: wordlist path for sub-scans.

---

## Return Values

### `dirfuzz_scan`

Returns a JSON object with this shape:
```json
{
  "target": "https://example.com",
  "scan_id": "uuid",
  "started_at": "2026-05-20T12:34:56.000000000Z",
  "duration_ms": 1234,
  "total_hits": 12,
  "capped": false,
  "results_file": "scan-uuid.jsonl",
  "scope_warnings": [],
  "results": [
    {
      "url": "https://example.com/admin",
      "status_code": 200,
      "method": "GET",
      "size_bytes": 1234,
      "content_type": "text/html; charset=utf-8",
      "severity": "high",
      "labels": ["status_200"]
    }
  ]
}
```

### `dirfuzz_scan_status`

Returns a JSON object with this shape:
```json
{
  "scan_id": "uuid",
  "target": "https://example.com",
  "started_at": "2026-05-20T12:34:56.000000000Z",
  "elapsed_ms": 1234,
  "requests_dispatched": 42,
  "results_collected": 12,
  "current_worker_count": 15,
  "current_rps": 8,
  "running": true,
  "canceled": false,
  "capped": false,
  "results_file": "scan-uuid.jsonl",
  "results_path": "/abs/path/to/output/scan-uuid.jsonl",
  "queue_depth": 18,
  "waf_detected": true,
  "waf_vendor_guess": "cloudflare",
  "waf_evasion_scoreboard": []
}
```

### `dirfuzz_cancel`

Returns a JSON object with this shape:
```json
{
  "scan_id": "uuid",
  "canceled": true,
  "message": "cancel signal sent"
}
```

### `dirfuzz_list_scope`

Returns a JSON object with this shape:
```json
{
  "generated_at": "2026-05-20T12:34:56Z",
  "directory": "/abs/path/to/scope",
  "total_files": 3,
  "total_assets": 42,
  "warnings": [],
  "files": [
    {
      "file": "program.json",
      "asset_count": 14,
      "bounty_eligible": 12,
      "url_assets": 8,
      "wildcard_assets": 4,
      "cidr_assets": 2,
      "ip_address_assets": 0,
      "source_code_assets": 0,
      "executable_assets": 0,
      "unsupported_assets": 0,
      "assets": []
    }
  ]
}
```

### `dirfuzz_waf_probe`

Returns a JSON object shaped like the engine’s WAF probe report:
```json
{
  "target": "https://example.com",
  "path": "/admin",
  "method": "GET",
  "vendor": "cloudflare",
  "detected": true,
  "confidence": "high",
  "evidence": ["cf-ray header or cloudflare body markers"],
  "baseline_status_code": 403,
  "baseline_size_bytes": 1234,
  "attempts": [],
  "scoreboard": []
}
```

### `dirfuzz_param_fuzz`

Returns a JSON object with a `report` field:
```json
{
  "scan_id": "uuid",
  "report": {
    "target": "https://example.com/admin",
    "path": "/admin",
    "method": "GET",
    "baseline_status_code": 200,
    "baseline_size_bytes": 1234,
    "baseline_hash": 123456789,
    "findings": [
      {
        "params": ["debug"],
        "probe_url": "https://example.com/admin?debug=a",
        "status_code": 200,
        "size_bytes": 1300,
        "words": 50,
        "lines": 10,
        "content_type": "text/html; charset=utf-8",
        "duration_ms": 123,
        "headers": {}
      }
    ]
  }
}
```

### `dirfuzz_auth_test`

Returns a JSON object with a `findings` array:
```json
{
  "scan_id": "uuid",
  "findings": [
    {
      "labels": ["AUTH-MATRIX", "BAC"],
      "confidence": "user=403;admin=200",
      "summary": "unauth=403/123 | user=403/123 | admin=200/456",
      "role": "admin"
    }
  ]
}
```

### `dirfuzz_analyze`

Returns a JSON object with this shape:
```json
{
  "target": "https://example.com",
  "scan_id": "uuid",
  "results_file": "scan-uuid.jsonl",
  "total_hits": 12,
  "findings": {
    "critical": [],
    "high": [],
    "medium": [],
    "info": []
  },
  "recommended_next_steps": []
}
```

### `dirfuzz_build_scan`

Returns a JSON object with this shape:
```json
{
  "recommended_params": {
    "target": "https://example.com",
    "wordlist": "/abs/path/to/wordlist.txt",
    "extensions": "php,env,blade.php",
    "threads": 20,
    "match_codes": "200,204,301,302,401,403",
    "recursive": false,
    "mutate": false,
    "smart_api": false
  },
  "reasoning": "Detected Laravel/PHP target."
}
```

### `dirfuzz_expand`

Returns a JSON object with this shape:
```json
{
  "base_target": "https://example.com",
  "hits_jsonl": "/abs/path/to/output/scan-uuid.jsonl",
  "wordlist": "common.txt",
  "max_depth": 2,
  "max_targets": 10,
  "expansions": [
    {
      "source_path": "/admin",
      "target": "https://example.com/admin",
      "score": 12,
      "wordlist": "common.txt",
      "result_count": 3,
      "error": "",
      "sub_results": []
    }
  ]
}
```

---

## Server Setup & Start

Requirements: Go 1.22+

```bash
# Build the MCP server binary
go build -o dirfuzz-mcp ./cmd/mcp
```

### Environment Configuration

Before starting, map your sandbox boundaries. **The Server refuses start-up if validation bounds are omitted.**

If `DIRFUZZ_OUTPUT_DIR` is missing, the server now prints a copy-paste Claude Desktop stanza that uses the binary's own path and the currently loaded scope and wordlist roots.

- **Required Variables**:
  - `DIRFUZZ_WORDLIST_DIR` — Dedicated root hierarchy containing fuzzing dictionaries (`.txt`).
  - `DIRFUZZ_SCOPE_DIR` — H1-Scope-Watcher domain definitions mapping in-scope bounding JSON schemas.
  - `DIRFUZZ_OUTPUT_DIR` — Directory for results tracking and analytical constraints.

- **Optional Modifications**:
  - `DIRFUZZ_SCAN_ENABLED` — Must be exactly `true` to allow `dirfuzz_scan` (Default: disabled).
  - `DIRFUZZ_SCAN_APPROVAL_TOKEN` — Optional server-side approval token. When set, `dirfuzz_scan` requires a matching `approval_token` argument.
  - `DIRFUZZ_MAX_THREADS` — Positive integer limit of worker concurrency configurations (Default: 15).
  - `DIRFUZZ_MAX_RESULTS` — Artificial ceiling truncating result sets to lower LLM Context overhead (Default: 200).
  - `DIRFUZZ_MAX_CONCURRENT_SCANS` — Maximum number of concurrent scans the MCP server will allow at once (Default: 5).
  - `DIRFUZZ_SCAN_RATE_LIMIT` — Maximum `dirfuzz_scan` invocations allowed within the rolling window (Default: 20).
  - `DIRFUZZ_TOOL_RATE_LIMIT` — Maximum invocations allowed for non-scan tools within the rolling window (Default: 60).
  - `DIRFUZZ_RATE_LIMIT_WINDOW_SECONDS` — Size of the rolling rate-limit window in seconds (Default: 600).
  - `DIRFUZZ_AUDIT_LOG` — Path to the JSONL audit log file (Default: `DIRFUZZ_OUTPUT_DIR/dirfuzz-audit.jsonl`).

```bash
export DIRFUZZ_WORDLIST_DIR=/srv/dirfuzz/wordlists
export DIRFUZZ_SCOPE_DIR=/srv/h1-scope-definitions
export DIRFUZZ_OUTPUT_DIR=/srv/dirfuzz/results
export DIRFUZZ_SCAN_ENABLED=false
export DIRFUZZ_MAX_THREADS=25
export DIRFUZZ_AUDIT_LOG=/srv/dirfuzz/logs/dirfuzz-audit.jsonl
./dirfuzz-mcp
```

### Safe Codex Desktop configuration

Keep scans disabled for normal Codex Desktop sessions:

```json
{
  "mcpServers": {
    "dirfuzz": {
      "command": "D:\\Tools\\DirFuzz-Mcp-Monitor\\dirfuzz-mcp.exe",
      "args": [],
      "env": {
        "DIRFUZZ_WORDLIST_DIR": "D:\\Tools\\DirFuzz-Mcp-Monitor\\wordlists",
        "DIRFUZZ_SCOPE_DIR": "D:\\Tools\\H1-Scope-Watcher\\definitions",
        "DIRFUZZ_OUTPUT_DIR": "D:\\Tools\\DirFuzz-Mcp-Monitor\\output",
        "DIRFUZZ_SCAN_ENABLED": "false"
      }
    }
  }
}
```

For a deliberately approved scan session, temporarily set:

```json
"DIRFUZZ_SCAN_ENABLED": "true",
"DIRFUZZ_SCAN_APPROVAL_TOKEN": "<my-secret-token>"
```

Then include the same secret as the `approval_token` argument on the `dirfuzz_scan` tool call.

On Windows, either double every backslash in the JSON file or use forward slashes in the paths. A ready-to-paste Windows-specific example is provided in [claude_desktop_config.example.windows.json](D:/projects/DirFuzzV3/claude_desktop_config.example.windows.json).

---

## Copilot / Claude Configurations

```json
"dirfuzz": {
  "command": "D:\projects\DirFuzzV3\dirfuzz-mcp.exe",
  "args": [],
  "env": {
    "DIRFUZZ_WORDLIST_DIR": "D:\projects\DirFuzzV3\wordlists",
    "DIRFUZZ_SCOPE_DIR": "D:\projects\H1-Scope-Watcher\definitions",
    "DIRFUZZ_OUTPUT_DIR": "D:\projects\DirFuzzV3\results"
  }
}
```

---

## Conversation Examples

```text
You: Probe for open hidden directories facing https://testphp.vulnweb.com/ using smaller dictionaries.

Claude: [Reads 'dirfuzz://wordlists']
        [Executes 'dirfuzz_scan' -> target: "https://testphp.vulnweb.com/", wordlist: "common.txt"]

{
  "target": "https://testphp.vulnweb.com/",
  "scan_id": "2fb0a6c4-ff6f-4f6a-8e73-8d1c8e7c1f85",
  "started_at": "2026-05-20T12:34:56Z",
  "duration_ms": 1842,
  "total_hits": 14,
  "capped": false,
  "results_file": "scan-2fb0a6c4-ff6f-4f6a-8e73-8d1c8e7c1f85.jsonl",
  "results": [
    { "url": "https://testphp.vulnweb.com/admin", "status_code": 200, "method": "GET", "size_bytes": 4821, "severity": "high" },
    { "url": "https://testphp.vulnweb.com/images", "status_code": 301, "method": "GET", "size_bytes": 0, "severity": "info" }
  ]
}

Claude: DirFuzz found 14 accessible directories. Notably an exposed /admin folder and the primary application login node. Let me know if you would like deeper recursive scanning.
```
