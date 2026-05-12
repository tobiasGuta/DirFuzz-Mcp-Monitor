# DirFuzz MCP Server

DirFuzz features an embedded **MCP (Model Context Protocol)** server binary (`cmd/mcp`). This server abstracts and exposes two secured tools (`dirfuzz_scan` & `dirfuzz_list_wordlists`) empowering AI assistants (Claude, Copilot) to conduct dynamic directory fuzzing directly from conversational prompts.

The MCP server wraps DirFuzz's high-performance engine in an iron-clad vulnerability sandboxing model, strictly validating target definitions and restricting AI path traversal capabilities to secure your environment.

---

## What makes it Safe?
To operate with AI systems without causing unintended exploitation risks, the server deploys specific limits:
- **H1-Style Scope Validation**: All requests submitted to the `dirfuzz_scan` tool must comply with the live validation scopes (read dynamically from JSON definitions spanning `DIRFUZZ_SCOPE_DIR`). Out-of-bounds target coordinates are immediately denied.
- **SSRF & Network Enforcement**: Limits scanning private/internal IP structures. Internal DNS rebinding protections execute preemptively.
- **Wordlist Sandboxing**: The `wordlist` properties strictly forbid path traversals (`../`). AI agents can only reference filename nodes available safely within `DIRFUZZ_WORDLIST_DIR`.
- **Credential Protection mechanisms**: Raw HTTP bodies and configuration headers are truncated or omitted completely (`--save-raw` is disabled internally) to prevent credential exfiltration passing into the AI inference context space.

---

## Output Restrictions & Bounds

The MCP server responds with a clear ASCII-formatted markdown table summary mapped against hit statuses. By clamping configurations through the `DIRFUZZ_MAX_RESULTS` environment variable, payloads are strictly throttled against LLM memory bounds. If the limits are hit, the tool automatically suggests narrowing search dimensions or re-evaluating wordlist scopes.

Furthermore, filesystem access permissions remain limited specifically to artifacts housed under `DIRFUZZ_OUTPUT_DIR`.

---

## MCP Tools Exposed

### `dirfuzz_scan`

Runs a highly concurrent directory fuzzing scan using DirFuzz's core Engine capabilities.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `target` | string | ✓ | Destination boundary URL (must pass scope checks) |
| `wordlist` | string | | Filename reference contained inside `DIRFUZZ_WORDLIST_DIR` |
| `threads` | number | | Configurable worker threads. Base: 10 |
| `match_codes` | string | | Target response indicators (e.g. `200,204,301,403`) |
| `extensions` | string | | Configurable lookup permutations (`php,html,js`) |
| `recursive` | boolean | | Expand scans traversing deeper directories dynamically |
| `max_depth` | number | | Recursion depth threshold boundaries |
| `timeout_seconds` | number | | Request connection timeout |
| `match_regex` | string | | Enforce hits strictly upon body regex matching |
| `filter_regex` | string | | Exclude false positives automatically matching regex bounds |
| `insecure` | boolean | | Bypasses TLS cert validation definitions |
| `max_results` | number | | Force override bounding of maximum hits parsed in context |

### `dirfuzz_list_wordlists`

Automatically inspects and formats a flat response hierarchy displaying available `.txt` wordlist records situated in the server bounds. Extensively used by AI to recognize dictionary structures dynamically without user probing.

---

## Server Setup & Start

Requirements: Go 1.22+

```bash
# Build the MCP server binary
go build -o dirfuzz-mcp ./cmd/mcp
```

### Environment Configuration

Before starting, map your sandbox boundaries. **The Server refuses start-up if validation bounds are omitted.**

- **Required Variables**:
  - `DIRFUZZ_WORDLIST_DIR` — Dedicated root hierarchy containing fuzzing dictionaries (`.txt`).
  - `DIRFUZZ_SCOPE_DIR` — H1-Scope-Watcher domain definitions mapping in-scope bounding JSON schemas.
  - `DIRFUZZ_OUTPUT_DIR` — Directory for results tracking and analytical constraints.

- **Optional Modifications**:
  - `DIRFUZZ_MAX_THREADS` — Positive integer limit of worker concurrency configurations (Default: 15).
  - `DIRFUZZ_MAX_RESULTS` — Artificial ceiling truncating result sets to lower LLM Context overhead (Default: 200).

```bash
export DIRFUZZ_WORDLIST_DIR=/srv/dirfuzz/wordlists
export DIRFUZZ_SCOPE_DIR=/srv/h1-scope-definitions
export DIRFUZZ_OUTPUT_DIR=/srv/dirfuzz/results
export DIRFUZZ_MAX_THREADS=25
./dirfuzz-mcp
```

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

Claude: [Executes 'dirfuzz_list_wordlists']
        [Executes 'dirfuzz_scan' -> target: "https://testphp.vulnweb.com/", wordlist: "common.txt"]

DirFuzz scan results for: https://testphp.vulnweb.com/
Total hits: 14

Status  Method    Size       URL
------------------------------------------------------------
200     GET       4821       https://testphp.vulnweb.com/admin
301     GET       0          https://testphp.vulnweb.com/images
200     GET       4600       https://testphp.vulnweb.com/login.php
...

Claude: DirFuzz found 14 accessible directories. Notably an exposed /admin folder and the primary application login node. Let me know if you would like deeper recursive scanning.
```
