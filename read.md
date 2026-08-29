# Modular SAST MCP Engine

An open-source, read-only Static Application Security Testing (SAST) engine
that analyzes source repositories and diffs through a hierarchy of MCP-style
agents.

The system routes 36 defensive security checks to specialized domain agents.
Each domain agent starts executable MCP sub-agents for its individual checks.
Those sub-agents run the analysis inside a restricted Docker container and
return structured findings to their parent.

## Architecture

```text
Main Orchestrator Agent
│
├── Agent A: Secrets & Identity Agent
│   ├── MCP child 01: DB Credentials
│   ├── MCP child 02: .env Files
│   ├── MCP child 03: Hardcoded Secrets
│   ├── MCP child 04: Weak Auth
│   ├── MCP child 05: Missing Authz
│   ├── MCP child 06: Cross-User Access
│   ├── MCP child 07: Open DB Permissions
│   ├── MCP child 11: Log Leaks
│   ├── MCP child 13: Git Secrets
│   ├── MCP child 14: JavaScript Secrets
│   ├── MCP child 24: Password Reset
│   ├── MCP child 25: Weak Sessions
│   ├── MCP child 26: JWT Secrets
│   └── MCP child 30: Default Credentials
│
├── Agent B: Input & Injection Agent
│   ├── MCP children 16-23
│   ├── MCP child 31: Unsigned Webhooks
│   ├── MCP child 33: IDOR / BOLA
│   └── MCP child 34: APIs + Input
│
├── Agent C: Infra & Client Agent
│   ├── MCP children 08-10
│   ├── MCP child 12: Verbose Errors
│   ├── MCP child 15: Client-only Security
│   ├── MCP children 27-29
│   ├── MCP child 32: Frontend Payment Checks
│   └── MCP children 35-36
│
└── Unified Supply Chain Worker
    ├── package.json
    ├── composer.json
    └── requirements.txt
```

The orchestrator also runs a parallel research layer:

```text
Orchestrator Research Layer
├── Cross-File Taint Analyzer
│   └── audit_taint(target_path)
├── Business Logic & Authorization Engine
│   └── audit_logic_flaws(target_path)
└── Automated Exploit Proof-of-Concept Generator
    └── generate_safe_poc(target_path)
```

The first two research servers return source-to-sink and authorization
evidence. The PoC server turns that evidence into local-only verification
blueprints. It does not generate exploit payloads, send network requests,
execute target code, or mutate the target.

> See `README.md` for the full, current guide (advanced research modules,
> extended finding schema, and optional LLM connection).

## Project layout

| Path | Purpose |
| --- | --- |
| `orchestrator/map_agent.py` | Main router, MCP client, parallel domain dispatch, and report aggregation |
| `orchestrator/web_research.py` | Main-agent outbound research (web fetch + optional LLM methodology synthesis) |
| `mcp_servers/secrets_agent.py` | Agent A parent MCP server |
| `mcp_servers/injection_agent.py` | Agent B parent MCP server |
| `mcp_servers/infra_agent.py` | Agent C parent MCP server |
| `mcp_servers/check_agent.py` | Generic executable MCP child for one check |
| `mcp_servers/domain_runtime.py` | Parent fan-out and child-report aggregation |
| `mcp_servers/sub_agent_client.py` | Stdio JSON-RPC client used by parent agents |
| `mcp_servers/supply_chain_agent.py` | Shared dependency-analysis MCP server |
| `mcp_servers/common.py` | JSON-RPC server implementation and tool schemas |
| `sandbox/runner.py` | Docker isolation boundary |
| `sandbox/worker.py` | In-container worker entrypoint |
| `sandbox/analysis.py` | AST, regex, filename, and dependency analysis |
| `sandbox/research.py` | Taint flows, business-logic context, and safe PoC blueprint generation |
| `sandbox/slicer.py` | AST context slicer and call-tree builder |
| `config/checks_map.json` | Source of truth for all 36 categories and routing rules |
| `config/llm.py` | Optional OpenAI-compatible LLM connection config |

## Requirements

- Python 3.10 or newer
- Docker CLI and a running Docker daemon
- Access to the configured Docker image:
  - Default: `python:3.12-slim`
  - Override with `SAST_SANDBOX_IMAGE`

The Python implementation uses only the standard library. No `pip install`
step is required.

## Running a complete audit

Audit a repository:

```bash
python -m orchestrator.map_agent /path/to/repository --output audit.json
```

Audit a diff file:

```bash
python -m orchestrator.map_agent changes.patch --output patch-audit.json
```

Associate a diff with a repository for traceability. The diff is the analyzed
input in this mode, while the repository path is retained in the report:

```bash
python -m orchestrator.map_agent /path/to/repository --diff changes.patch
```

Without `--output`, the report is printed to standard output:

```bash
python -m orchestrator.map_agent /path/to/repository
```

The main agent has outbound network access for methodology research and a
`clarify` channel to its sub-agents. Sandbox workers stay on `--network=none`.

```bash
python -m orchestrator.map_agent /path/to/repository \
  --research-url https://example.com/guide \
  --methodology-topic "authz gap detection" \
  --clarify 05 --clarify 33 \
  --clarify-question "Which patterns fire this check?"
```

See `README.md` for the full guide.

## Running MCP servers

All servers use newline-delimited JSON-RPC 2.0 over standard input and output.
They support `initialize`, `tools/list`, `tools/call`, and `ping`.

Start a parent agent:

```bash
python -m mcp_servers.secrets_agent
python -m mcp_servers.injection_agent
python -m mcp_servers.infra_agent
```

Start the shared supply-chain worker:

```bash
python -m mcp_servers.supply_chain_agent
```

Start an individual executable check sub-agent:

```bash
python -m mcp_servers.check_agent \
  --parent-agent secrets \
  --check-id 01
```

Each parent exposes one domain tool:

| Parent | Tool |
| --- | --- |
| Agent A | `audit_secrets(target_path)` |
| Agent B | `audit_injection(target_path)` |
| Agent C | `audit_infra(target_path)` |

The research layer exposes three additional MCP tools:

| Research server | Tool |
| --- | --- |
| Cross-File Taint Analyzer | `audit_taint(target_path)`, `trace_dataflow(source_file, sink_function)` |
| Business Logic & Authorization Engine | `audit_logic_flaws(target_path)` |
| Automated Exploit Proof-of-Concept Generator | `generate_safe_poc(target_path)`, `generate_poc(check_id, vulnerability_details)` |

Each check child exposes:

```text
audit_check(target_path)
```

The child validates that its check is routed to the requested parent, performs
the audit through the sandbox runner, and returns its own report.

## JSON-RPC example

Send initialization and tool discovery to a parent agent:

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
```

Call Agent A:

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "audit_secrets",
    "arguments": {
      "target_path": "/target/repository"
    }
  }
}
```

## Report contents

The orchestrator writes a JSON report containing:

- Audit ID and timestamp
- Original target and analysis input
- Main-agent routing metadata
- Parent domain-agent statuses
- Individual child-agent reports
- Child executable tool names
- Finding IDs and fingerprints
- Check category and severity
- Confidence level
- Relative file path and line number
- Redacted code snippet
- Rule identifier
- Description
- Remediation guidance
- Severity totals
- Unified supply-chain findings
- Research-layer findings, taint paths, business-logic evidence, and safe PoC blueprints

Example finding shape:

```json
{
  "id": "SAST-03-...",
  "check_id": "03",
  "category": "Hardcoded Secrets",
  "agent": "secrets",
  "sub_agent": "secrets.03",
  "severity": "critical",
  "confidence": "medium",
  "file": "src/config.py",
  "line": 12,
  "snippet": "API_KEY = \"[REDACTED]\"",
  "rule": "hardcoded-secret",
  "description": "Credential and API-token patterns should not be hardcoded.",
  "remediation": "Use runtime-injected secrets and rotate affected credentials."
}
```

## Sandbox security model

All filesystem traversal, regex matching, filename inspection, Python AST
parsing, and dependency analysis runs in the Docker worker.

The runner enforces:

- Read-only source mount
- Read-only analysis-code mount
- Disabled network with `--network=none`
- Read-only container filesystem
- Dropped Linux capabilities
- `no-new-privileges`
- CPU and memory limits
- Process-count limit
- Non-executable temporary filesystem
- No host-execution fallback

If Docker or the Docker daemon is unavailable, the affected child reports an
error and the overall audit is marked `completed_with_errors`. The engine does
not silently scan source code outside the sandbox.

Finding snippets redact common secret-shaped values before they leave the
worker.

## Research layer safety

Research workers use the same Docker boundary as the 36 static checks. The
taint and business-logic engines perform local source analysis only. The
automated PoC generator is deliberately non-executing: it produces a
reproducible test plan with a benign `TEST_MARKER_123` value and placeholder
request metadata for a disposable local fixture.

## Development checks

Compile Python modules:

```bash
python -m compileall -q mcp_servers sandbox orchestrator
```

Validate the check map:

```bash
python -m json.tool config/checks_map.json >/dev/null
```

The check configuration is data-driven. To add or revise a category, update
`config/checks_map.json` with its ID, parent agent, rule kind, patterns,
severity, description, and remediation. The parent agents automatically
discover the configured children at startup.
