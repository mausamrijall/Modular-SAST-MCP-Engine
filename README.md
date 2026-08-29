# Modular SAST MCP Engine

An open-source, read-only Static Application Security Testing (SAST) engine
that analyzes source repositories and diffs through a hierarchy of MCP-style
agents.

The system routes 36 defensive security checks to specialized domain agents.
Each domain agent starts executable MCP sub-agents for its individual checks.
Those sub-agents run the analysis inside a restricted Docker container and
return structured findings to their parent. A parallel research layer adds
context slicing, cross-file taint analysis, business-logic and authorization
checks, and safe proof-of-concept blueprints.

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

The orchestrator also runs a parallel advanced research layer:

```text
Orchestrator Research Layer
├── Cross-File Taint Analyzer
│   ├── audit_taint(target_path)
│   └── trace_dataflow(source_file, sink_function)
├── Business Logic & Authorization Engine
│   └── audit_logic_flaws(target_path)
└── Automated Exploit Proof-of-Concept Generator
    ├── generate_safe_poc(target_path)
    └── generate_poc(check_id, vulnerability_details)
```

The research servers return source-to-sink evidence, authorization and
business-control verdicts, and non-executing verification blueprints. They do
not generate exploit payloads, send network requests, execute target code, or
mutate the target.

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
| `mcp_servers/taint_analyzer.py` | Cross-file taint research MCP server |
| `mcp_servers/logic_flaw_agent.py` | Business logic and authorization research MCP server |
| `mcp_servers/poc_generator.py` | Safe proof-of-concept research MCP server |
| `mcp_servers/common.py` | JSON-RPC server implementation and tool schemas |
| `sandbox/runner.py` | Docker isolation boundary |
| `sandbox/worker.py` | In-container worker entrypoint |
| `sandbox/analysis.py` | AST, regex, filename, and dependency analysis |
| `sandbox/research.py` | Taint engine, logic-flaw engine, and safe PoC blueprint generation |
| `sandbox/slicer.py` | AST context slicer and call-tree builder |
| `config/checks_map.json` | Source of truth for all 36 categories, routing rules, and research wiring |
| `config/llm.py` | Optional OpenAI-compatible LLM connection config |
| `.env.example` | Placeholder template for LLM credentials |

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

Enable advanced research (taint analysis, business-logic and authorization
checks, and safe proof-of-concept generation):

```bash
python -m orchestrator.map_agent /path/to/repository \
  --with-taint \
  --with-poc \
  --output audit.json
```

The main agent also has outbound network access for methodology research and
can ask sub-agents clarifying questions. Sandbox workers keep `--network=none`;
only the orchestrator process makes these calls:

```bash
python -m orchestrator.map_agent /path/to/repository \
  --research-url https://example.com/owasp-guide \
  --methodology-topic "authorization gap detection" \
  --clarify 05 --clarify 33 \
  --clarify-question "Which patterns fire this check?" \
  --output audit.json
```

- `--research-url` (repeatable) fetches a public URL; the evidence lands in
  the report's `methodology_research` section.
- `--methodology-topic` labels that research.
- `--clarify` (repeatable) routes the question to the sub-agent owning the
  check; answers land in the report's `clarifications` section.
- `--clarify-question` sets the question text (has a sensible default).

Without `--output`, the report is printed to standard output:

```bash
python -m orchestrator.map_agent /path/to/repository
```

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

The research layer exposes the following MCP tools:

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

Every parent and research server also exposes a built-in `clarify` tool:

```text
clarify(check_id, question)
```

The main agent uses it to ask a sub-agent about its detection methodology —
patterns, severity, remediation, sources, and sinks. Answers are structured
`{agent, check_id, question, methodology}` responses.

## Advanced research modules

### Context slicer (`sandbox/slicer.py`)

Pulls focused code context around a hit so findings and child agents can reason
about a single function without shipping the whole repository.

- `get_code_slice(file_path, line_number)` — imports, the enclosing function or
  method, and the hit line with a small focus window.
- `build_call_tree(file_path)` — call relationships up to `MAX_DEPTH` for
  Python (AST), JavaScript/TypeScript, and PHP.
- Unreferenced imports are stripped from the slice.

### Cross-file taint engine (`sandbox/research.py`)

Bounded, variable-level dataflow tracking across files. Sources include HTTP
request data and route parameters; sinks include query/command builders and
filesystem access. A taint verdict is produced per flow:

- `taint_path` — ordered steps from source, through propagation, past any
  sanitizer, to the sink, with `file` and `line` per step.
- Sanitizer verdicts are recognized from `TAINT_SANITIZERS` (for example
  `int()`, `parameterized()`, prepared statements).
- `audit_taint` returns all flows plus only the unsanitized findings.
- `trace_dataflow(source_file, sink_function)` is the on-demand form used by
  the research MCP server.

### Business logic and authorization engine

Detects authorization and business-rule flaws for checks 05, 06, and 33 across
Express, FastAPI, and Laravel code:

- Route registration and HTTP-method parsing.
- Middleware / auth-signal detection to decide whether a route is protected.
- Route-parameter to database-query dataflow for ownership (IDOR / BOLA)
  verdicts.

### Safe proof-of-concept generator

Turns research evidence into reproducible, non-executing blueprints:

- `generate_poc(check_id, vulnerability_details)` — single-finding blueprint.
- `generate_safe_poc(target_path)` — batch mode over taint and logic evidence.
- Every blueprint is a curl / raw-HTTP template with a benign `TEST_MARKER_123`
  value and placeholder metadata for a disposable local fixture. Nothing is
  executed, sent over the network, or written into the target.

## Main-agent network access and sub-agent clarification

Only the main orchestrator agent has outbound network access. Sandbox workers
run with `--network=none`, so source analysis is never on the wire. The
orchestrator uses its network access for two purposes:

1. **Methodology research.** `orchestrator/web_research.py` fetches public
   documentation with bounded timeouts and response sizes. When `USER_LLM_*`
   is configured, it can ask the LLM to draft a methodology section from the
   fetched evidence. Requests only accept `http`/`https` URLs and never attach
   credentials.
2. **Sub-agent clarification.** The main agent routes `--clarify` requests to
   the sub-agent that owns a check (per `config/checks_map.json`) using the
   built-in `clarify` tool, so it can confirm detection methodology instead of
   guessing. Unknown checks fall back to the logic-flaw research engine.

The report carries `methodology_research` and `clarifications` sections when
these flags are used.

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
- Research-layer findings with taint paths, logic-flaw evidence, and safe PoC blueprints
- Main-agent methodology research (`methodology_research`)
- Sub-agent clarification answers (`clarifications`)

Every finding carries the extended schema with the optional `taint_path` and
`poc_payload` fields:

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
  "remediation": "Use runtime-injected secrets and rotate affected credentials.",
  "taint_path": [],
  "poc_payload": null
}
```

A tainted finding populated by the research layer:

```json
{
  "id": "SAST-33-...",
  "check_id": "33",
  "category": "IDOR / BOLA",
  "agent": "injection",
  "sub_agent": "injection.33",
  "severity": "high",
  "confidence": "medium",
  "file": "app/server.js",
  "line": 40,
  "snippet": "db.query(\"SELECT * FROM users WHERE id = \" + req.params.id)",
  "rule": "idor-bola",
  "description": "Cross-user access to records without ownership checks.",
  "remediation": "Bind parameters and verify record ownership.",
  "taint_path": [
    {"step": "source", "file": "app/server.js", "line": 38, "symbol": "req.params.id"},
    {"step": "propagate", "file": "app/server.js", "line": 40, "symbol": "req.params.id"},
    {"step": "sink", "file": "lib/db.js", "line": 9, "symbol": "run(driver, sql)"}
  ],
  "poc_payload": "curl -sS -H 'Cookie: session=TEST_MARKER_123' 'http://localhost/app/user/1' | grep -i 'email'"
}
```

- `taint_path` is a list of `{step, file, line, symbol}` steps for taint-backed
  findings; `[]` otherwise.
- `poc_payload` holds the non-executing proof blueprint when a safe PoC was
  generated for the finding; `null` otherwise.
- Research findings map back to the source check through `check_id`, so a
  domain finding and its research evidence share the same identifier.

## Sandbox security model

All filesystem traversal, regex matching, filename inspection, Python AST
parsing, dependency analysis, and research computation runs in the Docker
worker.

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

The single deliberate exception to the offline rule is the main agent itself:
its outbound methodology research runs on the host (see "Main-agent network
access and sub-agent clarification"). It is strictly outbound and bounded, and
it never inspects the target's source. Every sandbox worker still runs with
`--network=none`.

Finding snippets redact common secret-shaped values before they leave the
worker.

## Research layer safety

Research workers use the same Docker boundary as the 36 static checks. The
taint and logic-flaw engines perform local source analysis only. The automated
PoC generator is deliberately non-executing: it produces a reproducible test
plan with a benign `TEST_MARKER_123` value and placeholder request metadata for
a disposable local fixture.

## Optional LLM connection

The engine can talk to any OpenAI-compatible chat completions endpoint for
optional AI-assisted explanation of findings. Credentials are never bundled
with the project; you provide your own key.

Copy the template and fill in your own values:

```bash
cp .env.example .env
```

The module reads the following user-facing variables:

| Variable | Purpose | Default |
| --- | --- | --- |
| `USER_LLM_PROVIDER` | Provider display name | `openai-compatible` |
| `USER_LLM_BASE_URL` | Endpoint root of the chat completions API | `https://api.openai.com/v1` |
| `USER_LLM_API_KEY` | Your API key (required) | none |
| `USER_LLM_MODEL` | Model identifier | `gpt-4o-mini` |

Load the variables into the environment, then configure from code:

```python
from config.llm import LLMConfig

cfg = LLMConfig.from_env()
print(cfg.redacted())  # never logs the key itself
print(cfg.chat_url)
print(cfg.headers()["Authorization"].startswith("Bearer "))
```

If `USER_LLM_API_KEY` is missing, `LLMConfig.from_env()` raises `ValueError`
so misconfiguration fails loudly instead of silently sending unauthenticated
requests.

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
