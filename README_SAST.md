# Modular SAST MCP Engine

This repository contains a read-only static application security testing
engine with a parent/child reporting hierarchy:

```text
Main Orchestrator Agent (map/router)
├── Agent A: Secrets & Identity Agent
│   └── executable MCP child server for each category: 1-7, 11, 13-14, 24-26, 30
├── Agent B: Input & Injection Agent
│   └── executable MCP child server for each category: 16-23, 31, 33-34
├── Agent C: Infra & Client Agent
│   └── executable MCP child server for each category: 8-10, 12, 15, 27-29, 32, 35-36
└── Unified Supply Chain Worker
    └── package.json, composer.json, requirements.txt
```

## Requirements

- Python 3.10+
- Docker available on `PATH`
- The Docker image in `SAST_SANDBOX_IMAGE`, or the default
  `python:3.12-slim`

The engine has no Python package dependencies. Docker is intentionally
mandatory for analysis: the runner refuses to fall back to host execution.

## Run an audit

```bash
python -m orchestrator.map_agent /path/to/repository --output audit.json
```

To audit a patch, pass the patch file as the positional input:

```bash
python -m orchestrator.map_agent changes.patch --output patch-audit.json
```

For traceability, a repository path can also be supplied with `--diff`; in
that mode the diff is the analyzed input and the repository is retained as
the report's target metadata:

```bash
python -m orchestrator.map_agent /path/to/repository --diff changes.patch
```

The report contains finding IDs, categories, severity, confidence, relative
file paths, line numbers, redacted snippets, remediation steps, each domain
agent's sub-agent status, and the unified supply-chain report.

## Run one MCP server

Each parent and child server uses newline-delimited JSON-RPC 2.0 over stdio and
exposes `initialize`, `tools/list`, `tools/call`, and `ping`. Domain parents
spawn check children with `python -m mcp_servers.check_agent`; every child
exposes the executable `audit_check` tool and returns its own report to its
parent.

```bash
python -m mcp_servers.secrets_agent
python -m mcp_servers.injection_agent
python -m mcp_servers.infra_agent
python -m mcp_servers.supply_chain_agent
```

The check child is also directly executable:

```bash
python -m mcp_servers.check_agent --parent-agent secrets --check-id 01
```

## Isolation guarantees

The runner starts Docker with `--network=none`, `--read-only`, read-only
bind mounts for both source and analysis code, dropped Linux capabilities,
`no-new-privileges`, a PID limit, memory/CPU limits, and a non-executable
temporary filesystem. AST parsing, filename inspection, and regex matching
all run in `sandbox/worker.py` inside that container.
