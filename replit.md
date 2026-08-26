# Modular SAST MCP Engine

An open-source, read-only SAST engine that routes 36 defensive checks through MCP-style domain workers.

## Run & Operate

- `pnpm --filter @workspace/api-server run dev` — run the API server (port 5000)
- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from the OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- Required env: `DATABASE_URL` — Postgres connection string

## SAST CLI

- `python -m orchestrator.map_agent /path/to/repository --output audit.json` — run the complete isolated audit
- `python -m mcp_servers.secrets_agent` — start Agent A over stdio JSON-RPC
- `python -m mcp_servers.injection_agent` — start Agent B over stdio JSON-RPC
- `python -m mcp_servers.infra_agent` — start Agent C over stdio JSON-RPC
- `python -m mcp_servers.supply_chain_agent` — start the shared dependency worker

## Stack

- pnpm workspaces, Node.js 24, TypeScript 5.9
- API: Express 5
- DB: PostgreSQL + Drizzle ORM
- Validation: Zod (`zod/v4`), `drizzle-zod`
- API codegen: Orval (from OpenAPI spec)
- Build: esbuild (CJS bundle)

## Where things live

- `orchestrator/map_agent.py` — parent map/router and parallel MCP client
- `mcp_servers/` — Agent A, Agent B, Agent C, and the shared supply-chain worker
- `sandbox/runner.py` — Docker isolation boundary
- `sandbox/analysis.py` — analysis logic executed only inside the sandbox
- `config/checks_map.json` — all 36 routed categories and default rule definitions
- `README_SAST.md` — usage, protocol, and isolation documentation

## Architecture decisions

- Domain workers use stdio JSON-RPC with MCP-compatible `initialize`, `tools/list`, and `tools/call` methods, avoiding a mandatory SDK dependency.
- The parent orchestrator starts the three domain workers in parallel, then sends their dependency inventory to one unified supply-chain worker.
- Analysis is fail-closed on Docker availability; no host-execution fallback is provided.
- Findings redact credential-shaped values before returning snippets in reports.

## Product

_Describe the high-level user-facing capabilities of this app once they exist._

## User preferences

_Populate as you build — explicit user instructions worth remembering across sessions._

## Gotchas

_Populate as you build — sharp edges, "always run X before Y" rules._

## Pointers

- See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details
