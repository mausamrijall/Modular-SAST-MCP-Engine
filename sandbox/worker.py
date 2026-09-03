"""Entrypoint executed inside the restricted Docker container."""

from __future__ import annotations

import argparse
import json
import sys

from sandbox.analysis import audit_agent, audit_supply_chain
from sandbox.research import (
    audit_business_logic,
    audit_logic_flaws,
    audit_taint,
    generate_poc,
    generate_safe_pocs,
    trace_dataflow,
)
from sandbox.verify import assess_behavior, verify_pocs


def _research(kind: str, target: str) -> dict:
    if kind == "taint":
        return audit_taint(target)
    if kind == "business-logic":
        return audit_business_logic(target)
    if kind == "logic-flaw":
        return audit_logic_flaws(target)
    if kind == "safe-poc":
        return generate_safe_pocs(target)
    raise SystemExit("--research-kind is required for research")


def main() -> int:
    parser = argparse.ArgumentParser(description="SAST analysis worker; intended for sandbox execution")
    parser.add_argument(
        "--operation",
        choices=("audit", "supply-chain", "research", "trace", "poc", "verify-poc", "behavior"),
        required=True,
    )
    parser.add_argument(
        "--research-kind",
        choices=("taint", "business-logic", "logic-flaw", "safe-poc"),
        default=None,
    )
    parser.add_argument("--agent", choices=("secrets", "injection", "infra"), default=None)
    parser.add_argument("--target", required=True)
    parser.add_argument("--check-ids", default="[]")
    parser.add_argument("--requested-by", default="[]")
    parser.add_argument("--source-file", default=None)
    parser.add_argument("--sink-function", default=None)
    parser.add_argument("--check-id", default=None)
    parser.add_argument("--vulnerability-details", default=None)
    parser.add_argument("--findings", default=None)
    args = parser.parse_args()

    if args.operation == "audit":
        if args.agent is None:
            raise SystemExit("--agent is required for audit")
        result = audit_agent(args.target, args.agent, json.loads(args.check_ids))
    elif args.operation == "supply-chain":
        result = audit_supply_chain(args.target, json.loads(args.requested_by))
    elif args.operation == "research":
        result = _research(args.research_kind, args.target)
    elif args.operation == "trace":
        if not args.source_file or not args.sink_function:
            raise SystemExit("--source-file and --sink-function are required for trace")
        result = trace_dataflow(args.target, args.source_file, args.sink_function)
    elif args.operation == "verify-poc":
        if args.findings is None:
            raise SystemExit("--findings is required for verify-poc")
        result = verify_pocs(args.target, json.loads(args.findings))
    elif args.operation == "behavior":
        result = assess_behavior(args.target)
    else:
        if not args.check_id or not args.vulnerability_details:
            raise SystemExit("--check-id and --vulnerability-details are required for poc")
        result = generate_poc(args.check_id, json.loads(args.vulnerability_details))
    sys.stdout.write(json.dumps(result, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
