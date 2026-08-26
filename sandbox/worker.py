"""Entrypoint executed inside the restricted Docker container."""

from __future__ import annotations

import argparse
import json
import sys

from sandbox.analysis import audit_agent, audit_supply_chain
from sandbox.research import audit_business_logic, audit_taint, generate_safe_pocs


def main() -> int:
    parser = argparse.ArgumentParser(description="SAST analysis worker; intended for sandbox execution")
    parser.add_argument("--operation", choices=("audit", "supply-chain", "research"), required=True)
    parser.add_argument("--research-kind", choices=("taint", "business-logic", "safe-poc"), default=None)
    parser.add_argument("--agent", choices=("secrets", "injection", "infra"), default=None)
    parser.add_argument("--target", required=True)
    parser.add_argument("--check-ids", default="[]")
    parser.add_argument("--requested-by", default="[]")
    args = parser.parse_args()

    if args.operation == "audit":
        if args.agent is None:
            raise SystemExit("--agent is required for audit")
        result = audit_agent(args.target, args.agent, json.loads(args.check_ids))
    elif args.operation == "supply-chain":
        result = audit_supply_chain(args.target, json.loads(args.requested_by))
    else:
        if args.research_kind == "taint":
            result = audit_taint(args.target)
        elif args.research_kind == "business-logic":
            result = audit_business_logic(args.target)
        elif args.research_kind == "safe-poc":
            result = generate_safe_pocs(args.target)
        else:
            raise SystemExit("--research-kind is required for research")
    sys.stdout.write(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
