"""Entrypoint executed inside the restricted Docker container."""

from __future__ import annotations

import argparse
import json
import sys

from sandbox.analysis import audit_agent, audit_supply_chain


def main() -> int:
    parser = argparse.ArgumentParser(description="SAST analysis worker; intended for sandbox execution")
    parser.add_argument("--operation", choices=("audit", "supply-chain"), required=True)
    parser.add_argument("--agent", choices=("secrets", "injection", "infra"), default=None)
    parser.add_argument("--target", required=True)
    parser.add_argument("--check-ids", default="[]")
    parser.add_argument("--requested-by", default="[]")
    args = parser.parse_args()

    if args.operation == "audit":
        if args.agent is None:
            raise SystemExit("--agent is required for audit")
        result = audit_agent(args.target, args.agent, json.loads(args.check_ids))
    else:
        result = audit_supply_chain(args.target, json.loads(args.requested_by))
    sys.stdout.write(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
