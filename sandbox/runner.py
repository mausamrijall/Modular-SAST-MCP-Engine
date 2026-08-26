"""Docker boundary for all source analysis.

The default path refuses to execute analysis on the host.  Docker is invoked
without a shell, with no network, a read-only root filesystem, read-only
mounts, dropped capabilities, and resource limits.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path
from typing import Any


class SandboxError(RuntimeError):
    """Raised when the isolated runner cannot complete safely."""


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DOCKER_IMAGE = os.environ.get("SAST_SANDBOX_IMAGE", "python:3.12-slim")


def run_sandboxed(
    target_path: str,
    *,
    operation: str,
    agent: str | None = None,
    check_ids: list[str] | None = None,
    requested_by: list[str] | None = None,
    timeout_seconds: int = 180,
) -> dict[str, Any]:
    target = Path(target_path).expanduser().resolve()
    if not target.exists():
        raise SandboxError(f"Target does not exist: {target}")
    if target.is_symlink():
        raise SandboxError("Symlink targets are not allowed")
    if "," in str(target) or "," in str(PROJECT_ROOT):
        raise SandboxError("Paths containing commas are not supported by the Docker mount syntax")

    command = [
        "docker",
        "run",
        "--rm",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=128",
        "--memory=768m",
        "--cpus=2",
        "--tmpfs=/tmp:rw,noexec,nosuid,size=32m",
        "--mount",
        f"type=bind,source={PROJECT_ROOT},destination=/app,readonly",
        "--mount",
        f"type=bind,source={target},destination=/target,readonly",
        "--workdir=/app",
        DOCKER_IMAGE,
        "python",
        "/app/sandbox/worker.py",
        "--operation",
        operation,
        "--target",
        "/target",
        "--check-ids",
        json.dumps(check_ids or []),
        "--requested-by",
        json.dumps(requested_by or []),
    ]
    if agent:
        command.extend(["--agent", agent])

    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            env={"PATH": os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1"},
        )
    except FileNotFoundError as exc:
        raise SandboxError("Docker is required for analysis but was not found on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise SandboxError(f"Sandbox exceeded the {timeout_seconds}s timeout") from exc

    if completed.returncode != 0:
        detail = completed.stderr.strip()[-1000:]
        raise SandboxError(f"Sandbox exited with code {completed.returncode}: {detail}")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise SandboxError("Sandbox returned invalid JSON") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description="Run one SAST operation in Docker")
    parser.add_argument("target_path")
    parser.add_argument("--operation", choices=("audit", "supply-chain"), default="audit")
    parser.add_argument("--agent", choices=("secrets", "injection", "infra"))
    args = parser.parse_args()
    result = run_sandboxed(
        args.target_path,
        operation=args.operation,
        agent=args.agent,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
