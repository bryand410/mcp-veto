"""Command line: put the gate in front of any MCP stdio server."""

from __future__ import annotations

import argparse
import sys

from .approval import Approver
from .gate import Gate
from .policy import Policy
from .ui import ApprovalServer

__version__ = "0.1.0"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-veto",
        description="Hold a sensitive MCP tool call until a human approves it out of band.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="wrap a stdio MCP server")
    run.add_argument("--policy", help="JSON file: require_approval_patterns, allow, deny")
    run.add_argument("--timeout", type=float, default=120.0, help="seconds to wait for a human (default 120)")
    run.add_argument("--server", default="server", help="name used in the approval page and the token")
    run.add_argument("target", nargs=argparse.REMAINDER, help="-- command to run")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command != "run":
        return 2

    target = list(args.target)
    if target and target[0] == "--":
        target = target[1:]
    if not target:
        print("mcp-veto: no command given (usage: mcp-veto run -- <server command>)", file=sys.stderr)
        return 2

    policy = Policy.from_file(args.policy) if args.policy else Policy.default()
    server = ApprovalServer(ttl=args.timeout)
    approver = Approver(ttl=args.timeout)

    def ask(pending):
        # Register before announcing: a human can click the instant the URL is
        # printed, and a 404 on the first click would be a race, not a refusal.
        server.register(pending)
        print(f"[veto] approval needed: {server.url_for(pending)}", file=sys.stderr, flush=True)
        verdict = server.wait(pending)
        server.forget(pending)
        return verdict

    gate = Gate(policy, approver, ask, server_name=args.server)
    print(f"[veto] approval channel: {server.base}", file=sys.stderr, flush=True)
    print(f"[veto] guarding: {' '.join(target)}", file=sys.stderr, flush=True)

    try:
        return gate.run(target)
    finally:
        server.close()


if __name__ == "__main__":
    raise SystemExit(main())
