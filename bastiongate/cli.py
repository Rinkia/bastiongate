"""bastiongate command line.

    # put the gate in front of an MCP server; the agent launches THIS instead
    bastiongate run --log gate.jsonl -- npx -y @some/mcp-server
    bastiongate run --policy policy.yaml -- python my_server.py

The gate speaks MCP stdio to the agent on one side and to the real server on the
other. Point your MCP client's `command` at `bastiongate run -- <server...>`.
"""

from __future__ import annotations

import argparse
import sys

from .policy import GatePolicy, load_policy
from .proxy import run_stdio


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="bastiongate", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    pr = sub.add_parser("run", help="proxy an MCP stdio server through the gate")
    pr.add_argument("--policy", help="gate policy YAML/JSON (bastionsupply harden output works)")
    pr.add_argument("--log", help="write a JSONL trace of every call")
    pr.add_argument("--no-scan-tools", action="store_true", help="don't scan tools/list")
    pr.add_argument("--no-scan-results", action="store_true", help="don't scan tool results")
    pr.add_argument("server", nargs=argparse.REMAINDER,
                    help="-- then the MCP server command to run")

    args = ap.parse_args(argv)
    if args.cmd != "run":
        return 2

    server_argv = _strip_dashes(args.server)
    if not server_argv:
        print("bastiongate: give a server command after --", file=sys.stderr)
        return 2

    policy = load_policy(args.policy) if args.policy else GatePolicy()
    if args.no_scan_tools:
        policy = _replace(policy, scan_tools=False)
    if args.no_scan_results:
        policy = _replace(policy, scan_results=False)

    return run_stdio(server_argv, policy, args.log)


def _strip_dashes(rest: list[str]) -> list[str]:
    return rest[1:] if rest and rest[0] == "--" else rest


def _replace(policy: GatePolicy, **kw) -> GatePolicy:
    from dataclasses import replace

    return replace(policy, **kw)


if __name__ == "__main__":
    raise SystemExit(main())
