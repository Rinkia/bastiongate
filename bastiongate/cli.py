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

    ph = sub.add_parser("run-http", help="proxy an MCP Streamable-HTTP server through the gate")
    ph.add_argument("--upstream", required=True, help="upstream MCP server URL, e.g. http://127.0.0.1:8000/mcp")
    ph.add_argument("--host", default="127.0.0.1", help="listen host (default 127.0.0.1)")
    ph.add_argument("--port", type=int, default=9000, help="listen port (default 9000)")
    ph.add_argument("--auth-key", help="require this key in the X-Bastiongate-Key header "
                                       "(else env BASTIONGATE_PROXY_KEY)")
    ph.add_argument("--policy", help="gate policy YAML/JSON")
    ph.add_argument("--log", help="write a JSONL trace of every call")
    ph.add_argument("--no-scan-tools", action="store_true", help="don't scan tools/list")
    ph.add_argument("--no-scan-results", action="store_true", help="don't scan tool results")

    args = ap.parse_args(argv)

    if args.cmd == "run":
        server_argv = _strip_dashes(args.server)
        if not server_argv:
            print("bastiongate: give a server command after --", file=sys.stderr)
            return 2
        policy = _apply_flags(load_policy(args.policy) if args.policy else GatePolicy(), args)
        return run_stdio(server_argv, policy, args.log)

    if args.cmd == "run-http":
        import os

        from .http_proxy import run_http

        policy = _apply_flags(load_policy(args.policy) if args.policy else GatePolicy(), args)
        auth_key = args.auth_key or os.environ.get("BASTIONGATE_PROXY_KEY")
        return run_http(args.upstream, policy, args.host, args.port, args.log, auth_key)

    return 2


def _apply_flags(policy: GatePolicy, args) -> GatePolicy:
    if getattr(args, "no_scan_tools", False):
        policy = _replace(policy, scan_tools=False)
    if getattr(args, "no_scan_results", False):
        policy = _replace(policy, scan_results=False)
    return policy


def _strip_dashes(rest: list[str]) -> list[str]:
    return rest[1:] if rest and rest[0] == "--" else rest


def _replace(policy: GatePolicy, **kw) -> GatePolicy:
    from dataclasses import replace

    return replace(policy, **kw)


if __name__ == "__main__":
    raise SystemExit(main())
