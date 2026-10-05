"""bastiongate command line.

    # put the gate in front of an MCP server; the agent launches THIS instead
    bastiongate run --log gate.jsonl -- npx -y @some/mcp-server
    bastiongate run --policy policy.yaml -- python my_server.py

    # which flow-guard labels each tool gets (policy | pack | auto)
    bastiongate labels --policy policy.yaml tools.json

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
    _otel_args(pr)
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
    _otel_args(ph)

    pl = sub.add_parser("labels", help="show the flow-guard labels each tool gets, and why")
    pl.add_argument("--policy", help="gate policy YAML/JSON (per-tool `labels`, `label_packs`)")
    pl.add_argument("tools", nargs="?", help="a tools/list JSON dump; omit to list the built-in packs")

    args = ap.parse_args(argv)

    if args.cmd == "labels":
        return _cmd_labels(args)

    if args.cmd == "run":
        server_argv = _strip_dashes(args.server)
        if not server_argv:
            print("bastiongate: give a server command after --", file=sys.stderr)
            return 2
        policy = _apply_flags(load_policy(args.policy) if args.policy else GatePolicy(), args)
        return run_stdio(server_argv, policy, args.log, _otel_sink(args))

    if args.cmd == "run-http":
        import os

        from .http_proxy import run_http

        policy = _apply_flags(load_policy(args.policy) if args.policy else GatePolicy(), args)
        auth_key = args.auth_key or os.environ.get("BASTIONGATE_PROXY_KEY")
        return run_http(args.upstream, policy, args.host, args.port, args.log, auth_key, _otel_sink(args))

    return 2


def _otel_args(p) -> None:
    p.add_argument("--otel-out", help="write OTel GenAI execute_tool spans (OTLP/JSON lines) to this file")
    p.add_argument("--otel-endpoint", help="POST spans to this OTLP/HTTP collector (https, or http on loopback); "
                                          "headers from OTEL_EXPORTER_OTLP_HEADERS")
    p.add_argument("--otel-content", action="store_true",
                   help="include tool arguments/results in spans (PII-scrubbed, capped); default: hashes only")


def _otel_sink(args):
    if not (args.otel_out or args.otel_endpoint):
        return None
    from .otel import OtelSink

    try:
        return OtelSink(path=args.otel_out, endpoint=args.otel_endpoint, content=args.otel_content)
    except ValueError as e:
        raise SystemExit(f"bastiongate: {e}")


def _cmd_labels(args) -> int:
    """Print tool -> labels -> source (policy | pack:<name> | auto | none), no proxy."""
    import json
    from pathlib import Path

    from . import flows

    policy = load_policy(args.policy) if args.policy else GatePolicy()
    labels = flows.Labels()
    if args.tools:
        try:
            obj = json.loads(Path(args.tools).read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            print(f"bastiongate: cannot read tools file {args.tools}: {e}", file=sys.stderr)
            return 2
        if isinstance(obj, dict):
            obj = (obj.get("result") or obj).get("tools", [])
        tools = [t for t in obj if isinstance(t, dict)] if isinstance(obj, list) else []
        labels.learn(tools)
        names = [str(t.get("name", "")) for t in tools]
    else:
        names = [n for table in flows.PACKS.values() for n in table] if policy.label_packs else []
        names += [n for n in policy.tools if n not in names]
    print(f"{'TOOL':<30} {'LABELS':<28} SOURCE")
    for name in names:
        tool_labels, source = labels.lookup(name, policy)
        print(f"{name:<30} {','.join(sorted(tool_labels)) or '-':<28} {source}")
    return 0


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
