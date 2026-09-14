"""bastiongate — MCP security gateway.

An inline proxy that sits between an AI agent and its MCP servers and enforces
security on every call: it scans `tools/list` for poisoned tool definitions
(via bastionsupply), applies a tool allow/deny policy, scans tool-call results
for indirect prompt injection, and logs every message as a JSONL trace.

The runtime-enforcement leg of the bastion family — prevent (agentbastion),
attack (bastionprobe), investigate (bastiontrace), scan (bastionsupply),
**gate (bastiongate)**.

    from bastiongate import Gate, GatePolicy
    gate = Gate(GatePolicy(deny={"run_command"}))
    forward, reply = gate.handle_client_msg(msg)
"""

from __future__ import annotations

from .policy import GatePolicy, from_dict, load_policy
from .proxy import Gate, run_stdio

__version__ = "0.2.0"


def run_http(*args, **kwargs):
    """Lazy re-export of http_proxy.run_http (keeps import light)."""
    from .http_proxy import run_http as _run_http

    return _run_http(*args, **kwargs)


__all__ = ["Gate", "GatePolicy", "load_policy", "from_dict", "run_stdio", "run_http", "__version__"]
