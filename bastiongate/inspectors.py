"""Pluggable tool-result inspector.

Default is the static bastionsupply signature scan. `result_inspector:
agentbastion` swaps in agentbastion's Firewall (semantic detector + optional
LLM judge) for deeper inspection — see integrations/agentbastion.py.

Every inspector is wrapped with a fail policy: if the inspector raises, the
gate fails **closed** by default (treat the result as blocked) rather than
letting an un-inspected result through.
"""

from __future__ import annotations

from typing import Callable

from . import guards
from .policy import GatePolicy

Inspector = Callable[[str], guards.Decision]


def make_inspector(policy: GatePolicy) -> Inspector:
    if policy.result_inspector == "agentbastion":
        from .integrations.agentbastion import build_inspector

        inner = build_inspector(policy)
    else:
        inner = guards.scan_result_text

    fail_closed = policy.inspector_fail != "open"

    def inspect(text: str) -> guards.Decision:
        try:
            return inner(text)
        except Exception as e:  # never let an inspector crash the proxy
            if fail_closed:
                return guards.Decision(False, f"inspector error, failing closed: {type(e).__name__}")
            return guards.Decision(True, f"inspector error, failing open: {type(e).__name__}")

    return inspect
