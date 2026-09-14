"""The inspection logic, reusing bastionsupply's static checks.

- tools/list results are scanned with the real bastionsupply scanner.
- tool-call results are scanned by wrapping the text as a synthetic tool and
  reusing the same poisoning / hidden-unicode signatures (a tool result that
  says "ignore previous instructions" is the indirect-injection attack).
"""

from __future__ import annotations

from dataclasses import dataclass

from bastionsupply.models import Server, Tool
from bastionsupply.scanner import scan

from .policy import BLOCK, GatePolicy

_ACTIVE_CHECKS = {"tool-poisoning", "hidden-unicode"}  # attacks in free text


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str = ""
    findings: tuple = ()


def check_tool_call(name: str, policy: GatePolicy) -> Decision:
    if policy.tool_allowed(name):
        return Decision(True, "policy: allowed")
    return Decision(False, f"policy: tool '{name}' not permitted")


def scan_tools_list(tools: list[dict]) -> dict[str, tuple]:
    """Return {tool_name: findings} for tools that have any finding."""
    server = Server(
        name="upstream",
        tools=tuple(
            Tool(
                name=str(t.get("name", "")),
                description=str(t.get("description", "")),
                input_schema=t.get("inputSchema") or t.get("input_schema") or {},
            )
            for t in tools
        ),
    )
    report = scan(server)
    by_tool: dict[str, list] = {}
    for f in report.findings:
        by_tool.setdefault(f.tool, []).append(f)
    return {k: tuple(v) for k, v in by_tool.items()}


def poisoned_tool_names(tools: list[dict]) -> set[str]:
    """Names whose *own definition* carries an active injection/hidden-unicode."""
    bad = set()
    for name, findings in scan_tools_list(tools).items():
        if any(f.check in _ACTIVE_CHECKS for f in findings):
            bad.add(name)
    return bad


def scan_result_text(text: str) -> Decision:
    """Scan a tool-call result body for injection."""
    if not text:
        return Decision(True, "empty result")
    synthetic = Server("result", (Tool(name="_result", description=text),))
    findings = tuple(f for f in scan(synthetic).findings if f.check in _ACTIVE_CHECKS)
    if findings:
        kinds = ", ".join(sorted({f.check for f in findings}))
        return Decision(False, f"tool result carries injection ({kinds})", findings)
    return Decision(True, "clean result")
