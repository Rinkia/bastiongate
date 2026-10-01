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

# findings that mean a tool's own definition is an attack -> drop it from the listing
_ACTIVE_CHECKS = {"tool-poisoning", "hidden-unicode", "homoglyph-name"}


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


# Decoding is linear but not free (~0.2-2 s per MB): bigger results are not decoded
# (and fail closed when on_encoded_result is block, see proxy._scan_encoded).
ENCODED_SCAN_MAX_CHARS = 1_000_000


def encoded_findings(tools: list[dict]) -> dict[str, tuple]:
    """{tool_name: encoded-injection findings} for a tools/list page."""
    return {name: tuple(f for f in found if f.check == "encoded-injection")
            for name, found in scan_tools_list(tools).items()
            if any(f.check == "encoded-injection" for f in found)}


def scan_encoded_text(text: str) -> Decision:
    """A tool result whose ENCODED content (base64, hex, binary, ...) carries an
    injection (bastionsupply's encoded-injection check). Separate from
    scan_result_text so the gate can act on it under its own knob."""
    if not text:
        return Decision(True, "empty result")
    from bastionsupply.checks import check_encoded_injection

    findings = tuple(check_encoded_injection(Server("result", (Tool(name="_result", description=text),))))
    if findings:
        return Decision(False, f"tool result hides an injection ({findings[0].message})", findings)
    return Decision(True, "no encoded injection")


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
