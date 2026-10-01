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


def _as_server(tools: list[dict]) -> Server:
    return Server(name="upstream", tools=tuple(
        Tool(name=str(t.get("name", "")), description=str(t.get("description", "")),
             input_schema=t.get("inputSchema") or t.get("input_schema") or {})
        for t in tools))


def _active(server: Server) -> list:
    """Only the checks the gate enforces on (not the whole bastionsupply scan, which
    would also decode every text for a finding the gate then discards)."""
    from bastionsupply.checks import check_hidden_unicode, check_homoglyph_name, check_tool_poisoning

    return [f for check in (check_tool_poisoning, check_hidden_unicode, check_homoglyph_name)
            for f in check(server)]


def poisoned_tool_names(tools: list[dict]) -> set[str]:
    """Names whose *own definition* carries an active injection/hidden-unicode."""
    return {f.tool for f in _active(_as_server(tools)) if f.check in _ACTIVE_CHECKS}


# Decoding is linear but not free (~0.2-2 s per MB): bigger results are not decoded
# (and fail closed when on_encoded_result is block, see proxy._scan_encoded).
ENCODED_SCAN_MAX_CHARS = 1_000_000


def encoded_findings(tools: list[dict]) -> dict[str, tuple] | None:
    """{tool_name: encoded-injection findings} for a tools/list page, or None when the
    page is too large to decode (more than ENCODED_SCAN_MAX_CHARS of definitions)."""
    from bastionsupply.checks import check_encoded_injection

    size = sum(len(str(t.get("description", ""))) + len(str(t.get("inputSchema") or "")) for t in tools)
    if size > ENCODED_SCAN_MAX_CHARS:
        return None
    by_tool: dict[str, list] = {}
    for f in check_encoded_injection(_as_server(tools)):
        by_tool.setdefault(f.tool, []).append(f)
    return {k: tuple(v) for k, v in by_tool.items()}


def scan_encoded_text(text: str, views=None) -> Decision:
    """A tool result whose ENCODED content (base64, hex, binary, ...) carries an
    injection (bastionsupply's encoded-injection check). Separate from
    scan_result_text so the gate can act on it under its own knob. Pass `views`
    (bastionsupply.checks.decoded_views(text)) to reuse a decode."""
    if not text:
        return Decision(True, "empty result")
    from bastionsupply.checks import encoded_injection

    finding = encoded_injection(text, "The result", "_result", views=views)
    if finding:
        return Decision(False, f"tool result hides an injection ({finding.message})", (finding,))
    return Decision(True, "no encoded injection")


def scan_result_text(text: str) -> Decision:
    """Scan a tool-call result body for injection."""
    if not text:
        return Decision(True, "empty result")
    synthetic = Server("result", (Tool(name="_result", description=text),))
    findings = tuple(sorted((f for f in _active(synthetic) if f.check in _ACTIVE_CHECKS),
                            key=lambda f: (f.check, f.tool)))
    if findings:
        kinds = ", ".join(sorted({f.check for f in findings}))
        return Decision(False, f"tool result carries injection ({kinds})", findings)
    return Decision(True, "clean result")
