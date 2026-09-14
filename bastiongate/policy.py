"""Gate policy: what the proxy allows, and what it does about risk.

Loadable from a YAML/JSON dict so the same file bastionsupply `harden` emits
(default/allow/deny) drives the gate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

# action taken when a risk is detected
BLOCK = "block"  # refuse the call / drop the tool
WARN = "warn"  # log only, let it through
REDACT = "redact"  # (args only) replace the secret/PII, forward the rest


@dataclass(frozen=True)
class GatePolicy:
    default: str = "allow"  # allow | deny  (for tools matching nothing)
    allow: frozenset[str] = frozenset()
    deny: frozenset[str] = frozenset()

    scan_tools: bool = True  # run bastionsupply.scan on tools/list
    on_poisoned_tool: str = BLOCK  # drop poisoned tools from the listing
    scan_results: bool = True  # scan tool-call results for injection
    on_injected_result: str = BLOCK  # block a result that carries injection

    scrub_args: bool = True  # scan tool-call arguments for secrets/PII
    on_pii_arg: str = REDACT  # redact | block | warn when args carry PII

    scrub_results: bool = False  # scan tool-call RESULTS for secrets/PII (opt-in)
    on_pii_result: str = REDACT  # redact | block | warn when a result carries PII

    # deep result inspection (see inspectors.py)
    result_inspector: str = "static"  # static | agentbastion
    inspector_fail: str = "closed"  # closed | open  (behavior if inspector errors)
    inspector_judge: bool = False  # agentbastion: also use the Anthropic LLM judge
    inspector_semantic: bool = False  # agentbastion: also use the semantic detector

    # per-tool knob overrides: {tool_name: {knob: value}}
    tools: dict = field(default_factory=dict)

    # knobs that a per-tool override may set
    _OVERRIDABLE = ("scrub_args", "on_pii_arg", "scan_results", "on_injected_result",
                    "scrub_results", "on_pii_result")

    def tool_allowed(self, name: str) -> bool:
        if name in self.deny:
            return False
        if self.allow:
            return name in self.allow
        return self.default == "allow"

    def opt(self, tool: str, knob: str):
        """Value of `knob` for `tool` — a per-tool override, else the global."""
        override = self.tools.get(tool)
        if override and knob in override:
            return override[knob]
        return getattr(self, knob)


def load_policy(path: str | Path) -> GatePolicy:
    # YAML is a superset of JSON, so safe_load reads both harden output shapes.
    obj = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if not isinstance(obj, dict):
        raise ValueError("policy file must be a mapping")
    return from_dict(obj)


def from_dict(obj: dict) -> GatePolicy:
    return GatePolicy(
        default=obj.get("default", "allow"),
        allow=frozenset(obj.get("allow", []) or []),
        deny=frozenset(obj.get("deny", []) or []),
        scan_tools=obj.get("scan_tools", True),
        on_poisoned_tool=obj.get("on_poisoned_tool", BLOCK),
        scan_results=obj.get("scan_results", True),
        on_injected_result=obj.get("on_injected_result", BLOCK),
        scrub_args=obj.get("scrub_args", True),
        on_pii_arg=obj.get("on_pii_arg", REDACT),
        scrub_results=obj.get("scrub_results", False),
        on_pii_result=obj.get("on_pii_result", REDACT),
        result_inspector=obj.get("result_inspector", "static"),
        inspector_fail=obj.get("inspector_fail", "closed"),
        inspector_judge=obj.get("inspector_judge", False),
        inspector_semantic=obj.get("inspector_semantic", False),
        tools=obj.get("tools", {}) or {},
    )
