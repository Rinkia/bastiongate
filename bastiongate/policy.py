"""Gate policy: what the proxy allows, and what it does about risk.

Loadable from a YAML/JSON dict so the same file bastionsupply `harden` emits
(default/allow/deny) drives the gate.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

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

    # deep result inspection (see inspectors.py)
    result_inspector: str = "static"  # static | agentbastion
    inspector_fail: str = "closed"  # closed | open  (behavior if inspector errors)
    inspector_judge: bool = False  # agentbastion: also use the Anthropic LLM judge

    def tool_allowed(self, name: str) -> bool:
        if name in self.deny:
            return False
        if self.allow:
            return name in self.allow
        return self.default == "allow"


def load_policy(path: str | Path) -> GatePolicy:
    obj = json.loads(Path(path).read_text(encoding="utf-8")) if str(path).endswith(".json") else _yaml(path)
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
        result_inspector=obj.get("result_inspector", "static"),
        inspector_fail=obj.get("inspector_fail", "closed"),
        inspector_judge=obj.get("inspector_judge", False),
    )


def _yaml(path: str | Path) -> dict:
    """Tiny YAML reader for the subset bastionsupply harden emits.

    Handles `key: value`, `key:` followed by `  - item` lists, comments, and
    bare true/false. Avoids a PyYAML dependency for this flat shape.
    ponytail: swap for PyYAML if policies ever get nested.
    """
    out: dict = {}
    cur_key = None
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if line.lstrip().startswith("- "):
            item = line.lstrip()[2:].strip().strip('"')
            if cur_key:
                out.setdefault(cur_key, []).append(item)
            continue
        if ":" in line:
            key, _, val = line.partition(":")
            key = key.strip()
            val = val.strip().strip('"')
            cur_key = key
            if val == "":
                out.setdefault(key, [])
            else:
                out[key] = {"true": True, "false": False}.get(val.lower(), val)
    return out
