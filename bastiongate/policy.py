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

# flow-guard tool labels (see flows.py)
LABEL_NAMES = ("private", "untrusted", "egress")


@dataclass(frozen=True)
class GatePolicy:
    default: str = "allow"  # allow | deny  (for tools matching nothing)
    allow: frozenset[str] = frozenset()
    deny: frozenset[str] = frozenset()

    scan_tools: bool = True  # run bastionsupply.scan on tools/list
    on_poisoned_tool: str = BLOCK  # drop poisoned tools from the listing
    scan_results: bool = True  # scan tool-call results for injection
    scan_resources: bool = True  # include resource blocks / resources/read in result scans (0.10)
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

    # flow guard (flows.py): untrusted + private read in one session, then egress
    scan_flows: bool = True  # track session taint and check egress calls
    on_tainted_egress: str = WARN  # warn (shadow, default) | block (-32005)
    # encoded injection in tool results (base64/hex/binary... decoded by bastioncorpus)
    on_encoded_result: str = WARN  # warn (shadow, default) | block (-32006)
    label_packs: bool = True  # built-in labels for common servers (github, fetch, ...)

    # per-tool knob overrides: {tool_name: {knob: value}}; `labels` sets flow labels
    tools: dict = field(default_factory=dict)

    # policy_version 2: detector modes forwarded to agentbastion deep-inspect,
    # {bastion.* / custom.*: off | shadow | enforce}. Gate's own checks have no
    # detector IDs: their knobs are the modes (scan_*: false = off, on_*: warn = shadow).
    detector_modes: dict = field(default_factory=dict)

    # knobs that a per-tool override may set
    _OVERRIDABLE = ("scrub_args", "on_pii_arg", "scan_results", "on_injected_result",
                    "scrub_results", "on_pii_result", "on_tainted_egress", "on_encoded_result",
                    "scan_resources")

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

    def tool_labels(self, tool: str) -> frozenset[str] | None:
        """Explicit flow labels for `tool` from its per-tool override, else None."""
        override = self.tools.get(tool)
        if isinstance(override, dict) and "labels" in override:
            return frozenset(override["labels"])
        return None


class PolicyError(ValueError):
    """A policy that must not load. policy_version 2 fails loudly instead of ignoring lines."""


def load_policy(path: str | Path) -> GatePolicy:
    # YAML is a superset of JSON, so safe_load reads both harden output shapes.
    obj = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if not isinstance(obj, dict):
        raise PolicyError("policy file must be a mapping")
    return from_dict(obj)


def from_dict(obj: dict) -> GatePolicy:
    version = obj.get("policy_version", 1)
    if isinstance(version, bool) or version not in (1, 2):
        raise PolicyError(f"unsupported policy_version {version!r}; this bastiongate reads 1 and 2")
    if version == 2:
        return _from_v2(obj)
    if "detectors" in obj:
        raise PolicyError(
            "`detectors:` requires `policy_version: 2` at the top of the file; "
            "without it the block would be silently ignored"
        )
    return _from_v1(obj)


# --- policy_version 2 --------------------------------------------------------
# Top level = a frozen shared core + one block per tool. Gate reads its own `gate:`
# block strictly and never looks inside another tool's block.
_V2_CORE = frozenset({"policy_version", "default", "allow", "deny", "rate_limits", "detectors"})
_V2_BLOCKS = frozenset({"gate", "bastion", "supply", "skill"})
_TOOL_POLICY_LISTS = ("allow", "deny", "rate_limits")
_BOOL_KNOBS = ("scan_tools", "scan_results", "scrub_args", "scrub_results",
               "inspector_judge", "inspector_semantic", "scan_flows", "label_packs", "scan_resources")
_CHOICE_KNOBS = {
    "on_poisoned_tool": (BLOCK, WARN),
    "on_injected_result": (BLOCK, WARN),
    "on_pii_arg": (REDACT, BLOCK, WARN),
    "on_pii_result": (REDACT, BLOCK, WARN),
    "on_tainted_egress": (WARN, BLOCK),
    "on_encoded_result": (WARN, BLOCK),
    "result_inspector": ("static", "agentbastion"),
    "inspector_fail": ("closed", "open"),
}
_FLOW_KNOBS = ("scan_flows", "on_tainted_egress", "label_packs", "on_encoded_result", "scan_resources")
_GATE_KNOBS = frozenset(_BOOL_KNOBS) | frozenset(_CHOICE_KNOBS) | {"tools"}
_MODES = ("off", "shadow", "enforce")
_INSPECTOR_NAMESPACES = ("bastion.", "custom.")  # run by agentbastion deep-inspect
_IGNORED_NAMESPACES = ("supply.", "skill.")  # tools gate never runs


def _from_v2(obj: dict) -> GatePolicy:
    unknown = set(obj) - _V2_CORE - _V2_BLOCKS
    if unknown:
        misplaced = sorted(unknown & _GATE_KNOBS)
        if misplaced:
            raise PolicyError(f"in policy_version 2 gate knobs live under `gate:`; move {misplaced} there")
        raise PolicyError(
            f"unknown top-level key(s) {sorted(unknown)}; policy_version 2 allows "
            f"{sorted(_V2_CORE | _V2_BLOCKS)}"
        )
    gate = obj.get("gate") or {}
    if not isinstance(gate, dict):
        raise PolicyError("`gate:` must be a mapping of gate knobs")
    stray = set(gate) - _GATE_KNOBS
    if stray:
        raise PolicyError(f"unknown key(s) in `gate:` {sorted(stray)}; allowed: {sorted(_GATE_KNOBS)}")
    for knob, value in gate.items():
        if knob != "tools":
            _check_knob(knob, value, "gate")
    tools = gate.get("tools") or {}
    _check_per_tool(tools)

    modes = _v2_detector_modes(obj.get("detectors"))
    if modes and gate.get("result_inspector", "static") != "agentbastion":
        raise PolicyError(
            f"detector modes {sorted(modes)} run in agentbastion deep-inspect; set "
            "`gate: {result_inspector: agentbastion}`, or remove them (a kill switch must "
            "never look honored when nothing executes it)"
        )
    knobs = {k: v for k, v in gate.items() if k != "tools"}
    return GatePolicy(
        default=_v2_default(obj),
        allow=frozenset(obj.get("allow", []) or []),
        deny=frozenset(obj.get("deny", []) or []),
        tools=tools,
        detector_modes=modes,
        **knobs,
    )


def _check_knob(knob: str, value, where: str) -> None:
    if knob in _BOOL_KNOBS and not isinstance(value, bool):
        raise PolicyError(f"`{where}.{knob}` must be true or false, got {value!r}")
    if knob in _CHOICE_KNOBS and value not in _CHOICE_KNOBS[knob]:
        raise PolicyError(f"`{where}.{knob}`: {value!r} is not one of {' | '.join(_CHOICE_KNOBS[knob])}")


def _check_per_tool(tools) -> None:
    if not isinstance(tools, dict):
        raise PolicyError("`gate.tools` must map tool names to knob overrides")
    for tool, override in tools.items():
        if not isinstance(override, dict):
            raise PolicyError(f"`gate.tools.{tool}` must be a mapping of knob overrides")
        per_tool = set(GatePolicy._OVERRIDABLE) | {"labels"}
        not_overridable = set(override) - per_tool
        if not_overridable:
            raise PolicyError(
                f"`gate.tools.{tool}`: {sorted(not_overridable)} cannot be set per tool; "
                f"per-tool knobs: {sorted(per_tool)}"
            )
        for knob, value in override.items():
            if knob == "labels":
                _check_labels(value, f"gate.tools.{tool}")
            else:
                _check_knob(knob, value, f"gate.tools.{tool}")


def _check_labels(value, where: str) -> None:
    if not isinstance(value, list) or not all(v in LABEL_NAMES for v in value):
        raise PolicyError(
            f"`{where}.labels` must be a list drawn from {' | '.join(LABEL_NAMES)}, got {value!r}"
        )


def _v2_default(obj: dict) -> str:
    if "default" not in obj:
        if any(key in obj for key in _TOOL_POLICY_LISTS):
            raise PolicyError("`default:` (allow or deny) is required when allow, deny or rate_limits is set")
        return "allow"  # no tool lists: every tool allowed, as with gate's v1 default
    default = str(obj["default"]).lower()
    if default not in ("allow", "deny"):
        raise PolicyError(f"`default:` must be allow or deny, got {obj['default']!r}")
    if default == "allow" and obj.get("allow"):
        raise PolicyError(
            "`default: allow` contradicts a non-empty allow list: whenever an allow list exists, "
            "unlisted tools are denied. Use `default: deny`, or drop the allow list"
        )
    return default


def _v2_detector_modes(raw) -> dict:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise PolicyError("`detectors:` must be a mapping of detector ID to off | shadow | enforce")
    modes = {}
    for det_id, mode in raw.items():
        if not isinstance(det_id, str):
            raise PolicyError(f"detector ID must be a string, got {det_id!r}")
        if det_id.startswith("gate."):
            raise PolicyError(
                f"{det_id!r}: bastiongate has no detector IDs; its `gate:` knobs are the modes "
                "(off = scan_tools/scan_results/scrub_args/scrub_results/scan_flows: false, shadow = on_*: warn, "
                "e.g. on_poisoned_tool, on_injected_result, on_pii_arg, on_pii_result, on_tainted_egress)"
            )
        if det_id.startswith(_IGNORED_NAMESPACES):
            continue
        if not det_id.startswith(_INSPECTOR_NAMESPACES):
            hint = f"; did you mean {'bastion.' + det_id!r}?" if "." not in det_id else ""
            raise PolicyError(f"detector ID {det_id!r} has no known namespace{hint}")
        modes[det_id] = _mode(det_id, mode)
    return modes


def _mode(det_id: str, mode) -> str:
    # YAML 1.1 reads unquoted off/no/false as False, on/yes/true as True.
    if mode is False:
        return "off"
    if mode is True:
        raise PolicyError(f"detector {det_id!r}: mode `on`/`true` is ambiguous; write enforce or shadow")
    if mode not in _MODES:
        raise PolicyError(f"detector {det_id!r}: mode {mode!r} is not one of off | shadow | enforce")
    return mode


# --- policy_version 1 (lenient, as before; flow-guard keys added in 0.9) --------

def _from_v1(obj: dict) -> GatePolicy:
    # keys added in 0.9 are validated even in v1 (no older file can contain them);
    # pre-0.9 v1 keys stay lenient so existing files load exactly as before
    for knob in _FLOW_KNOBS:
        if knob in obj:
            _check_knob(knob, obj[knob], "policy")
    tools = obj.get("tools", {}) or {}
    if isinstance(tools, dict):
        for tool, override in tools.items():
            if not isinstance(override, dict):
                continue
            # a string `labels: "egress"` must never be iterated character by character
            if "labels" in override:
                _check_labels(override["labels"], f"tools.{tool}")
            for knob in ("on_tainted_egress", "on_encoded_result", "scan_resources"):
                if knob in override:
                    _check_knob(knob, override[knob], f"tools.{tool}")
    return GatePolicy(
        default=obj.get("default", "allow"),
        allow=frozenset(obj.get("allow", []) or []),
        deny=frozenset(obj.get("deny", []) or []),
        scan_tools=obj.get("scan_tools", True),
        on_poisoned_tool=obj.get("on_poisoned_tool", BLOCK),
        scan_results=obj.get("scan_results", True),
        scan_resources=obj.get("scan_resources", True),
        on_injected_result=obj.get("on_injected_result", BLOCK),
        scrub_args=obj.get("scrub_args", True),
        on_pii_arg=obj.get("on_pii_arg", REDACT),
        scrub_results=obj.get("scrub_results", False),
        on_pii_result=obj.get("on_pii_result", REDACT),
        result_inspector=obj.get("result_inspector", "static"),
        inspector_fail=obj.get("inspector_fail", "closed"),
        inspector_judge=obj.get("inspector_judge", False),
        inspector_semantic=obj.get("inspector_semantic", False),
        scan_flows=obj.get("scan_flows", True),
        on_tainted_egress=obj.get("on_tainted_egress", WARN),
        on_encoded_result=obj.get("on_encoded_result", WARN),
        label_packs=obj.get("label_packs", True),
        tools=tools,
    )
