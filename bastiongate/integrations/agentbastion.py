"""Deep result inspection via agentbastion's Firewall.

Swaps the default static (bastionsupply-signature) result scan for
agentbastion's inbound guard: the heuristic detector by default, and the
Anthropic LLM judge when `inspector_judge` is set and credentials are present.

Enabled with policy `result_inspector: agentbastion`. Requires the optional
dependency:  pip install "bastiongateway[agentbastion]"
"""

from __future__ import annotations

import os

from ..guards import Decision
from ..policy import GatePolicy


def build_inspector(policy: GatePolicy):
    try:
        from agentbastion import Firewall
    except ImportError as e:  # fail fast at gate construction, not per-call
        raise RuntimeError(
            "result_inspector='agentbastion' needs the optional dependency: "
            'pip install "bastiongateway[agentbastion]"'
        ) from e

    firewall = _with_judge(policy) or Firewall()

    def inspect(text: str) -> Decision:
        if not text:
            return Decision(True, "empty result")
        verdict = firewall.check_tool_result(text)
        if verdict.allowed:
            return Decision(True, "agentbastion: clean")
        return Decision(False, f"agentbastion blocked: {verdict.reason}", tuple(verdict.matches))

    return inspect


def _with_judge(policy: GatePolicy):
    """Build a judge-backed Firewall if requested and credentials exist, else None."""
    if not policy.inspector_judge:
        return None
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise RuntimeError("inspector_judge=true but ANTHROPIC_API_KEY is not set")
    try:
        import anthropic
        from agentbastion import Firewall
    except ImportError as e:
        raise RuntimeError(
            'inspector_judge=true needs anthropic: pip install "bastiongateway[agentbastion-judge]"'
        ) from e
    model = os.environ.get("BASTIONGATE_JUDGE_MODEL", "claude-haiku-4-5")
    timeout_s = float(os.environ.get("BASTIONGATE_JUDGE_TIMEOUT", "10"))
    return Firewall.with_judge(anthropic.Anthropic(api_key=key), model=model, timeout_s=timeout_s)
