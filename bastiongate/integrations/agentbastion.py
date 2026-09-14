"""Deep result inspection via agentbastion's Firewall.

Swaps the default static (bastionsupply-signature) result scan for
agentbastion's inbound guard, composed from up to three tiers:

    heuristics (always)  +  semantic detector (inspector_semantic)  +  LLM judge (inspector_judge)

Enabled with policy `result_inspector: agentbastion`. Requires the optional
dependency:  pip install "bastiongateway[agentbastion]"  (add httpx for the
semantic embedder, anthropic for the judge).
"""

from __future__ import annotations

import os

from ..guards import Decision
from ..policy import GatePolicy


def build_inspector(policy: GatePolicy):
    try:
        from agentbastion import Firewall
        from agentbastion.inbound import InboundGuard
    except ImportError as e:  # fail fast at gate construction, not per-call
        raise RuntimeError(
            "result_inspector='agentbastion' needs the optional dependency: "
            'pip install "bastiongateway[agentbastion]"'
        ) from e

    detectors = []
    if policy.inspector_semantic:
        detectors.append(_semantic_detector())
    judge = _judge() if policy.inspector_judge else None

    if detectors or judge:
        firewall = Firewall(inbound=InboundGuard(judge=judge, detectors=detectors))
    else:
        firewall = Firewall()  # heuristic only

    def inspect(text: str) -> Decision:
        if not text:
            return Decision(True, "empty result")
        verdict = firewall.check_tool_result(text)
        if verdict.allowed:
            return Decision(True, "agentbastion: clean")
        return Decision(False, f"agentbastion blocked: {verdict.reason}", tuple(verdict.matches))

    return inspect


def _semantic_detector():
    from agentbastion.semantic import SemanticDetector

    threshold = float(os.environ.get("BASTIONGATE_SEMANTIC_THRESHOLD", "0.75"))
    return SemanticDetector(_make_embedder(), threshold=threshold)


def _make_embedder():
    """Embedder for the semantic detector — a self-hosted embeddings endpoint."""
    url = os.environ.get("BASTIONGATE_EMBED_URL")
    if not url:
        raise RuntimeError(
            "inspector_semantic=true needs an embeddings endpoint in BASTIONGATE_EMBED_URL "
            '(and httpx: pip install "bastiongateway[agentbastion-semantic]")'
        )
    from agentbastion.semantic import http_embedder

    return http_embedder(url)


def _judge():
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise RuntimeError("inspector_judge=true but ANTHROPIC_API_KEY is not set")
    try:
        import anthropic
        from agentbastion.inbound import LLMJudge
    except ImportError as e:
        raise RuntimeError(
            'inspector_judge=true needs anthropic: pip install "bastiongateway[agentbastion-judge]"'
        ) from e
    model = os.environ.get("BASTIONGATE_JUDGE_MODEL", "claude-haiku-4-5")
    timeout_s = float(os.environ.get("BASTIONGATE_JUDGE_TIMEOUT", "10"))
    return LLMJudge(anthropic.Anthropic(api_key=key), model=model, timeout_s=timeout_s)
