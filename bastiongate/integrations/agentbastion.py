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
        # a verdict cache spares repeat results the judge/semantic round-trip
        cache = _cache() if judge else None
        firewall = Firewall(inbound=InboundGuard(judge=judge, detectors=detectors, cache=cache))
        if policy.inspector_semantic:
            _warm(firewall)  # load the model + embed templates now, not on first result
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


def _warm(firewall) -> None:
    """Force the semantic model to load and embed its templates at startup, so
    the first real result isn't stuck behind a cold model load. Bounded by a
    timeout so a hung/huge download fails fast instead of hanging forever."""
    if os.environ.get("BASTIONGATE_EMBED_WARM", "1") == "0":
        return
    import threading

    timeout = float(os.environ.get("BASTIONGATE_EMBED_INIT_TIMEOUT", "120"))
    err: list[Exception] = []

    def run():
        try:
            firewall.check_tool_result("warmup")
        except Exception as e:  # surface at startup, not per-request
            err.append(e)

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout=timeout)
    if t.is_alive():
        raise RuntimeError(f"semantic embedder init timed out after {timeout}s")
    if err:
        raise err[0]


def _cache():
    from agentbastion.cache import TTLCache

    ttl = int(os.environ.get("BASTIONGATE_JUDGE_CACHE_TTL", "300"))
    size = int(os.environ.get("BASTIONGATE_JUDGE_CACHE_SIZE", "1024"))
    return TTLCache(maxsize=size, ttl_s=ttl)


def _semantic_detector():
    from agentbastion.semantic import SemanticDetector

    threshold = float(os.environ.get("BASTIONGATE_SEMANTIC_THRESHOLD", "0.75"))
    return SemanticDetector(_make_embedder(), threshold=threshold)


def _make_embedder():
    """Embedder for the semantic detector.

    Two backends, in priority order:
      - BASTIONGATE_EMBED_MODEL: a local sentence-transformers model — result
        text never leaves the process (no egress).
      - BASTIONGATE_EMBED_URL: a self-hosted embeddings endpoint (result text is
        POSTed to it).
    """
    model_name = os.environ.get("BASTIONGATE_EMBED_MODEL")
    if model_name:
        return _local_embedder(model_name)
    url = os.environ.get("BASTIONGATE_EMBED_URL")
    if url:
        from agentbastion.semantic import http_embedder

        return http_embedder(url)
    raise RuntimeError(
        "inspector_semantic=true needs an embedder: set BASTIONGATE_EMBED_MODEL "
        '(local: pip install "bastiongateway[agentbastion-local]") or '
        'BASTIONGATE_EMBED_URL (remote: pip install "bastiongateway[agentbastion-semantic]")'
    )


def _local_embedder(model_name: str):
    """A local, in-process embedder — no network, no result-text egress."""
    model = _load_st_model(model_name)

    def embed(texts):
        vecs = model.encode(list(texts), normalize_embeddings=True)
        return vecs.tolist() if hasattr(vecs, "tolist") else [list(v) for v in vecs]

    return embed


def _load_st_model(model_name: str):
    try:
        from sentence_transformers import SentenceTransformer
    except ImportError as e:
        raise RuntimeError(
            'BASTIONGATE_EMBED_MODEL needs sentence-transformers: '
            'pip install "bastiongateway[agentbastion-local]"'
        ) from e
    return SentenceTransformer(model_name)


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
