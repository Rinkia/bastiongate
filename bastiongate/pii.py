"""Redact secrets / PII in the arguments an agent sends to a tool.

The gate scans `tools/call` arguments on the way *out* (agent -> tool) so a
poisoned or over-curious tool cannot harvest credentials the model was tricked
into forwarding. Matches are replaced with `[REDACTED:<kind>]`; only the *kind*
is ever logged, never the value.

Patterns are anchored and linear (no nested quantifiers) to avoid ReDoS.
"""

from __future__ import annotations

import re

# (kind, compiled pattern). Order matters: more specific first.
_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----")),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("openai-key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("us-ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("credit-card", re.compile(r"\b(?:\d[ -]?){13,19}\b")),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
)

# credit-card needs a Luhn check to cut false positives (order numbers, ids)
_CC_KIND = "credit-card"


def _luhn_ok(digits: str) -> bool:
    nums = [int(c) for c in digits if c.isdigit()]
    if not (13 <= len(nums) <= 19):
        return False
    total, alt = 0, False
    for d in reversed(nums):
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def scrub_text(text: str) -> tuple[str, list[str]]:
    """Redact every match in `text`. Return (redacted_text, kinds_found)."""
    kinds: list[str] = []

    def _sub(kind):
        def repl(m):
            if kind == _CC_KIND and not _luhn_ok(m.group(0)):
                return m.group(0)  # not a real card number; leave it
            kinds.append(kind)
            return f"[REDACTED:{kind}]"

        return repl

    for kind, rx in _PATTERNS:
        text = rx.sub(_sub(kind), text)
    return text, kinds


def scrub(obj):
    """Recursively redact strings inside a JSON-ish structure (dict/list/str).

    Returns (new_obj, kinds_found). Never mutates the input.
    """
    kinds: list[str] = []

    def walk(o):
        if isinstance(o, str):
            new, found = scrub_text(o)
            kinds.extend(found)
            return new
        if isinstance(o, dict):
            return {k: walk(v) for k, v in o.items()}
        if isinstance(o, list):
            return [walk(v) for v in o]
        if isinstance(o, tuple):
            return tuple(walk(v) for v in o)
        return o

    return walk(obj), kinds
