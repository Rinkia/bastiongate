"""The inspection logic, reusing bastionsupply's static checks.

- tools/list results are scanned with the real bastionsupply scanner.
- tool-call results are scanned by wrapping the text as a synthetic tool and
  reusing the same poisoning / hidden-unicode signatures (a tool result that
  says "ignore previous instructions" is the indirect-injection attack).
"""

from __future__ import annotations

import functools
import json
import re
import unicodedata
import urllib.parse
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


def _model_text(t: dict) -> str:
    """Everything in a tool definition besides inputSchema that reaches the model:
    description, title, annotations.title, outputSchema (scanned as one text)."""
    parts = [str(t.get("description", ""))]
    if isinstance(t.get("title"), str):
        parts.append(t["title"])
    ann = t.get("annotations")
    if isinstance(ann, dict) and isinstance(ann.get("title"), str):
        parts.append(ann["title"])
    if t.get("outputSchema") is not None:
        parts.append(json.dumps(t["outputSchema"], default=str))
    return "\n".join(p for p in parts if p)


def _as_server(tools: list[dict]) -> Server:
    return Server(name="upstream", tools=tuple(
        Tool(name=str(t.get("name", "")), description=_model_text(t),
             input_schema=t.get("inputSchema") or t.get("input_schema") or {})
        for t in tools if isinstance(t, dict)))  # malformed entries: see proxy._filter_tools


def _active(server: Server) -> list:
    """Only the checks the gate enforces on (not the whole bastionsupply scan, which
    would also decode every text for a finding the gate then discards)."""
    from bastionsupply.checks import check_hidden_unicode, check_homoglyph_name, check_tool_poisoning

    return [f for check in (check_tool_poisoning, check_hidden_unicode, check_homoglyph_name)
            for f in check(server)]


# Decoding is linear but not free (~0.2-0.7 s per MB): bigger results are not decoded
# (and fail closed when on_encoded_result is block, see proxy._scan_encoded).
ENCODED_SCAN_MAX_CHARS = 1_000_000
# A tool definition bigger than this is not scanned: it is treated as poisoned (fail
# closed). No real tool needs a megabyte of description, and the plain scan of a
# tools/list page has no other bound (~0.3 s per MB per tool).
TOOL_DEF_MAX_CHARS = 1_000_000
# ...and a tools/list page bigger than this in total stops being scanned at the tool that
# crosses it; that tool and every later one fail closed the same way.
TOOLS_PAGE_MAX_CHARS = 5_000_000
# decode_transforms adds whole-text rewrites (4 more views of the full text): only on
# results up to this size, the same bound agentbastion's input guard uses.
TRANSFORM_MAX_CHARS = 65_536


def _def_size(t: dict) -> int:
    if not isinstance(t, dict):
        return 0
    return len(str(t))  # every field counts, whatever its name or nesting


def _split_oversize(tools: list[dict]) -> tuple[list[dict], set[str]]:
    """(tools to scan, names that fail closed): a definition over TOOL_DEF_MAX_CHARS,
    and every tool from the one that pushes the page past TOOLS_PAGE_MAX_CHARS."""
    eligible, over, total = [], set(), 0
    for t in tools:
        size = _def_size(t)
        total += size
        if size > TOOL_DEF_MAX_CHARS or total > TOOLS_PAGE_MAX_CHARS:
            over.add(str(t.get("name", "")) if isinstance(t, dict) else "")
        else:
            eligible.append(t)
    return eligible, over


def oversize_tool_names(tools: list[dict]) -> set[str]:
    return _split_oversize(tools)[1]


def poisoned_tool_names(tools: list[dict]) -> set[str]:
    """Names whose *own definition* carries an active injection/hidden-unicode.
    Oversize definitions are skipped here; see oversize_tool_names."""
    eligible, _over = _split_oversize(tools)
    return {f.tool for f in _active(_as_server(eligible)) if f.check in _ACTIVE_CHECKS}


def encoded_findings(tools: list[dict]) -> tuple[dict[str, tuple], list[str]]:
    """({tool_name: encoded-injection findings}, [names skipped]) for a tools/list page.
    The size cap is per tool definition: padding one tool cannot switch the check off
    for the others on the page."""
    from bastionsupply.checks import check_encoded_injection

    page, over = _split_oversize(tools)
    eligible = [t for t in page if _def_size(t) <= ENCODED_SCAN_MAX_CHARS]
    skipped = sorted(over | {str(t.get("name", "")) for t in page if _def_size(t) > ENCODED_SCAN_MAX_CHARS})
    by_tool: dict[str, list] = {}
    for f in check_encoded_injection(_as_server(eligible)):
        by_tool.setdefault(f.tool, []).append(f)
    return {k: tuple(v) for k, v in by_tool.items()}, skipped


def scan_encoded_text(text: str, views=None, *, transforms: bool = False) -> Decision:
    """A tool result whose ENCODED content (base64, hex, binary, ...) carries an
    injection (bastionsupply's encoded-injection check). Separate from
    scan_result_text so the gate can act on it under its own knob. Pass `views`
    (bastionsupply.checks.decoded_views(text)) to reuse a decode. `transforms` adds the
    rot13 / leet / reversed / spaced-letter views on texts up to TRANSFORM_MAX_CHARS."""
    if not text:
        return Decision(True, "empty result")
    from bastionsupply.checks import decoded_views, encoded_injection

    if views is None and transforms and len(text) <= TRANSFORM_MAX_CHARS:
        views = decoded_views(text, transforms=True)

    finding = encoded_injection(text, "The result", "_result", views=views)
    if finding:
        return Decision(False, f"tool result hides an injection ({finding.message})", (finding,))
    return Decision(True, "no encoded injection")


_ASCII_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
# legitimate invisible characters in prompt text: a joiner inside an emoji sequence
# ("man" ZWJ "laptop") and a byte-order mark at the very start
_EMOJI_ZWJ = re.compile("(?<=[\U0001F000-\U0001FAFF\u2600-\u27BF\uFE0F])\u200D(?=[\U0001F000-\U0001FAFF\u2600-\u27BF])")
_JOINERS = re.compile("[\u200C\u200D]")
# variation selectors carry no text of their own: a run of them (or any from the
# supplement) after one character is a known steganography channel
_VS_STEGO = re.compile("[\U000E0100-\U000E01EF]|[\uFE00-\uFE0F]{2,}")
_MARKUP = re.compile(r"[*_`~|>#]+")
# scripts where ZWJ/ZWNJ are ordinary spelling (Indic, Arabic-script and a few others);
# NOT Cyrillic/Greek/Latin, where a joiner between letters only hides text
_JOINER_SCRIPTS = ("DEVANAGARI", "BENGALI", "GURMUKHI", "GUJARATI", "ORIYA", "TAMIL", "TELUGU",
                   "KANNADA", "MALAYALAM", "SINHALA", "ARABIC", "SYRIAC", "MYANMAR", "KHMER",
                   "TIBETAN", "MONGOLIAN", "THAANA", "NKO")
PROMPT_SCAN_MAX_CHARS = 1_000_000  # bigger prompts are not scanned: they fail closed under block


def _script_letter(c: str) -> bool:
    """A letter or combining mark of a script where ZWJ/ZWNJ between two of them is
    ordinary orthography (Indic, Arabic, Persian...), not hidden text."""
    return unicodedata.category(c)[0] in "LM" and unicodedata.name(c, "").startswith(_JOINER_SCRIPTS)


def _drop_script_joiners(text: str) -> str:
    def keep(m):
        i = m.start()
        ok = 0 < i < len(text) - 1 and _script_letter(text[i - 1]) and _script_letter(text[i + 1])
        return "" if ok else m.group(0)
    return _JOINERS.sub(keep, text)


@functools.lru_cache(maxsize=1)
def _confusables():
    try:
        from bastionsupply.checks import _HOMOGLYPHS
        return str.maketrans(dict(_HOMOGLYPHS))
    except Exception:  # noqa: BLE001 - optional: an older bastionsupply has no table
        return {}


def _fold(text: str) -> str:
    """NFKC, lowercase, look-alike letters to Latin, markdown emphasis removed,
    whitespace collapsed: `**Ignоre** all previous` matches `ignore all previous`."""
    text = _JOINERS.sub("", unicodedata.normalize("NFKC", text)).lower().translate(_confusables())
    return re.sub(r"\s+", " ", _MARKUP.sub(" ", text)).strip()


@functools.lru_cache(maxsize=1)
def _folded_signatures() -> tuple[str, ...]:
    from bastionsupply.corpus import poison_signatures

    # folded like the text, trailing punctuation dropped so a missing "." still matches
    return tuple(dict.fromkeys(_fold(p).rstrip(".!?;:, ") for _cat, p in poison_signatures()))


def scan_instruction_text(text: str, views=None) -> Decision:
    """Checks for text that is instructions BY DESIGN (a prompt template): only the
    high-precision ones, so "always do X" never false-positives. Hidden/control
    unicode, a known bastioncorpus payload, or one hidden in an encoding.
    (bastionmesh runs the same checks on delegations; it can switch to this one
    once it pins bastiongateway >= 0.11.)"""
    if not text:
        return Decision(True, "empty")
    from bastionsupply.checks import check_hidden_unicode, decoded_views

    if _VS_STEGO.search(text):
        return Decision(False, "prompt carries hidden text in variation selectors")
    visible = _drop_script_joiners(_EMOJI_ZWJ.sub("", text.removeprefix("\ufeff")))
    if (not visible.isascii() or _ASCII_CONTROL.search(visible)) and \
            check_hidden_unicode(Server("prompt", (Tool(name="_", description=visible),))):
        return Decision(False, "prompt carries hidden/control unicode")
    sigs = _folded_signatures()
    low = _fold(text)
    if any(phrase in low for phrase in sigs):
        return Decision(False, "prompt carries a known prompt-injection payload (bastioncorpus)")
    for d in (decoded_views(text) if views is None else views):
        low = _fold(d.text)
        if any(phrase in low for phrase in sigs):
            return Decision(False, f"prompt carries a known prompt-injection payload hidden in {d.encoding} encoding")
    return Decision(True, "clean prompt")


def listing_entry_text(item: dict) -> str:
    """What a resources/list, resources/templates/list or prompts/list entry shows the
    model: name, title, description, uri / uriTemplate, prompt argument descriptions."""
    parts = [item.get(k) for k in ("name", "title", "description", "uri", "uriTemplate")]
    parts += [urllib.parse.unquote(item[k]) for k in ("uri", "uriTemplate") if isinstance(item.get(k), str)]
    for arg in item.get("arguments") or [] if isinstance(item.get("arguments"), list) else []:
        if isinstance(arg, dict):
            parts += [arg.get("name"), arg.get("title"), arg.get("description")]
    return "\n".join(p for p in parts if isinstance(p, str))


def poisoned_listing_indexes(items: list) -> set[int]:
    """Indexes of listing entries to drop: poisoned (same checks as a tool definition),
    oversize, or malformed (not an object)."""
    pseudo = [{"name": f"#{i}", "description": listing_entry_text(it)} if isinstance(it, dict) else None
              for i, it in enumerate(items)]
    bad = {i for i, p in enumerate(pseudo) if p is None}
    tools = [p for p in pseudo if p is not None]
    names = poisoned_tool_names(tools) | oversize_tool_names(tools)
    return bad | {int(n[1:]) for n in names if n.startswith("#")}


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
