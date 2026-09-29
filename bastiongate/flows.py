"""Flow guard: catch the lethal trifecta across calls in one session.

A chain can pass every per-call check and still leak: the agent reads untrusted
content (a public issue carrying an injection), reads private data (a private repo
file, a secret), then calls a tool that sends data out. This module keeps a small
per-session taint record and labels each tool:

    untrusted  its result is attacker-reachable content
    private    its result is private data
    egress     calling it sends data out of the session

    session taint:   {} --untrusted result--> {U} --private result--> {U,P}
                     egress call with {U,P} ---> tainted_egress (warn | block -32005)
                     idle > TAINT_IDLE_SECONDS or `initialize` ---> {}

Label precedence: policy `labels` > built-in pack (exact tool name) > auto
(bastionsupply capability categories; auto only ever yields `egress`).

Ceiling: taint is per session per upstream server. A chain that crosses two MCP
servers (two gate processes) is not seen; see TODOS.md E4.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, replace

from bastionsupply.checks import capability_categories
from bastionsupply.models import Tool

from .policy import GatePolicy

UNTRUSTED, PRIVATE, EGRESS = "untrusted", "private", "egress"

# ponytail: in-memory per-process store; a shared cross-gate store is TODOS.md E4
MAX_TAINT_SESSIONS = 10000
TAINT_IDLE_SECONDS = 1800
# ponytail: private sources kept per session; the first one is enough to report
MAX_PRIVATE_SOURCES = 32

# pii.py kinds that make a forwarded result "private" (credentials, not contact data)
SECRET_KINDS = frozenset({"private-key", "aws-access-key", "openai-key", "google-api-key",
                          "github-token", "slack-token", "jwt"})

_AUTO_EGRESS = frozenset({"network", "email-egress"})


def _labels(*names: str) -> frozenset[str]:
    return frozenset(names)


# Built-in label packs, keyed by exact tool names of common MCP servers. Re-check
# these against upstream tool names on every gate release (RELEASE.md).
PACKS: dict[str, dict[str, frozenset[str]]] = {
    # github/github-mcp-server: current consolidated names plus the legacy ones
    "github": {
        **{t: _labels(UNTRUSTED) for t in (
            "issue_read", "list_issues", "search_issues", "pull_request_read",
            "list_pull_requests", "search_pull_requests", "get_job_logs",
            "get_issue", "get_issue_comments", "get_pull_request", "get_pull_request_comments")},
        **{t: _labels(PRIVATE) for t in ("get_file_contents", "search_code", "get_commit")},
        **{t: _labels(EGRESS) for t in (
            "issue_write", "add_issue_comment", "update_issue_comment", "create_pull_request",
            "update_pull_request", "pull_request_review_write", "add_comment_to_pending_review",
            "add_reply_to_pull_request_comment", "create_or_update_file", "push_files",
            "create_repository", "fork_repository", "create_issue", "update_issue")},
    },
    "filesystem": {t: _labels(PRIVATE) for t in ("read_file", "read_text_file", "read_multiple_files")},
    "fetch": {"fetch": _labels(UNTRUSTED, EGRESS)},
    "slack": {
        "slack_get_channel_history": _labels(UNTRUSTED),
        "slack_get_thread_replies": _labels(UNTRUSTED),
        "slack_post_message": _labels(EGRESS),
        "slack_reply_to_thread": _labels(EGRESS),
    },
    "gmail": {
        "read_email": _labels(UNTRUSTED, PRIVATE),
        "search_emails": _labels(UNTRUSTED, PRIVATE),
        "send_email": _labels(EGRESS),
    },
}


def repo_of(tool: str, args) -> str | None:
    """`owner/repo` a GitHub-pack call targets, from its arguments; else None."""
    if tool not in PACKS["github"] or not isinstance(args, dict):
        return None
    owner, repo = args.get("owner"), args.get("repo")
    if isinstance(owner, str) and isinstance(repo, str) and owner and repo:
        repo = repo.lower().removesuffix(".git")
        return f"{owner.lower()}/{repo}"
    return None


class Labels:
    """Gate-wide tool labels: auto labels learned from tools/list, merged across
    paginated pages. Never cleared: a server-sent list_changed must not be able to
    strip egress labels (extra stale labels only make the guard stricter)."""

    def __init__(self) -> None:
        self._auto: dict[str, frozenset[str]] = {}
        self._lock = threading.Lock()

    def learn(self, tools: list) -> None:
        """Merge auto labels for a tools/list page. Raises if derivation fails; the
        caller keeps the previous cache."""
        learned = {}
        for t in tools:
            if not isinstance(t, dict):
                continue
            tool = Tool(name=str(t.get("name", "")), description=str(t.get("description", "")))
            learned[tool.name] = _labels(EGRESS) if capability_categories(tool) & _AUTO_EGRESS else frozenset()
        with self._lock:
            self._auto.update(learned)

    def lookup(self, name: str, policy: GatePolicy) -> tuple[frozenset[str], str]:
        """(labels, source) where source is policy | pack:<name> | auto | none."""
        explicit = policy.tool_labels(name)
        if explicit is not None:
            return explicit, "policy"
        if policy.label_packs:
            for pack, table in PACKS.items():
                if name in table:
                    return table[name], f"pack:{pack}"
        with self._lock:
            auto = self._auto.get(name, frozenset())
        return (auto, "auto") if auto else (frozenset(), "none")


@dataclass(frozen=True)
class Taint:
    untrusted_from: str | None = None
    private: tuple[tuple[str, str | None], ...] = ()  # (tool, owner/repo or None)
    private_overflow: str | None = None  # first private source past the cap: never exempt
    touched: float = 0.0


class FlowGuard:
    """Per-session taint, bounded (LRU + idle TTL) and separate from the gate's
    request/response correlation table (that one forgets a session once idle)."""

    def __init__(self, bump) -> None:
        self._taint: OrderedDict = OrderedDict()
        self._lock = threading.Lock()
        self._bump = bump

    def _live(self, session, now: float) -> Taint | None:
        taint = self._taint.get(session)
        if taint is not None and now - taint.touched > TAINT_IDLE_SECONDS:
            del self._taint[session]
            return None
        return taint

    def reset(self, session) -> None:
        with self._lock:
            self._taint.pop(session, None)

    def touch(self, session) -> None:
        """Any call counts as activity: taint expires only after the session is idle."""
        now = time.monotonic()
        with self._lock:
            taint = self._live(session, now)
            if taint is not None:
                self._taint[session] = replace(taint, touched=now)
                self._taint.move_to_end(session)

    def record_result(self, session, tool: str, repo: str | None, *, untrusted: bool, private: bool) -> None:
        if not (untrusted or private):
            return
        now = time.monotonic()
        with self._lock:
            taint = self._live(session, now) or Taint()
            if untrusted and taint.untrusted_from is None:
                taint = replace(taint, untrusted_from=tool)
            source = (tool, repo)
            if private and source not in taint.private:
                if len(taint.private) < MAX_PRIVATE_SOURCES:
                    taint = replace(taint, private=taint.private + (source,))
                elif taint.private_overflow is None:
                    # past the cap we can no longer prove a same-repo exemption: count it
                    taint = replace(taint, private_overflow=tool)
            if session not in self._taint and len(self._taint) >= MAX_TAINT_SESSIONS:
                self._taint.popitem(last=False)
                self._bump("taint_evicted")
            self._taint[session] = replace(taint, touched=now)
            self._taint.move_to_end(session)

    def check(self, session, egress_repo: str | None) -> tuple[str, str] | None:
        """(untrusted_from, private_from) when an egress call would complete the
        trifecta. A private read from the same GitHub repo the egress call targets
        does not count: that is the everyday "fix issue #N" flow, not a leak."""
        now = time.monotonic()
        with self._lock:
            taint = self._live(session, now)
            if taint is None:
                return None
            self._taint[session] = replace(taint, touched=now)
            self._taint.move_to_end(session)
        if taint.untrusted_from is None:
            return None
        if taint.private_overflow is not None:
            return taint.untrusted_from, taint.private_overflow
        for tool, repo in taint.private:
            if repo is None or egress_repo is None or repo != egress_repo:
                return taint.untrusted_from, tool
        return None

    def snapshot(self, session) -> Taint:
        with self._lock:
            return self._taint.get(session) or Taint()
