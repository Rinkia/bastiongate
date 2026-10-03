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

Taint is per session per upstream server, unless gates share a `taint_group`
(taint_store.py): then every gate in the group also sees the others' taint, so a chain
that crosses MCP servers (fetch -> filesystem -> fetch) completes the trifecta too.
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

# in-memory per-process store; cross-gate sharing is opt-in (taint_store.SharedTaint)
MAX_TAINT_SESSIONS = 10000
TAINT_IDLE_SECONDS = 1800
# ponytail: private sources kept per session; the first one is enough to report
MAX_PRIVATE_SOURCES = 32
STORE_MAX_FAILURES = 3  # consecutive hard shared-store errors before falling back for good
MAX_WRITTEN = 256  # (kind, tool) sources remembered as already in the shared store

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

    def __init__(self, bump, shared=None, on_shared_error=None) -> None:
        self._taint: OrderedDict = OrderedDict()
        self._lock = threading.Lock()
        self._bump = bump
        self.shared = shared  # taint_store.SharedTaint or None
        self._on_shared_error = on_shared_error or (lambda e: None)
        self._written: dict = {}  # (kind, tool) -> repo already in the shared store
        self._store_failures = 0

    def _shared(self, op, *args):
        """Run a shared-store operation; returns (ok, result). A store error never
        breaks the proxy: the check uses local taint only. A lock timeout (another gate
        writing) is transient; after STORE_MAX_FAILURES other errors in a row (corrupt or
        unwritable file) the store is dropped for good."""
        from .taint_store import StoreBusy

        if self.shared is None:
            return False, None
        try:
            result = op(*args)
        except StoreBusy:
            self._bump("taint_store_busy")
            return False, None
        except Exception as e:  # noqa: BLE001 - sqlite3.Error, OSError, corrupt file...
            self._store_failures += 1
            self._bump("taint_store_error")
            self._on_shared_error(e)
            if self._store_failures >= STORE_MAX_FAILURES:
                self.shared = None
            return False, None
        self._store_failures = 0
        return True, result

    def heartbeat(self) -> None:
        """Re-stamp this gate's shared rows while its own taint is live, so other gates
        keep seeing them; once it expires (or the gate dies) they go stale."""
        now = time.monotonic()
        with self._lock:
            live = any(self._live(s, now) is not None for s in list(self._taint))
        if live and self.shared is not None:
            self._shared(self.shared.heartbeat)

    def _live(self, session, now: float) -> Taint | None:
        taint = self._taint.get(session)
        if taint is not None and now - taint.touched > TAINT_IDLE_SECONDS:
            del self._taint[session]
            return None
        return taint

    def reset(self, session) -> None:
        with self._lock:
            self._taint.pop(session, None)
            self._written.clear()
        if self.shared is not None:
            self._shared(self.shared.clear_own)

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
            wanted = ((("U", tool, None),) if untrusted else ()) + ((("P", tool, repo),) if private else ())
            new = [(k, t, r) for k, t, r in wanted if self._written.get((k, t), "-") != r]
        for kind, t, r in new:
            ok, _ = self._shared(self.shared.add, kind, t, r) if self.shared is not None else (False, None)
            if ok:  # remembered only once written: a failed write is retried next time
                with self._lock:
                    if (kind, t) in self._written or len(self._written) < MAX_WRITTEN:
                        # a second repo for the same source is stored as "any repo" (None)
                        prev = self._written.get((kind, t), r)
                        self._written[(kind, t)] = r if prev == r else None

    def check(self, session, egress_repo: str | None) -> tuple[str, str, bool] | None:
        """(untrusted_from, private_from, cross_server) when an egress call would
        complete the trifecta. A private read from the same GitHub repo the egress
        call targets does not count: that is the everyday "fix issue #N" flow, not a
        leak. With a shared store, the group's rows from other gates count too."""
        now = time.monotonic()
        with self._lock:
            taint = self._live(session, now)
            if taint is not None:
                self._taint[session] = replace(taint, touched=now)
                self._taint.move_to_end(session)
        taint = taint or Taint()
        rows = self._shared(self.shared.rows)[1] if self.shared is not None else None
        others = [r for r in rows or () if r.writer != self.shared_writer()]
        untrusted, cross_u = taint.untrusted_from, False
        if untrusted is None:
            first = next((r for r in others if r.kind == "U"), None)
            if first is None:
                return None
            untrusted, cross_u = first.source, True
        if taint.private_overflow is not None:
            return untrusted, taint.private_overflow, cross_u
        private = [(tool, repo, False) for tool, repo in taint.private] + \
                  [(r.source, r.repo, True) for r in others if r.kind == "P"]
        for tool, repo, cross_p in private:
            if repo is None or egress_repo is None or repo != egress_repo:
                return untrusted, tool, cross_u or cross_p
        return None

    def shared_writer(self) -> str | None:
        return self.shared.writer if self.shared is not None else None

    def snapshot(self, session) -> Taint:
        with self._lock:
            return self._taint.get(session) or Taint()
