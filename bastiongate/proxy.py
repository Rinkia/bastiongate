"""The gate: a message-transform core plus a stdio proxy around it.

`Gate` is pure and testable — feed it JSON-RPC dicts, get back what to forward
(or a block/replacement). Its flow guard (flows.py) keeps per-session taint so an
egress call after untrusted + private reads is warned about or blocked (-32005). `run_stdio` wires it between the agent (this process's
stdin/stdout) and a spawned upstream MCP server.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from collections import Counter, OrderedDict, deque

from . import flows, guards, jsonrpc, pii
from .inspectors import make_inspector
from .policy import BLOCK, REDACT, WARN, GatePolicy
from .trace import Trace

BLOCK_TOOL_CODE = -32001
BLOCK_RESULT_CODE = -32002
BLOCK_ARG_CODE = -32003
BLOCK_RESULT_PII_CODE = -32004
BLOCK_FLOW_CODE = -32005
BLOCK_ENCODED_CODE = -32006

# in-flight correlation bounds (per session, so one busy/abusive session can't
# evict another's entries)
MAX_PENDING_PER_SESSION = 1000
PENDING_TTL_SECONDS = 300  # reclaim entries whose response never came
MAX_SESSIONS = 10000  # backstop: bound distinct tracked sessions (forged-id flood)


def _stderr_warn(line: str) -> None:
    print(line, file=sys.stderr, flush=True)


class Gate:
    def __init__(self, policy: GatePolicy, trace: Trace | None = None, *,
                 warn=_stderr_warn, transport: str = "stdio") -> None:
        self.policy = policy
        self.trace = trace or Trace(None)
        self._warn = warn  # operator-visible one-liners (stderr by default)
        self._transport = transport  # stdio: one process session | http: per Mcp-Session-Id
        self._warned_once: set[str] = set()
        self.labels = flows.Labels()
        self.flows = flows.FlowGuard(self._bump)
        self._pending: dict = {}  # (session, id) -> (method, tool, ts)
        self._order: OrderedDict = OrderedDict()  # session -> deque of keys; LRU order
        self._lock = threading.Lock()
        self._metrics: Counter = Counter()
        self._metrics_lock = threading.Lock()
        self._inspect = make_inspector(policy)  # tool-result inspector

    def _bump(self, name: str, n: int = 1) -> None:
        with self._metrics_lock:
            self._metrics[name] += n

    def metrics_snapshot(self) -> dict:
        with self._metrics_lock:
            m = dict(self._metrics)
        with self._lock:
            m["pending_entries"] = len(self._pending)
            m["tracked_sessions"] = len(self._order)
        return m

    # --- agent -> server -----------------------------------------------------
    def handle_client_msg(self, msg: dict, session=None) -> tuple[dict | None, dict | None]:
        """Return (forward_to_server, reply_to_client). Exactly one is usually set.

        `session` scopes request/response correlation so one Gate serving many
        HTTP sessions cannot cross-correlate on a reused JSON-RPC id.
        """
        if not jsonrpc.is_request(msg):
            return msg, None
        method = jsonrpc.method_of(msg)
        if method == "initialize":
            self.flows.reset(session)  # a new MCP session starts with clean taint
        elif method == "tools/call":
            name = (msg.get("params") or {}).get("name", "")
            decision = guards.check_tool_call(name, self.policy)
            if not decision.allowed:
                self.trace.emit("tool_call_blocked", id=msg.get("id"), tool=name, reason=decision.reason)
                self._bump("tool_call_blocked")
                return None, jsonrpc.error_response(msg.get("id"), BLOCK_TOOL_CODE, decision.reason)
            if self.policy.opt(name, "scrub_args"):
                msg, reply = self._scrub_args(msg, name)
                if reply is not None:
                    return None, reply
            args = (msg.get("params") or {}).get("arguments")
            reply = self._flow_check(msg.get("id"), name, args, session)
            if reply is not None:
                return None, reply
            self._remember(session, msg.get("id"), "tools/call", name, flows.repo_of(name, args))
            self.trace.emit("tool_call", id=msg.get("id"), tool=name)
        elif method == "tools/list":
            self._remember(session, msg.get("id"), "tools/list", None)
        return msg, None

    def _scrub_args(self, msg: dict, name: str) -> tuple[dict | None, dict | None]:
        """Redact/block secrets in tool-call arguments. Only kinds are logged."""
        params = msg.get("params") or {}
        args = params.get("arguments")
        if args is None:
            return msg, None
        new_args, hits = pii.scrub(args)
        if not hits:
            return msg, None
        kinds = sorted(set(hits))
        mode = self.policy.opt(name, "on_pii_arg")
        if mode == BLOCK:
            self.trace.emit("arg_pii_blocked", id=msg.get("id"), tool=name, kinds=kinds, count=len(hits))
            self._bump("arg_pii_blocked")
            return None, jsonrpc.error_response(
                msg.get("id"), BLOCK_ARG_CODE,
                f"bastiongate blocked tool call: arguments carry secret/PII ({', '.join(kinds)})",
            )
        if mode == WARN:
            self.trace.emit("arg_pii_detected", id=msg.get("id"), tool=name, kinds=kinds, count=len(hits))
            return msg, None
        # REDACT (default): forward a copy with values replaced
        self.trace.emit("arg_pii_redacted", id=msg.get("id"), tool=name, kinds=kinds, count=len(hits))
        self._bump("arg_pii_redacted")
        new_msg = dict(msg)
        new_params = dict(params)
        new_params["arguments"] = new_args
        new_msg["params"] = new_params
        return new_msg, None

    def _flow_check(self, mid, name: str, args, session) -> dict | None:
        """Warn about (or block) an egress call that would complete the trifecta.
        Returns an error reply to send instead of forwarding, or None."""
        if not self.policy.scan_flows:
            return None
        if self._transport == "http" and session is None:
            # no Mcp-Session-Id: never pool every client into one shared taint bucket
            if self._once("flow_guard_no_session"):
                self.trace.emit("flow_guard_no_session")
                self._warn("bastiongate: WARN flow guard off for requests without an "
                           "Mcp-Session-Id (upstream issues no session ids)")
            return None
        self.flows.touch(session)
        labels, _source = self.labels.lookup(name, self.policy)
        if flows.EGRESS not in labels:
            return None
        hit = self.flows.check(session, flows.repo_of(name, args))
        if hit is None:
            return None
        untrusted_from, private_from = hit
        action = self.policy.opt(name, "on_tainted_egress")
        self.trace.emit("tainted_egress", id=mid, tool=name, action=action, labels=sorted(labels),
                        untrusted_from=untrusted_from, private_from=private_from,
                        session=_session_hash(session))
        if action == BLOCK:
            self._bump("tainted_egress_blocked")
            return jsonrpc.error_response(
                mid, BLOCK_FLOW_CODE,
                f"bastiongate blocked tool call '{name}': it sends data out after this session read "
                f"untrusted content (from '{untrusted_from}') and private data (from '{private_from}'). "
                f"If this flow is expected, set `tools: {{{name}: {{labels: [...]}}}}` for the tools "
                "involved, or `on_tainted_egress: warn` (README #flow-guard).",
            )
        self._bump("tainted_egress_warned")
        self._warn(f"bastiongate: WARN tainted egress: {name} (untrusted from {untrusted_from}, "
                   f"private from {private_from}) - set labels or on_tainted_egress: block")
        return None

    def _once(self, key: str) -> bool:
        with self._metrics_lock:
            if key in self._warned_once:
                return False
            self._warned_once.add(key)
            return True

    def labels_for(self, name: str) -> tuple[frozenset, str]:
        """(labels, source) the flow guard uses for `name`: policy | pack:<x> | auto | none."""
        return self.labels.lookup(name, self.policy)

    # --- server -> agent -----------------------------------------------------
    def handle_server_msg(self, msg: dict, session=None) -> dict | None:
        """Return the (possibly replaced/filtered) message to forward to the agent."""
        if not jsonrpc.is_response(msg):
            return msg
        method, tool, repo = self._recall(session, msg.get("id"))

        if method == "tools/list":
            self._learn_labels(msg)
            return self._filter_tools(msg) if self.policy.scan_tools else msg
        if method == "tools/call":
            out, flagged = msg, False
            if self.policy.opt(tool or "", "scan_results"):
                out, flagged = self._scan_result(out, tool)
                if "error" in out:  # injection blocked; nothing left to scrub
                    return out
                # runs even when the plain scan already flagged (warn mode): one plain
                # trigger phrase must not exempt an encoded payload from on_encoded_result
                out, encoded_flagged = self._scan_encoded(out, tool)
                if "error" in out:
                    return out
                flagged = flagged or encoded_flagged
            if self.policy.opt(tool or "", "scrub_results"):
                out = self._scrub_result(out, tool)
            if self.policy.scan_flows and isinstance(out.get("result"), dict):
                self._record_taint(out, tool or "", repo, flagged, session)
            return out
        return msg

    def _learn_labels(self, msg: dict) -> None:
        tools = jsonrpc.tools_from_list_result(msg)
        if not tools:
            return
        try:
            self.labels.learn(tools)
        except Exception as e:  # noqa: BLE001 - label derivation must never crash the proxy
            self.trace.emit("labels_unavailable", reason=type(e).__name__)
            self._bump("labels_unavailable")
            if self._once("labels_unavailable"):
                self._warn("bastiongate: WARN tool labels unavailable "
                           f"({type(e).__name__}); flow guard uses policy and pack labels only")

    def _record_taint(self, out: dict, tool: str, repo, flagged: bool, session) -> None:
        """Taint from what the agent will actually read: the forwarded result."""
        labels, _source = self.labels.lookup(tool, self.policy)
        text = jsonrpc.result_text(out)
        structured = out["result"].get("structuredContent")
        if structured is not None:
            text = f"{text}\n{json.dumps(structured)}"
        _red, kinds = pii.scrub_text(text)
        self.flows.record_result(
            session, tool, repo,
            untrusted=flagged or flows.UNTRUSTED in labels,
            private=flows.PRIVATE in labels or bool(flows.SECRET_KINDS & set(kinds)),
        )

    # --- helpers -------------------------------------------------------------
    def _filter_tools(self, msg: dict) -> dict:
        tools = jsonrpc.tools_from_list_result(msg)
        if not tools:
            return msg
        encoded = guards.encoded_findings(tools)
        if encoded is None:
            self.trace.emit("tools_list_encoded_skipped", count=len(tools))
            self._bump("encoded_scan_skipped")
        elif encoded:  # warn only: a decoded payload in a tool definition is reported, never dropped (yet)
            self.trace.emit("tools_list_encoded", tools=sorted(encoded))
            self._bump("tools_encoded_warned")
            self._warn(f"bastiongate: WARN tool definition(s) hide an encoded injection: {', '.join(sorted(encoded))}")
        bad = guards.poisoned_tool_names(tools)
        if not bad:
            self.trace.emit("tools_list_scanned", count=len(tools), poisoned=0)
            return msg
        self.trace.emit("tools_list_scanned", count=len(tools), poisoned=len(bad), dropped=sorted(bad))
        self._bump("tools_dropped", len(bad))
        if self.policy.on_poisoned_tool != BLOCK:
            return msg
        kept = [t for t in tools if t.get("name") not in bad]
        new = dict(msg)
        new_result = dict(msg.get("result") or {})
        new_result["tools"] = kept
        new["result"] = new_result
        return new

    def _scan_encoded(self, msg: dict, tool: str | None) -> tuple[dict, bool]:
        """Encoded injection in a result (base64/hex/binary...): warn (default) or
        block per on_encoded_result. A result too big to decode is never silently
        passed under `block`: it fails closed."""
        text = jsonrpc.result_text(msg)
        result = msg.get("result")
        if isinstance(result, dict) and result.get("structuredContent") is not None:
            text = f"{text}\n{json.dumps(result['structuredContent'])}"
        action = self.policy.opt(tool or "", "on_encoded_result")
        if len(text) > guards.ENCODED_SCAN_MAX_CHARS:
            self.trace.emit("encoded_scan_skipped", id=msg.get("id"), tool=tool, chars=len(text), action=action)
            self._bump("encoded_scan_skipped")
            if action == BLOCK:
                return jsonrpc.error_response(
                    msg.get("id"), BLOCK_ENCODED_CODE,
                    f"bastiongate blocked tool result: {len(text)} characters is too large to check for "
                    f"encoded injection (limit {guards.ENCODED_SCAN_MAX_CHARS}); on_encoded_result is block",
                ), False
            return msg, False
        decision = guards.scan_encoded_text(text)
        if decision.allowed:
            return msg, False
        self.trace.emit("encoded_injection", id=msg.get("id"), tool=tool, action=action,
                        checks=sorted({f.check for f in decision.findings}))
        if action == BLOCK:
            self._bump("encoded_injection_blocked")
            return jsonrpc.error_response(msg.get("id"), BLOCK_ENCODED_CODE,
                                          f"bastiongate blocked tool result: {decision.reason}"), False
        self._bump("encoded_injection_warned")
        self._warn(f"bastiongate: WARN encoded injection in result of {tool}: {decision.reason} "
                   "- set on_encoded_result: block to stop it")
        return msg, True  # forwarded in warn mode: the agent reads flagged content (taints the session)

    def _scan_result(self, msg: dict, tool: str | None) -> tuple[dict, bool]:
        text = jsonrpc.result_text(msg)
        # also scan structuredContent — an injection can hide in structured JSON,
        # not just in text blocks
        result = msg.get("result")
        if isinstance(result, dict) and result.get("structuredContent") is not None:
            text = f"{text}\n{json.dumps(result['structuredContent'])}"
        decision = self._inspect(text)
        if decision.allowed:
            return msg, False
        self.trace.emit("result_blocked", id=msg.get("id"), tool=tool, reason=decision.reason)
        self._bump("result_injection_blocked")
        if self.policy.opt(tool or "", "on_injected_result") != BLOCK:
            return msg, True  # forwarded in warn mode: the agent reads flagged content
        return jsonrpc.error_response(
            msg.get("id"),
            BLOCK_RESULT_CODE,
            f"bastiongate blocked tool result: {decision.reason}",
        ), False

    def _scrub_result(self, msg: dict, tool: str | None) -> dict:
        """Redact/block secrets a tool RETURNS — in text content blocks AND in
        the result's structuredContent."""
        result = msg.get("result")
        if not isinstance(result, dict):
            return msg
        kinds: list[str] = []
        new_result = dict(result)

        blocks = result.get("content")
        if isinstance(blocks, list):
            new_blocks = []
            for b in blocks:
                if isinstance(b, dict) and b.get("type") == "text" and isinstance(b.get("text"), str):
                    red, found = pii.scrub_text(b["text"])
                    if found:
                        kinds.extend(found)
                        b = {**b, "text": red}
                new_blocks.append(b)
            new_result["content"] = new_blocks

        structured = result.get("structuredContent")
        if structured is not None:
            new_structured, found = pii.scrub(structured)
            if found:
                kinds.extend(found)
                new_result["structuredContent"] = new_structured

        if not kinds:
            return msg
        uniq = sorted(set(kinds))
        mode = self.policy.opt(tool or "", "on_pii_result")
        if mode == BLOCK:
            self.trace.emit("result_pii_blocked", id=msg.get("id"), tool=tool, kinds=uniq, count=len(kinds))
            self._bump("result_pii_blocked")
            return jsonrpc.error_response(
                msg.get("id"), BLOCK_RESULT_PII_CODE,
                f"bastiongate blocked tool result: it carries secret/PII ({', '.join(uniq)})",
            )
        if mode == WARN:
            self.trace.emit("result_pii_detected", id=msg.get("id"), tool=tool, kinds=uniq, count=len(kinds))
            return msg
        self.trace.emit("result_pii_redacted", id=msg.get("id"), tool=tool, kinds=uniq, count=len(kinds))
        self._bump("result_pii_redacted")
        return {**msg, "result": new_result}

    def _remember(self, session, mid, method, tool, repo=None) -> None:
        now = time.monotonic()
        key = (session, mid)
        with self._lock:
            if session not in self._order and len(self._order) >= MAX_SESSIONS:
                # evict the least-recently-used other session wholesale
                for s in list(self._order):  # OrderedDict: oldest-touched first
                    if s != session:
                        for k in self._order.pop(s):
                            self._pending.pop(k, None)
                        break
            dq = self._order.get(session)
            if dq is None:
                dq = self._order[session] = deque()
            self._order.move_to_end(session)  # mark most-recently-used
            # reclaim this session's expired entries (oldest-first, cheap)
            while dq and self._pending.get(dq[0], (None, None, 0.0))[2] < now - PENDING_TTL_SECONDS:
                self._pending.pop(dq.popleft(), None)
            # enforce this session's cap (evict only this session's oldest)
            while len(dq) >= MAX_PENDING_PER_SESSION:
                self._pending.pop(dq.popleft(), None)
            self._pending[key] = (method, tool, now, repo)
            dq.append(key)

    def _recall(self, session, mid) -> tuple[str | None, str | None, str | None]:
        key = (session, mid)
        with self._lock:
            entry = self._pending.pop(key, None)
            dq = self._order.get(session)
            if dq is not None:
                if dq:
                    self._order.move_to_end(session)  # activity: refresh LRU
                else:
                    self._order.pop(session, None)
            if entry is None:
                return (None, None, None)
            return (entry[0], entry[1], entry[3])


def _session_hash(session) -> str | None:
    """Stable, non-reversible session label for the trace (never the raw id)."""
    if session is None:
        return None
    return hashlib.sha256(str(session).encode("utf-8")).hexdigest()[:12]


def run_stdio(server_argv: list[str], policy: GatePolicy, log_path: str | None = None) -> int:
    """Run the gate between this process's stdio and a spawned MCP server."""
    trace = Trace(log_path)
    gate = Gate(policy, trace)
    proc = subprocess.Popen(
        server_argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,  # server logs pass through to our stderr, not the agent
        env=os.environ.copy(),
        text=True,
        bufsize=1,
    )
    trace.emit("gate_start", server=" ".join(server_argv))

    def pump_client_to_server() -> None:
        for msg in jsonrpc.read_messages(sys.stdin):
            forward, reply = gate.handle_client_msg(msg)
            if reply is not None:
                jsonrpc.write_message(sys.stdout, reply)
            if forward is not None:
                jsonrpc.write_message(proc.stdin, forward)
        try:
            proc.stdin.close()
        except OSError:
            pass

    def pump_server_to_client() -> None:
        for msg in jsonrpc.read_messages(proc.stdout):
            out = gate.handle_server_msg(msg)
            if out is not None:
                jsonrpc.write_message(sys.stdout, out)

    t1 = threading.Thread(target=pump_client_to_server, daemon=True)
    t2 = threading.Thread(target=pump_server_to_client, daemon=True)
    t1.start()
    t2.start()
    code = proc.wait()
    t2.join(timeout=2)
    trace.emit("gate_metrics", **gate.metrics_snapshot())
    trace.emit("gate_stop", exit=code)
    trace.close()
    return code
