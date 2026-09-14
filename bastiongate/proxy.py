"""The gate: a message-transform core plus a stdio proxy around it.

`Gate` is pure and testable — feed it JSON-RPC dicts, get back what to forward
(or a block/replacement). `run_stdio` wires it between the agent (this process's
stdin/stdout) and a spawned upstream MCP server.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading

from . import guards, jsonrpc, pii
from .inspectors import make_inspector
from .policy import BLOCK, REDACT, WARN, GatePolicy
from .trace import Trace

BLOCK_TOOL_CODE = -32001
BLOCK_RESULT_CODE = -32002
BLOCK_ARG_CODE = -32003
BLOCK_RESULT_PII_CODE = -32004

MAX_PENDING = 10000  # cap in-flight correlation entries (bounds memory)


class Gate:
    def __init__(self, policy: GatePolicy, trace: Trace | None = None) -> None:
        self.policy = policy
        self.trace = trace or Trace(None)
        self._pending: dict = {}  # (session, request id) -> (method, tool_name)
        self._lock = threading.Lock()
        self._inspect = make_inspector(policy)  # tool-result inspector

    # --- agent -> server -----------------------------------------------------
    def handle_client_msg(self, msg: dict, session=None) -> tuple[dict | None, dict | None]:
        """Return (forward_to_server, reply_to_client). Exactly one is usually set.

        `session` scopes request/response correlation so one Gate serving many
        HTTP sessions cannot cross-correlate on a reused JSON-RPC id.
        """
        if not jsonrpc.is_request(msg):
            return msg, None
        method = jsonrpc.method_of(msg)
        if method == "tools/call":
            name = (msg.get("params") or {}).get("name", "")
            decision = guards.check_tool_call(name, self.policy)
            if not decision.allowed:
                self.trace.emit("tool_call_blocked", id=msg.get("id"), tool=name, reason=decision.reason)
                return None, jsonrpc.error_response(msg.get("id"), BLOCK_TOOL_CODE, decision.reason)
            if self.policy.opt(name, "scrub_args"):
                msg, reply = self._scrub_args(msg, name)
                if reply is not None:
                    return None, reply
            self._remember(session, msg.get("id"), "tools/call", name)
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
            return None, jsonrpc.error_response(
                msg.get("id"), BLOCK_ARG_CODE,
                f"bastiongate blocked tool call: arguments carry secret/PII ({', '.join(kinds)})",
            )
        if mode == WARN:
            self.trace.emit("arg_pii_detected", id=msg.get("id"), tool=name, kinds=kinds, count=len(hits))
            return msg, None
        # REDACT (default): forward a copy with values replaced
        self.trace.emit("arg_pii_redacted", id=msg.get("id"), tool=name, kinds=kinds, count=len(hits))
        new_msg = dict(msg)
        new_params = dict(params)
        new_params["arguments"] = new_args
        new_msg["params"] = new_params
        return new_msg, None

    # --- server -> agent -----------------------------------------------------
    def handle_server_msg(self, msg: dict, session=None) -> dict | None:
        """Return the (possibly replaced/filtered) message to forward to the agent."""
        if not jsonrpc.is_response(msg):
            return msg
        method, tool = self._recall(session, msg.get("id"))

        if method == "tools/list" and self.policy.scan_tools:
            return self._filter_tools(msg)
        if method == "tools/call":
            out = msg
            if self.policy.opt(tool or "", "scan_results"):
                out = self._scan_result(out, tool)
                if "error" in out:  # injection blocked; nothing left to scrub
                    return out
            if self.policy.opt(tool or "", "scrub_results"):
                out = self._scrub_result(out, tool)
            return out
        return msg

    # --- helpers -------------------------------------------------------------
    def _filter_tools(self, msg: dict) -> dict:
        tools = jsonrpc.tools_from_list_result(msg)
        if not tools:
            return msg
        bad = guards.poisoned_tool_names(tools)
        if not bad:
            self.trace.emit("tools_list_scanned", count=len(tools), poisoned=0)
            return msg
        self.trace.emit("tools_list_scanned", count=len(tools), poisoned=len(bad), dropped=sorted(bad))
        if self.policy.on_poisoned_tool != BLOCK:
            return msg
        kept = [t for t in tools if t.get("name") not in bad]
        new = dict(msg)
        new_result = dict(msg.get("result") or {})
        new_result["tools"] = kept
        new["result"] = new_result
        return new

    def _scan_result(self, msg: dict, tool: str | None) -> dict:
        text = jsonrpc.result_text(msg)
        decision = self._inspect(text)
        if decision.allowed:
            return msg
        self.trace.emit("result_blocked", id=msg.get("id"), tool=tool, reason=decision.reason)
        if self.policy.opt(tool or "", "on_injected_result") != BLOCK:
            return msg
        return jsonrpc.error_response(
            msg.get("id"),
            BLOCK_RESULT_CODE,
            f"bastiongate blocked tool result: {decision.reason}",
        )

    def _scrub_result(self, msg: dict, tool: str | None) -> dict:
        """Redact/block secrets a tool RETURNS, in the result's text blocks."""
        result = msg.get("result")
        if not isinstance(result, dict):
            return msg
        blocks = result.get("content")
        if not isinstance(blocks, list):
            return msg
        kinds: list[str] = []
        new_blocks = []
        for b in blocks:
            if isinstance(b, dict) and b.get("type") == "text" and isinstance(b.get("text"), str):
                red, found = pii.scrub_text(b["text"])
                if found:
                    kinds.extend(found)
                    b = {**b, "text": red}
            new_blocks.append(b)
        if not kinds:
            return msg
        uniq = sorted(set(kinds))
        mode = self.policy.opt(tool or "", "on_pii_result")
        if mode == BLOCK:
            self.trace.emit("result_pii_blocked", id=msg.get("id"), tool=tool, kinds=uniq, count=len(kinds))
            return jsonrpc.error_response(
                msg.get("id"), BLOCK_RESULT_PII_CODE,
                f"bastiongate blocked tool result: it carries secret/PII ({', '.join(uniq)})",
            )
        if mode == WARN:
            self.trace.emit("result_pii_detected", id=msg.get("id"), tool=tool, kinds=uniq, count=len(kinds))
            return msg
        self.trace.emit("result_pii_redacted", id=msg.get("id"), tool=tool, kinds=uniq, count=len(kinds))
        new_result = {**result, "content": new_blocks}
        return {**msg, "result": new_result}

    def _remember(self, session, mid, method, tool) -> None:
        with self._lock:
            if len(self._pending) >= MAX_PENDING:
                # evict oldest (orphaned request whose response never came)
                self._pending.pop(next(iter(self._pending)))
            self._pending[(session, mid)] = (method, tool)

    def _recall(self, session, mid) -> tuple[str | None, str | None]:
        with self._lock:
            return self._pending.pop((session, mid), (None, None))


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
    trace.emit("gate_stop", exit=code)
    trace.close()
    return code
