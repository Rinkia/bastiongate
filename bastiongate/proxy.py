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

from . import guards, jsonrpc
from .policy import BLOCK, GatePolicy
from .trace import Trace

BLOCK_TOOL_CODE = -32001
BLOCK_RESULT_CODE = -32002


class Gate:
    def __init__(self, policy: GatePolicy, trace: Trace | None = None) -> None:
        self.policy = policy
        self.trace = trace or Trace(None)
        self._pending: dict = {}  # request id -> (method, tool_name)
        self._lock = threading.Lock()

    # --- agent -> server -----------------------------------------------------
    def handle_client_msg(self, msg: dict) -> tuple[dict | None, dict | None]:
        """Return (forward_to_server, reply_to_client). Exactly one is usually set."""
        if jsonrpc.is_request(msg):
            method = jsonrpc.method_of(msg)
            if method == "tools/call":
                name = (msg.get("params") or {}).get("name", "")
                decision = guards.check_tool_call(name, self.policy)
                if not decision.allowed:
                    self.trace.emit("tool_call_blocked", id=msg.get("id"), tool=name, reason=decision.reason)
                    return None, jsonrpc.error_response(msg.get("id"), BLOCK_TOOL_CODE, decision.reason)
                self._remember(msg.get("id"), "tools/call", name)
                self.trace.emit("tool_call", id=msg.get("id"), tool=name)
            elif method == "tools/list":
                self._remember(msg.get("id"), "tools/list", None)
        return msg, None

    # --- server -> agent -----------------------------------------------------
    def handle_server_msg(self, msg: dict) -> dict | None:
        """Return the (possibly replaced/filtered) message to forward to the agent."""
        if not jsonrpc.is_response(msg):
            return msg
        method, tool = self._recall(msg.get("id"))

        if method == "tools/list" and self.policy.scan_tools:
            return self._filter_tools(msg)
        if method == "tools/call" and self.policy.scan_results:
            return self._scan_result(msg, tool)
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
        decision = guards.scan_result_text(text)
        if decision.allowed:
            return msg
        self.trace.emit("result_blocked", id=msg.get("id"), tool=tool, reason=decision.reason)
        if self.policy.on_injected_result != BLOCK:
            return msg
        return jsonrpc.error_response(
            msg.get("id"),
            BLOCK_RESULT_CODE,
            f"bastiongate blocked tool result: {decision.reason}",
        )

    def _remember(self, mid, method, tool) -> None:
        with self._lock:
            self._pending[mid] = (method, tool)

    def _recall(self, mid) -> tuple[str | None, str | None]:
        with self._lock:
            return self._pending.pop(mid, (None, None))


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
