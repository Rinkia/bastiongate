"""The gate as an OpenTelemetry GenAI span producer (TODOS.md T3).

Every `tools/call` the gate sees becomes one `execute_tool` span (OTel GenAI semantic
conventions) with the gate's verdict as attributes, so traces exist even when the agent
framework exports none, and bastiontrace can analyze them (`bastiontrace analyze --otel`).

    sinks     --otel-out FILE      OTLP/JSON, one export object per line (the Collector
                                   file-exporter format bastiontrace imports)
              --otel-endpoint URL  OTLP/HTTP JSON POST to <URL>/v1/traces (https, or http
                                   on loopback); headers from OTEL_EXPORTER_OTLP_HEADERS
    content   hashes only (bastion.gate.args_sha256 / result_sha256) unless --otel-content:
              then gen_ai.tool.call.arguments / .result, PII-scrubbed, MAX_CONTENT_CHARS each
    traces    one trace per gate session (stdio run / HTTP Mcp-Session-Id)
    verdict   bastion.gate.verdict forwarded | warned | blocked | error, .code, .checks
              (the gate's trace events for the call), .tainted_egress

Stdlib only. Export never blocks the proxy: spans queue (bounded, drops counted) and a
background thread flushes them; a failed export drops that batch.
"""

from __future__ import annotations

import atexit
import contextlib
import hashlib
import ipaddress
import json
import os
import secrets
import threading
import time
import urllib.parse
import urllib.request
from collections import OrderedDict, deque

from . import __version__, jsonrpc, pii

FLUSH_SECONDS = 2.0
MAX_QUEUE = 10_000  # spans waiting for export
MAX_PENDING = 10_000  # calls started, response not seen yet
MAX_TRACES = 10_000  # sessions with a trace id
MAX_CONTENT_CHARS = 16_384
TRUNCATED = "...[truncated by bastiongate]"
HTTP_TIMEOUT = 5.0
GATE_CODES = frozenset(range(-32006, -32000))  # -32001 .. -32006


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _endpoint(url: str) -> str:
    parts = urllib.parse.urlparse(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"--otel-endpoint must be an http(s) URL, got {url!r}")
    if parts.scheme == "http":
        host = parts.hostname
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = host == "localhost"
        if not loopback:
            raise ValueError("--otel-endpoint over plain http is allowed only on loopback "
                             "(spans carry tool names and verdicts); use https")
    url = url.rstrip("/")
    return url if url.endswith("/v1/traces") else url + "/v1/traces"


def _headers() -> dict:
    """OTEL_EXPORTER_OTLP_HEADERS: comma-separated key=value, values URL-encoded."""
    out = {"Content-Type": "application/json"}
    for item in os.environ.get("OTEL_EXPORTER_OTLP_HEADERS", "").split(","):
        if "=" in item:
            k, v = item.split("=", 1)
            if k.strip():
                out[k.strip()] = urllib.parse.unquote(v.strip())
    return out


def _attr(key: str, value) -> dict:
    if isinstance(value, bool):
        return {"key": key, "value": {"boolValue": value}}
    if isinstance(value, int):
        return {"key": key, "value": {"intValue": str(value)}}
    return {"key": key, "value": {"stringValue": str(value)}}


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def _cap(text: str) -> str:
    return text if len(text) <= MAX_CONTENT_CHARS else text[:MAX_CONTENT_CHARS] + TRUNCATED


class OtelSink:
    def __init__(self, path: str | None = None, endpoint: str | None = None, *, content: bool = False,
                 server: str = "upstream", flush_every: float | None = FLUSH_SECONDS) -> None:
        self.path = path
        self.url = _endpoint(endpoint) if endpoint else None
        self.headers = _headers() if endpoint else {}
        self.content = content
        self.server = server
        self.dropped = 0
        self._queue: deque = deque()
        self._pending: OrderedDict = OrderedDict()  # (session, id) -> open span
        self._traces: OrderedDict = OrderedDict()  # session -> trace id
        self._lock = threading.Lock()
        self._io_lock = threading.Lock()
        self._local = threading.local()  # the call whose trace events are being collected
        if flush_every:
            threading.Thread(target=self._loop, args=(flush_every,), name="bastiongate-otel",
                             daemon=True).start()
        atexit.register(self.flush)

    # --- collection ---------------------------------------------------------------
    @contextlib.contextmanager
    def collect(self, session, mid):
        """Gate trace events emitted while handling (session, mid) attach to its span."""
        self._local.key, self._local.events = (session, mid), []
        try:
            yield self._local.events
        finally:
            self._local.key = None

    def on_event(self, event: str, fields: dict) -> None:
        if getattr(self._local, "key", None) is not None and fields.get("id", self._local.key[1]) == self._local.key[1]:
            self._local.events.append((event, fields))

    def _trace_id(self, session) -> str:
        tid = self._traces.get(session)
        if tid is None:
            tid = secrets.token_hex(16)
            if len(self._traces) >= MAX_TRACES:
                self._traces.popitem(last=False)
            self._traces[session] = tid
        self._traces.move_to_end(session)
        return tid

    def call_started(self, session, mid, tool: str, args, reply: dict | None) -> None:
        """A tools/call request: open its span, or close it at once if the gate replied."""
        events = list(getattr(self._local, "events", []) or [])
        args_text = json.dumps(args, sort_keys=True, default=str) if args is not None else ""
        with self._lock:
            span = {"traceId": self._trace_id(session), "spanId": secrets.token_hex(8), "tool": str(tool),
                    "id": mid, "start": time.time_ns(), "args": args_text, "events": events}
            if reply is not None:
                self._enqueue(self._finish(span, reply, []))
                return
            key = (session, mid)
            self._pending.pop(key, None)
            if len(self._pending) >= MAX_PENDING:
                self._pending.popitem(last=False)
                self.dropped += 1
            self._pending[key] = span

    def call_ended(self, session, mid, out: dict | None, upstream: dict | None = None) -> None:
        """The response the agent gets (`out`); `upstream` is what the server sent."""
        events = list(getattr(self._local, "events", []) or [])
        with self._lock:
            span = self._pending.pop((session, mid), None)
            if span is not None:
                self._enqueue(self._finish(span, out or {}, events, upstream))

    # --- span building ------------------------------------------------------------
    def _finish(self, span: dict, out: dict, events: list, upstream: dict | None = None) -> dict:
        events = span["events"] + events
        checks = sorted({e for e, _ in events if e not in ("tool_call",)})
        err = out.get("error") if isinstance(out.get("error"), dict) else None
        code = err.get("code") if err else None
        if err and code in GATE_CODES:
            verdict = "blocked"
        elif err:
            verdict = "error"
        elif checks:
            verdict = "warned"
        else:
            verdict = "forwarded"
        result_text = jsonrpc.result_text(out) if not err else str(err.get("message", ""))
        attrs = [
            _attr("gen_ai.operation.name", "execute_tool"),
            _attr("gen_ai.tool.name", span["tool"]),
            _attr("gen_ai.tool.call.id", str(span["id"])),
            _attr("server.address", self.server),
            _attr("bastion.gate.verdict", verdict),
            _attr("bastion.gate.args_sha256", _sha(span["args"])),
            _attr("bastion.gate.result_sha256", _sha(result_text)),
        ]
        if checks:
            attrs.append(_attr("bastion.gate.checks", ",".join(checks)))
        if code is not None:
            attrs.append(_attr("bastion.gate.code", str(code)))
        if any(e == "tainted_egress" for e, _ in events):
            attrs.append(_attr("bastion.gate.tainted_egress", True))
        if self.content:
            attrs.append(_attr("gen_ai.tool.call.arguments", _cap(pii.scrub_text(span["args"])[0])))
            attrs.append(_attr("gen_ai.tool.call.result", _cap(pii.scrub_text(result_text)[0])))
            if verdict == "blocked" and upstream is not None and upstream is not out:
                # evidence of what the gate stopped; the agent never read it, so it is
                # not gen_ai.tool.call.result (forensics must not treat it as context)
                attrs.append(_attr("bastion.gate.upstream_result",
                                   _cap(pii.scrub_text(jsonrpc.result_text(upstream))[0])))
        return {"traceId": span["traceId"], "spanId": span["spanId"], "name": f"execute_tool {span['tool']}",
                "kind": 3, "startTimeUnixNano": str(span["start"]), "endTimeUnixNano": str(time.time_ns()),
                "attributes": attrs, "status": {"code": 2 if verdict in ("blocked", "error") else 1}}

    def _enqueue(self, span: dict) -> None:  # caller holds self._lock
        if len(self._queue) >= MAX_QUEUE:
            self.dropped += 1
            return
        self._queue.append(span)

    # --- export ---------------------------------------------------------------------
    def _export_obj(self, spans: list) -> dict:
        return {"resourceSpans": [{
            "resource": {"attributes": [_attr("service.name", "bastiongate"),
                                        _attr("service.version", __version__),
                                        _attr("bastion.gate.server", self.server)]},
            "scopeSpans": [{"scope": {"name": "bastiongate", "version": __version__}, "spans": spans}],
        }]}

    def flush(self) -> None:
        with self._lock:
            spans = list(self._queue)
            self._queue.clear()
        if not spans:
            return
        body = json.dumps(self._export_obj(spans), ensure_ascii=False)
        with self._io_lock:
            if self.path:
                try:
                    with open(self.path, "a", encoding="utf-8") as fh:
                        fh.write(body + "\n")
                except OSError:
                    self.dropped += len(spans)
            if self.url:
                try:
                    req = urllib.request.Request(self.url, data=body.encode("utf-8"), headers=self.headers,
                                                 method="POST")
                    with _OPENER.open(req, timeout=HTTP_TIMEOUT) as resp:
                        resp.read(65_536)
                except Exception:  # noqa: BLE001 - export must never break the proxy
                    self.dropped += len(spans)

    def _loop(self, every: float) -> None:
        while True:
            time.sleep(every)
            self.flush()
