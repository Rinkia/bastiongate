"""The gate as an OpenTelemetry GenAI span producer (TODOS.md T3).

Every `tools/call` the gate sees becomes one `execute_tool` span (OTel GenAI semantic
conventions) with the gate's verdict as attributes, so traces exist even when the agent
framework exports none, and bastiontrace can analyze them (`bastiontrace analyze --otel`).

    sinks     --otel-out FILE      OTLP/JSON, one export object per line (the Collector
                                   file-exporter format bastiontrace imports), mode 0600
              --otel-endpoint URL  OTLP/HTTP JSON POST to <URL>/v1/traces (https, or http
                                   on loopback; no credentials, query or fragment in the
                                   URL; no proxy); headers from OTEL_EXPORTER_OTLP_HEADERS
    content   keyed digests only (bastion.gate.args_hmac / result_hmac, HMAC-SHA256 with a
              per-process key: comparable within one gate run, useless for guessing short
              secrets) unless --otel-content: then gen_ai.tool.call.arguments / .result,
              secret-keyed fields and PII redacted, MAX_CONTENT_CHARS each
    traces    one trace per gate session (stdio run / HTTP Mcp-Session-Id)
    verdict   bastion.gate.verdict forwarded | warned | blocked | error, .code, .checks
              (the gate's trace events for the call), .tainted_egress

Stdlib only. Export never blocks or breaks the proxy: spans queue (bounded, drops
counted and reported once) and a background thread flushes them; a failed export drops
that batch; a POST has a total deadline.
"""

from __future__ import annotations

import atexit
import contextlib
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import sys
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
MAX_NAME_CHARS = 256
TRUNCATED = "...[truncated by bastiongate]"
HTTP_DEADLINE = 10.0  # whole POST, connect to last byte
INFO_EVENTS = frozenset({"tool_call", "response_unmatched", "taint_group"})  # not a warning
# argument keys whose values are secrets whatever they look like
SECRET_KEY = re.compile(r"pass(word|wd|code)?|secret|token|api[_-]?key|auth|bearer|cookie|session|pin|otp|"
                        r"credential|private[_-]?key", re.I)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


# no ProxyHandler from the environment: a loopback endpoint must not go out via a proxy
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)


def _endpoint(url: str) -> str:
    parts = urllib.parse.urlparse(url)
    where = f"{parts.scheme}://{parts.hostname or '?'}"  # never echo credentials
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"--otel-endpoint must be an http(s) URL, got {where}")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError("--otel-endpoint must not carry credentials, a query or a fragment "
                         "(put auth in OTEL_EXPORTER_OTLP_HEADERS)")
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
            k, v = k.strip(), urllib.parse.unquote(v.strip())
            if not k:
                continue
            if any(c in k + v for c in "\r\n\0") or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", k):
                raise ValueError(f"OTEL_EXPORTER_OTLP_HEADERS: header {k[:40]!r} has an invalid name or value")
            out[k] = v
    return out


def _attr(key: str, value) -> dict:
    if isinstance(value, bool):
        return {"key": key, "value": {"boolValue": value}}
    if isinstance(value, int):
        return {"key": key, "value": {"intValue": str(value)}}
    return {"key": key, "value": {"stringValue": str(value)}}


def _cap(text: str, n: int | None = None) -> str:
    n = MAX_CONTENT_CHARS if n is None else n
    return text if len(text) <= n else text[:n] + TRUNCATED


def _redact_keys(obj, depth: int = 0):
    """Values under secret-named keys become [REDACTED:key], at any nesting depth."""
    if depth > 32:
        return "[REDACTED:depth]"
    if isinstance(obj, dict):
        return {k: ("[REDACTED:key]" if isinstance(k, str) and SECRET_KEY.search(k)
                    else _redact_keys(v, depth + 1)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact_keys(v, depth + 1) for v in obj]
    return obj


def _clean(text: str) -> str:
    """Capped first (bounded regex work), then PII-scrubbed, then capped again."""
    return _cap(pii.scrub_text(text[: MAX_CONTENT_CHARS * 2])[0])


def _key(session, mid):
    """A hashable pending key whatever JSON type the id has (a list id must not crash)."""
    ok = isinstance(mid, (int, str)) and not isinstance(mid, bool)
    return session, (mid if ok else json.dumps(mid, sort_keys=True, default=str))


class OtelSink:
    def __init__(self, path: str | None = None, endpoint: str | None = None, *, content: bool = False,
                 server: str = "upstream", flush_every: float | None = FLUSH_SECONDS, warn=None) -> None:
        self.path = path
        self.url = _endpoint(endpoint) if endpoint else None
        self.headers = _headers() if endpoint else {}
        self.content = content
        self.server = server
        self.dropped = 0
        self._warn = warn or (lambda line: print(line, file=sys.stderr, flush=True))
        self._warned = False
        self._hkey = secrets.token_bytes(32)  # per process: digests correlate within a run only
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

    def _digest(self, text: str) -> str:
        return hmac.new(self._hkey, text.encode("utf-8", "replace"), hashlib.sha256).hexdigest()

    def _drop(self, n: int, why: str) -> None:
        self.dropped += n
        if not self._warned:
            self._warned = True
            self._warn(f"bastiongate: WARN OTel export dropped {n} span(s): {why}")

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
        key = getattr(self._local, "key", None)
        if key is not None and fields.get("id", key[1]) == key[1]:
            self._local.events.append((event, fields))

    def _trace_id(self, session) -> str:
        session = session if isinstance(session, (str, int, type(None))) else repr(session)
        tid = self._traces.get(session)
        if tid is None:
            tid = secrets.token_hex(16)
            if len(self._traces) >= MAX_TRACES:
                self._traces.popitem(last=False)
            self._traces[session] = tid
        self._traces.move_to_end(session)
        return tid

    def _args(self, args) -> tuple[str, str | None]:
        """(digest, exportable text or None): secret keys and PII removed before either."""
        cleaned = pii.scrub(_redact_keys(args))[0] if args is not None else None
        text = json.dumps(cleaned, sort_keys=True, default=str) if cleaned is not None else ""
        return self._digest(text), (_cap(text) if self.content else None)

    def call_started(self, session, mid, tool: str, args, reply: dict | None) -> None:
        """A tools/call request: open its span, or close it at once if the gate replied."""
        events = list(getattr(self._local, "events", []) or [])
        digest, text = self._args(args)
        with self._lock:
            span = {"traceId": self._trace_id(session), "spanId": secrets.token_hex(8),
                    "tool": _cap(str(tool), MAX_NAME_CHARS), "id": mid, "start": time.time_ns(),
                    "args_digest": digest, "args": text, "events": events}
            if reply is not None:  # the gate answered itself: always the gate's verdict
                self._enqueue(self._finish(span, reply, [], gate_replaced=True))
                return
            key = _key(session, mid)
            self._pending.pop(key, None)
            if len(self._pending) >= MAX_PENDING:
                self._pending.popitem(last=False)
                self.dropped += 1
            self._pending[key] = span

    def call_ended(self, session, mid, out: dict | None, upstream: dict | None = None) -> None:
        """The response the agent gets (`out`); `upstream` is what the server sent."""
        events = list(getattr(self._local, "events", []) or [])
        with self._lock:
            span = self._pending.pop(_key(session, mid), None)
        if span is not None:
            done = self._finish(span, out or {}, events, upstream=upstream,
                                gate_replaced=upstream is not None and out is not upstream)
            with self._lock:
                self._enqueue(done)

    # --- span building ------------------------------------------------------------
    @staticmethod
    def _seen_text(msg: dict) -> str:
        err = msg.get("error")
        if isinstance(err, dict):
            return str(err.get("message", ""))
        text = jsonrpc.result_text(msg)
        result = msg.get("result")
        if isinstance(result, dict) and result.get("structuredContent") is not None:
            text = f"{text}\n{json.dumps(result['structuredContent'], default=str)}"
        return text

    def _finish(self, span: dict, out: dict, events: list, upstream: dict | None = None,
                gate_replaced: bool = False) -> dict:
        events = span["events"] + events
        checks = sorted({e for e, _ in events} - INFO_EVENTS)
        err = out.get("error") if isinstance(out.get("error"), dict) else None
        code = err.get("code") if err else None
        if err and gate_replaced:
            verdict = "blocked"
        elif err:
            verdict = "error"  # the server's own error, whatever its code
        elif checks:
            verdict = "warned"
        else:
            verdict = "forwarded"
        seen = self._seen_text(out)
        attrs = [
            _attr("gen_ai.operation.name", "execute_tool"),
            _attr("gen_ai.tool.name", span["tool"]),
            _attr("gen_ai.tool.call.id", _cap(str(span["id"]), MAX_NAME_CHARS)),
            _attr("server.address", self.server),
            _attr("bastion.gate.verdict", verdict),
            _attr("bastion.gate.args_hmac", span["args_digest"]),
            _attr("bastion.gate.result_hmac", self._digest(seen)),
        ]
        if checks:
            attrs.append(_attr("bastion.gate.checks", ",".join(checks)))
        if code is not None:
            attrs.append(_attr("bastion.gate.code", str(code)))
        if any(e == "tainted_egress" for e, _ in events):
            attrs.append(_attr("bastion.gate.tainted_egress", True))
        if self.content:
            attrs.append(_attr("gen_ai.tool.call.arguments", span["args"] or ""))
            attrs.append(_attr("gen_ai.tool.call.result", _clean(seen)))
            if verdict == "blocked" and upstream is not None:
                # evidence of what the gate stopped; the agent never read it, so it is
                # not gen_ai.tool.call.result (forensics must not treat it as context)
                attrs.append(_attr("bastion.gate.upstream_result", _clean(self._seen_text(upstream))))
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

    def _write_file(self, body: str) -> None:
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(body + "\n")

    def _post(self, body: str) -> str | None:
        """POST with a total deadline (a drip-feeding collector cannot hang a flush or
        the exit). Returns an error description or None."""
        outcome: list = []

        def run() -> None:
            try:
                req = urllib.request.Request(self.url, data=body.encode("utf-8"), headers=self.headers,
                                             method="POST")
                with _OPENER.open(req, timeout=HTTP_DEADLINE) as resp:
                    resp.read(65_536)
                outcome.append(None)
            except Exception as e:  # noqa: BLE001 - export must never break the proxy
                outcome.append(type(e).__name__)

        worker = threading.Thread(target=run, name="bastiongate-otel-post", daemon=True)
        worker.start()
        worker.join(HTTP_DEADLINE)
        return outcome[0] if outcome else "deadline exceeded"

    def flush(self) -> None:
        with self._lock:
            spans = list(self._queue)
            self._queue.clear()
        if not spans:
            return
        body = json.dumps(self._export_obj(spans))  # ASCII: a lone surrogate cannot break a write
        with self._io_lock:
            if self.path:
                try:
                    self._write_file(body)
                except (OSError, ValueError) as e:
                    self._drop(len(spans), f"cannot write {self.path} ({type(e).__name__})")
            if self.url:
                why = self._post(body)
                if why:
                    self._drop(len(spans), f"collector POST failed ({why})")

    def _loop(self, every: float) -> None:
        while True:
            time.sleep(every)
            try:
                self.flush()
            except Exception:  # noqa: BLE001 - the exporter thread must never die
                self.dropped += 1
