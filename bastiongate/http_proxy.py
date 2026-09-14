"""HTTP proxy for the MCP Streamable HTTP transport.

Sits in front of an upstream HTTP MCP server and applies the same `Gate` as the
stdio proxy: POST bodies (agent -> server) are gated, JSON and SSE responses
(server -> agent) are transformed on the way back.

Security posture:
    - binds 127.0.0.1 by default (never public without an explicit host)
    - the upstream URL is fixed by the operator, never taken from the client,
      so a client cannot use the proxy for SSRF
    - request bodies are capped (MAX_BODY) to bound memory
    - only a safelist of headers is forwarded upstream

ponytail: JSON-RPC *batch* arrays on the request side are passed through
un-gated (responses are still scanned); single messages — the normal MCP case —
are fully gated. Add per-element batch gating if batching ever shows up in use.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import jsonrpc
from .policy import GatePolicy
from .proxy import Gate
from .trace import Trace

MAX_BODY = 25 * 1024 * 1024  # 25 MB request cap
UPSTREAM_TIMEOUT = 60.0


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse to follow redirects: a malicious upstream must not be able to
    bounce the proxy to file:// or an internal address (SSRF / local read)."""

    def redirect_request(self, *args, **kwargs):
        return None


# opener with only http/https handlers and no redirect following
_OPENER = urllib.request.build_opener(
    _NoRedirect,
    urllib.request.HTTPHandler,
    urllib.request.HTTPSHandler,
)
# headers we forward agent -> upstream (lowercased); everything else is dropped
_FWD_REQ_HEADERS = {"content-type", "accept", "mcp-session-id", "mcp-protocol-version", "authorization", "last-event-id"}
# headers we copy upstream -> agent
_FWD_RESP_HEADERS = {"mcp-session-id", "mcp-protocol-version"}


def make_handler(upstream: str, gate: Gate, trace: Trace):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):  # silence default stderr spam
            pass

        # --- agent -> server ---------------------------------------------------
        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                return self._simple(413, "request too large")
            raw = self.rfile.read(length) if length else b""
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                return self._simple(400, "invalid JSON body")

            body = raw
            if isinstance(msg, dict):
                forward, reply = gate.handle_client_msg(msg)
                if reply is not None:
                    return self._json(200, reply)  # blocked before upstream
                body = json.dumps(forward).encode("utf-8")
            else:
                trace.emit("http_batch_passthrough", n=len(msg) if isinstance(msg, list) else 0)

            self._forward("POST", body)

        # server-initiated stream (notifications, sampling)
        def do_GET(self):
            self._forward("GET", None)

        def do_DELETE(self):
            self._forward("DELETE", None)

        # --- forward to upstream, transform response --------------------------
        def _forward(self, method: str, body: bytes | None):
            req = urllib.request.Request(upstream, data=body, method=method)
            for h, v in self.headers.items():
                if h.lower() in _FWD_REQ_HEADERS:
                    req.add_header(h, v)
            try:
                resp = _OPENER.open(req, timeout=UPSTREAM_TIMEOUT)
            except urllib.error.HTTPError as e:
                # upstream returned a real HTTP error; relay status + body
                return self._relay_error(e)
            except (urllib.error.URLError, TimeoutError) as e:
                trace.emit("http_upstream_error", error=str(e))
                return self._simple(502, "upstream unreachable")

            ctype = resp.headers.get("Content-Type", "")
            if ctype.startswith("text/event-stream"):
                self._stream_sse(resp)
            else:
                self._relay_json(resp)

        def _relay_json(self, resp):
            data = resp.read(MAX_BODY)
            out = data
            try:
                parsed = json.loads(data)
                parsed = self._transform(parsed)
                out = json.dumps(parsed).encode("utf-8")
            except json.JSONDecodeError:
                pass  # non-JSON (e.g. empty 202); relay verbatim
            self.send_response(resp.status)
            self._copy_resp_headers(resp)
            self.send_header("Content-Type", resp.headers.get("Content-Type", "application/json"))
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        def _stream_sse(self, resp):
            self.send_response(resp.status)
            self._copy_resp_headers(resp)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            for event in _iter_sse_events(resp):
                out = _transform_sse_event(event, self._transform)
                self.wfile.write(out.encode("utf-8"))
                self.wfile.flush()

        def _transform(self, parsed):
            if isinstance(parsed, dict):
                return gate.handle_server_msg(parsed)
            if isinstance(parsed, list):
                return [gate.handle_server_msg(m) if isinstance(m, dict) else m for m in parsed]
            return parsed

        # --- small response helpers -------------------------------------------
        def _copy_resp_headers(self, resp):
            for h in _FWD_RESP_HEADERS:
                v = resp.headers.get(h)
                if v:
                    self.send_header(h, v)

        def _json(self, status, obj):
            out = json.dumps(obj).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        def _simple(self, status, text):
            out = text.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        def _relay_error(self, e: urllib.error.HTTPError):
            data = e.read() or b""
            self.send_response(e.code)
            self.send_header("Content-Type", e.headers.get("Content-Type", "application/json"))
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return Handler


# --- SSE framing (module-level so it's unit-testable) -----------------------
def _iter_sse_events(resp):
    """Yield raw SSE event blocks (list of lines) from a streaming response."""
    lines: list[str] = []
    for raw in resp:
        line = raw.decode("utf-8").rstrip("\n").rstrip("\r")
        if line == "":
            if lines:
                yield lines
                lines = []
            continue
        lines.append(line)
    if lines:
        yield lines


def _transform_sse_event(lines: list[str], transform) -> str:
    """Rebuild one SSE event, running `transform` over its JSON `data:` payload."""
    out_lines: list[str] = []
    data_parts: list[str] = []
    for line in lines:
        if line.startswith("data:"):
            data_parts.append(line[5:].lstrip())
        else:
            out_lines.append(line)  # event:, id:, retry:, comments
    if data_parts:
        payload = "\n".join(data_parts)
        try:
            transformed = transform(json.loads(payload))
            payload = json.dumps(transformed)
        except json.JSONDecodeError:
            pass
        for chunk in payload.split("\n"):
            out_lines.append(f"data: {chunk}")
    return "\n".join(out_lines) + "\n\n"


def run_http(upstream: str, policy: GatePolicy, host: str = "127.0.0.1",
             port: int = 9000, log_path: str | None = None) -> int:
    """Serve the gate in front of `upstream` until interrupted."""
    scheme = urllib.parse.urlparse(upstream).scheme
    if scheme not in ("http", "https"):
        raise ValueError(f"upstream must be http/https, got {scheme!r}")
    trace = Trace(log_path)
    gate = Gate(policy, trace)
    httpd = ThreadingHTTPServer((host, port), make_handler(upstream, gate, trace))
    trace.emit("gate_http_start", upstream=upstream, listen=f"{host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
        trace.emit("gate_http_stop")
        trace.close()
    return 0
