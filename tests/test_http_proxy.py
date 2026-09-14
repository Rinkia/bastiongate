import json
import sys
import threading
import time
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from bastiongate.http_proxy import _iter_sse_events, _transform_sse_event, make_handler
from bastiongate.policy import GatePolicy
from bastiongate.proxy import Gate
from bastiongate.trace import Trace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples"))
import http_echo_server  # noqa: E402


# --- SSE framing (pure, no sockets) -----------------------------------------
class _FakeResp:
    def __init__(self, data: bytes):
        self._lines = data.splitlines(keepends=True)

    def __iter__(self):
        return iter(self._lines)


def test_sse_event_iteration_and_transform():
    stream = b"event: message\ndata: {\"id\": 1, \"result\": {\"tools\": []}}\n\n"
    events = list(_iter_sse_events(_FakeResp(stream)))
    assert len(events) == 1
    seen = {}

    def transform(obj):
        seen["got"] = obj
        return obj

    out = _transform_sse_event(events[0], transform)
    assert seen["got"]["id"] == 1
    assert out.startswith("event: message")
    assert "data: {" in out and out.endswith("\n\n")


# --- full HTTP integration: agent -> gate -> upstream -----------------------
def _serve(server: ThreadingHTTPServer):
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return t


def _post(url, obj):
    req = urllib.request.Request(url, data=json.dumps(obj).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


@pytest.fixture
def gate_over_http(tmp_path):
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), http_echo_server.Handler)
    up_port = upstream.server_address[1]
    _serve(upstream)

    gate = Gate(GatePolicy(), Trace(tmp_path / "http.jsonl"))
    handler = make_handler(f"http://127.0.0.1:{up_port}/mcp", gate, Trace(None))
    proxy = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    px_port = proxy.server_address[1]
    _serve(proxy)
    time.sleep(0.05)
    yield f"http://127.0.0.1:{px_port}/mcp"
    proxy.shutdown()
    upstream.shutdown()


def test_http_tools_list_drops_poisoned(gate_over_http):
    resp = _post(gate_over_http, {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    names = [t["name"] for t in resp["result"]["tools"]]
    assert "search_docs" not in names
    assert set(names) == {"echo", "fetch_page"}


def test_http_injected_result_blocked(gate_over_http):
    resp = _post(gate_over_http, {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                  "params": {"name": "fetch_page", "arguments": {"url": "http://x"}}})
    assert "error" in resp and resp["error"]["code"] == -32002


def test_http_arg_pii_redacted_before_upstream(gate_over_http):
    # echo returns exactly what upstream received; if redaction worked the
    # email never reaches upstream, so it can't be echoed back.
    resp = _post(gate_over_http, {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                  "params": {"name": "echo", "arguments": {"text": "mail a@b.com"}}})
    echoed = resp["result"]["content"][0]["text"]
    assert "a@b.com" not in echoed
    assert "REDACTED:email" in echoed


def test_upstream_scheme_is_validated():
    import pytest

    from bastiongate.http_proxy import run_http
    from bastiongate.policy import GatePolicy

    with pytest.raises(ValueError):
        run_http("file:///etc/passwd", GatePolicy(), port=0)


def test_upstream_redirect_is_not_followed(tmp_path):
    # an upstream that 302s to file:// must NOT be followed by the proxy
    import urllib.error

    from http.server import BaseHTTPRequestHandler

    class Redirector(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self.send_response(302)
            self.send_header("Location", "file:///etc/passwd")
            self.send_header("Content-Length", "0")
            self.end_headers()

    up = ThreadingHTTPServer(("127.0.0.1", 0), Redirector)
    _serve(up)
    gate = Gate(GatePolicy(), Trace(None))
    handler = make_handler(f"http://127.0.0.1:{up.server_address[1]}/mcp", gate, Trace(None))
    proxy = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    _serve(proxy)
    time.sleep(0.05)
    url = f"http://127.0.0.1:{proxy.server_address[1]}/mcp"
    # the 302 is relayed as-is; the proxy never fetches file:///etc/passwd
    req = urllib.request.Request(url, data=b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}',
                                 method="POST", headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            status = r.status
    except urllib.error.HTTPError as e:
        status = e.code
    assert status == 302  # relayed, not followed
    proxy.shutdown()
    up.shutdown()


@pytest.fixture
def authed_gate(tmp_path):
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), http_echo_server.Handler)
    _serve(upstream)
    gate = Gate(GatePolicy(), Trace(None))
    handler = make_handler(f"http://127.0.0.1:{upstream.server_address[1]}/mcp", gate, Trace(None), auth_key="s3cret")
    proxy = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    _serve(proxy)
    time.sleep(0.05)
    yield f"http://127.0.0.1:{proxy.server_address[1]}/mcp"
    proxy.shutdown()
    upstream.shutdown()


def _post_raw(url, obj, headers):
    import urllib.error
    req = urllib.request.Request(url, data=json.dumps(obj).encode(), method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, None


def test_auth_rejects_without_key(authed_gate):
    status, _ = _post_raw(authed_gate, {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
                          {"Content-Type": "application/json"})
    assert status == 401


def test_auth_accepts_with_key(authed_gate):
    status, body = _post_raw(authed_gate, {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
                            {"Content-Type": "application/json", "X-Bastiongate-Key": "s3cret"})
    assert status == 200 and "result" in body


def test_auth_rejects_wrong_key(authed_gate):
    status, _ = _post_raw(authed_gate, {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
                          {"Content-Type": "application/json", "X-Bastiongate-Key": "wrong"})
    assert status == 401


def test_auth_throttles_after_repeated_failures(authed_gate):
    from bastiongate.http_proxy import AUTH_MAX_FAILS

    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    hdr = {"Content-Type": "application/json", "X-Bastiongate-Key": "wrong"}
    codes = [_post_raw(authed_gate, body, hdr)[0] for _ in range(AUTH_MAX_FAILS + 2)]
    assert codes[0] == 401
    assert 429 in codes  # throttled once the window fills


def test_http_clean_call_roundtrips(gate_over_http):
    resp = _post(gate_over_http, {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                                  "params": {"name": "echo", "arguments": {"text": "hi"}}})
    assert "hi" in resp["result"]["content"][0]["text"]


def test_http_sse_response_transformed(gate_over_http):
    # Accept: text/event-stream makes upstream reply as an event-stream (the
    # proxy forwards Accept); the gate must still drop the poisoned tool.
    req = urllib.request.Request(gate_over_http,
                                 data=json.dumps({"jsonrpc": "2.0", "id": 5, "method": "tools/list", "params": {}}).encode(),
                                 method="POST",
                                 headers={"Content-Type": "application/json", "Accept": "text/event-stream"})
    with urllib.request.urlopen(req, timeout=10) as r:
        assert r.headers.get("Content-Type", "").startswith("text/event-stream")
        body = r.read().decode()
    data_line = [l for l in body.splitlines() if l.startswith("data:")][0]
    payload = json.loads(data_line[5:].strip())
    names = [t["name"] for t in payload["result"]["tools"]]
    assert "search_docs" not in names
