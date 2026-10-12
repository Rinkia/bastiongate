"""The promotion-bar tally: `bastiongate log --summary`.

The flow guard ships in warn mode behind a written bar — 20+ real sessions with
0 false blocks on benign flows, then `on_tainted_egress` defaults to `block`.
Nothing could report those numbers before this, so the bar could never be met.
See suite-tally-DESIGN.md.
"""

from __future__ import annotations

import json

from bastiongate.cli import main


def _log(tmp_path, rows, name="gate.jsonl"):
    p = tmp_path / name
    p.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return str(p)


def _summary(tmp_path, rows, capsys):
    assert main(["log", _log(tmp_path, rows), "--summary"]) == 0
    return json.loads(capsys.readouterr().out)


def test_summary_counts_sessions_firings_and_the_action_split(tmp_path, capsys):
    rows = [
        {"ts": 1.0, "event": "gate_start", "server": "npx -y some-server"},
        {"ts": 2.0, "event": "session_seen", "session": "aaaa"},
        {"ts": 3.0, "event": "tool_call", "id": 1, "tool": "fetch"},
        {"ts": 4.0, "event": "tainted_egress", "action": "warn", "tool": "http_post",
         "session": "aaaa"},
        {"ts": 5.0, "event": "session_seen", "session": "bbbb"},
        {"ts": 6.0, "event": "tainted_egress", "action": "block", "tool": "send_email",
         "session": "bbbb"},
        {"ts": 7.0, "event": "tool_call_blocked", "id": 2, "tool": "delete_file"},
    ]
    out = _summary(tmp_path, rows, capsys)
    assert out["tool"] == "bastiongate"
    assert out["unit"] == "session" and "Mcp-Session-Id" in out["counted_as"]
    assert out["sessions"] == 2, "two distinct sessions, countable only via session_seen"
    assert out["runs"] == 1
    assert out["fired_by_rule"] == {"tainted_egress": 2, "tool_call_blocked": 1}
    assert out["by_action"] == {"tainted_egress": {"warn": 1, "block": 1}}
    assert out["window"] == {"first_ts": 1.0, "last_ts": 7.0}


def test_a_clean_session_still_counts_toward_the_bar(tmp_path, capsys):
    """The regression this instrumentation exists for: before `session_seen`,
    only `tainted_egress` carried a session, so a session where nothing fired
    was invisible — and the bar is 20 sessions, most of them clean."""
    rows = [{"ts": 1.0, "event": "gate_start"},
            {"ts": 2.0, "event": "session_seen", "session": "quiet"},
            {"ts": 3.0, "event": "tool_call", "tool": "read"}]
    out = _summary(tmp_path, rows, capsys)
    assert out["sessions"] == 1
    assert out["fired_by_rule"] == {}, "nothing fired, and that is the point"


def test_no_log_is_not_reported_as_clean(tmp_path, capsys):
    """An unmeasured run must never read as a measured, clean one."""
    assert main(["log", str(tmp_path / "absent.jsonl"), "--summary"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["records"] is None and out["sessions"] is None
    assert "no log" in out["note"].lower()


def test_empty_log_is_zeros_not_null(tmp_path, capsys):
    out = _summary(tmp_path, [], capsys)
    assert out["records"] == 0 and out["sessions"] == 0 and "note" not in out


def test_damaged_lines_do_not_break_the_tally(tmp_path, capsys):
    p = tmp_path / "gate.jsonl"
    p.write_text("\n".join([
        json.dumps({"event": "session_seen", "session": "a", "ts": 1.0}),
        "{truncated",                    # a live process was mid-write
        json.dumps([1, 2]),              # valid JSON, not a row
        json.dumps({"event": "tainted_egress", "action": "block", "session": "a", "ts": 2.0,
                    "future_field": 1}),
    ]) + "\n", encoding="utf-8")
    assert main(["log", str(p), "--summary"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["records"] == 2 and out["sessions"] == 1
    assert out["fired_by_rule"] == {"tainted_egress": 1}


def test_repeats_are_reported_as_unmeasured_not_zero(tmp_path, capsys):
    """Gate events carry no fired/repeat distinction. Saying "zero repeats"
    would be a claim this tool has not earned (bastionfuse issue #6)."""
    out = _summary(tmp_path, [{"event": "session_seen", "session": "a"}], capsys)
    assert out["repeat_by_rule"] is None


def test_log_is_read_only(tmp_path, capsys):
    rows = [{"event": "session_seen", "session": "a", "ts": 1.0}]
    path = _log(tmp_path, rows)
    before = open(path, encoding="utf-8").read()
    _summary(tmp_path, rows, capsys)
    assert open(path, encoding="utf-8").read() == before


def test_session_seen_does_not_flip_an_otel_span_verdict():
    """Regression: `session_seen` is tally bookkeeping, not a check. When it was
    not in INFO_EVENTS, every forwarded call's OTel span reported
    `bastion.gate.verdict = warned`, so adding the instrumentation silently
    corrupted the gate's own telemetry."""
    from bastiongate.otel import INFO_EVENTS

    assert "session_seen" in INFO_EVENTS


def test_a_stdio_session_is_countable(tmp_path, capsys):
    """Found by a live smoke, missed by every unit test above: in stdio there is
    no session id — one process IS the session — so `_session_hash(None)` is
    None, every stdio run logged a null session, and a genuine run tallied
    `sessions: 0`. The run id stands in for it."""
    rows = [{"ts": 1.0, "event": "gate_start", "server": "python server.py"},
            {"ts": 2.0, "event": "session_seen", "session": "run:ab12cd34"},
            {"ts": 3.0, "event": "tool_call", "tool": "read_file"}]
    out = _summary(tmp_path, rows, capsys)
    assert out["sessions"] == 1 and out["runs"] == 1


def test_two_stdio_runs_in_one_log_count_as_two_sessions(tmp_path, capsys):
    """A run id rather than a constant, so a log appended to by several runs
    does not collapse them into one session."""
    rows = [{"ts": 1.0, "event": "gate_start"},
            {"ts": 2.0, "event": "session_seen", "session": "run:aaaaaaaa"},
            {"ts": 3.0, "event": "gate_start"},
            {"ts": 4.0, "event": "session_seen", "session": "run:bbbbbbbb"}]
    out = _summary(tmp_path, rows, capsys)
    assert out["sessions"] == 2 and out["runs"] == 2


def test_the_logged_session_label_is_never_the_raw_id():
    """A hashed id for real sessions, a run id for stdio, never the raw value."""
    from bastiongate.proxy import Gate
    from bastiongate.policy import GatePolicy

    g = Gate(GatePolicy())
    assert g._log_session(None).startswith("run:")
    label = g._log_session("Mcp-Session-Id-secret-value")
    assert "secret" not in label and len(label) == 12
