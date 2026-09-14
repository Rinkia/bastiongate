from bastiongate import pii
from bastiongate.policy import GatePolicy
from bastiongate.proxy import BLOCK_ARG_CODE, Gate


def _call(mid, name, args):
    return {"jsonrpc": "2.0", "id": mid, "method": "tools/call",
            "params": {"name": name, "arguments": args}}


# --- pii.scrub_text ---------------------------------------------------------
def test_scrub_text_redacts_email_and_key():
    out, kinds = pii.scrub_text("mail me at a@b.com with AKIAIOSFODNN7EXAMPLE")
    assert "a@b.com" not in out
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert set(kinds) == {"email", "aws-access-key"}


def test_luhn_gate_on_credit_card():
    valid, k1 = pii.scrub_text("card 4242424242424242")
    assert "REDACTED:credit-card" in valid and "credit-card" in k1
    # a 16-digit order id that fails Luhn is left alone
    invalid, k2 = pii.scrub_text("order 1234567812345678")
    assert "1234567812345678" in invalid and "credit-card" not in k2


def test_scrub_is_recursive_and_immutable():
    original = {"a": "x@y.com", "nested": {"list": ["ok", "b@c.com"]}}
    snapshot = {"a": "x@y.com", "nested": {"list": ["ok", "b@c.com"]}}
    new, kinds = pii.scrub(original)
    assert original == snapshot  # input not mutated
    assert new["a"].startswith("[REDACTED")
    assert new["nested"]["list"][1].startswith("[REDACTED")
    assert kinds.count("email") == 2


# --- Gate integration -------------------------------------------------------
def test_redact_mode_forwards_scrubbed_args():
    gate = Gate(GatePolicy())  # default on_pii_arg = redact
    fwd, reply = gate.handle_client_msg(_call(1, "send", {"body": "ping a@b.com"}))
    assert reply is None
    assert "a@b.com" not in fwd["params"]["arguments"]["body"]
    assert "[REDACTED:email]" in fwd["params"]["arguments"]["body"]


def test_block_mode_refuses_call():
    gate = Gate(GatePolicy(on_pii_arg="block"))
    fwd, reply = gate.handle_client_msg(_call(2, "send", {"key": "AKIAIOSFODNN7EXAMPLE"}))
    assert fwd is None
    assert reply["error"]["code"] == BLOCK_ARG_CODE
    # the error message names the kind, never the secret value
    assert "AKIAIOSFODNN7EXAMPLE" not in reply["error"]["message"]


def test_warn_mode_forwards_unchanged():
    gate = Gate(GatePolicy(on_pii_arg="warn"))
    fwd, reply = gate.handle_client_msg(_call(3, "send", {"body": "a@b.com"}))
    assert reply is None
    assert fwd["params"]["arguments"]["body"] == "a@b.com"


def test_no_pii_passes_through_untouched():
    gate = Gate(GatePolicy())
    args = {"city": "Rome"}
    fwd, reply = gate.handle_client_msg(_call(4, "weather", args))
    assert fwd["params"]["arguments"] == args


def test_trace_records_kinds_not_values(tmp_path):
    from bastiongate.trace import Trace

    log = tmp_path / "t.jsonl"
    gate = Gate(GatePolicy(), Trace(log))
    gate.handle_client_msg(_call(5, "send", {"body": "secret a@b.com"}))
    text = log.read_text(encoding="utf-8")
    assert "a@b.com" not in text
    assert "arg_pii_redacted" in text and "email" in text
