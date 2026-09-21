"""bastiongate consumer side of the policy.yaml contract (PRP §1.3).

bastiongate loads the SAME policy.yaml that `bastionsupply harden` emits (kept
byte-identical in bastiongate/tests/fixtures/policy_golden.yaml). This asserts gate
parses and applies every key it relies on — including the per-tool `tools:` /
`scrub_results` overrides that agentbastion ignores but gate honors. A format drift
fails here as well as on the producer, never silently.
"""

from __future__ import annotations

from pathlib import Path

from bastiongate.policy import load_policy

GOLDEN = Path(__file__).parent / "fixtures" / "policy_golden.yaml"


def test_loads_golden_tool_policy():
    pol = load_policy(GOLDEN)
    assert pol.default == "deny"
    assert "run_task" in pol.deny
    assert {"list_files", "sendEmail"} <= pol.allow


def test_allow_deny_enforced_from_golden():
    pol = load_policy(GOLDEN)
    assert pol.tool_allowed("run_task") is False       # on deny-list
    assert pol.tool_allowed("list_files") is True        # on allow-list
    assert pol.tool_allowed("other_tool") is False       # default deny + allow-list set


def test_per_tool_scrub_override_from_golden():
    pol = load_policy(GOLDEN)
    # The golden marks sendEmail scrub_results:true (bastiongate-specific key).
    assert pol.opt("sendEmail", "scrub_results") is True
    # A tool without an override falls back to the global default (False).
    assert pol.opt("list_files", "scrub_results") is False
