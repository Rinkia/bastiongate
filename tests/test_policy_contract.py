"""bastiongate consumer side of the policy.yaml contract (PRP §1.3).

bastiongate loads the SAME policy.yaml that `bastionsupply harden` emits (kept
byte-identical in tests/fixtures/policy_v2_harden_golden.yaml; policy_golden.yaml is
its v1 output up to bastionsupply 0.7, where the overrides were a top-level `tools:`). This asserts gate
parses and applies every key it relies on — including the per-tool `tools:` /
`scrub_results` overrides that agentbastion ignores but gate honors. A format drift
fails here as well as on the producer, never silently.
"""

from __future__ import annotations

from pathlib import Path

from bastiongate.policy import load_policy

import pytest

FIX = Path(__file__).parent / "fixtures"
# v1 = bastionsupply harden output up to 0.7 (v1 files still load unchanged);
# v2 = its output from 0.8 on. Same decisions from both.
GOLDENS = [FIX / "policy_golden.yaml", FIX / "policy_v2_harden_golden.yaml"]
golden = pytest.mark.parametrize("GOLDEN", GOLDENS, ids=["v1", "v2"])


@golden
def test_loads_golden_tool_policy(GOLDEN):
    pol = load_policy(GOLDEN)
    assert pol.default == "deny"
    assert "run_task" in pol.deny
    assert {"list_files", "sendEmail"} <= pol.allow


@golden
def test_allow_deny_enforced_from_golden(GOLDEN):
    pol = load_policy(GOLDEN)
    assert pol.tool_allowed("run_task") is False       # on deny-list
    assert pol.tool_allowed("list_files") is True        # on allow-list
    assert pol.tool_allowed("other_tool") is False       # default deny + allow-list set


@golden
def test_per_tool_scrub_override_from_golden(GOLDEN):
    pol = load_policy(GOLDEN)
    # The golden marks sendEmail scrub_results:true (bastiongate-specific key).
    assert pol.opt("sendEmail", "scrub_results") is True
    # A tool without an override falls back to the global default (False).
    assert pol.opt("list_files", "scrub_results") is False
