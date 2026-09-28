"""policy_version 2 loader for bastiongate: v1 unchanged, v2 strict.

v2 shape = a frozen shared core (policy_version default allow deny rate_limits
detectors) + one block per tool. Gate's knobs live in `gate:` and are validated
strictly; other tools' blocks (bastion:, supply:, skill:) are never inspected.
Detector IDs: bastion.* / custom.* go to agentbastion deep-inspect (they require
`result_inspector: agentbastion`); gate.* raises (gate has no detector IDs, its
knobs are the modes); supply.* / skill.* are ignored.
"""

from __future__ import annotations

import pytest

from bastiongate.policy import BLOCK, WARN, GatePolicy, PolicyError, from_dict


def _v2(**body):
    return {"policy_version": 2, **body}


# --- v1 unchanged ------------------------------------------------------------

def test_v1_dict_loads_as_before():
    policy = from_dict({"default": "deny", "allow": ["read_file"], "on_injected_result": "warn"})
    assert (policy.default, policy.allow, policy.on_injected_result) == ("deny", frozenset({"read_file"}), WARN)
    assert policy.detector_modes == {}


def test_v1_missing_default_keeps_gates_implicit_allow():
    assert from_dict({"deny": ["run_task"]}).default == "allow"


# --- v2 happy paths ----------------------------------------------------------

def test_v2_gate_block_sets_knobs():
    policy = from_dict(_v2(gate={"scan_results": False, "on_poisoned_tool": "warn",
                                 "result_inspector": "agentbastion", "inspector_fail": "open"}))
    assert policy.scan_results is False
    assert policy.on_poisoned_tool == WARN
    assert policy.result_inspector == "agentbastion"
    assert policy.inspector_fail == "open"
    assert policy.on_injected_result == BLOCK  # untouched knobs keep their defaults


def test_v2_per_tool_overrides_inside_gate_block():
    policy = from_dict(_v2(gate={"tools": {"fetch_url": {"scrub_results": True}}}))
    assert policy.opt("fetch_url", "scrub_results") is True
    assert policy.opt("other", "scrub_results") is False


def test_v2_tool_policy():
    policy = from_dict(_v2(default="deny", allow=["read_file"], deny=["run_task"]))
    assert policy.tool_allowed("read_file") and not policy.tool_allowed("send_email")
    assert not policy.tool_allowed("run_task")


def test_v2_without_tool_lists_allows_every_tool():
    policy = from_dict(_v2(detectors={"bastion.exfil_action": "off"}, gate={"result_inspector": "agentbastion"}))
    assert policy.tool_allowed("anything") is True


def test_v2_keeps_bastion_and_custom_modes():
    policy = from_dict(_v2(
        gate={"result_inspector": "agentbastion"},
        detectors={"bastion.exfil_action": False, "custom.my_rule": "shadow"},  # False = YAML `off`
    ))
    assert policy.detector_modes == {"bastion.exfil_action": "off", "custom.my_rule": "shadow"}


def test_v2_ignores_supply_and_skill_ids():
    policy = from_dict(_v2(detectors={"supply.tool_poisoning": "off", "skill.egress": "shadow"}))
    assert policy.detector_modes == {}


def test_v2_never_inspects_other_tools_blocks():
    from_dict(_v2(bastion={"anything": 1}, supply={"x": [1]}, skill={"y": {}}))  # no error


def test_v2_rate_limits_are_accepted_and_ignored():
    policy = from_dict(_v2(default="deny", allow=["read_file"], rate_limits={"read_file": 5}))
    assert policy.tool_allowed("read_file")


# --- v2 strict errors --------------------------------------------------------

@pytest.mark.parametrize(
    ("body", "needle"),
    [
        ({"scan_results": False}, "gate:"),                                  # v1-style top-level knob
        ({"detecters": {}}, "detecters"),                                    # typo at top level
        ({"gate": {"scan_result": False}}, "scan_result"),                   # typo in gate block
        ({"gate": {"on_injected_result": "wran"}}, "wran"),                  # bad action
        ({"gate": {"on_poisoned_tool": "redact"}}, "redact"),                # redact is args/results PII only
        ({"gate": {"result_inspector": "llm"}}, "llm"),
        ({"gate": {"inspector_fail": "maybe"}}, "maybe"),
        ({"gate": {"scan_tools": "yes"}}, "scan_tools"),                     # must be a bool
        ({"gate": {"tools": {"fetch_url": {"scan_tools": True}}}}, "scan_tools"),  # not per-tool
        ({"allow": ["read_file"]}, "default"),                               # lists need default
        ({"default": "allow", "allow": ["read_file"]}, "contradict"),
        ({"default": "sometimes"}, "default"),
        ({"detectors": {"gate.poisoned_tool": "off"}}, "on_poisoned_tool"),  # gate has no detector IDs
        ({"detectors": {"exfil_action": "off"}}, "bastion.exfil_action"),    # unnamespaced
        ({"detectors": {"bastion.exfil_action": "disable"}}, "disable"),
        ({"detectors": {"bastion.exfil_action": True}}, "ambiguous"),         # YAML `on`
        ({"detectors": ["bastion.exfil_action"]}, "detectors"),
        ({"detectors": {"bastion.exfil_action": "off"}}, "result_inspector"),  # nothing would run it
    ],
)
def test_v2_rejects(body, needle):
    with pytest.raises(PolicyError, match=needle):
        from_dict(_v2(**body))


def test_unsupported_policy_version():
    with pytest.raises(PolicyError, match="policy_version"):
        from_dict({"policy_version": 3})


def test_policy_error_is_a_value_error():
    assert issubclass(PolicyError, ValueError)


def test_gate_policy_default_has_no_detector_modes():
    assert GatePolicy().detector_modes == {}


def test_detectors_without_version_2_raises():
    with pytest.raises(PolicyError, match="policy_version: 2"):
        from_dict({"default": "allow", "detectors": {"bastion.exfil_action": "off"}})
