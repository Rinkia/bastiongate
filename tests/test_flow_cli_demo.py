import json

from bastiongate import cli, demo


def test_labels_command_prints_source_per_tool(tmp_path, capsys):
    tools = tmp_path / "tools.json"
    tools.write_text(json.dumps({"tools": [
        {"name": "get_issue", "description": "Get an issue."},
        {"name": "web", "description": "fetch http pages"},
        {"name": "add", "description": "Add two numbers."},
    ]}), encoding="utf-8")
    policy = tmp_path / "p.yaml"
    policy.write_text("tools:\n  add:\n    labels: [private]\n", encoding="utf-8")
    assert cli.main(["labels", "--policy", str(policy), str(tools)]) == 0
    out = capsys.readouterr().out
    rows = {line.split()[0]: line.split()[-1] for line in out.splitlines()[1:] if line.strip()}
    assert rows == {"get_issue": "pack:github", "web": "auto", "add": "policy"}


def test_labels_command_without_tools_lists_packs(capsys):
    assert cli.main(["labels"]) == 0
    out = capsys.readouterr().out
    assert "create_pull_request" in out and "pack:github" in out and "fetch" in out


def test_labels_command_bad_tools_file_exits_2(tmp_path, capsys):
    bad = tmp_path / "x.json"
    bad.write_text("not json", encoding="utf-8")
    assert cli.main(["labels", str(bad)]) == 2
    assert "tools file" in capsys.readouterr().err


def test_demo_includes_toxic_flow_replay(capsys):
    demo.demo()
    out = capsys.readouterr()
    assert "tainted egress" in out.err  # the warn line an operator sees
    assert "-32005" in out.out
