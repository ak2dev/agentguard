"""The audit log: one hash-chained JSON line per governance action, written by install, baseline, fix, update and
rules import; a changed or removed entry breaks the chain."""

from __future__ import annotations

import datetime as dt
import json

from typer.testing import CliRunner

from agentguard.audit import log_path, read_log, record, verify
from agentguard.cli.app import app

T0 = dt.datetime(2026, 11, 17, 9, 30, tzinfo=dt.UTC)


def test_entries_chain_and_verify(tmp_path):
    p = tmp_path / "audit.jsonl"
    record("baseline-create", actor="sec@example.invalid", target=".", details={"components": 2}, path=p, now=T0)
    record("install", actor="", target="./skill", details={"verdict": "ALLOW"}, path=p, now=T0)
    entries = read_log(p)
    assert [e["action"] for e in entries] == ["baseline-create", "install"]
    assert entries[0]["prev"] == "" and len(entries[1]["prev"]) == 64
    assert entries[0]["at"] == "2026-11-17T09:30:00Z"
    assert verify(p) == (2, "")


def test_editing_or_removing_an_entry_breaks_the_chain(tmp_path):
    p = tmp_path / "audit.jsonl"
    for i in range(3):
        record("fix", target=f"t{i}", path=p, now=T0)
    lines = p.read_text(encoding="utf-8").splitlines()
    edited = json.loads(lines[1])
    edited["target"] = "someone-else"
    p.write_text("\n".join([lines[0], json.dumps(edited, sort_keys=True, separators=(",", ":")), lines[2]]) + "\n", encoding="utf-8")
    n, problem = verify(p)
    assert n == 3 and "entry 3 does not follow entry 2" in problem
    p.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")
    assert "entry 2" in verify(p)[1]
    assert verify(tmp_path / "missing.jsonl") == (0, "")


def test_commands_write_the_log(tmp_path, monkeypatch):
    root = tmp_path / "proj"
    (root / ".claude").mkdir(parents=True)
    (root / ".claude" / "settings.json").write_text('{"enableAllProjectMcpServers": true}\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    done = runner.invoke(app, ["fix", "proj", "--apply", "--safe-only"])
    assert done.exit_code == 0, done.output
    assert runner.invoke(app, ["baseline", "create", "proj", "--approved-by", "sec@example.invalid"]).exit_code == 0
    actions = [(e["action"], e["actor"]) for e in read_log()]
    assert actions == [("fix", ""), ("baseline-create", "sec@example.invalid")]
    fixed = read_log()[0]["details"]
    assert fixed["files"] == [".claude/settings.json"] and fixed["fixed"][0].startswith("AG-CFG-001 ")
    assert verify() == (2, "") and log_path().name == "audit.jsonl"
