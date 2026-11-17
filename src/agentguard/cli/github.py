"""GitHub Actions output for the composite action (``action.yml``).

``python -m agentguard.cli.github <report.json>`` prints one workflow command
per finding that bears on the verdict, so a pull request shows them inline on
the changed lines even where code scanning (the SARIF upload) is not available,
and writes ``verdict``, ``score`` and ``findings`` to ``$GITHUB_OUTPUT``.

An annotation carries the rule id, the rule's own title and the fix summary.
Text from the scanned repository is not put into a workflow command: the
runner interprets what a step prints, and a pull request is hostile input.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

MAX_ANNOTATIONS = 50            # GitHub shows a limited number per step; the report has the rest
_LEVEL = {"block": "error", "review": "warning"}


def _data(value: str) -> str:
    """Escape the message part of a workflow command."""
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _prop(value: str) -> str:
    """Escape a property value (file, title) of a workflow command."""
    return _data(value).replace(":", "%3A").replace(",", "%2C")


def _safe_path(path: str) -> str:
    """A file name from the scanned tree, reduced to characters a path needs."""
    return "".join(ch for ch in path if ch.isprintable() and ch not in "\"'`<>|*?")[:300]


def annotations(report: dict[str, Any]) -> list[str]:
    """Workflow commands for the findings that decide the verdict (block first, then review)."""
    from ..core.models import Report
    from ..core.rules.pack import RulePack
    from ..core.verdict import effect

    rep = Report.model_validate(report)
    pack = RulePack.default()
    rows: list[tuple[int, str]] = []
    for f in rep.findings:
        how = effect(f, rep.chains)
        if how not in _LEVEL or f.location is None or "!/" in f.location.file:
            continue
        det = pack.detectors.get(f.key)
        title = det.title if det is not None else f.id
        fix = (det.remediation if det is not None else "")[:300]
        line = max(1, f.location.start.line)
        message = f"{title}. {fix}".strip() if fix else title
        rows.append((0 if how == "block" else 1,
                     f"::{_LEVEL[how]} file={_prop(_safe_path(f.location.file))},line={line},title={_prop(f.key)}::{_data(message)}"))
    rows.sort(key=lambda r: r[0])
    out = [cmd for _, cmd in rows[:MAX_ANNOTATIONS]]
    if len(rows) > MAX_ANNOTATIONS:
        out.append(f"::notice::{len(rows) - MAX_ANNOTATIONS} more finding(s) are in the report and the SARIF file.")
    return out


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print("usage: python -m agentguard.cli.github <report.json>", file=sys.stderr)
        return 64
    try:
        with open(args[0], encoding="utf-8") as fh:
            report = json.load(fh)
    except (OSError, ValueError):
        print("::error::Agent Guard wrote no readable report.")
        return 70
    for cmd in annotations(report):
        print(cmd)
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as fh:
            fh.write(f"verdict={report.get('verdict', '')}\nscore={report.get('score', '')}\nfindings={len(report.get('findings', []))}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
