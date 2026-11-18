"""`agentguard bench incidents`: one defanged reproduction per incident class, each must be caught (PLAN §12.1).

The cases live under ``<corpus>/corpus/incidents/<id>/`` and are listed in ``<corpus>/incidents.yaml``
(both written by ``bench/generate_incidents.py``). A case is laid out like a rule fixture: the files to
scan, plus ``_case.yaml`` for recorded facts, ``_context/`` for installed components and
``agentguard.lock`` for a baseline.

A case is *caught* when all three hold:

* the verdict is at least the one the manifest asks for (REVIEW or BLOCK);
* every rule the manifest names fired;
* every expected location is reported: a finding of that rule in that file whose span covers that line.

The suite passes only when every case is caught. A case is kept forever: a rule change that loses one
fails the suite.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..core.engine import scan
from ..core.models import Report
from ..core.parsers.safe_yaml import safe_load
from ..core.rules.pack import RulePack
from ..rules_dev import load_case
from .metrics import RANK, ratio

MANIFEST = "incidents.yaml"


def load_incidents(root: Path) -> list[dict[str, Any]]:
    res = safe_load((root / MANIFEST).read_text(encoding="utf-8"), max_nodes=200_000)
    if res.error:
        raise ValueError(f"{MANIFEST}: {res.error}")
    return list((res.value or {}).get("incidents", []))


def scan_incident(root: Path, entry: dict[str, Any], pack: RulePack) -> Report:
    case = load_case(entry["id"], "positive", root / "corpus" / entry["path"])
    options = case.options
    if "policy" not in case.config:
        # Fixtures switch the advisory lane on; an incident is judged under the default policy a user gets.
        options = options.model_copy(update={"policy": None})
    return scan(case.tree, options, pack)


def _fired(report: Report, rule: str) -> bool:
    return any(rule in (f.id, f.key) for f in report.findings)


def _located(report: Report, rule: str, path: str, line: int) -> bool:
    for f in report.findings:
        if rule not in (f.id, f.key) or f.location is None or f.location.file != path:
            continue
        last = f.location.end.line if f.location.end is not None else f.location.start.line
        if f.location.start.line <= line <= max(last, f.location.start.line):
            return True
    return False


def check_incident(entry: dict[str, Any], report: Report) -> dict[str, Any]:
    expect = entry.get("expect", {})
    want = str(expect.get("verdict", "REVIEW"))
    verdict = report.verdict.value
    missing = [r for r in expect.get("rules", []) if not _fired(report, r)]
    misplaced = [f"{a['rule']} at {a['file']}:{a['line']}" for a in expect.get("at", [])
                 if not _located(report, a["rule"], a["file"], int(a["line"]))]
    weak = RANK[verdict] < RANK.get(want, 1)
    return {"id": entry["id"], "incident": entry.get("incident", ""), "source": entry.get("source", ""),
            "verdict": verdict, "expected_verdict": want, "score": report.score,
            "rules": sorted({f.key for f in report.findings if "coverage" not in f.tags}),
            "missing_rules": missing, "wrong_location": misplaced, "verdict_too_weak": weak,
            "caught": not (missing or misplaced or weak)}


def run_incidents(*, corpus: Path = Path("bench"), limit: int | None = None, pack: RulePack | None = None, **_: Any) -> dict[str, Any]:
    from ..runner import UsageError

    if not (corpus / MANIFEST).is_file():
        raise UsageError(f"no {MANIFEST} under {corpus} (write it with bench/generate_incidents.py)")
    pack = pack or RulePack.default()
    entries = load_incidents(corpus)[: limit or None]
    rows = [check_incident(e, scan_incident(corpus, e, pack)) for e in entries]
    caught = sum(1 for r in rows if r["caught"])
    lines = [f"Incident corpus: {caught} of {len(rows)} incident reproduction(s) caught "
             f"(verdict, rules and the reported file and line all as expected)."]
    for r in rows:
        if r["caught"]:
            continue
        why = []
        if r["verdict_too_weak"]:
            why.append(f"verdict {r['verdict']}, expected at least {r['expected_verdict']}")
        if r["missing_rules"]:
            why.append("did not fire: " + ", ".join(r["missing_rules"]))
        if r["wrong_location"]:
            why.append("not reported at: " + "; ".join(r["wrong_location"]))
        lines.append(f"NOT caught: {r['id']}: " + " · ".join(why))

    def mark(r: dict[str, Any]) -> str:
        return "yes" if r["caught"] else "NO"

    return {
        "suite": "incidents", "schema": "agentguard-bench-incidents/1", "rule_pack": {"version": pack.version},
        "incidents": len(rows), "caught": caught, "caught_rate": ratio(caught, len(rows)), "items": rows, "lines": lines,
        "table": {"title": "Per incident", "columns": ["Case", "Incident class", "Reported in", "Verdict", "Expected", "Caught"],
                  "rows": [[r["id"], r["incident"], r["source"], r["verdict"], "≥ " + r["expected_verdict"], mark(r)] for r in rows]},
        "ok": bool(rows) and caught == len(rows),
    }


__all__ = ["check_incident", "load_incidents", "run_incidents", "scan_incident"]
