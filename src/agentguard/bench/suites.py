"""`agentguard bench <suite>`: the suites and their scorecards (PLAN §12).

| Suite             | What it measures                                                    | Data                         |
|-------------------|---------------------------------------------------------------------|------------------------------|
| ``corpus``        | precision, recall, F1 and false-positive rate on the labelled corpus | ``bench/`` in the repository |
| ``evasion``       | whether findings and verdicts survive each published evasion operator | generated from the corpus    |
| ``incidents``     | one defanged reproduction per incident class, each must be caught    | ``corpus/incidents``         |
| ``perf``          | scan time for 100 skills and 20 configurations                       | generated                    |
| ``malskillbench`` | recall and false positives on MalSkillBench                          | a local copy (``--data``)    |
| ``skilltrustbench`` | three-class scoring on SkillTrustBench                             | a local copy (``--data``)    |

The two public benchmarks restrict use and contain live malware; their data is
never shipped with Agent Guard and is read only from the directory you pass.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from rich.console import Console
from rich.markup import escape
from rich.table import Table

Suite = Callable[..., dict[str, Any]]


def _corpus(*, corpus: Path, split: str, perf: bool, profile: str = "quick", **_: Any) -> dict[str, Any]:
    from .runner import perf_check, run_bench

    if not (corpus / "manifest.yaml").is_file():
        from ..runner import UsageError

        raise UsageError(f"no manifest.yaml under {corpus}")
    # The corpus is scanned statically; `deep` adds detonation, which the evasion suite exercises.
    results = run_bench(corpus, split=split, profile="standard" if profile == "deep" else profile)
    if perf:
        results["performance"]["perf_check"] = perf_check()
    results["suite"] = "corpus"
    results["ok"] = all(t["met"] for t in results["targets"].values())
    return results


def _perf(**_: Any) -> dict[str, Any]:
    from .runner import perf_check

    p = perf_check()
    return {"suite": "perf", "performance": {"perf_check": p}, "ok": bool(p["met"])}


def _lazy(module: str, func: str) -> Suite:
    def run(**kw: Any) -> dict[str, Any]:
        import importlib

        return getattr(importlib.import_module(f"agentguard.bench.{module}"), func)(**kw)

    return run


SUITES: dict[str, Suite] = {
    "corpus": _corpus,
    "evasion": _lazy("evasion", "run_evasion"),
    "incidents": _lazy("incidents", "run_incidents"),
    "perf": _perf,
    "malskillbench": _lazy("public", "run_malskillbench"),
    "skilltrustbench": _lazy("public", "run_skilltrustbench"),
}
# `all` runs the suites that need no download.
LOCAL_SUITES = ("corpus", "evasion", "incidents")


def run_suite(suite: str, **kw: Any) -> dict[str, Any]:
    if suite != "all":
        return SUITES[suite](**kw)
    parts = {name: SUITES[name](**kw) for name in LOCAL_SUITES}
    return {"suite": "all", "suites": parts, "ok": all(p.get("ok", True) for p in parts.values())}


def _print_corpus(r: dict[str, Any], con: Console) -> None:
    from .runner import THRESHOLDS

    c = r["corpus"]
    con.print(f"[bold]Corpus[/bold] ({r['split']}): {c['items']} items: {c['malicious']} malicious, "
              f"{c['adversarial']} adversarial, {c['benign']} benign · sources {c['sources']}")
    if "verdicts" in r:
        v = r["verdicts"]
        t = Table(title="Verdicts (rows: label, columns: verdict)", title_justify="left")
        for col in ("Label", "ALLOW", "REVIEW", "BLOCK"):
            t.add_column(col)
        for label, row in v["matrix"].items():
            t.add_row(label, *(str(row.get(k, 0)) for k in ("ALLOW", "REVIEW", "BLOCK")))
        con.print(t)
        con.print(f"malicious recall (REVIEW or BLOCK) {v['malicious_recall']} · blocked {v['malicious_blocked']} · "
                  f"benign flagged {v['benign_flagged']} · macro-F1 {v['macro_f1']}")
    t = Table(title="Overall by severity threshold (item level)", title_justify="left")
    for col in ("Threshold", "Precision", "Recall", "F1", "FPR", "TP", "FP", "FN", "TN"):
        t.add_column(col)
    for th in THRESHOLDS:
        m = r["overall"][th.value]
        t.add_row(f">= {th.value}", *(str(m[k]) for k in ("precision", "recall", "f1", "fpr", "tp", "fp", "fn", "tn")))
    con.print(t)
    ct = Table(title="Per category", title_justify="left")
    for col in ("Category", "Label", "Items", "@critical", "@high", "@medium", "Expected rule hit"):
        ct.add_column(col)
    for name, e in r["categories"].items():
        key = "recall" if e["label"] != "benign" else "fpr"
        ct.add_row(name, e["label"], str(e["items"]), *(f"{key} {e.get(f'{key}_{s}')}" for s in ("critical", "high", "medium")),
                   str(e.get("expected_rule_hit_rate", "")))
    con.print(ct)
    for name, tgt in r["targets"].items():
        style = "green" if tgt["met"] else "red"
        bound = "≤" if tgt.get("at_most") else "≥"
        con.print(f"[{style}]{name}: actual {tgt['actual']} vs target {bound} {tgt['target']}: "
                  f"{'met' if tgt['met'] else 'NOT met'}[/{style}]")
    if r["benign_hits_by_rule"]:
        con.print(f"benign hits (>= medium) by rule: {escape(str(r['benign_hits_by_rule']))}")


def print_scorecard(results: dict[str, Any], con: Console) -> None:
    if results.get("suite") == "all":
        for part in results["suites"].values():
            print_scorecard(part, con)
        return
    if results.get("suite") == "corpus":
        _print_corpus(results, con)
    for line in results.get("lines", []):
        con.print(escape(line))
    table = results.get("table")
    if table:
        t = Table(title=table.get("title", ""), title_justify="left")
        for col in table["columns"]:
            t.add_column(col, overflow="fold")
        for row in table["rows"]:
            t.add_row(*(escape(str(x)) for x in row))
        con.print(t)
    p = results.get("performance", {}).get("perf_check")
    if p:
        con.print(f"perf: {p['skills']} skills + {p['configs']} configs in {p['seconds']}s (target < {p['target_seconds']}s)")
    if "ok" in results:
        con.print(f"[{'green' if results['ok'] else 'red'}]{results.get('suite', 'suite')}: "
                  f"{'targets met' if results['ok'] else 'targets NOT met'}[/]")
