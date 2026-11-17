"""CI gate for the benchmark.

    python scripts/check_bench.py NEW COMMITTED [BASE]

NEW is a fresh `agentguard bench` run, COMMITTED is bench/results/latest.json,
BASE (optional) is latest.json from the branch a pull request targets.

1. Targets: NEW meets the targets, which are stated in verdicts as PLAN §12.2 states them (attacks caught,
   benign items flagged within the false-positive budget) plus precision at CRITICAL.
2. Fresh: COMMITTED is exactly what the current rules produce — every item's
   flags, maximum severity and fired rules, and every aggregate — so the
   committed numbers (README, docs, website) cannot go stale. Only the date
   and timings may differ.
3. No regression against BASE: no attack's verdict weakens and no benign item's
   verdict rises; no positive item loses its CRITICAL or HIGH flag, no benign
   item gains one, no item that met its expected severity falls below it; and
   (when the corpus is unchanged) the verdict rates, precision, FPR and
   per-category recall do not move the wrong way by more than 0.02.

   When BASE comes from an engine that reported no verdicts (before the 23-family
   catalogue, whose rules carry the severities of spec/rules.md), severities are
   not comparable, so the check is the plan's own (PLAN §11, Phase 3): no attack
   that BASE flagged at HIGH is now allowed, and the number of benign items
   flagged does not rise (BASE: flagged at HIGH; NEW: REVIEW or BLOCK).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

TOL = 0.02
RANK = {"ALLOW": 0, "REVIEW": 1, "BLOCK": 2}
_VOLATILE = {"date", "performance"}
_ITEM_VOLATILE = {"ms"}


def _stable(results: dict) -> dict:
    out = {k: v for k, v in results.items() if k not in _VOLATILE and k != "items"}
    out["items"] = {r["id"]: {k: v for k, v in r.items() if k not in _ITEM_VOLATILE} for r in results.get("items", [])}
    return out


def freshness(new: dict, committed: dict) -> list[str]:
    a, b = _stable(new), _stable(committed)
    if a == b:
        return []
    problems = ["bench/results/latest.json is stale: run `agentguard bench --output bench/results/latest.json` and commit it"]
    changed = sorted(i for i in set(a["items"]) | set(b["items"]) if a["items"].get(i) != b["items"].get(i))
    for item in changed[:10]:
        old, cur = b["items"].get(item), a["items"].get(item)
        if old is None or cur is None:
            problems.append(f"  {item}: {'added' if old is None else 'removed'}")
        else:
            fields = sorted(k for k in set(old) | set(cur) if old.get(k) != cur.get(k))
            problems.append(f"  {item}: " + ", ".join(f"{k} {old.get(k)!r} -> {cur.get(k)!r}" for k in fields))
    if len(changed) > 10:
        problems.append(f"  ... and {len(changed) - 10} more item(s)")
    other = sorted(k for k in set(a) | set(b) if k != "items" and a.get(k) != b.get(k))
    if other and not changed:
        problems.append("  aggregates differ: " + ", ".join(other))
    return problems


def transition(new: dict, base: dict) -> tuple[list[str], list[str]]:
    """(problems, notes) against BASE results that carry no verdicts: compared on what was caught and flagged."""
    problems: list[str] = []
    notes = ["base results come from an engine without verdicts and an earlier rule catalogue: severities are not "
             "comparable, so attacks caught and benign items flagged are compared (PLAN §11, Phase 3)"]
    old = {r["id"]: r for r in base.get("items", [])}
    shared = [r for r in new.get("items", []) if r["id"] in old and "verdict" in r]
    for r in shared:
        if r["positive"] and old[r["id"]]["flags"]["high"] and r["verdict"] == "ALLOW":
            problems.append(f"{r['id']} was flagged at HIGH and is now allowed")
    base_flagged = sum(1 for r in shared if not r["positive"] and old[r["id"]]["flags"]["high"])
    new_flagged = sum(1 for r in shared if not r["positive"] and r["verdict"] != "ALLOW")
    if new_flagged > base_flagged:
        problems.append(f"benign items flagged rose: {base_flagged} flagged at HIGH before, {new_flagged} at REVIEW or BLOCK now")
    caught_before = sum(1 for r in shared if r["positive"] and old[r["id"]]["flags"]["high"])
    caught_now = sum(1 for r in shared if r["positive"] and r["verdict"] != "ALLOW")
    notes.append(f"attacks caught: {caught_before} flagged at HIGH before, {caught_now} at REVIEW or BLOCK now; "
                 f"benign items flagged: {base_flagged} before, {new_flagged} now")
    for r in shared:
        if not r["positive"] and r["verdict"] != "ALLOW" and not old[r["id"]]["flags"]["high"]:
            notes.append(f"benign {r['id']} is now {r['verdict']}: {r.get('benign_hits')}")
    return problems, notes


def regressions(new: dict, base: dict) -> list[str]:
    problems = []
    old_items = {r["id"]: r for r in base.get("items", [])}
    for r in new.get("items", []):
        o = old_items.get(r["id"])
        if o is None:
            continue
        if r.get("verdict") in RANK and o.get("verdict") in RANK:
            if r["positive"] and RANK[r["verdict"]] < RANK[o["verdict"]]:
                problems.append(f"{r['id']} verdict weakened: {o['verdict']} -> {r['verdict']}")
            if not r["positive"] and RANK[r["verdict"]] > RANK[o["verdict"]]:
                problems.append(f"benign {r['id']} verdict rose: {o['verdict']} -> {r['verdict']}")
        for sev in ("critical", "high"):
            if r["positive"] and o["flags"][sev] and not r["flags"][sev]:
                problems.append(f"{r['id']} is no longer flagged at {sev} or above")
            if not r["positive"] and r["flags"][sev] and not o["flags"][sev]:
                problems.append(f"benign {r['id']} is now flagged at {sev} or above: {r.get('benign_hits')}")
    if set(old_items) != {r["id"] for r in new.get("items", [])}:
        # Rates over a different corpus are not comparable; the item checks above cover the shared items.
        return problems + _severity_met(new, base)
    nv, ov = new.get("verdicts") or {}, base.get("verdicts") or {}
    if nv.get("benign_flagged") is not None and ov.get("benign_flagged") is not None \
            and nv["benign_flagged"] > ov["benign_flagged"] + TOL:
        problems.append(f"benign items flagged rose {ov['benign_flagged']} -> {nv['benign_flagged']}")
    if nv.get("malicious_recall") is not None and ov.get("malicious_recall") is not None \
            and nv["malicious_recall"] < ov["malicious_recall"] - TOL:
        problems.append(f"attacks caught fell {ov['malicious_recall']} -> {nv['malicious_recall']}")
    for sev in ("critical", "high"):
        n, o = new["overall"][sev], base["overall"][sev]
        if n["precision"] is not None and o["precision"] is not None and n["precision"] < o["precision"] - TOL:
            problems.append(f"precision@{sev} regressed {o['precision']} -> {n['precision']}")
        if n["fpr"] is not None and o["fpr"] is not None and n["fpr"] > o["fpr"] + TOL:
            problems.append(f"FPR@{sev} regressed {o['fpr']} -> {n['fpr']}")
    for cat, e in new["categories"].items():
        prev = base["categories"].get(cat)
        if prev and e.get("recall_high") is not None and prev.get("recall_high") is not None:
            if e["recall_high"] < prev["recall_high"] - TOL:
                problems.append(f"recall@high for {cat} regressed {prev['recall_high']} -> {e['recall_high']}")
    return problems + _severity_met(new, base)


def _severity_met(new: dict, base: dict) -> list[str]:
    problems = []
    was_met = {r["id"] for r in base.get("items", []) if r.get("severity_met")}
    for r in new.get("items", []):
        if r["id"] in was_met and r.get("severity_met") is False:
            problems.append(f"{r['id']} no longer reaches its expected severity ({r.get('expected_severity')}); now {r.get('max_severity')}")
    return problems


def main(argv: list[str]) -> int:
    new = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    committed = json.loads(Path(argv[2]).read_text(encoding="utf-8"))
    problems = [f"target {name} not met: {t['actual']} vs {t['target']}" for name, t in new["targets"].items() if not t["met"]]
    problems += freshness(new, committed)
    notes: list[str] = []
    if len(argv) > 3 and Path(argv[3]).is_file():
        base = json.loads(Path(argv[3]).read_text(encoding="utf-8"))
        if base.get("items") and not any("verdict" in r for r in base["items"]):
            found, notes = transition(new, base)
            problems += found
        else:
            problems += regressions(new, base)
    for n in notes:
        print(f"note: {n}")
    for p in problems:
        print(p)
    print("benchmark OK" if not problems else f"{sum(1 for p in problems if not p.startswith('  '))} benchmark problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
