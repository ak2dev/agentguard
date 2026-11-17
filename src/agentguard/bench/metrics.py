"""Verdict-based metrics shared by the benchmark suites (spec/interfaces.md §8, PLAN §12).

A scan ends in one of three verdicts, and the three-class benchmarks use three labels, so the mapping is
direct: ALLOW = normal, REVIEW = suspicious, BLOCK = malicious. For a two-class corpus (malicious and
benign) the same numbers are reported, with "caught" meaning REVIEW or BLOCK.
"""

from __future__ import annotations

from typing import Any

VERDICTS = ("ALLOW", "REVIEW", "BLOCK")
RANK = {"ALLOW": 0, "REVIEW": 1, "BLOCK": 2}
# Which verdict a label calls for.
EXPECTED = {"benign": "ALLOW", "normal": "ALLOW", "suspicious": "REVIEW", "malicious": "BLOCK", "adversarial": "BLOCK"}


def ratio(n: int, d: int) -> float | None:
    return round(n / d, 4) if d else None


def verdict_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """`rows` carry `label` and `verdict`. Returns the confusion matrix (rows: label, columns: verdict) and:

    * malicious_recall   malicious (and adversarial) items that were not allowed: REVIEW or BLOCK
    * malicious_blocked  malicious items that were blocked outright
    * benign_flagged     benign or normal items that were not allowed (the false-positive rate)
    * macro_f1           mean F1 over the verdict classes that have at least one item expected or predicted
    """
    matrix: dict[str, dict[str, int]] = {}
    for r in rows:
        matrix.setdefault(r["label"], {v: 0 for v in VERDICTS})[r["verdict"]] += 1
    bad = [r for r in rows if EXPECTED.get(r["label"]) == "BLOCK"]
    good = [r for r in rows if EXPECTED.get(r["label"]) == "ALLOW"]
    f1s: list[float] = []
    per_class: dict[str, Any] = {}
    for cls in VERDICTS:
        tp = sum(1 for r in rows if EXPECTED.get(r["label"]) == cls and r["verdict"] == cls)
        fp = sum(1 for r in rows if EXPECTED.get(r["label"]) != cls and r["verdict"] == cls)
        fn = sum(1 for r in rows if EXPECTED.get(r["label"]) == cls and r["verdict"] != cls)
        if tp + fp + fn == 0:
            continue
        p, rc = ratio(tp, tp + fp) or 0.0, ratio(tp, tp + fn) or 0.0
        f1 = round(2 * p * rc / (p + rc), 4) if p + rc else 0.0
        per_class[cls] = {"precision": p, "recall": rc, "f1": f1, "tp": tp, "fp": fp, "fn": fn}
        f1s.append(f1)
    return {
        "matrix": dict(sorted(matrix.items())),
        "malicious_recall": ratio(sum(1 for r in bad if r["verdict"] != "ALLOW"), len(bad)),
        "malicious_blocked": ratio(sum(1 for r in bad if r["verdict"] == "BLOCK"), len(bad)),
        "benign_flagged": ratio(sum(1 for r in good if r["verdict"] != "ALLOW"), len(good)),
        "false_positives": sum(1 for r in good if r["verdict"] != "ALLOW"),
        "macro_f1": round(sum(f1s) / len(f1s), 4) if f1s else None,
        "per_class": per_class,
    }


__all__ = ["EXPECTED", "RANK", "VERDICTS", "ratio", "verdict_metrics"]
