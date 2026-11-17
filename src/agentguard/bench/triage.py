"""Training and evaluation of the triage model (engine K; PLAN §7.1).

The model is trained on Agent Guard's own labelled corpus (``bench/manifest.yaml``), never on a public benchmark
(their licences restrict use, PLAN §12.1):

* every component of a ``benign`` item is a negative;
* a component of a ``malicious`` or ``adversarial`` item is a positive when it carries a finding of one of the
  item's expected rules; the item's other components are left out, because the label says nothing about them;
* fitting uses the ``dev`` split only; the figures written into the model file come from the ``heldout`` split,
  which the trainer never fits on.

The learner is plain gradient boosting with the logistic loss (Newton steps, depth-2 trees, L2-regularised leaves,
classes weighted to balance), followed by Platt calibration fitted on out-of-fold predictions (5 folds grouped by
item). Everything is deterministic: no sampling, ties broken by feature order. Pure Python, so it needs nothing
beyond the engine's own dependencies; the corpus is small enough for that.
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..core.models.enums import Category, Severity
from ..core.rules.pack import RulePack
from ..core.triage import DEFAULT_AGREES, FORMAT, TriageModel, feature_names
from .runner import Item, _scan_item, load_manifest

FOLDS = 5


@dataclass(frozen=True)
class Row:
    item: str
    split: str
    label: int
    component: str
    x: dict[str, float]


# ---------------------------------------------------------------- dataset --
def _matches(expected: Sequence[str], key: str, rule_id: str) -> bool:
    return any(e == key or e == rule_id or key.startswith(e + "/") for e in expected)


def rows_for_item(item: Item, pack: RulePack) -> tuple[list[Row], str]:
    """The labelled component rows of one corpus item, and a note when the item contributed none."""
    got: dict[str, dict[str, float]] = {}
    report = _scan_item(item, pack, on_triage_features=got.update)
    if item.label == "benign":
        return [Row(item.id, item.split, 0, cid, x) for cid, x in sorted(got.items())], ""
    expected = [pack.resolve_key(e) or e for e in item.expected_rules]
    carriers = {cid for f in report.findings if _matches(expected, f.key, f.id) for cid in f.component_ids}
    note = ""
    if not carriers:
        # None of the expected rules fired (the item is caught by others, or lists none): the components that
        # carry its high-severity malice findings are the ones the label is about.
        carriers = {cid for f in report.findings if f.category == Category.malice and f.severity.at_least(Severity.high)
                    for cid in f.component_ids}
        note = "labelled by its high-severity malice findings (no expected rule fired)"
    rows = [Row(item.id, item.split, 1, cid, got[cid]) for cid in sorted(carriers) if cid in got]
    return rows, note if rows else "no component carries an expected rule or a high-severity malice finding"


def collect(root: Path, pack: RulePack | None = None,
            on_item: Callable[[Item, int], None] | None = None) -> tuple[list[Row], dict[str, str]]:
    pack = pack or RulePack.default()
    rows: list[Row] = []
    skipped: dict[str, str] = {}
    for item in load_manifest(root):
        got, note = rows_for_item(item, pack)
        rows.extend(got)
        if note:
            skipped[item.id] = note
        if on_item is not None:
            on_item(item, len(got))
    return rows, skipped


# ------------------------------------------------------------------- learner --
def _sigmoid(z: float) -> float:
    z = max(-60.0, min(60.0, z))
    return 1.0 / (1.0 + math.exp(-z))


def _predict_tree(node: Any, x: Sequence[float]) -> float:
    while isinstance(node, list):
        node = node[2] if x[node[0]] <= node[1] else node[3]
    return float(node)


def _build(idx: list[int], orders: list[list[int]], X: list[list[float]], g: list[float], h: list[float],
           depth: int, max_depth: int, lam: float, min_child: float, lr: float) -> Any:
    G = sum(g[i] for i in idx)
    H = sum(h[i] for i in idx)
    leaf = round(-G / (H + lam) * lr, 6)
    if depth >= max_depth or len(idx) < 2:
        return leaf
    member = set(idx)
    parent = G * G / (H + lam)
    best: tuple[float, int, float] | None = None
    for j, order in enumerate(orders):
        gl = hl = 0.0
        sub = [i for i in order if i in member]
        for k in range(len(sub) - 1):
            i = sub[k]
            gl += g[i]
            hl += h[i]
            v, nxt = X[i][j], X[sub[k + 1]][j]
            if v == nxt or hl < min_child or H - hl < min_child:
                continue
            gain = gl * gl / (hl + lam) + (G - gl) ** 2 / (H - hl + lam) - parent
            if gain > 1e-9 and (best is None or gain > best[0] + 1e-12):
                best = (gain, j, (v + nxt) / 2.0)
    if best is None:
        return leaf
    _, j, thr = best
    left = [i for i in idx if X[i][j] <= thr]
    right = [i for i in idx if X[i][j] > thr]
    return [j, round(thr, 6),
            _build(left, orders, X, g, h, depth + 1, max_depth, lam, min_child, lr),
            _build(right, orders, X, g, h, depth + 1, max_depth, lam, min_child, lr)]


def fit_boosted(X: list[list[float]], y: list[int], *, rounds: int = 60, lr: float = 0.15, max_depth: int = 2,
                lam: float = 1.0, min_child: float = 0.5) -> tuple[float, list[Any], list[float]]:
    """(base margin, trees, splits per feature) for the logistic loss, classes weighted to balance."""
    n = len(y)
    pos = sum(y)
    neg = n - pos
    if not pos or not neg:
        raise ValueError("training needs both classes")
    w = [(n / (2.0 * pos)) if t else (n / (2.0 * neg)) for t in y]
    base = 0.0     # balanced weights: the prior log-odds is 0
    margin = [base] * n
    orders = [sorted(range(n), key=lambda i, j=j: (X[i][j], i)) for j in range(len(X[0]) if X else 0)]
    trees: list[Any] = []
    splits = [0.0] * (len(X[0]) if X else 0)
    for _ in range(rounds):
        p = [_sigmoid(m) for m in margin]
        g = [w[i] * (p[i] - y[i]) for i in range(n)]
        h = [max(w[i] * p[i] * (1.0 - p[i]), 1e-6) for i in range(n)]
        tree = _build(list(range(n)), orders, X, g, h, 0, max_depth, lam, min_child, lr)
        if not isinstance(tree, list):
            break          # nothing left to split on
        _count_splits(tree, splits)
        trees.append(tree)
        margin = [margin[i] + _predict_tree(tree, X[i]) for i in range(n)]
    return base, trees, splits


def _count_splits(node: Any, acc: list[float]) -> None:
    if isinstance(node, list):
        acc[node[0]] += 1.0
        _count_splits(node[2], acc)
        _count_splits(node[3], acc)


def fit_platt(margins: Sequence[float], y: Sequence[int], iters: int = 100) -> tuple[float, float]:
    """``p = sigmoid(a·margin + b)`` by Newton's method on the log loss, with Platt's target smoothing."""
    pos = sum(y)
    neg = len(y) - pos
    hi, lo = (pos + 1.0) / (pos + 2.0), 1.0 / (neg + 2.0)
    t = [hi if v else lo for v in y]
    a, b = 1.0, 0.0
    for _ in range(iters):
        ga = gb = haa = hab = hbb = 0.0
        for m, ti in zip(margins, t):
            p = _sigmoid(a * m + b)
            d = p - ti
            s = max(p * (1.0 - p), 1e-12)
            ga += d * m
            gb += d
            haa += s * m * m
            hab += s * m
            hbb += s
        haa += 1e-9
        hbb += 1e-9
        det = haa * hbb - hab * hab
        if abs(det) < 1e-18:
            break
        da = (hbb * ga - hab * gb) / det
        db = (haa * gb - hab * ga) / det
        a, b = a - da, b - db
        if abs(da) < 1e-10 and abs(db) < 1e-10:
            break
    return round(a, 6), round(b, 6)


def _fold(item: str) -> int:
    return int(hashlib.sha256(item.encode("utf-8")).hexdigest()[:8], 16) % FOLDS


def _matrix(rows: Iterable[Row], names: Sequence[str]) -> tuple[list[list[float]], list[int]]:
    rows = list(rows)
    return [[float(r.x.get(n, 0.0)) for n in names] for r in rows], [r.label for r in rows]


# ---------------------------------------------------------------- metrics --
def auc(scores: Sequence[float], y: Sequence[int]) -> float | None:
    """Area under the ROC curve (Mann-Whitney, ties counted as half)."""
    pos = [s for s, t in zip(scores, y) if t]
    neg = [s for s, t in zip(scores, y) if not t]
    if not pos or not neg:
        return None
    wins = sum(1.0 if p > q else 0.5 if p == q else 0.0 for p in pos for q in neg)
    return round(wins / (len(pos) * len(neg)), 4)


def evaluate(model: TriageModel, rows: Sequence[Row]) -> dict[str, Any]:
    probs = [model.predict(r.x) for r in rows]
    y = [r.label for r in rows]
    n = len(rows)
    if not n:
        return {"components": 0}
    tp = sum(1 for p, t in zip(probs, y) if t and p >= model.agrees)
    fp = sum(1 for p, t in zip(probs, y) if not t and p >= model.agrees)
    pos = sum(y)
    items_pos = {r.item for r in rows if r.label}
    items_hit = {r.item for r, p in zip(rows, probs) if r.label and p >= model.agrees}
    items_neg = {r.item for r in rows if not r.label}
    items_fp = {r.item for r, p in zip(rows, probs) if not r.label and p >= model.agrees}
    return {
        "components": n, "positives": pos,
        "auc": auc(probs, y),
        "brier": round(sum((p - t) ** 2 for p, t in zip(probs, y)) / n, 4),
        "at_agrees": {
            "threshold": model.agrees, "tp": tp, "fp": fp, "fn": pos - tp, "tn": n - pos - fp,
            "recall": round(tp / pos, 4) if pos else None,
            "false_agreement_rate": round(fp / (n - pos), 4) if n - pos else None,
            "malicious_items_agreed": f"{len(items_hit)} of {len(items_pos)}",
            "benign_items_with_a_false_agreement": f"{len(items_fp)} of {len(items_neg)}",
        },
    }


# ------------------------------------------------------------------ train --
def train(rows: Sequence[Row], *, version: str, rounds: int = 60, lr: float = 0.15,
          agrees: float = DEFAULT_AGREES) -> TriageModel:
    """Fit on the ``dev`` rows, calibrate on their out-of-fold predictions, evaluate on ``heldout``."""
    names = feature_names()
    dev = [r for r in rows if r.split == "dev"]
    held = [r for r in rows if r.split != "dev"]
    oof_margin: list[float] = []
    oof_y: list[int] = []
    for k in range(FOLDS):
        fit_rows = [r for r in dev if _fold(r.item) != k]
        test_rows = [r for r in dev if _fold(r.item) == k]
        if not test_rows or len({r.label for r in fit_rows}) < 2:
            continue
        X, y = _matrix(fit_rows, names)
        base, trees, _ = fit_boosted(X, y, rounds=rounds, lr=lr)
        Xt, yt = _matrix(test_rows, names)
        oof_margin += [base + sum(_predict_tree(t, x) for t in trees) for x in Xt]
        oof_y += yt
    a, b = fit_platt(oof_margin, oof_y)
    X, y = _matrix(dev, names)
    base, trees, splits = fit_boosted(X, y, rounds=rounds, lr=lr)
    top = sorted(((s, n) for s, n in zip(splits, names) if s), key=lambda t: (-t[0], t[1]))[:15]
    model = TriageModel(features=tuple(names), base=base, trees=tuple(trees), calibration=(a, b), agrees=agrees,
                        version=version, info={})
    oof_probs = [_sigmoid(a * m + b) for m in oof_margin]
    info = {
        "trained": {"corpus": "bench/manifest.yaml", "split": "dev", "items": len({r.item for r in dev}),
                    "components": len(dev), "positives": sum(r.label for r in dev), "rounds": len(trees),
                    "learning_rate": lr, "max_depth": 2,
                    "out_of_fold": {"auc": auc(oof_probs, oof_y),
                                    "false_agreements": sum(1 for p, t in zip(oof_probs, oof_y) if not t and p >= agrees),
                                    "agreements": sum(1 for p, t in zip(oof_probs, oof_y) if t and p >= agrees)}},
        "heldout": {"split": "heldout", "items": len({r.item for r in held}), **evaluate(model, held)},
        # The features the trees split on most often.
        "importance": [n for _, n in top],
    }
    return TriageModel(features=model.features, base=model.base, trees=model.trees, calibration=model.calibration,
                       agrees=model.agrees, version=version, info=info)


def model_document(model: TriageModel, skipped: dict[str, str]) -> dict[str, Any]:
    doc = model.to_dict()
    doc["format"] = FORMAT
    doc["notes"] = ("Trained by scripts/train_triage.py on Agent Guard's own corpus (dev split); figures under "
                    "'heldout' come from items the trainer never fitted on. Advisory only: it never produces a "
                    "verdict alone and never lowers a finding.")
    if skipped:
        doc["trained"]["label_notes"] = dict(sorted(skipped.items()))
    return doc
