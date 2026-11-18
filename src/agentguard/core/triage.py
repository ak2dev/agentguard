"""The triage model (engine K; PLAN §7.1).

A small gradient-boosted classifier over what the deterministic engines have already computed for one component:
rule hits by family, lane and category, the strongest severity and confidence, hidden and decoded content, how many
distinct rules and independent engines fired, the component's capability labels and its kind. It returns a
calibrated probability that the component is malicious.

What the probability is used for, and what it is not:

* it decides where the adjudicator's budget goes (``judge.stage.gated_components``);
* when it agrees with a rule (probability at or above the model's ``agrees`` threshold), an evidence-lane finding on
  that component counts towards the verdict and is tagged ``triage-agrees`` (``core/verdict.py``);
* it never produces a finding or a verdict on its own, and never lowers, dismisses or removes a finding.

The model is data, ``rules/data/triage-model.json``, versioned with the rule pack. ``scripts/train_triage.py`` trains
it on the internal corpus (``bench/``): the ``dev`` split for fitting, the ``heldout`` split for the figures recorded
in the file. No public benchmark data is used for training (PLAN §12.1).

Inference is pure Python (a sum over shallow trees and a logistic calibration), so the engine keeps its small
dependency set and runs in the browser build too. Multilingual sentence embeddings of the instruction text, which
PLAN §7.1 also names as input, are not part of this model: they need an embedding model that is not bundled.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .models import Finding
from .models.enums import ArtifactRole, CapLabel, Category, ComponentKind, Lane, Severity

if TYPE_CHECKING:
    from .inventory import Inventory

FORMAT = 1
DEFAULT_AGREES = 0.80
FAMILIES = ("INJ", "OBF", "MM", "EXF", "CRED", "EXEC", "PERSIST", "IMPACT", "MANIP", "PRIV", "CFG", "PLUG", "MCP",
            "VULN", "SUPPLY", "META", "FLOW", "CI", "WS", "IMG", "CONN", "EVADE", "HYG")
_LANES = (Lane.block, Lane.evidence, Lane.hunt)
_CATEGORIES = (Category.malice, Category.vulnerability, Category.hygiene)
_KINDS = tuple(ComponentKind)
_CODE_ROLES = frozenset({ArtifactRole.script, ArtifactRole.source_code, ArtifactRole.binary})
_SEVERITY = {Severity.info: 0.0, Severity.low: 1.0, Severity.medium: 2.0, Severity.high: 3.0, Severity.critical: 4.0}
_CONFIDENCE = {"low": 1.0, "medium": 2.0, "high": 3.0}
# Findings about the scan itself (coverage, policy, the model and dynamic tiers) say nothing about the component.
_NOT_SIGNAL_RULES = ("AG-POL-", "AG-EVADE-016", "AG-EVADE-021")


def feature_names() -> list[str]:
    """The features this version of the engine computes, in a fixed order."""
    names = [f"lane_{lane.value}_{cat.value}" for lane in _LANES for cat in _CATEGORIES]
    names += [f"family_{fam}" for fam in FAMILIES]
    names += ["max_severity_malice", "max_severity_vulnerability", "max_confidence_malice", "block_malice_high",
              "distinct_rules", "distinct_engines", "hidden", "decoded", "mentions", "chained",
              "files", "code_files"]
    names += [f"cap_{label.value}" for label in CapLabel]
    names += [f"kind_{kind.value}" for kind in _KINDS]
    return names


def _signal(f: Finding) -> bool:
    return not f.id.startswith(_NOT_SIGNAL_RULES) and "coverage" not in f.tags


def component_features(findings: Iterable[Finding], inv: Inventory) -> dict[str, dict[str, float]]:
    """``component id -> {feature: value}`` for every component of the inventory. Only non-zero values are kept."""
    by_comp: dict[str, list[Finding]] = {cid: [] for cid in inv.components}
    for f in findings:
        if not _signal(f):
            continue
        for cid in f.component_ids:
            if cid in by_comp:
                by_comp[cid].append(f)
    files: dict[str, int] = {}
    code: dict[str, int] = {}
    for art in inv.artifacts.values():
        files[art.component_id] = files.get(art.component_id, 0) + 1
        if art.role in _CODE_ROLES:
            code[art.component_id] = code.get(art.component_id, 0) + 1
    out: dict[str, dict[str, float]] = {}
    for cid, comp in inv.components.items():
        x: dict[str, float] = {}

        def add(name: str, value: float = 1.0) -> None:
            if value:
                x[name] = x.get(name, 0.0) + value

        mine = by_comp.get(cid, [])
        rules: set[str] = set()
        engines: set[str] = set()
        for f in mine:
            add(f"lane_{f.lane.value}_{f.category.value}")
            if f.category != Category.hygiene:
                fam = f.family or (f.id.split("-")[1] if f.id.count("-") >= 2 else "")
                if fam in FAMILIES:
                    add(f"family_{fam}")
                rules.add(f.id)
                engines.update(f.engines)
                if "hidden" in f.tags:
                    add("hidden")
                if f.evidence.derivation:
                    add("decoded")
                if "mention" in f.tags:
                    add("mentions")
                if f.chain:
                    add("chained")
            sev = _SEVERITY.get(f.severity, 0.0)
            if f.category == Category.malice:
                x["max_severity_malice"] = max(x.get("max_severity_malice", 0.0), sev)
                x["max_confidence_malice"] = max(x.get("max_confidence_malice", 0.0), _CONFIDENCE.get(f.confidence.value, 0.0))
                if f.lane == Lane.block and f.severity.at_least(Severity.high):
                    x["block_malice_high"] = 1.0
            elif f.category == Category.vulnerability:
                x["max_severity_vulnerability"] = max(x.get("max_severity_vulnerability", 0.0), sev)
        add("distinct_rules", float(len(rules)))
        add("distinct_engines", float(len(engines)))
        add("files", float(files.get(cid, 0)))
        add("code_files", float(code.get(cid, 0)))
        for label in comp.labels():
            add(f"cap_{label.value}")
        add(f"kind_{comp.kind.value}")
        out[cid] = {k: v for k, v in x.items() if v}
    return out


# ------------------------------------------------------------------ model --
def _tree_value(node: Any, x: list[float]) -> float:
    """A leaf is a number; an inner node is ``[feature index, threshold, left, right]`` (left when ``x <= threshold``)."""
    while isinstance(node, list):
        node = node[2] if x[node[0]] <= node[1] else node[3]
    return float(node)


@dataclass(frozen=True)
class TriageModel:
    features: tuple[str, ...]
    base: float
    trees: tuple[Any, ...]
    calibration: tuple[float, float] = (1.0, 0.0)
    agrees: float = DEFAULT_AGREES
    version: str = ""
    info: Mapping[str, Any] = field(default_factory=dict)

    def vector(self, values: Mapping[str, float]) -> list[float]:
        return [float(values.get(name, 0.0)) for name in self.features]

    def margin(self, values: Mapping[str, float]) -> float:
        x = self.vector(values)
        return self.base + sum(_tree_value(t, x) for t in self.trees)

    def predict(self, values: Mapping[str, float]) -> float:
        a, b = self.calibration
        z = a * self.margin(values) + b
        z = max(-60.0, min(60.0, z))
        return 1.0 / (1.0 + math.exp(-z))

    def to_dict(self) -> dict[str, Any]:
        return {"format": FORMAT, "version": self.version, "features": list(self.features), "base": self.base,
                "trees": list(self.trees), "calibration": {"a": self.calibration[0], "b": self.calibration[1]},
                "agrees": self.agrees, **dict(self.info)}


def _valid_tree(node: Any, n: int, depth: int = 0) -> bool:
    if isinstance(node, (int, float)) and not isinstance(node, bool):
        return math.isfinite(float(node))
    return (isinstance(node, list) and len(node) == 4 and depth < 16 and isinstance(node[0], int) and 0 <= node[0] < n
            and isinstance(node[1], (int, float)) and _valid_tree(node[2], n, depth + 1) and _valid_tree(node[3], n, depth + 1))


def load_model(doc: Any) -> TriageModel | None:
    """The model from its JSON document, or None when there is none or it is not one this engine reads."""
    if not isinstance(doc, dict) or doc.get("format") != FORMAT:
        return None
    feats = doc.get("features")
    trees = doc.get("trees")
    if not isinstance(feats, list) or not all(isinstance(f, str) for f in feats) or not isinstance(trees, list):
        return None
    if not all(_valid_tree(t, len(feats)) for t in trees):
        return None
    cal = doc.get("calibration") or {}
    try:
        base = float(doc.get("base", 0.0))
        a, b = float(cal.get("a", 1.0)), float(cal.get("b", 0.0))
        agrees = float(doc.get("agrees", DEFAULT_AGREES))
    except (TypeError, ValueError):
        return None
    if not (math.isfinite(base) and math.isfinite(a) and math.isfinite(b) and 0.5 <= agrees < 1.0):
        return None
    info = {k: v for k, v in doc.items() if k in ("trained", "heldout", "importance", "notes")}
    return TriageModel(features=tuple(feats), base=base, trees=tuple(trees), calibration=(a, b), agrees=agrees,
                       version=str(doc.get("version", "")), info=info)


def score(model: TriageModel, features: Mapping[str, Mapping[str, float]]) -> dict[str, float]:
    """``component id -> probability`` (rounded, so reports are stable across platforms)."""
    return {cid: round(model.predict(x), 4) for cid, x in sorted(features.items())}
