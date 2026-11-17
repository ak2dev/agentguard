"""Verdict, score, confidence, corroboration and risk tier (spec/interfaces.md §8).

The verdict is rule-based; the score never decides it alone, and a model never
decides it at all. Everything here is a pure function of the findings.

Lanes keep high-recall heuristics from producing verdicts alone:

* ``block``   counts on its own;
* ``evidence`` counts only when corroborated: it is part of a chain, it sits in
  hidden or decoded content, dynamic evidence or the adjudicator confirms it,
  the triage model agrees (tagged ``triage-agrees``), or a different engine reported, on the same
  component, a malice signal or anything but hygiene in the same file (a
  package's own tests and test data stand aside from this, and so do the
  capability findings of the flow engine, which describe what a component
  could be made to do and are tied to no file: only a malice signal that
  itself counts backs them);
* ``hunt``    is advisory: dropped unless the policy turns the lane on, and then
  treated like ``evidence``.
"""

from __future__ import annotations

from collections import defaultdict

from .models import Chain, Finding
from .models.enums import CapLabel, Category, Confidence, FindingSource, Lane, RiskTier, Severity, Verdict

REVIEW_SCORE = 40
INDICATOR_RULES = ("AG-SUPPLY-002", "AG-SUPPLY-017")
POLICY_DENY_RULE = "AG-POL-001"
# Policy outcomes that require a review but are not a deny.
POLICY_REVIEW_RULES = ("AG-POL-002", "AG-POL-004", "AG-POL-007")
COMPOSITION_RULES = "AG-FLOW-"
# Set by the drift analyzer on a finding that says an approved component changed since the baseline.
DRIFT_TAG = "baseline-drift"
TRIAGE_AGREES = 0.80

_WEIGHT = {Severity.critical: 10.0, Severity.high: 7.0, Severity.medium: 4.0, Severity.low: 1.5, Severity.info: 0.0}
_CONF = {Confidence.high: 1.0, Confidence.medium: 0.7, Confidence.low: 0.4}
_CATEGORY = {Category.malice: 1.0, Category.vulnerability: 0.6, Category.hygiene: 0.1}

_L3 = {CapLabel.persistence, CapLabel.destructive, CapLabel.financial, CapLabel.host_elevated}
_L2 = {CapLabel.code_exec, CapLabel.shell, CapLabel.external_egress, CapLabel.credential_access}
_L1 = {CapLabel.fs_write_workspace, CapLabel.fs_write_outside}


_TEST_DIRS = frozenset({"test", "tests", "__tests__", "spec", "specs", "testdata", "test-data", "__fixtures__", "__mocks__", "e2e"})
_TEST_FILE_ENDS = (".test.ts", ".test.tsx", ".test.js", ".test.jsx", ".test.mjs", ".test.cjs", ".spec.ts", ".spec.tsx", ".spec.js",
                   ".spec.jsx", ".spec.mjs", ".spec.cjs", "_test.py", "_test.go", "_test.rb", ".integration.ts", ".e2e.ts")
_TEST_FILE_STARTS = ("test_", "conftest.", "vitest.config.", "vitest.setup.", "jest.config.", "jest.setup.", "playwright.config.")


def is_test_path(path: str) -> bool:
    """A file of a package's own test suite, by the usual directory and file names."""
    parts = path.lower().split("/")
    base = parts[-1]
    return bool(_TEST_DIRS.intersection(parts[:-1])) or base.endswith(_TEST_FILE_ENDS) or base.startswith(_TEST_FILE_STARTS)


def score(findings: list[Finding]) -> int:
    """``round(100 × (1 − ∏(1 − (w/10) × c × k)))`` over the findings that count.

    One high-confidence high-severity malice finding scores 70. The product
    form saturates, so fifty hygiene notes cannot outscore one real attack."""
    remaining = 1.0
    for f in findings:
        if f.suppressed or not f.corroborated:
            continue
        remaining *= 1.0 - (_WEIGHT[f.severity] / 10.0) * _CONF[f.confidence] * _CATEGORY[f.category]
    return int(round(100.0 * (1.0 - remaining)))


def risk_tier(labels: set[CapLabel], *, runs_code: bool = False) -> RiskTier:
    """Assigned from capabilities, independently of findings."""
    if labels & _L3:
        return RiskTier.L3
    if runs_code or labels & _L2:
        return RiskTier.L2
    if labels & _L1:
        return RiskTier.L1
    return RiskTier.L0


def raise_for_agreement(findings: list[Finding]) -> None:
    """Two independent engines on the same line raise confidence one level."""
    engines_at: dict[tuple[str, int], set[str]] = defaultdict(set)
    for f in findings:
        if f.location and f.category != Category.hygiene:
            engines_at[(f.location.file, f.location.start.line)].update(f.engines)
    order = [Confidence.low, Confidence.medium, Confidence.high]
    for f in findings:
        if not f.location or f.category == Category.hygiene:
            continue
        seen = engines_at[(f.location.file, f.location.start.line)]
        if len(seen - set(f.engines)) >= 1 and len(seen) >= 2 and "multi-engine" not in f.tags:
            f.confidence = order[min(order.index(f.confidence) + 1, 2)]
            f.tags = sorted({*f.tags, "multi-engine"})


def corroborate(findings: list[Finding], *, hunt: bool = False, triage: dict[str, float] | None = None,
                aside: frozenset[str] = frozenset(), agrees: float = TRIAGE_AGREES) -> None:
    """Set ``corroborated`` on every finding (see the module docstring).

    One engine backs another's finding on the same component when its own finding is a malice signal, or
    is in the same file: an unpinned dependency in ``package.json`` says nothing about a pattern matched in
    a source file. ``aside`` names the files a component does not ship to an agent (its tests and test
    data): an evidence-lane finding there neither gains nor gives backing through engine agreement."""
    triage = triage or {}

    def where(f: Finding) -> str:
        return f.location.file if f.location else ""

    def capability(f: Finding) -> bool:
        """A flow-engine statement about what the component can do: its location is an anchor, not a match."""
        return f.id.startswith(COMPOSITION_RULES) and f.category != Category.malice

    by_component: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        for cid in f.component_ids or [""]:
            by_component[cid].append(f)
    # Capability findings last: what backs one is a malice signal that itself counts, so those are settled first.
    for f in sorted(findings, key=capability):
        if f.lane == Lane.block:
            f.corroborated = True
            continue
        if "dismissed" in f.tags:
            # The adjudicator dismissed it: it stays in the report and stops counting.
            f.corroborated = False
            continue
        if f.lane == Lane.hunt and not hunt:
            f.corroborated = False
            continue
        if f.category == Category.hygiene:
            # Hygiene notes are informational; they neither need nor give corroboration.
            f.corroborated = True
            continue
        backed = (
            f.chain is not None
            or "hidden" in f.tags
            or "dynamic-confirmed" in f.tags
            or f.source == FindingSource.dynamic
            or (f.adjudication is not None and f.adjudication.status == "confirmed")
        )
        if not backed and where(f) not in aside:
            mine = set(f.engines)
            for cid in f.component_ids:
                for g in by_component[cid]:
                    if g is f or g.id == f.id or g.category == Category.hygiene:
                        continue
                    if g.lane == Lane.hunt and not hunt:
                        continue
                    if "dismissed" in g.tags or (g.lane != Lane.block and where(g) in aside):
                        continue
                    if g.category != Category.malice and (where(g) != where(f) or capability(f) or capability(g)):
                        continue
                    if capability(f) and not g.corroborated:
                        continue            # a signal that does not count on its own does not make a capability count
                    if set(g.engines) - mine:
                        backed = True
                        break
                if backed:
                    break
        if not backed and any(triage.get(cid, 0.0) >= agrees for cid in f.component_ids):
            # The triage model agrees with the rule: the finding counts. The model never adds a finding of its own.
            backed = True
            f.tags = sorted({*f.tags, "triage-agrees"})
        f.corroborated = backed


def decide(findings: list[Finding], chains: list[Chain], *, score_value: int | None = None) -> tuple[Verdict, list[str]]:
    """Evaluate the verdict rules in order. Returns the verdict and the reasons
    for it, each naming the rule that fired and the finding that triggered it."""
    live = [f for f in findings if not f.suppressed]
    counting = [f for f in live if f.corroborated]
    reasons: list[str] = []

    def cite(f: Finding) -> str:
        where = f" at {f.location.file}:{f.location.start.line}" if f.location else ""
        return f"{f.id}{where}"

    for f in counting:
        if (f.lane == Lane.block and f.category == Category.malice and f.severity.at_least(Severity.high)
                and f.confidence.rank >= Confidence.medium.rank):
            reasons.append(f"block-lane malice finding at {f.severity.value} severity: {cite(f)}")
            break
    for f in counting:
        if f.severity == Severity.critical and f.confidence == Confidence.high:
            reasons.append(f"critical finding with high confidence: {cite(f)}")
            break
    for f in live:
        if f.id in INDICATOR_RULES:
            reasons.append(f"indicator match: {cite(f)}")
            break
    by_fp = {f.fingerprint: f for f in live}
    for ch in chains:
        steps = [by_fp[s] for s in ch.steps if s in by_fp]
        if len(steps) >= 2 and ch.sink:
            reasons.append(f"confirmed chain {ch.id} ending in {ch.sink}: " + " → ".join(s.id for s in steps))
            break
    for f in live:
        if f.id == POLICY_DENY_RULE or "policy-deny" in f.tags:
            reasons.append(f"policy deny entry matches: {cite(f)}")
            break
    if reasons:
        return Verdict.block, reasons

    for f in counting:
        if f.severity.at_least(Severity.high):
            reasons.append(f"finding at {f.severity.value} severity: {cite(f)}")
            break
    for f in counting:
        if f.category == Category.malice and f.confidence.rank >= Confidence.medium.rank:
            reasons.append(f"malice finding with {f.confidence.value} confidence: {cite(f)}")
            break
    for f in live:
        if "coverage" in f.tags:
            reasons.append(f"content could not be analysed: {cite(f)}")
            break
    for f in live:
        if DRIFT_TAG in f.tags:
            reasons.append(f"differs from the approved baseline: {cite(f)}")
            break
    value = score(live) if score_value is None else score_value
    if value >= REVIEW_SCORE:
        reasons.append(f"score {value} is {REVIEW_SCORE} or more")
    for f in live:
        if f.id in POLICY_REVIEW_RULES or "policy-review" in f.tags:
            reasons.append(f"policy requires review: {cite(f)}")
            break
    if reasons:
        return Verdict.review, reasons
    return Verdict.allow, []


def effect(f: Finding, chains: list[Chain] | None = None) -> str:
    """How one finding bears on the verdict: ``block``, ``review`` or ``info``."""
    if f.suppressed:
        return "info"
    if f.id in INDICATOR_RULES or f.id == POLICY_DENY_RULE or "policy-deny" in f.tags:
        return "block"
    if f.chain and any(ch.id == f.chain and ch.sink and len(ch.steps) >= 2 for ch in chains or []):
        return "block"
    if f.corroborated:
        if (f.lane == Lane.block and f.category == Category.malice and f.severity.at_least(Severity.high)
                and f.confidence.rank >= Confidence.medium.rank):
            return "block"
        if f.severity == Severity.critical and f.confidence == Confidence.high:
            return "block"
        if f.severity.at_least(Severity.high) or (f.category == Category.malice and f.confidence.rank >= Confidence.medium.rank):
            return "review"
    if "coverage" in f.tags or DRIFT_TAG in f.tags or f.id in POLICY_REVIEW_RULES or "policy-review" in f.tags:
        return "review"
    return "info"
