"""Every detector must have at least one positive and one negative fixture, and
each fixture must behave as labelled. CI fails otherwise."""

from __future__ import annotations

import os

import pytest

from agentguard.core.analyzers import registry
from agentguard.core.engine import scan
from agentguard.core.models import AnalyzerMatch
from agentguard.core.models.enums import FAMILIES, RuleStatus, Severity
from agentguard.core.rules.pack import RulePack

from fixture_harness import detector_dir, iter_cases, load_case, missing_native

PACK = RulePack.default()
DETECTOR_KEYS = sorted(PACK.detectors)
# Optional native analyzers CI installs and therefore must not be skipped.
REQUIRED_NATIVE = {a for a in os.environ.get("AG_REQUIRE_NATIVE", "").split(",") if a}
STABLE_MIN_FIXTURES = 5


def _cases(key: str, side: str) -> list:
    d = detector_dir(key) / side
    return [p for p in d.iterdir() if p.is_dir()] if d.is_dir() else []


@pytest.mark.parametrize("key", DETECTOR_KEYS)
def test_detector_has_fixtures(key):
    for side in ("positive", "negative"):
        assert _cases(key, side), f"{key}: missing {side} fixture"


@pytest.mark.parametrize(
    "key,side,case_dir",
    iter_cases(DETECTOR_KEYS),
    ids=lambda v: v if isinstance(v, str) else v.name,
)
def test_fixture(key, side, case_dir, monkeypatch):
    case = load_case(key, side, case_dir)
    missing = missing_native(case)
    if missing:
        if REQUIRED_NATIVE & set(missing):
            pytest.fail(f"{case.id}: required analyzer not installed: {', '.join(sorted(REQUIRED_NATIVE & set(missing)))}")
        pytest.skip(f"optional analyzer not installed: {', '.join(missing)}")
    fault = case.config.get("fault")
    if fault:
        cls = next(c for c in registry.all_stages() if c.id == fault)

        def boom(self, ctx):
            raise RuntimeError("injected fault (fixture)")

        monkeypatch.setattr(cls, "run", boom)
    report = scan(case.tree, case.options, PACK)
    everything = [*report.findings, *report.suppressed_findings]
    fired = {f.key for f in everything}
    if side == "positive":
        assert key in fired, f"{case.id}: expected {key}; fired {sorted(fired)}"
        if case.config.get("verdict"):
            assert report.verdict.value == case.config["verdict"], f"{case.id}: verdict {report.verdict.value}: {report.verdict_reasons}"
    elif case.config.get("max_severity"):
        # A mention the rule reports at a lower severity (e.g. a quoted pattern in a
        # reference doc): it may fire, but never above max_severity.
        cap = Severity(case.config["max_severity"])
        over = [f for f in everything if f.key == key and f.severity.rank > cap.rank]
        assert not over, f"{case.id}: {key} fired above {cap.value}: " + "; ".join(
            f"{f.severity.value}: {f.message}" for f in over)
    else:
        assert key not in fired, f"{case.id}: {key} fired on a negative fixture: " + "; ".join(
            f.message for f in report.findings if f.key == key
        )
    for f in everything:
        assert f.location is not None or f.id.startswith(("AG-POL-", "AG-EVADE-", "AG-FLOW-")) or not f.component_ids, \
            f"{case.id}: {f.key} has no location"


def test_analyzer_rule_consistency():
    stages = {c.id: c for c in registry.all_stages()}
    for det in PACK.detectors.values():
        if isinstance(det.match, AnalyzerMatch):
            if det.match.analyzer == "engine":
                continue
            assert det.match.analyzer in stages, f"{det.key}: unknown analyzer {det.match.analyzer}"
            assert det.key in stages[det.match.analyzer].rules, f"{det.key} not declared by {det.match.analyzer}"
    for cls in stages.values():
        for key in cls.rules:
            assert key in PACK.detectors, f"{cls.id} declares unknown rule {key}"


def test_every_rule_is_mapped():
    for rule in PACK.rules.values():
        for m in rule.mappings:
            assert m.id or m.todo
        if rule.family in FAMILIES and rule.implemented:
            assert any(m.id for m in rule.mappings) or rule.family == "HYG", f"{rule.id}: no standards mapping"


def test_catalogue_is_the_specification():
    """23 families and 450 rules; anything else is marked as an extension."""
    core = [r for r in PACK.rules.values() if not r.extension]
    assert len(core) == 450
    assert {r.family for r in core} == set(FAMILIES)
    assert all(r.id.split("-")[1] == r.family for r in PACK.rules.values())


def test_stable_rules_have_five_and_five():
    for rule in PACK.rules.values():
        if rule.status != RuleStatus.stable:
            continue
        keys = [d.key for d in PACK.detectors.values() if d.rule_id == rule.id]
        pos = sum(len(_cases(k, "positive")) for k in keys)
        neg = sum(len(_cases(k, "negative")) for k in keys)
        assert pos >= STABLE_MIN_FIXTURES and neg >= STABLE_MIN_FIXTURES, \
            f"{rule.id} is marked stable with {pos} positive / {neg} negative fixtures"


def test_aliases_resolve():
    for alias, key in PACK.aliases.items():
        assert PACK.resolve_key(alias) == key
        assert PACK.rule(alias).id == key.split("/")[0]
