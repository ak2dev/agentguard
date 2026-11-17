"""Rule development: fixtures, scaffolding and validation
(`agentguard rules new | test | validate`; also the loader the test suite uses).

Fixture layout: ``<fixtures>/<RULE>/{positive,negative}/<case>/`` for a rule's
own detector and ``<fixtures>/<RULE>/variants/<variant>/{positive,negative}/<case>/``
for a variant. A case directory holds the files to scan plus optional control
files (``_case.yaml``, ``_archive.zip``, ``agentguard.lock``).
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .core.archive import from_archive
from .core.engine import scan
from .core.models import (
    AdjudicationResult,
    DependencyFact,
    DynamicEvidence,
    LoadLimits,
    Lockfile,
    PackageFacts,
    Policy,
    RemoteProbe,
    Report,
    ScanOptions,
    Suppression,
)
from .core.models.enums import RuleStatus, Severity
from .core.parsers.safe_yaml import safe_load
from .core.rules.pack import RulePack, bundled_dirs
from .core.tree import ArtifactTree
from .io.fs_loader import load_path

CONTROL_FILES = ("_case.yaml", "_archive.zip", "agentguard.lock")
CONTEXT_DIR = "_context/"
STABLE_MIN_FIXTURES = 5
# ScanOptions fields a case may set directly from _case.yaml.
_PLAIN_OPTIONS = ("dynamic_ran", "dynamic_level", "dynamic_not_reached", "llm_complete", "profile", "own_repo",
                  "media_text", "facts", "agent_safe")


def default_fixtures_dir() -> Path:
    rules_dir, _ = bundled_dirs()
    return rules_dir.parent / "fixtures" / "rules"


@dataclass
class Case:
    rule_id: str          # detector key: "AG-X-001" or "AG-X-001/variant"
    side: str
    name: str
    path: Path
    tree: ArtifactTree
    options: ScanOptions
    config: dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        return f"{self.rule_id}/{self.side}/{self.name}"


def detector_dir(key: str, fixtures: Path | None = None) -> Path:
    rule_id, _, variant = key.partition("/")
    base = fixtures or default_fixtures_dir()
    return base / rule_id / "variants" / variant if variant else base / rule_id


def load_case(rule_id: str, side: str, case_dir: Path) -> Case:
    cfg: dict[str, Any] = {}
    if (case_dir / "_case.yaml").exists():
        res = safe_load((case_dir / "_case.yaml").read_text(encoding="utf-8"))
        if res.error is not None:
            raise ValueError(f"{case_dir / '_case.yaml'}: {res.error}")
        cfg = res.value or {}
    limits = LoadLimits(**cfg.get("limits", {}))
    if (case_dir / "_archive.zip").exists():
        tree = from_archive((case_dir / "_archive.zip").read_bytes(), limits=limits)
    else:
        tree = load_path(case_dir, limits)
        for name in CONTROL_FILES:
            tree.files.pop(name, None)
    opts: dict[str, Any] = {"limits": limits}
    # Files under `_context/` are the installed components the candidate is composed with, not part of the candidate.
    installed = {p[len(CONTEXT_DIR):]: tree.files[p].data for p in list(tree.files) if p.startswith(CONTEXT_DIR)}
    if installed:
        for p in [p for p in tree.files if p.startswith(CONTEXT_DIR)]:
            tree.files.pop(p)
        opts["context"] = ArtifactTree.from_mapping(installed, limits)
    if "popular_skills" in cfg:
        opts["popular_skills"] = cfg["popular_skills"]
    # Fixtures exercise every lane, so the advisory (hunt) lane is on unless a case says otherwise.
    policy = dict(cfg.get("policy") or {})
    policy.setdefault("lanes", {"hunt": True})
    opts["policy"] = Policy.model_validate(policy)
    if (case_dir / "agentguard.lock").exists():
        opts["lock"] = Lockfile.model_validate_json((case_dir / "agentguard.lock").read_text(encoding="utf-8"))
    if "network" in cfg:
        opts["network"] = cfg["network"]
    if "suppressions" in cfg:
        opts["suppressions"] = [Suppression.model_validate(s) for s in cfg["suppressions"]]
    if "today" in cfg:
        opts["today"] = dt.date.fromisoformat(str(cfg["today"]))
    if "remote_probes" in cfg:
        opts["remote_probes"] = [RemoteProbe.model_validate(x) for x in cfg["remote_probes"]]
    if "package_facts" in cfg:
        opts["package_facts"] = [PackageFacts.model_validate(x) for x in cfg["package_facts"]]
    if "dependency_facts" in cfg:
        opts["dependency_facts"] = [DependencyFact.model_validate(x) for x in cfg["dependency_facts"]]
    if "judge_results" in cfg:
        from .core.judge_models import JudgeResult

        opts["judge_results"] = [JudgeResult.model_validate(x) for x in cfg["judge_results"]]
    if "adjudications" in cfg:
        opts["adjudications"] = [AdjudicationResult.model_validate(x) for x in cfg["adjudications"]]
    if "dynamic_evidence" in cfg:
        opts["dynamic_evidence"] = [DynamicEvidence.model_validate(x) for x in cfg["dynamic_evidence"]]
    for key in _PLAIN_OPTIONS:
        if key in cfg and key in ScanOptions.model_fields:
            opts[key] = cfg[key]
    if cfg.get("intel"):
        from .core.intel.feed import verify_feed
        from .io.intel_store import bundled_intel_dir, trusted_keys

        d = bundled_intel_dir()
        opts["intel"] = verify_feed((d / "sample-feed.json").read_bytes(), (d / "sample-feed.json.sig").read_bytes(), trusted_keys())
    if "changed_paths" in cfg:
        opts["changed_paths"] = set(cfg["changed_paths"])
    if "context" in cfg:
        # Installed components the candidate is composed with: a sibling directory of the case.
        opts["context"] = load_path(case_dir.parent / str(cfg["context"]), limits)
    return Case(rule_id, side, case_dir.name, case_dir, tree, ScanOptions(**opts), cfg)


def iter_cases(keys: list[str], fixtures: Path | None = None) -> list[tuple[str, str, Path]]:
    out = []
    for key in keys:
        for side in ("positive", "negative"):
            d = detector_dir(key, fixtures) / side
            if d.is_dir():
                for case in sorted(p for p in d.iterdir() if p.is_dir()):
                    out.append((key, side, case))
    return out


def missing_native(case: Case) -> list[str]:
    """Analyzers a case requires (``requires: [code.ts, yara]`` in _case.yaml)
    whose optional native dependencies are not installed."""
    from .core.analyzers import registry

    stages = {c.id: c for c in registry.all_stages()}
    return [a for a in case.config.get("requires", []) if a in stages and not registry.native_available(stages[a])]


def check_case(case: Case, report: Report) -> str | None:
    """None when the case behaves as labelled, else what went wrong."""
    key = case.rule_id
    everything = [*report.findings, *report.suppressed_findings]
    fired = {f.key for f in everything}
    if case.side == "positive":
        if key not in fired:
            return f"expected {key}; fired {sorted(fired)}"
        if case.config.get("verdict") and report.verdict.value != case.config["verdict"]:
            return f"verdict {report.verdict.value}, expected {case.config['verdict']}: {report.verdict_reasons}"
    elif case.config.get("max_severity"):
        # A mention the rule reports at a lower severity: it may fire, but never above max_severity.
        cap = Severity(case.config["max_severity"])
        over = [f for f in everything if f.key == key and f.severity.rank > cap.rank]
        if over:
            return f"{key} fired above {cap.value}: " + "; ".join(f"{f.severity.value}: {f.message}" for f in over)
    elif key in fired:
        return f"{key} fired on a negative fixture: " + "; ".join(f.message for f in everything if f.key == key)
    for f in everything:
        if f.location is None and f.component_ids and not f.id.startswith(("AG-POL-", "AG-EVADE-", "AG-FLOW-")):
            return f"{f.key} has no location"
    return None


@dataclass
class TestResult:
    __test__ = False      # not a pytest class

    case: str
    status: str           # passed | failed | skipped | error
    detail: str = ""


def run_fixtures(pack: RulePack, fixtures: Path | None = None, selector: str | None = None) -> list[TestResult]:
    """Run every fixture of the selected detectors (`agentguard rules test`)."""
    keys = sorted(pack.detectors)
    if selector:
        ids = pack.canonical_ids(selector)
        resolved = pack.resolve_key(selector)
        keys = [k for k in keys if k == resolved or k.partition("/")[0] in ids]
    results: list[TestResult] = []
    for key in keys:
        cases = iter_cases([key], fixtures)
        for side in ("positive", "negative"):
            if not any(s == side for _, s, _ in cases):
                results.append(TestResult(f"{key}/{side}", "failed", f"no {side} fixture"))
        for _, side, case_dir in cases:
            name = f"{key}/{side}/{case_dir.name}"
            try:
                case = load_case(key, side, case_dir)
                if case.config.get("fault"):
                    results.append(TestResult(name, "skipped", "fault-injection case (run by the test suite)"))
                    continue
                missing = missing_native(case)
                if missing:
                    results.append(TestResult(name, "skipped", f"optional analyzer not installed: {', '.join(missing)}"))
                    continue
                problem = check_case(case, scan(case.tree, case.options, pack))
            except Exception as exc:  # noqa: BLE001 - a broken fixture is a result, not a crash
                results.append(TestResult(name, "error", f"{type(exc).__name__}: {str(exc)[:200]}"))
                continue
            results.append(TestResult(name, "failed" if problem else "passed", problem or ""))
    return results


def validate_pack(pack: RulePack, fixtures: Path | None = None) -> list[str]:
    """Problems with a loaded pack: detectors without fixtures, ``stable`` rules
    with fewer than five of each, analyzers that are not registered."""
    from .core.analyzers import registry
    from .core.models import AnalyzerMatch
    from .core.rules.export import fixture_counts

    fixtures = fixtures or default_fixtures_dir()
    problems: list[str] = []
    stages = {c.id: c for c in registry.all_stages()}
    for det in pack.detectors.values():
        if isinstance(det.match, AnalyzerMatch) and det.match.analyzer != "engine":
            if det.match.analyzer not in stages:
                problems.append(f"{det.key}: unknown analyzer {det.match.analyzer}")
            elif det.key not in stages[det.match.analyzer].rules:
                problems.append(f"{det.key}: not declared by analyzer {det.match.analyzer}")
        if fixtures.is_dir():
            for side in ("positive", "negative"):
                d = detector_dir(det.key, fixtures) / side
                if not d.is_dir() or not any(p.is_dir() for p in d.iterdir()):
                    problems.append(f"{det.key}: missing {side} fixture")
    for rule in pack.rules.values():
        if rule.status == RuleStatus.stable and fixtures.is_dir():
            n = fixture_counts(fixtures, [d.key for d in pack.detectors.values() if d.rule_id == rule.id])
            if n["positive"] < STABLE_MIN_FIXTURES or n["negative"] < STABLE_MIN_FIXTURES:
                problems.append(f"{rule.id}: stable with {n['positive']} positive / {n['negative']} negative fixtures "
                                f"(needs {STABLE_MIN_FIXTURES} of each)")
    problems += [f"crosswalk entry without a rule: {r}" for r in pack.crosswalk_orphans]
    return problems


RULE_TEMPLATE = """# Detection entry for {rule_id}{variant_note} ({title}).
# Catalogue: severity {severity}, lane {lane}, fix {fix}. A detection entry adds the matching logic and the wording.
rules:
  - id: {rule_id}
{variant_line}    version: 1
    description: >-
      What exactly matches, in one or two sentences.
    why: >-
      What could happen if this is loaded, in plain language.
    confidence: medium
    applies_to: [skill_md, instruction_md, reference]
    match:
      type: regex
      scopes: [body, hidden, decoded]
      patterns:
        - |-
          \\breplace this pattern\\b
      unless:
        - |-
          \\b(?:example|for instance|such as)\\b
      window: 0
    remediation: >-
      What to change, as an instruction to the author.
"""


def scaffold(pack: RulePack, rule_id: str, variant: str | None, out_dir: Path) -> list[Path]:
    """Write a detection-entry template and an empty positive and negative
    fixture for a catalogue rule (`agentguard rules new`)."""
    rule = pack.rule(rule_id)
    key = f"{rule.id}/{variant}" if variant else rule.id
    if key in pack.detectors:
        raise ValueError(f"{key} already has a detector; add a variant with --variant <key>")
    name = f"{rule.id.lower()}{'-' + variant if variant else ''}.yaml"
    rules_file = out_dir / "rules" / name
    rules_file.parent.mkdir(parents=True, exist_ok=True)
    rules_file.write_text(RULE_TEMPLATE.format(
        rule_id=rule.id, title=rule.title, severity=rule.severity.value, lane=rule.lane.value, fix=rule.fix.value,
        variant_note=f"/{variant}" if variant else "",
        variant_line=f"    variant: {variant}\n    title: A short title for this variant\n" if variant else "",
    ), encoding="utf-8", newline="\n")
    written = [rules_file]
    base = detector_dir(key, out_dir / "fixtures" / "rules")
    for side, body in (("positive", "A file the rule must match.\n"), ("negative", "A similar file the rule must not match.\n")):
        f = base / side / "example" / "demo" / "SKILL.md"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(f"---\nname: demo\ndescription: Demo skill for {rule.id}.\n---\n{body}", encoding="utf-8", newline="\n")
        written.append(f)
    return written
