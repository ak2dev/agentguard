"""CI gate for the rule pack.

* the strict (hardened) YAML load agrees with the fast one;
* every detector has at least one positive and one negative fixture;
* a rule marked ``stable`` has at least five of each;
* the catalogue is the specification: 23 families, 450 rules, everything else marked as an extension;
* the crosswalk has no entry without a rule.

A catalogue rule with no detection entry is ``planned``; that is reported as a
count, not as a problem.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from agentguard.core.models.enums import FAMILIES, RuleStatus  # noqa: E402
from agentguard.core.rules.export import detector_fixture_dir, fixture_counts  # noqa: E402
from agentguard.core.rules.pack import RulePack, RulePackError, strict_pack_check  # noqa: E402

FIXTURES = ROOT / "fixtures" / "rules"


def main() -> int:
    pack = RulePack.default()
    problems = []
    try:
        strict = strict_pack_check(ROOT / "rules", ROOT / "mappings")
        if strict.digest != pack.digest or set(strict.rules) != set(pack.rules):
            problems.append("strict and fast rule-pack loads disagree")
    except RulePackError as exc:
        problems.append(f"strict rule-pack load failed: {exc}")
    for key in pack.detectors:
        for side in ("positive", "negative"):
            d = detector_fixture_dir(FIXTURES, key) / side
            if not d.is_dir() or not any(p.is_dir() for p in d.iterdir()):
                problems.append(f"{key}: missing {side} fixture")
    for rule in pack.rules.values():
        if rule.status == RuleStatus.stable:
            n = fixture_counts(FIXTURES, [d.key for d in pack.detectors.values() if d.rule_id == rule.id])
            if n["positive"] < 5 or n["negative"] < 5:
                problems.append(f"{rule.id}: stable with {n['positive']} positive / {n['negative']} negative fixtures")
    core = [r for r in pack.rules.values() if not r.extension]
    if len(core) != 450 or {r.family for r in core} != set(FAMILIES):
        problems.append(f"catalogue has {len(core)} rules in {len({r.family for r in core})} families (expected 450 in 23)")
    problems += [f"crosswalk entry without rule: {r}" for r in pack.crosswalk_orphans]
    for p in problems:
        print(p)
    planned = sum(1 for r in core if not r.implemented)
    print(f"{len(core)} catalogue rules ({len(core) - planned} implemented, {planned} planned), "
          f"{len(pack.detectors)} detectors checked; {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
