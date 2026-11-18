"""Rule pack export for the website and docs (`agentguard rules list --format json`).

One entry per catalogue rule: its head, its status, and its detectors (the
rule's own and its variants). Unsafe/safe examples come from the inert rule
fixtures; the export includes them only when a fixtures directory is
available (repo checkout)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import regex

from ..models.finding import mapping_dict
from ..models.rule import Detector, RuleDef
from ..redact import redact_snippet
from .pack import RulePack, bundled_dirs

MAX_EXAMPLE = 1200
CONTROL_FILES = ("_case.yaml", "_archive.zip", "agentguard.lock")

_PRINTABLE = regex.compile(rb"[\x20-\x7e]{4,}")


def _example(case_dir: Path, binary: bool = False) -> dict[str, str] | None:
    """The first text file of a fixture case; for YARA rules (``binary``), the
    printable strings of the first binary file, which is what the rule matches."""
    files = sorted(
        (p for p in case_dir.rglob("*") if p.is_file() and not p.name.startswith("_") and p.name != "agentguard.lock"),
        # Sort by the POSIX string, not Path: Windows paths compare case-insensitively.
        key=lambda p: p.relative_to(case_dir).as_posix(),
    )
    if not files:
        return None
    for f in files:
        data = f.read_bytes()
        is_binary = b"\x00" in data[:4096]
        if binary and is_binary:
            strings = "\n".join(m.group(0).decode("ascii") for m in _PRINTABLE.finditer(data))
            return {"path": f.relative_to(case_dir).as_posix(),
                    "text": redact_snippet("(printable strings of a binary file)\n" + strings, MAX_EXAMPLE)}
        if binary or is_binary:
            continue
        text = data.decode("utf-8", "replace")
        return {"path": f.relative_to(case_dir).as_posix(), "text": redact_snippet(text, MAX_EXAMPLE)}
    return {"path": files[0].relative_to(case_dir).as_posix(), "text": "(binary fixture)"}


def detector_fixture_dir(fixtures_dir: Path, key: str) -> Path:
    rule_id, _, variant = key.partition("/")
    return fixtures_dir / rule_id / "variants" / variant if variant else fixtures_dir / rule_id


def fixture_counts(fixtures_dir: Path | None, keys: list[str]) -> dict[str, int]:
    out = {"positive": 0, "negative": 0}
    if fixtures_dir is None:
        return out
    for key in keys:
        for side in out:
            d = detector_fixture_dir(fixtures_dir, key) / side
            if d.is_dir():
                out[side] += sum(1 for c in d.iterdir() if c.is_dir())
    return out


def _examples(fixtures_dir: Path | None, det: Detector) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    if fixtures_dir is None:
        return out
    for side, label in (("positive", "unsafe"), ("negative", "safe")):
        d = detector_fixture_dir(fixtures_dir, det.key) / side
        if d.is_dir():
            case = next((c for c in sorted(d.iterdir(), key=lambda p: p.name) if c.is_dir()), None)
            ex = _example(case, binary=det.match is not None and det.match.type == "yara") if case else None
            if ex:
                out[label] = ex
    return out


def _match_type(det: Detector) -> str:
    m = det.match
    if m is None:
        return "planned"
    return f"analyzer:{m.analyzer}" if m.type == "analyzer" else m.type


def export_rule(pack: RulePack, r: RuleDef, fixtures_dir: Path | None = None) -> dict[str, Any]:
    detectors = [d for d in pack.detectors.values() if d.rule_id == r.id]
    own = next((d for d in detectors if d.variant is None), None)
    first = own or (detectors[0] if detectors else None)
    entry: dict[str, Any] = {
        "id": r.id,
        "version": r.version,
        "title": r.title,
        "family": r.family,
        "category": r.category.value,
        "severity": r.severity.value,
        "severity_from_content": r.severity_from_content,
        "confidence": r.confidence.value,
        "lane": r.lane.value,
        "engine": r.engine,
        "fix": r.fix.value,
        "fix_action": r.fix_action,
        "status": r.status.value,
        "blocks_allow": r.blocks_allow,
        "extension": r.extension,
        "description": r.description or (first.description if first else ""),
        "why": r.why or (first.why if first else ""),
        "remediation": r.remediation or (first.remediation if first else ""),
        "references": sorted({ref for d in detectors for ref in d.references} | set(r.references)),
        "network": r.network or (bool(detectors) and all(d.network for d in detectors)),
        "mappings": [m.model_dump(exclude_none=True) for m in r.mappings],
        "mapping_ids": mapping_dict(r.mappings),
        "aliases": sorted({a for d in detectors for a in d.aliases}),
        "match_type": _match_type(first) if first else "planned",
        "fixtures": fixture_counts(fixtures_dir, [d.key for d in detectors]),
        "variants": [
            {"key": d.variant, "title": d.title, "severity": d.severity.value, "confidence": d.confidence.value,
             "lane": d.lane.value, "category": d.category.value, "description": d.description, "why": d.why,
             "remediation": d.remediation, "aliases": list(d.aliases), "match_type": _match_type(d)}
            for d in detectors if d.variant
        ],
        "examples": _examples(fixtures_dir, first) if first else {},
    }
    return entry


def export_rules(pack: RulePack, fixtures_dir: Path | None = None) -> dict[str, Any]:
    if fixtures_dir is None:
        rules_dir, _ = bundled_dirs()
        candidate = rules_dir.parent / "fixtures" / "rules"
        fixtures_dir = candidate if candidate.is_dir() else None
    rules = [export_rule(pack, r, fixtures_dir) for r in pack.rules.values()]
    frameworks = {
        fw.framework: {"name": fw.name, "version": fw.version, "source": fw.source, "notes": fw.notes, "items": fw.items}
        for fw in pack.frameworks.values()
    }
    families = [
        {"family": f.family, "name": f.name, "about": f.about, "rules": len(f.rule_ids),
         "implemented": sum(1 for rid in f.rule_ids if pack.rules[rid].implemented)}
        for f in pack.families.values()
    ]
    core = [r for r in pack.rules.values() if not r.extension]
    return {
        "rule_pack": {"version": pack.version, "digest": pack.digest, "rules": len(core),
                      "implemented": sum(1 for r in core if r.implemented), "detectors": len(pack.detectors)},
        "families": families,
        "rules": rules,
        "frameworks": frameworks,
    }
