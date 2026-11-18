"""Rule pack + standards crosswalk loading.

The pack is plain data:

* ``rules/pack.yaml``: pack version.
* ``rules/catalog/*.yaml``: the catalogue, one file per family. Each row is
  ``[id, severity, fix, title, {overrides}]``; the file carries the family's
  defaults (category, lane, confidence, engine) and its standards mappings.
* every other ``rules/**/*.yaml``: detection entries (``rules:`` list). An
  entry names a catalogue ``id`` and optionally a ``variant``.
* ``rules/data/*.yaml|*.txt``: lists used by analyzers.
* ``rules/yara/*.yar``: YARA sources.
* ``mappings/*.yaml``: framework catalogs + the per-rule crosswalk.

``RulePack.from_files`` takes an in-memory mapping so the same loader works
under Pyodide and in hosted workers. The digest covers every file, so any
change to rules, data, or mappings changes the report cache key.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import regex
from pydantic import ValidationError

from ..models import Mapping, RuleDef, RulePackInfo, YaraMatch
from ..models.enums import FAMILIES, SYSTEM_FAMILIES, FixKind, RuleStatus, Severity
from ..models.finding import FRAMEWORKS
from ..models.rule import LEGACY_ID_RE, RULE_ID_RE, Detector, RuleVariant, resolve, split_key
from ..parsers.safe_yaml import safe_load
from ..textutil import sha256_hex

NSA_TODO = "NSA AISC CSI (MCP, May 2026) mapping not yet reviewed for this rule"

_SEV = {"C": "critical", "H": "high", "M": "medium", "L": "low", "I": "info", "var": "medium"}
_FIX = {"A": "auto", "P": "patch", "G": "guidance", "X": "remove", "-": "none", "—": "none"}
# Head fields a detection entry may set. Title, severity and fix type belong to the catalogue.
_HEAD_ENTRY_FIELDS = {
    "id", "aliases", "version", "description", "why", "remediation", "match", "applies_to", "references",
    "cvss4_vector", "aivss", "tags", "network", "enabled", "status", "fix_action", "confidence", "lane", "category",
    "engine",
}


class RulePackError(ValueError):
    pass


@dataclass
class FrameworkCatalog:
    framework: str
    name: str
    version: str
    source: str
    items: dict[str, str]  # id -> title
    notes: str = ""


@dataclass
class FamilyInfo:
    family: str
    name: str
    about: str = ""
    rule_ids: list[str] = field(default_factory=list)
    mappings: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class RulePack:
    version: str
    digest: str
    rules: dict[str, RuleDef]                 # every catalogue rule, implemented or planned
    data: dict[str, Any]
    frameworks: dict[str, FrameworkCatalog]
    crosswalk: dict[str, dict[str, list[str] | None]]
    detectors: dict[str, Detector] = field(default_factory=dict)   # by detector key
    aliases: dict[str, str] = field(default_factory=dict)          # legacy id -> detector key
    families: dict[str, FamilyInfo] = field(default_factory=dict)
    yara_sources: dict[str, str] = field(default_factory=dict)
    min_engine: str = "0.1.0"

    @property
    def crosswalk_orphans(self) -> list[str]:
        """Crosswalk entries without a rule (a CI test keeps this list empty)."""
        return sorted(set(self.crosswalk) - set(self.rules))

    @property
    def implemented(self) -> list[RuleDef]:
        return [r for r in self.rules.values() if r.implemented]

    @property
    def info(self) -> RulePackInfo:
        return RulePackInfo(version=self.version, digest=self.digest, rule_count=len(self.rules))

    # -- lookup ------------------------------------------------------------
    def resolve_key(self, key: str) -> str | None:
        """A detector key for a rule id, ``id/variant``, or a legacy alias."""
        if key in self.detectors:
            return key
        if key in self.aliases:
            return self.aliases[key]
        up = key.upper()
        if up in self.detectors:
            return up
        return self.aliases.get(up)

    def detector(self, key: str) -> Detector:
        try:
            return self.detectors[key]
        except KeyError:
            raise RulePackError(f"unknown rule id {key!r}") from None

    def rule(self, rule_id: str) -> RuleDef:
        """The catalogue rule for an id, ``id/variant`` key or legacy alias."""
        rid = split_key(rule_id)[0]
        if rid in self.rules:
            return self.rules[rid]
        key = self.resolve_key(rule_id)
        if key is not None:
            return self.rules[split_key(key)[0]]
        raise RulePackError(f"unknown rule id {rule_id!r}")

    def canonical_ids(self, selector: str) -> set[str]:
        """Rule ids a user-written selector names: an id, an alias, a family
        (``INJ``) or a prefix (``AG-INJ-``). Used by suppressions and --rules."""
        sel = selector.strip()
        if not sel:
            return set()
        up = sel.upper()
        if up in self.rules:
            return {up}
        key = self.resolve_key(sel)
        if key is not None:
            return {split_key(key)[0]}
        if up in self.families:
            return set(self.families[up].rule_ids)
        if up.endswith(("-", "*")):
            prefix = up.rstrip("*")
            return {r for r in self.rules if r.startswith(prefix)}
        return set()

    def list_data(self, name: str) -> list[str]:
        value = self.data.get(name, [])
        return list(value) if isinstance(value, list) else []

    # -- loading -----------------------------------------------------------
    @classmethod
    def from_files(cls, files: dict[str, bytes]) -> RulePack:
        """``files`` keys are paths like ``rules/inj.yaml`` or ``mappings/cwe.yaml``."""
        digest = sha256_hex("\n".join(f"{p}\0{sha256_hex(files[p])}" for p in sorted(files)))
        pack_meta: dict[str, Any] = {}
        rules: dict[str, RuleDef] = {}
        families: dict[str, FamilyInfo] = {}
        entries: list[tuple[str, dict[str, Any]]] = []
        data: dict[str, Any] = {}
        frameworks: dict[str, FrameworkCatalog] = {}
        crosswalk: dict[str, dict[str, list[str] | None]] = {}
        yara_sources: dict[str, str] = {}
        rule_mappings: dict[str, dict[str, list[str]]] = {}
        errors: list[str] = []

        for path in sorted(files):
            text = files[path].decode("utf-8")
            if path == "rules/pack.yaml":
                pack_meta = _yaml(path, text)
            elif path.startswith("rules/data/"):
                name = path.rsplit("/", 1)[1].rsplit(".", 1)[0]
                if path.endswith(".txt"):
                    data[name] = [
                        ln.strip() for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")
                    ]
                elif path.endswith((".yaml", ".yml")):
                    data[name] = _yaml(path, text)
                elif path.endswith(".json"):
                    try:
                        data[name] = json.loads(text)
                    except ValueError as exc:
                        errors.append(f"{path}: not valid JSON ({exc})")
            elif path.startswith("rules/yara/") and path.endswith(".yar"):
                yara_sources[path] = text
            elif path.startswith("rules/catalog/") and path.endswith((".yaml", ".yml")):
                _load_family(path, _yaml(path, text) or {}, rules, families, rule_mappings, errors)
            elif path.startswith("rules/") and path.endswith((".yaml", ".yml")):
                doc = _yaml(path, text)
                for raw in (doc or {}).get("rules", []):
                    entries.append((path, raw))
            elif path == "mappings/crosswalk.yaml":
                crosswalk = _yaml(path, text) or {}
            elif path.startswith("mappings/") and path.endswith((".yaml", ".yml")):
                doc = _yaml(path, text) or {}
                fw = doc.get("framework")
                if fw not in FRAMEWORKS:
                    errors.append(f"{path}: unknown framework {fw!r}")
                    continue
                frameworks[fw] = FrameworkCatalog(
                    framework=fw,
                    name=doc.get("name", fw),
                    version=str(doc.get("version", "")),
                    source=doc.get("source", ""),
                    items={str(i["id"]): i.get("title", "") for i in doc.get("items") or []},
                    notes=doc.get("notes", ""),
                )

        _apply_entries(entries, rules, errors)

        for rule in rules.values():
            for m in [rule.match, *(v.match for v in rule.variants)]:
                if isinstance(m, YaraMatch) and m.rule_file not in yara_sources:
                    errors.append(f"{rule.id}: YARA rule file {m.rule_file} not found in rules/yara/")

        # Standards: the family default, overridden per framework by the rule's
        # catalogue row and then by mappings/crosswalk.yaml (data, not code).
        for rule_id, rule in rules.items():
            fam = families.get(rule.family)
            merged: dict[str, list[str] | None] = {fw: list(ids) for fw, ids in (fam.mappings if fam else {}).items()}
            merged.update(rule_mappings.get(rule_id, {}))
            for fw, ids in (crosswalk.get(rule_id) or {}).items():
                merged[fw] = ids
            mappings: list[Mapping] = []
            for fw in FRAMEWORKS:
                if fw not in merged:
                    continue
                ids = merged[fw]
                if ids is None:
                    todo = NSA_TODO if fw == "nsa-csi-mcp-2026-05" else "mapping not yet reviewed"
                    mappings.append(Mapping(framework=fw, id=None, todo=todo))
                    continue
                catalog = frameworks.get(fw)
                for mid in ids:
                    mid = str(mid)
                    if catalog is not None and catalog.items and mid not in catalog.items:
                        errors.append(f"mappings: {rule_id} maps to unknown {fw} id {mid}")
                    title = catalog.items.get(mid) if catalog else None
                    mappings.append(Mapping(framework=fw, id=mid, title=title or None))
            for fw in merged:
                if fw not in FRAMEWORKS:
                    errors.append(f"mappings: {rule_id} names unknown framework {fw!r}")
            rule.mappings = mappings

        detectors: dict[str, Detector] = {}
        aliases: dict[str, str] = {}
        for rule in rules.values():
            found: list[Detector] = []
            if rule.match is not None:
                found.append(resolve(rule))
            for v in rule.variants:
                if v.match is None:
                    errors.append(f"{rule.id}/{v.key}: variant has no match")
                    continue
                found.append(resolve(rule, v))
            for det in found:
                detectors[det.key] = det
                for alias in det.aliases:
                    if alias in rules:
                        errors.append(f"{det.key}: alias {alias} is the id of a catalogue rule")
                    elif alias in aliases:
                        errors.append(f"{det.key}: alias {alias} already names {aliases[alias]}")
                    elif not regex.fullmatch(LEGACY_ID_RE, alias):
                        errors.append(f"{det.key}: alias {alias!r} is not a rule id")
                    else:
                        aliases[alias] = det.key
            if rule.implemented and not found:
                errors.append(f"{rule.id}: has a detection entry but no match")

        if errors:
            raise RulePackError("invalid rule pack:\n  " + "\n  ".join(errors))
        return cls(
            version=str(pack_meta.get("version", "0.0.0")),
            min_engine=str(pack_meta.get("min_engine", "0.1.0")),
            digest=digest,
            rules=dict(sorted(rules.items())),
            data=data,
            frameworks=frameworks,
            crosswalk=crosswalk,
            detectors=dict(sorted(detectors.items())),
            aliases=dict(sorted(aliases.items())),
            families=families,
            yara_sources=yara_sources,
        )

    @classmethod
    def load_dirs(cls, rules_dir: Path, mappings_dir: Path) -> RulePack:
        files: dict[str, bytes] = {}
        for base, prefix in ((rules_dir, "rules"), (mappings_dir, "mappings")):
            for root, _dirs, names in os.walk(base):
                for name in names:
                    if name.startswith("."):
                        continue
                    full = Path(root) / name
                    rel = full.relative_to(base).as_posix()
                    files[f"{prefix}/{rel}"] = full.read_bytes()
        return cls.from_files(files)

    @classmethod
    def default(cls) -> RulePack:
        global _DEFAULT
        if _DEFAULT is None:
            rules_dir, mappings_dir = data_dirs()
            _DEFAULT = cls.load_dirs(rules_dir, mappings_dir)
        return _DEFAULT


def _load_family(path: str, doc: dict[str, Any], rules: dict[str, RuleDef], families: dict[str, FamilyInfo],
                 rule_mappings: dict[str, dict[str, list[str]]], errors: list[str]) -> None:
    family = str(doc.get("family") or "")
    if family not in FAMILIES and family not in SYSTEM_FAMILIES:
        errors.append(f"{path}: unknown family {family!r}")
        return
    if family in families:
        errors.append(f"{path}: family {family} defined twice")
        return
    defaults = dict(doc.get("defaults") or {})
    info = FamilyInfo(family=family, name=str(doc.get("name") or family), about=str(doc.get("about") or ""),
                      mappings={fw: [str(i) for i in ids] for fw, ids in (doc.get("mappings") or {}).items()})
    families[family] = info
    # A family file lists rules directly, in named groups (each with its own
    # defaults and mappings on top of the family's), or both.
    rows: list[tuple[Any, dict[str, Any], dict[str, Any]]] = [(row, {}, {}) for row in doc.get("rules") or []]
    for group in doc.get("groups") or []:
        rows += [(row, dict(group.get("defaults") or {}), dict(group.get("mappings") or {}))
                 for row in group.get("rules") or []]
    for row, group_defaults, group_mappings in rows:
        if not isinstance(row, list) or len(row) not in (4, 5):
            errors.append(f"{path}: catalogue row must be [id, severity, fix, title, {{overrides}}]: {row!r}")
            continue
        rule_id, sev, fix, title = (str(x) for x in row[:4])
        over = dict(row[4]) if len(row) == 5 else {}
        if not regex.fullmatch(RULE_ID_RE, rule_id) or rule_id.split("-")[1] != family:
            errors.append(f"{path}: {rule_id} is not an {family} rule id")
            continue
        if rule_id in rules:
            errors.append(f"{path}: duplicate rule id {rule_id}")
            continue
        own = {**group_mappings, **over.pop("mappings", {})}
        if own:
            rule_mappings[rule_id] = {fw: [str(i) for i in ids] for fw, ids in own.items()}
        fields: dict[str, Any] = {**defaults, **group_defaults, **over}
        if sev == "var":
            fields["severity_from_content"] = True
        try:
            rules[rule_id] = RuleDef(
                id=rule_id, title=title, family=family,
                severity=Severity(_SEV.get(sev, sev)), fix=FixKind(_FIX.get(fix, fix)), **fields,
            )
        except (ValidationError, ValueError) as exc:
            errors.append(f"{path}: {rule_id}: {_first_error(exc)}")
            continue
        info.rule_ids.append(rule_id)


def _apply_entries(entries: list[tuple[str, dict[str, Any]]], rules: dict[str, RuleDef], errors: list[str]) -> None:
    heads: set[str] = set()
    for path, raw in entries:
        if not isinstance(raw, dict) or "id" not in raw:
            errors.append(f"{path}: detection entry without an id")
            continue
        rule = rules.get(str(raw["id"]))
        if rule is None:
            errors.append(f"{path}: {raw['id']} is not in the catalogue")
            continue
        fields = {k: v for k, v in raw.items() if k != "id"}
        status = fields.pop("status", None) if "variant" in fields else None
        try:
            if "variant" in fields:
                fields["key"] = fields.pop("variant")
                variant = RuleVariant.model_validate(fields)
                if rule.variant(variant.key) is not None:
                    errors.append(f"{path}: duplicate variant {rule.id}/{variant.key}")
                    continue
                rule.variants.append(variant)
                if rule.status == RuleStatus.planned:
                    rule.status = RuleStatus(status) if status else RuleStatus.experimental
                continue
            unknown = set(fields) - _HEAD_ENTRY_FIELDS
            if unknown:
                errors.append(f"{path}: {rule.id}: {sorted(unknown)} belong to the catalogue or a variant, not a detection entry")
                continue
            if rule.id in heads:
                errors.append(f"{path}: {rule.id} has two detection entries (use a variant)")
                continue
            heads.add(rule.id)
            fields.setdefault("status", "experimental")
            merged = RuleDef.model_validate({**rule.model_dump(exclude={"variants", "mappings"}), **fields})
            merged.variants = rule.variants
            rules[rule.id] = merged
        except (ValidationError, ValueError) as exc:
            errors.append(f"{path}: {raw.get('id', '?')}{'/' + str(raw.get('variant')) if raw.get('variant') else ''}: {_first_error(exc)}")


def _first_error(exc: Exception) -> str:
    if isinstance(exc, ValidationError):
        err = exc.errors()[0]
        return f"{err['msg']} at {err['loc']}"
    return str(exc)


_DEFAULT: RulePack | None = None
_STRICT = False


def strict_pack_check(rules_dir: Path, mappings_dir: Path) -> RulePack:
    """Load the pack with the hardened YAML loader (no aliases/tags, duplicate
    keys rejected). Used by CI so the fast runtime path loads vetted files."""
    global _STRICT
    _STRICT = True
    try:
        return RulePack.load_dirs(rules_dir, mappings_dir)
    finally:
        _STRICT = False


_ACTIVE_DIRS: tuple[Path, Path] | None = None


def use_dirs(rules_dir: Path | None, mappings_dir: Path | None = None) -> None:
    """Make another rule pack directory the default one (the host does this for a rule pack installed
    by `agentguard update`, after verifying its signature). ``None`` goes back to the bundled pack."""
    global _ACTIVE_DIRS, _DEFAULT
    new = (Path(rules_dir), Path(mappings_dir)) if rules_dir is not None and mappings_dir is not None else None
    if new != _ACTIVE_DIRS:
        _ACTIVE_DIRS, _DEFAULT = new, None


def data_dirs() -> tuple[Path, Path]:
    """The rule pack in use: one installed by a verified update, else the bundled one."""
    return _ACTIVE_DIRS if _ACTIVE_DIRS is not None else bundled_dirs()


def bundled_dirs() -> tuple[Path, Path]:
    """Locate the bundled rule pack (wheel) or the repo checkout (dev). Trusted keys, the sample feed and
    the fixtures are always looked up beside this one, never beside an installed update."""
    pkg = Path(__file__).resolve().parents[2]  # .../agentguard
    bundled = pkg / "_data"
    if (bundled / "rules" / "pack.yaml").exists():
        return bundled / "rules", bundled / "mappings"
    repo = pkg.parents[1]  # src/agentguard -> repo root
    if (repo / "rules" / "pack.yaml").exists():
        return repo / "rules", repo / "mappings"
    raise RulePackError("rule pack not found (expected agentguard/_data/rules or ./rules)")


def _yaml(path: str, text: str) -> Any:
    """Load rule-pack YAML. The pack ships with Agent Guard (it is not scanned
    input), so at run time the fast C safe loader is used when available; CI
    validates the same files with the hardened loader (``strict_pack_check``)."""
    if not _STRICT:
        try:
            import yaml

            loader = getattr(yaml, "CSafeLoader", None)
            if loader is not None:
                return yaml.load(text, Loader=loader)  # noqa: S506 - safe loader
        except Exception as exc:  # noqa: BLE001
            raise RulePackError(f"{path}: YAML error: {str(exc).splitlines()[0][:200]}") from exc
    res = safe_load(text, max_nodes=500_000)
    if res.error:
        raise RulePackError(f"{path}: {res.error}")
    if res.duplicate_keys:
        raise RulePackError(f"{path}: duplicate keys {res.duplicate_keys[:3]}")
    return res.value
