"""Rule packs beside the built-in one: ``--rule-pack <dir>`` directories and the
packs installed by ``agentguard rules import`` and ``agentguard update``.

An extra pack is detection entries only. Each entry attaches to a rule of the
catalogue (as a variant), so the 450-rule catalogue stays the single list of
what Agent Guard reports, and an imported community rule cannot invent a
severity or a lane the catalogue does not have. Community packs import into
the advisory ``hunt`` lane.

Layout of a pack directory::

    pack.json            {"name", "version", "source", "licence", "sha256", "signed_by"}
    rules/*.yaml         detection entries (``rules:`` list)
    data/*.txt|*.yaml    lists used by analyzers (merged under a pack-specific name)
    yara/*.yar           YARA sources
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .io.intel_store import data_home

_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def packs_home() -> Path:
    return data_home() / "packs"


def pack_name(d: Path) -> str:
    meta = d / "pack.json"
    if meta.is_file():
        try:
            name = json.loads(meta.read_text(encoding="utf-8")).get("name")
            if isinstance(name, str) and name.strip():
                return _SAFE.sub("-", name.strip())[:60]
        except (OSError, ValueError):
            pass
    return _SAFE.sub("-", d.name)[:60] or "pack"


def pack_dir_files(d: Path) -> dict[str, bytes]:
    """The files of one pack directory under the keys ``RulePack.from_files`` expects."""
    name = pack_name(d)
    out: dict[str, bytes] = {}
    rules = d / "rules" if (d / "rules").is_dir() else d
    for p in sorted(rules.glob("*.y*ml")):
        if p.name not in ("pack.yaml", "pack.yml"):
            out[f"rules/ext/{name}/{p.name}"] = p.read_bytes()
    for p in sorted((d / "data").glob("*")) if (d / "data").is_dir() else []:
        if p.suffix in (".txt", ".yaml", ".yml"):
            out[f"rules/data/{name}-{p.name}"] = p.read_bytes()
    for p in sorted((d / "yara").glob("*.yar")) if (d / "yara").is_dir() else []:
        out[f"rules/yara/{name}-{p.name}"] = p.read_bytes()
    return out


def installed_packs() -> list[dict]:
    """Packs under the data directory, with their metadata. Disabled packs are listed, not loaded."""
    home = packs_home()
    out = []
    if not home.is_dir():
        return out
    for d in sorted(p for p in home.iterdir() if p.is_dir()):
        meta: dict = {}
        if (d / "pack.json").is_file():
            try:
                meta = json.loads((d / "pack.json").read_text(encoding="utf-8"))
            except (OSError, ValueError):
                meta = {}
        out.append({"dir": str(d), "name": pack_name(d), "enabled": not (d / "DISABLED").exists(), **{
            k: meta.get(k) for k in ("version", "source", "licence", "sha256", "signed_by", "rules", "imported_at")}})
    return out


def installed_pack_files() -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for pack in installed_packs():
        if pack["enabled"]:
            out.update(pack_dir_files(Path(pack["dir"])))
    return out
