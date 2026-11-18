"""`--machine`: a read-only walk of each agent's known locations
(spec/ecosystems.md §11). Files are read, never modified. Paths in the tree
are virtual (``~/…``, ``@system/…``), so a report never carries a user name."""

from __future__ import annotations

from pathlib import Path

from ..io.discovery import discover
from . import AcquireContext, Acquired
from .targets import Target


def acquire_machine(target: Target, ctx: AcquireContext) -> Acquired:
    home = ctx.home or user_home()
    projects = recorded_projects(home) if ctx.include_user else []
    disc = discover(ctx.cwd, include_user=ctx.include_user, limits=ctx.limits, home=home, extra_projects=projects)
    found = sum(1 for r in disc.records if r.exists)
    notes = [f"checked {len(disc.records)} known agent locations; {found} exist on this machine"]
    if projects:
        notes.append(f"{len(projects)} project director{'y' if len(projects) == 1 else 'ies'} recorded in agent state "
                     "were scanned as well")
    return Acquired(target=target, tree=disc.tree, notes=notes)


MAX_RECORDED_PROJECTS = 200


def recorded_projects(home: Path) -> list[Path]:
    """Project directories the agents themselves remember (spec/ecosystems.md §11):
    the ``projects`` map of ``~/.claude.json``, the ``projects`` table of
    ``~/.codex/config.toml`` and ``~/.gemini/trustedFolders.json``. The state
    files are read, never modified; a path that no longer exists is dropped."""
    import json
    import os

    from ..core.parsers import parse_toml

    found: list[str] = []

    def read(path: Path) -> str:
        try:
            if path.is_file() and path.stat().st_size <= 8 * 1024 * 1024:
                return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            pass
        return ""

    text = read(home / ".claude.json")
    if text:
        try:
            data = json.loads(text)
        except ValueError:
            data = {}
        if isinstance(data, dict) and isinstance(data.get("projects"), dict):
            found += [str(k) for k in data["projects"]]
    codex = Path(os.environ["CODEX_HOME"]) if os.environ.get("CODEX_HOME") else home / ".codex"
    text = read(codex / "config.toml")
    if text:
        value = parse_toml(text).value
        if isinstance(value, dict) and isinstance(value.get("projects"), dict):
            found += [str(k) for k in value["projects"]]
    text = read(home / ".gemini" / "trustedFolders.json")
    if text:
        try:
            data = json.loads(text)
        except ValueError:
            data = {}
        if isinstance(data, dict):
            found += [str(k) for k, v in data.items() if not isinstance(v, str) or v.upper() != "DO_NOT_TRUST"]
    out: list[Path] = []
    seen: set[str] = set()
    for raw in found:
        p = Path(raw).expanduser()
        key = os.path.normcase(str(p))
        if key in seen or not p.is_absolute():
            continue
        seen.add(key)
        try:
            if p.is_dir():
                out.append(p)
        except OSError:
            continue
        if len(out) >= MAX_RECORDED_PROJECTS:
            break
    return out


def user_home() -> Path:
    """The home directory agent files are looked up in. ``AGENTGUARD_USER_HOME``
    overrides it (tests, containers that mount another user's files)."""
    import os

    override = os.environ.get("AGENTGUARD_USER_HOME")
    return Path(override) if override else Path.home()
