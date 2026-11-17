"""Loading .agentguard.yaml, policy files and baselines (host side).

Configuration is read from the directory the user runs from, then from the
user's own config directory, then built-in defaults. A config file inside a
scanned third-party target is never honoured: content under review must not
be able to configure the scanner (spec/interfaces.md §4).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from pydantic import ValidationError

from ..core.models import Lockfile, Policy, ProjectConfig
from ..core.models.config import POLICY_PRESETS
from ..core.parsers.safe_yaml import safe_load

CONFIG_NAMES = (".agentguard.yaml", ".agentguard.yml", "agentguard.yml", "agentguard.yaml")
LOCK_NAME = "agentguard.lock"


class ConfigError(ValueError):
    pass


def parse_project_config(text: str, origin: str) -> ProjectConfig:
    res = safe_load(text)
    if res.error:
        raise ConfigError(f"{origin}: {res.error}")
    try:
        return ProjectConfig.model_validate(res.value or {})
    except ValidationError as exc:
        raise ConfigError(f"{origin}: {exc.errors()[0]['msg']} at {'.'.join(map(str, exc.errors()[0]['loc']))}") from exc


def find_project_config(root: Path) -> Path | None:
    base = root if root.is_dir() else root.parent
    for name in CONFIG_NAMES:
        if (base / name).is_file():
            return base / name
    return None


def user_config_dir() -> Path:
    override = os.environ.get("AGENTGUARD_CONFIG_HOME")
    if override:
        return Path(override)
    if sys.platform == "win32":
        return Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming") / "agentguard"
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "agentguard"


def load_user_level_config() -> tuple[ProjectConfig | None, Path | None]:
    for name in ("config.yml", "config.yaml"):
        candidate = user_config_dir() / name
        if candidate.is_file():
            return parse_project_config(candidate.read_text(encoding="utf-8"), str(candidate)), candidate
    return None, None


def load_user_config(cwd: Path, explicit: Path | None = None) -> tuple[ProjectConfig | None, Path | None]:
    """The configuration in force: ``--config``, else the one in the directory
    the user runs from, else the user-level one. Never one from a scan target."""
    if explicit is not None:
        if not explicit.is_file():
            raise ConfigError(f"config file not found: {explicit}")
        return parse_project_config(explicit.read_text(encoding="utf-8"), str(explicit)), explicit
    found = find_project_config(cwd)
    if found is None:
        return load_user_level_config()
    return parse_project_config(found.read_text(encoding="utf-8"), str(found)), found


def load_policy(path: Path) -> Policy:
    res = safe_load(path.read_text(encoding="utf-8"))
    if res.error:
        raise ConfigError(f"{path}: {res.error}")
    try:
        return Policy.model_validate(res.value or {})
    except ValidationError as exc:
        raise ConfigError(f"{path}: {exc.errors()[0]['msg']} at {'.'.join(map(str, exc.errors()[0]['loc']))}") from exc


def resolve_policy(value: str | None, pconf: ProjectConfig | None, cwd: Path) -> Policy:
    """``--policy`` is a preset name or a file; without it, the configured policy, else ``balanced``."""
    if value:
        if value in POLICY_PRESETS:
            return Policy.preset(value)
        path = Path(value) if Path(value).is_absolute() else cwd / value
        if not path.is_file():
            raise ConfigError(f"--policy: {value!r} is neither a preset (strict, balanced, permissive) nor a file")
        return load_policy(path)
    configured = pconf.resolved_policy() if pconf is not None else None
    return configured or Policy.preset("balanced")


def load_baseline(path: Path) -> tuple[Lockfile | None, set[str] | None]:
    """``--baseline``: a lockfile (what was approved), a previous JSON report,
    or ``{"fingerprints": [...]}``. Returns (lock, fingerprints to treat as known)."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"{path}: cannot read baseline: {exc}") from exc
    return parse_baseline(text, str(path))


def parse_baseline(text: str, origin: str) -> tuple[Lockfile | None, set[str] | None]:
    """``load_baseline`` for text already read (``origin`` names it in errors), such as the
    lockfile at a pull request's base commit."""
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ConfigError(f"{origin}: cannot read baseline: {exc}") from exc
    if isinstance(data, dict) and ("lock_version" in data or "artifacts" in data and "findings" not in data or "entries" in data):
        try:
            lock = Lockfile.model_validate(data)
        except ValidationError as exc:
            raise ConfigError(f"{origin}: not a valid lockfile: {exc.errors()[0]['msg']}") from exc
        accepted = {fp for e in lock.artifacts for fp in e.accepted_findings}
        return lock, accepted or None
    if isinstance(data, dict) and isinstance(data.get("fingerprints"), list):
        return None, {str(x) for x in data["fingerprints"]}
    if isinstance(data, dict) and isinstance(data.get("findings"), list):
        return None, {str(f.get("fingerprint")) for f in data["findings"] if isinstance(f, dict) and f.get("fingerprint")}
    raise ConfigError(f"{origin}: not a lockfile, a baseline or an Agent Guard report")
