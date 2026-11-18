"""`agentguard install`: the install gate (spec/interfaces.md §13).

    1. fetch the source to quarantine (memory) at a pinned identifier;
    2. scan it with the installed context;
    3. print the install receipt: every file that would be written, every
       setting, hook, MCP entry or instruction file that would change, and the
       verdict. Nothing has been written at this point;
    4. on ALLOW (or REVIEW with --accept) copy the *scanned* bytes into place
       and update agentguard.lock.

The bytes that are installed are the bytes that were scanned: nothing is
fetched a second time, and nothing from the source is ever executed.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from .core.engine import scan as core_scan
from .core.lock import build_lock, dump_lock, load_lock
from .core.models import ScanOptions
from .core.models.enums import ComponentKind, Severity
from .core.report.agent_safe import clean
from .core.textutil import sha256_hex
from .core.tree import ArtifactTree
from .runner import ScanOutcome, ScanRequest, UsageError, run_scan

__all__ = ["AGENTS", "InstallPlan", "Installed", "perform_install", "plan_install", "render_receipt"]

LOCK_NAME = "agentguard.lock"

# Where each agent keeps what, relative to the install root (the project directory, or the user's home).
# `mcp` is (file, key holding the servers, format). Locations are the ones in io/discovery/locations.py.
AGENTS: dict[str, dict[str, dict[str, Any]]] = {
    "claude-code": {
        "project": {"skills": ".claude/skills", "agents": ".claude/agents", "commands": ".claude/commands",
                    "plugins": ".claude/plugins", "rules": ".claude/rules", "mcp": (".mcp.json", "mcpServers", "json")},
        "user": {"skills": ".claude/skills", "agents": ".claude/agents", "commands": ".claude/commands",
                 "plugins": ".claude/plugins/local", "rules": ".claude/rules", "mcp": (".claude.json", "mcpServers", "json")},
    },
    "codex": {
        "project": {"skills": ".agents/skills", "agents": ".codex/agents", "plugins": ".codex/plugins",
                    "mcp": (".codex/config.toml", "mcp_servers", "toml")},
        "user": {"skills": ".agents/skills", "agents": ".codex/agents", "commands": ".codex/prompts", "plugins": ".codex/plugins",
                 "mcp": (".codex/config.toml", "mcp_servers", "toml")},
    },
    "cursor": {
        "project": {"skills": ".cursor/skills", "agents": ".cursor/agents", "commands": ".cursor/commands",
                    "rules": ".cursor/rules", "plugins": ".cursor/plugins", "mcp": (".cursor/mcp.json", "mcpServers", "json")},
        "user": {"skills": ".cursor/skills", "agents": ".cursor/agents", "plugins": ".cursor/plugins",
                 "mcp": (".cursor/mcp.json", "mcpServers", "json")},
    },
    "gemini": {
        "project": {"skills": ".gemini/skills", "commands": ".gemini/commands", "plugins": ".gemini/extensions",
                    "mcp": (".gemini/settings.json", "mcpServers", "json")},
        "user": {"skills": ".gemini/skills", "commands": ".gemini/commands", "plugins": ".gemini/extensions",
                 "mcp": (".gemini/settings.json", "mcpServers", "json")},
    },
    "copilot": {
        "project": {"skills": ".github/skills", "agents": ".github/agents", "rules": ".github/instructions",
                    "mcp": (".vscode/mcp.json", "servers", "json")},
        "user": {"skills": ".copilot/skills", "agents": ".copilot/agents", "rules": ".copilot/instructions",
                 "mcp": (".copilot/mcp-config.json", "mcpServers", "json")},
    },
    "openclaw": {
        "project": {"skills": "skills", "plugins": ".openclaw/extensions"},
        "user": {"skills": ".openclaw/skills", "plugins": ".openclaw/extensions"},
    },
}
_ALIASES = {"claude": "claude-code", "gemini-cli": "gemini", "vscode": "copilot", "github-copilot": "copilot"}
_SERVER_KEYS = ("mcpServers", "servers", "mcp_servers", "context_servers")
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")
_ACTIVATES = {ComponentKind.hook: "hook", ComponentKind.settings: "setting", ComponentKind.mcp_server: "mcp-server",
              ComponentKind.instruction_file: "instruction-file", ComponentKind.command: "command",
              ComponentKind.subagent: "agent", ComponentKind.skill: "skill"}


@dataclass
class Write:
    dest: str               # relative to the install root
    source: str             # path in the scanned tree
    size: int
    sha256: str
    state: str = "new"      # new | replace | unchanged


@dataclass
class Change:
    kind: str               # skill | plugin | agent | command | instruction-file | mcp-entry | hook | setting | mcp-server
    target: str             # the file that changes or the component that becomes active
    detail: str = ""


@dataclass
class Merge:
    file: str               # relative to the install root
    key: str
    fmt: str                # json | toml
    name: str
    entry: dict[str, Any]
    state: str = "new"      # new | replace


@dataclass
class InstallPlan:
    outcome: ScanOutcome
    agent: str
    scope: str
    root: Path
    source: str
    writes: list[Write] = field(default_factory=list)
    changes: list[Change] = field(default_factory=list)
    merges: list[Merge] = field(default_factory=list)
    not_installed: list[str] = field(default_factory=list)
    tree: ArtifactTree | None = field(default=None, repr=False)
    cwd: Path = field(default_factory=Path.cwd)

    @property
    def pinned(self) -> str:
        t = self.outcome.report.target
        return t.commit or t.tree_sha256 or ""

    def to_dict(self) -> dict[str, Any]:
        """The receipt for a machine or an agent: no text from the source beyond cleaned names and paths."""
        rep = self.outcome.report
        return {
            "source": clean(self.source, 200),
            "pinned": clean(self.pinned, 80),
            "agent": self.agent, "scope": self.scope, "install_root": str(self.root),
            "verdict": rep.verdict.value, "score": rep.score, "risk_tier": rep.risk_tier.value,
            "coverage": {"files_total": rep.coverage.files_total, "files_analysed": rep.coverage.files_analysed,
                         "analyzability": rep.coverage.analyzability},
            "findings": [{"id": f.id, "severity": f.severity.value, "title": f.title,
                          "file": clean(f.location.file, 200) if f.location else "",
                          "line": f.location.start.line if f.location else 0, "fix": f.fix.summary}
                         for f in rep.findings],
            "writes": [{"path": clean(w.dest, 240), "bytes": w.size, "sha256": w.sha256, "state": w.state} for w in self.writes],
            "changes": [{"kind": c.kind, "target": clean(c.target, 240), "detail": clean(c.detail, 120)} for c in self.changes],
            "not_installed": [clean(n, 240) for n in self.not_installed],
            "installable": bool(self.writes or self.merges),
        }


@dataclass
class Installed:
    written: list[Path]
    root: Path
    lock_path: Path


def _safe(name: str) -> str:
    cleaned = _SAFE_NAME.sub("-", name.strip()).strip("-.")
    if not cleaned:
        raise UsageError(f"cannot install a component with the name {name!r}")
    return cleaned[:80]


def _install_root(scope: str, dest: Path | None, cwd: Path) -> Path:
    if dest is not None:
        return dest if dest.is_absolute() else cwd / dest
    if scope == "user":
        from .acquire.machine import user_home

        return user_home()
    return cwd


def _raw_server_entry(tree: ArtifactTree, config_path: str, name: str) -> dict[str, Any] | None:
    blob = tree.files.get(config_path)
    if blob is None:
        return None
    try:
        data = json.loads(blob.data.decode("utf-8-sig"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    for key in _SERVER_KEYS:
        servers = data.get(key)
        if isinstance(servers, dict) and isinstance(servers.get(name), dict):
            return servers[name]
    return None


def plan_install(req: ScanRequest, *, agent: str = "claude-code", scope: str = "project", dest: Path | None = None) -> InstallPlan:
    """Fetch, scan and work out what an install would write. Writes nothing."""
    agent = _ALIASES.get(agent.lower(), agent.lower())
    if agent not in AGENTS:
        raise UsageError(f"--agent: unknown agent {agent!r} (choose from {', '.join(AGENTS)})")
    if scope not in ("project", "user"):
        raise UsageError("--scope must be project or user")
    if len(req.targets) != 1:
        raise UsageError("install takes exactly one source")
    layout = AGENTS[agent][scope]
    root = _install_root(scope, dest, req.cwd)
    outcome = run_scan(req)
    tree, report = outcome.tree, outcome.report
    plan = InstallPlan(outcome=outcome, agent=agent, scope=scope, root=root, source=req.targets[0], tree=tree, cwd=req.cwd)
    comps = sorted(report.inventory, key=lambda c: (len(c.root), c.root, c.kind.value, c.name))
    files_of: dict[str, list[str]] = {}
    for art in report.files:
        files_of.setdefault(art.component_id, []).append(art.path)
    taken: list[str] = []          # tree roots already placed (a plugin carries its skills with it)
    used: dict[str, str] = {}      # tree path -> destination

    def inside(path: str) -> bool:
        return any(path == r or path.startswith(r + "/") or r == "" for r in taken)

    def place(tree_root: str, dest_dir: str, kind: str, name: str) -> None:
        prefix = tree_root + "/" if tree_root else ""
        paths = [p for p in tree.paths() if (p.startswith(prefix) if prefix else True) and "!/" not in p]
        if not paths:
            return
        for p in paths:
            rel = p[len(prefix):]
            used[p] = f"{dest_dir}/{rel}"
        taken.append(tree_root)
        plan.changes.append(Change(kind, dest_dir, name))

    # Plugins first (they contain skills, agents, hooks and servers), then stand-alone components.
    for comp in comps:
        if comp.kind == ComponentKind.plugin and "plugins" in layout and not inside(comp.root):
            place(comp.root, f"{layout['plugins']}/{_safe(comp.name)}", "plugin", comp.name)
    for comp in comps:
        if comp.kind == ComponentKind.plugin and "plugins" not in layout:
            plan.not_installed.append(f"plugin {comp.name}: {agent} has no plugin directory at {scope} scope")
        elif comp.kind == ComponentKind.skill and not inside(comp.root):
            if "skills" not in layout:
                plan.not_installed.append(f"skill {comp.name}: {agent} has no skills directory at {scope} scope")
                continue
            place(comp.root, f"{layout['skills']}/{_safe(comp.name)}", "skill", comp.name)
    for comp in comps:
        own = sorted(files_of.get(comp.id, []))
        if comp.kind in (ComponentKind.subagent, ComponentKind.command, ComponentKind.instruction_file) and own \
                and not any(inside(p) for p in own):
            slot = {ComponentKind.subagent: "agents", ComponentKind.command: "commands", ComponentKind.instruction_file: "rules"}[comp.kind]
            label = _ACTIVATES[comp.kind]
            if slot not in layout:
                plan.not_installed.append(f"{label} {comp.name}: {agent} has no {slot} directory at {scope} scope; add it by hand")
                continue
            for p in own:
                if "!/" in p:
                    continue
                used[p] = f"{layout[slot]}/{_safe(p.rsplit('/', 1)[-1])}"
                plan.changes.append(Change(label, used[p], comp.name if label != "instruction-file"
                                           else "loaded into every session"))
        elif comp.kind == ComponentKind.mcp_server and comp.server is not None and not inside(comp.server.config_path):
            entry = _raw_server_entry(tree, comp.server.config_path, comp.name)
            if entry is None or "mcp" not in layout:
                why = f"{agent} keeps no MCP file at {scope} scope" if "mcp" not in layout else "its configuration is not a JSON server entry"
                plan.not_installed.append(f"MCP server {comp.name}: {why}; add it by hand")
                continue
            file, key, fmt = layout["mcp"]
            plan.merges.append(Merge(file=file, key=key, fmt=fmt, name=comp.name, entry=entry))
    # What becomes active because it sits inside something that is installed.
    for comp in comps:
        label = _ACTIVATES.get(comp.kind)
        if label in ("hook", "setting", "mcp-server", "instruction-file") and comp.root is not None:
            anchor = comp.server.config_path if comp.server is not None else (sorted(files_of.get(comp.id, [])) or [comp.root])[0]
            if anchor in used:
                plan.changes.append(Change(label, used[anchor], f"{comp.name} (active once installed)"))

    for src in sorted(used):
        blob = tree.files[src]
        target = _resolve_inside(root, used[src])
        state = "new"
        if target.exists():
            try:
                state = "unchanged" if target.is_file() and sha256_hex(target.read_bytes()) == blob.sha256 else "replace"
            except OSError:
                state = "replace"
        plan.writes.append(Write(dest=used[src], source=src, size=blob.size, sha256=blob.sha256, state=state))
    for m in plan.merges:
        target = _resolve_inside(root, m.file)
        existing = _read_servers(target, m.key, m.fmt) if target.is_file() else {}
        m.state = "replace" if m.name in existing else "new"
        plan.changes.append(Change("mcp-entry", m.file, f"{m.name} ({'replaces the existing entry' if m.state == 'replace' else 'new entry'})"))
    plan.changes.sort(key=lambda c: (c.kind, c.target, c.detail))
    return plan


def _resolve_inside(root: Path, rel: str) -> Path:
    target = root / rel
    base = root.resolve()
    resolved = target.resolve()
    if resolved != base and not resolved.is_relative_to(base):
        raise UsageError(f"refusing to write outside the install root: {rel}")
    return target


def _read_servers(path: Path, key: str, fmt: str) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise UsageError(f"cannot read {path}: {type(exc).__name__}") from exc
    if fmt == "toml":
        import tomllib

        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError as exc:
            raise UsageError(f"{path} is not valid TOML; fix it before installing into it") from exc
    else:
        from .core.parsers.json5 import parse_json5

        try:
            data = json.loads(text) if text.strip() else {}
        except ValueError:
            parsed = parse_json5(text)
            if parsed.error is not None:
                raise UsageError(f"{path} is not valid JSON; fix it before installing into it") from None
            data = parsed.value
    servers = data.get(key) if isinstance(data, dict) else None
    return servers if isinstance(servers, dict) else {}


def _toml_value(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, list):
        return "[" + ", ".join(_toml_value(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{ " + ", ".join(f"{json.dumps(str(k))} = {_toml_value(x)}" for k, x in v.items()) + " }"
    return json.dumps(str(v), ensure_ascii=False)


def _apply_merge(root: Path, m: Merge) -> Path:
    target = _resolve_inside(root, m.file)
    target.parent.mkdir(parents=True, exist_ok=True)
    if m.fmt == "toml":
        if target.is_file() and m.name in _read_servers(target, m.key, m.fmt):
            raise UsageError(f"{m.file} already has a server named {m.name!r}; remove it first (TOML entries are not rewritten)")
        name = m.name if re.fullmatch(r"[A-Za-z0-9_-]+", m.name) else json.dumps(m.name)
        block = [f"[{m.key}.{name}]"] + [f"{k} = {_toml_value(v)}" for k, v in m.entry.items() if v is not None]
        old = target.read_text(encoding="utf-8") if target.is_file() else ""
        sep = "" if not old or old.endswith("\n\n") else ("\n" if old.endswith("\n") else "\n\n")
        target.write_bytes((old + sep + "\n".join(block) + "\n").encode("utf-8"))
        return target
    data: dict[str, Any] = {}
    if target.is_file():
        text = target.read_text(encoding="utf-8-sig")
        if text.strip():
            try:
                data = json.loads(text)
            except ValueError as exc:
                raise UsageError(f"{target} holds comments or is not strict JSON; add the server entry by hand") from exc
        if not isinstance(data, dict):
            raise UsageError(f"{target} is not a JSON object")
    servers = data.setdefault(m.key, {})
    if not isinstance(servers, dict):
        raise UsageError(f"{target}: {m.key} is not an object")
    servers[m.name] = m.entry
    target.write_bytes((json.dumps(data, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))
    return target


def perform_install(plan: InstallPlan, *, approved_by: str = "") -> Installed:
    """Copy the scanned bytes into place and record them in agentguard.lock."""
    if plan.tree is None or not (plan.writes or plan.merges):
        raise UsageError("nothing to install: no skill, plugin, agent, command, instruction file or MCP server entry was found "
                         f"in {plan.source}")
    verdict = plan.outcome.report.verdict.value
    if verdict == "BLOCK":
        raise UsageError("a BLOCK verdict is never installed")
    written: list[Path] = []
    installed: dict[str, bytes] = {}
    for w in plan.writes:
        target = _resolve_inside(plan.root, w.dest)
        data = plan.tree.files[w.source].data
        installed[w.dest] = data
        if w.state == "unchanged":
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name(target.name + ".agentguard-tmp")
        tmp.write_bytes(data)
        os.replace(tmp, target)
        written.append(target)
    for m in plan.merges:
        target = _apply_merge(plan.root, m)
        installed[m.file] = target.read_bytes()
        written.append(target)

    # The lock records what is now installed, at the paths it was installed to.
    report = core_scan(ArtifactTree.from_mapping(installed, plan.outcome.options.limits),
                       ScanOptions(policy=plan.outcome.options.policy), plan.outcome.pack)
    report.target = plan.outcome.report.target
    approved_at = dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    fresh = build_lock(report, approved_by=approved_by, approved_at=approved_at, accept_findings=verdict == "REVIEW")
    for e in fresh.artifacts:
        e.source = plan.source
    lock_path = plan.cwd / LOCK_NAME
    if lock_path.is_file():
        try:
            old = load_lock(lock_path.read_text(encoding="utf-8"))
        except ValueError as exc:
            raise UsageError(f"{lock_path} is not a valid lockfile; the files were installed but the lock was not updated") from exc
        keys = {e.key for e in fresh.artifacts}
        fresh.artifacts = sorted([e for e in old.artifacts if e.key not in keys] + fresh.artifacts, key=lambda e: e.key)
    lock_path.write_bytes(dump_lock(fresh).encode("utf-8"))
    return Installed(written=written, root=plan.root, lock_path=lock_path)


def render_receipt(plan: InstallPlan, console: Console) -> None:
    """The install receipt, for a person. Strings from the source are cleaned and escaped."""
    rep = plan.outcome.report
    style = {"ALLOW": "green", "REVIEW": "yellow", "BLOCK": "red"}[rep.verdict.value]
    console.print(f"[bold]Install receipt[/bold]  {escape(clean(plan.source, 200))}")
    if plan.pinned:
        console.print(f"  scanned at   {escape(clean(plan.pinned, 80))}")
    console.print(f"  for          {plan.agent} ({plan.scope}) → {escape(str(plan.root))}")
    console.print(f"  verdict      [bold {style}]{rep.verdict.value}[/bold {style}]  score {rep.score}  tier {rep.risk_tier.value}  "
                  f"coverage {rep.coverage.files_analysed}/{rep.coverage.files_total} files")
    if plan.writes:
        t = Table(title="Files that would be written", title_justify="left")
        for col in ("Path", "Bytes", "State", "SHA-256"):
            t.add_column(col, overflow="fold")
        for w in plan.writes[:200]:
            t.add_row(escape(clean(w.dest, 240)), str(w.size), w.state, w.sha256[:16])
        console.print(t)
        if len(plan.writes) > 200:
            console.print(f"  … and {len(plan.writes) - 200} more file(s)")
    if plan.changes:
        t = Table(title="What would change for the agent", title_justify="left")
        for col in ("Kind", "Where", "What"):
            t.add_column(col, overflow="fold")
        for c in plan.changes:
            t.add_row(c.kind, escape(clean(c.target, 240)), escape(clean(c.detail, 120)))
        console.print(t)
    for note in plan.not_installed:
        console.print(f"  [dim]not installed: {escape(clean(note, 240))}[/dim]")
    if not (plan.writes or plan.merges):
        console.print("  [yellow]Nothing installable was found in the source.[/yellow]")
    shown = [f for f in rep.findings if f.severity.at_least(Severity.low)]
    if shown:
        console.print(f"[bold]{len(rep.findings)} finding(s)[/bold]")
        for f in shown[:15]:
            where = f"{clean(f.location.file, 200)}:{f.location.start.line}" if f.location else ""
            console.print(f"  {f.severity.value.upper():8} {f.key}  {escape(f.title)}  [dim]{escape(where)}[/dim]")
        if len(shown) > 15:
            console.print(f"  … and {len(shown) - 15} more; see `agentguard explain <fingerprint>` or the last report")
    for reason in rep.verdict_reasons[:5]:
        console.print(f"  [dim]why: {escape(clean(reason, 240))}[/dim]")
    console.print("Nothing has been written yet.")
