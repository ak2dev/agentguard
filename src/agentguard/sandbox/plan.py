"""What a detonation runs (spec/sandbox.md §6.2 and §6.3): every script, hook command, install step and
local MCP server found statically, each tied to the file and line it came from.

This is direct execution. It does not need an agent, and an agent may decline to run something anyway.
What cannot be run here (an interpreter the image lacks, a server whose package is on a registry the
sandbox cannot reach) is listed as not reached, never silently skipped.
"""

from __future__ import annotations

import io
import json
import os
import re
import shlex
import tarfile
from dataclasses import dataclass, field
from typing import Any

from ..core.analyzers.base import Context
from ..core.analyzers.config_units import ConfigUnitsBuilder
from ..core.inventory import Inventory, build_inventory
from ..core.models import ScanOptions
from ..core.models.enums import ArtifactRole
from ..core.rules.pack import RulePack
from ..core.tree import ArtifactTree
from .honey import PROJECT, Honey

TARGET_DIR = "/work/target"
MAX_ENTRIES = 40
MAX_BLOCKS_PER_FILE = 6
RUNNERS = {".py": ["python3"], ".sh": ["/bin/bash"], ".bash": ["/bin/bash"], ".zsh": ["/bin/bash"], ".js": ["node"], ".mjs": ["node"],
           ".cjs": ["node"]}
NOT_RUNNABLE = {".ps1": "PowerShell is not in the sandbox image", ".psm1": "PowerShell is not in the sandbox image",
                ".bat": "Windows batch files do not run in the Linux sandbox", ".cmd": "Windows batch files do not run in the Linux sandbox",
                ".rb": "Ruby is not in the sandbox image", ".ts": "TypeScript needs a build step that is not run", ".go": "Go is not in the sandbox image",
                ".exe": "Windows programs do not run in the Linux sandbox"}
_FENCE = re.compile(r"(?m)^[ \t]{0,3}(`{3,}|~{3,})[ \t]*([\w+-]*)[^\n]*\n(.*?)^[ \t]{0,3}\1[ \t]*$", re.S)
_SHELL_LANGS = {"", "sh", "bash", "shell", "zsh", "console", "terminal", "shell-session", "bash-session"}
# A block is run when it does something worth watching; `ls` and `git status` examples are left alone.
_ACTIVE = re.compile(r"(?i)\b(?:curl|wget|nc|ncat|bash|sh|zsh|python3?|node|npx|bunx|uvx|pipx?|pip3?|npm|pnpm|yarn|chmod|base64|eval|source|"
                     r"openssl|xxd|crontab|ssh|scp|tar|unzip|dd|rm|mv|cp|tee|echo|printf|cat)\b")
_NETWORK_OR_EXEC = re.compile(r"(?i)\b(?:curl|wget|nc|ncat|base64\s+(?:-d|--decode)|eval|\|\s*(?:ba|z)?sh\b|python3?\s+-c|node\s+-e|crontab|"
                              r"chmod\s+\+x|>>?\s*~?/?\S*(?:rc|profile|authorized_keys|settings\.json|CLAUDE\.md|AGENTS\.md)|\.ssh|\.aws|\.env\b)")
_PLACEHOLDER = re.compile(r"^(?:<[^>]+>|\{[^}]+\}|\[[^\]]+\]|\$\{?[A-Z_]+\}?|path/to/\S+|your[-_]\S+|\S*example\.\w+|FILE|INPUT|PATH)$")
_HOOK_SURFACES = ("claude.", "codex.", "cursor.", "gemini.", "copilot.", "openclaw.", "plugin.", "hooks.", "ws.")


@dataclass
class Plan:
    job: dict[str, Any]
    tar: bytes
    sources: dict[str, tuple[str, int]] = field(default_factory=dict)   # entry id -> (path, line)
    not_reached: dict[str, str] = field(default_factory=dict)           # path -> why
    servers: dict[str, str] = field(default_factory=dict)               # entry id -> server (component) name
    hosts_named: set[str] = field(default_factory=set)


def tar_of(tree: ArtifactTree) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for path in sorted(tree.files):
            if "!/" in path or path.startswith(("/", "..")):
                continue                              # files inside archives are scanned statically, not laid out
            data = tree.files[path].data
            info = tarfile.TarInfo(path)
            info.size, info.mode = len(data), 0o755 if data[:2] == b"#!" else 0o644
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _hosts(inv: Inventory) -> set[str]:
    out: set[str] = set()
    for at in inv.texts.values():
        out.update(h.lower() for h in re.findall(r"(?i)\b(?:[a-z0-9-]+\.)+[a-z]{2,24}\b", at.text[:400_000]))
    return out


def _args_for(script: str, comp_texts: list[tuple[str, str]]) -> list[str]:
    """Arguments the instructions give a script, with placeholders replaced by a real file in the decoy project."""
    base = re.escape(script.rsplit("/", 1)[-1])
    for _path, text in comp_texts:
        m = re.search(rf"(?m)^[ \t$>]*(?:(?:python3?|bash|sh|node|uv run|\./)\s*)?[\w./-]*{base}\b([^\n`|;&]{{0,200}})", text)
        if m and m.group(1).strip():
            try:
                raw = shlex.split(m.group(1).strip())
            except ValueError:
                continue
            return [f"{PROJECT}/README.md" if _PLACEHOLDER.match(a) else a for a in raw][:8]
    return []


def build_plan(tree: ArtifactTree, honey: Honey, options: ScanOptions, pack: RulePack | None = None, *, timeout: int = 900,
               call_tools: bool = True, fuzz: bool = True, vary: bool | None = None, nonce: str = "", marker: str = "") -> Plan:
    inv = build_inventory(tree, options.limits)
    ctx = Context(inventory=inv, pack=pack or RulePack.default(), options=options)
    ConfigUnitsBuilder().run(ctx)
    entries: list[dict[str, Any]] = []
    plan = Plan(job={}, tar=tar_of(tree), hosts_named=_hosts(inv))

    def add(kind: str, path: str, line: int, **fields: Any) -> None:
        if len(entries) >= MAX_ENTRIES:
            plan.not_reached.setdefault(path, f"more than {MAX_ENTRIES} things to run; this one was not run")
            return
        eid = f"e{len(entries) + 1}"
        entries.append({"id": eid, "kind": kind, "source": {"path": path, "line": line}, **fields})
        plan.sources[eid] = (path, line)

    by_comp: dict[str, list[tuple[str, str]]] = {}
    for at in sorted(inv.texts.values(), key=lambda t: t.path):
        if at.artifact.role in (ArtifactRole.skill_md, ArtifactRole.instruction_md, ArtifactRole.reference):
            by_comp.setdefault(at.artifact.component_id, []).append((at.path, at.text.replace("\r\n", "\n")))

    # 1. Scripts a skill, plugin or instruction file ships.
    for path in sorted(inv.artifacts):
        art = inv.artifacts[path]
        if art.role != ArtifactRole.script or "!/" in path:
            continue
        ext = os.path.splitext(path)[1].lower()
        data = tree.files[path].data if path in tree.files else b""
        runner = RUNNERS.get(ext)
        if runner is None and data[:2] == b"#!":
            first = data[:120].split(b"\n", 1)[0].decode("latin-1")
            runner = ["python3"] if "python" in first else ["node"] if "node" in first else ["/bin/bash"] if "sh" in first else None
        if runner is None:
            plan.not_reached[path] = NOT_RUNNABLE.get(ext, "no interpreter in the sandbox image runs this file")
            continue
        add("script", path, 1, argv=[*runner, f"{TARGET_DIR}/{path}", *_args_for(path, by_comp.get(art.component_id, []))],
            cwd=os.path.dirname(path))

    # 2. Commands configuration would run: hooks, lifecycle commands, editor tasks, directory environment files.
    for cmd in ctx.data.get("config_commands", []):                         # type: ignore[union-attr]
        if cmd.role != "config_command" or not cmd.surface.startswith(_HOOK_SURFACES) or not cmd.text.strip():
            continue
        comp = inv.components.get(cmd.component_id)
        root = f"{TARGET_DIR}/{comp.root}".rstrip("/") if comp is not None and comp.root else TARGET_DIR
        payload = {"hook_event_name": cmd.event or "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "ls"}, "cwd": PROJECT,
                   "session_id": "00000000-0000-4000-8000-000000000000"}
        add("command", cmd.path, cmd.span.start_line, shell=cmd.text[:4000], cwd=os.path.dirname(cmd.path), stdin=json.dumps(payload),
            env={"CLAUDE_PLUGIN_ROOT": root, "CLAUDE_PROJECT_DIR": PROJECT, "CURSOR_PROJECT_DIR": PROJECT, "GEMINI_PROJECT_DIR": PROJECT})

    # 3. Install steps and helper commands the instructions tell the reader to run.
    for comp_id in sorted(by_comp):
        for path, text in by_comp[comp_id]:
            taken = 0
            text = text.replace("\r\n", "\n")          # same line numbers; the fence pattern expects bare newlines
            for m in _FENCE.finditer(text):
                lang, body = m.group(2).lower(), m.group(3)
                line = text.count("\n", 0, m.start(3)) + 1
                if lang in ("powershell", "pwsh", "ps1", "bat", "cmd"):
                    if re.search(r"(?i)\b(?:iwr|irm|invoke-|iex|curl|start-process|downloadstring)\b", body):
                        plan.not_reached.setdefault(path, "a PowerShell or batch command block; neither runs in the Linux sandbox")
                    continue
                if lang not in _SHELL_LANGS or len(body) > 4000 or not _NETWORK_OR_EXEC.search(body):
                    continue
                lines = [re.sub(r"^\s*[$>#]\s(?=\S)", "", ln) if ln.lstrip().startswith(("$ ", "> ")) else ln for ln in body.splitlines()]
                script = "\n".join(ln for ln in lines if ln.strip() and not ln.lstrip().startswith("#"))
                if not _ACTIVE.search(script):
                    continue
                if taken >= MAX_BLOCKS_PER_FILE:
                    plan.not_reached.setdefault(path, f"more than {MAX_BLOCKS_PER_FILE} command blocks; the rest were not run")
                    break
                taken += 1
                add("command", path, line, shell=script, cwd=os.path.dirname(path))

    # 4. MCP servers whose program is in the target.
    canary_path = f"{honey.home}/.ssh/id_ed25519"
    canary = next((c for c, label in honey.canaries.items() if label.startswith("SSH private key")), "")
    for comp in sorted(inv.components.values(), key=lambda c: c.id):
        spec = comp.server
        if spec is None or not spec.command:
            continue
        where = spec.config_path or comp.root
        base = os.path.dirname(spec.config_path) if spec.config_path else comp.root
        argv, local = [spec.command], False
        for arg in spec.args:
            rel = os.path.normpath(os.path.join(base, arg)).replace("\\", "/") if not arg.startswith(("-", "/")) else ""
            hit = next((p for p in (rel, arg.lstrip("./")) if p and p in tree.files), None)
            if hit is None:
                var = re.sub(r"\$\{?(?:CLAUDE_PLUGIN_ROOT|__dirname|extensionPath|workspaceFolder)\}?/?", "", arg)
                hit = next((p for p in (os.path.normpath(os.path.join(comp.root, var)).replace("\\", "/"), var) if var != arg and p in tree.files), None)
            local = local or hit is not None
            argv.append(f"{TARGET_DIR}/{hit}" if hit else arg)
        exe = os.path.basename(spec.command).lower()
        if exe in ("python", "py"):
            argv[0] = "python3"
        line = spec.config_span.start_line if spec.config_span else 1
        if not local:
            plan.not_reached[where] = (f"the server `{comp.name}` is started from a package registry or a program outside the target; "
                                       "the sandbox has no network, so it was not started")
            continue
        add("mcp", where, line, argv=argv, cwd=base, timeout=min(180, max(40, timeout // 3)), call_tools=call_tools, fuzz=fuzz,
            canary_path=canary_path, canary=canary[:70])
        plan.servers[entries[-1]["id"]] = comp.name

    scripts = [e for e in entries if e["kind"] == "script"]
    vary = (0 < len(scripts) <= 12) if vary is None else vary
    per_entry = max(10, min(60, timeout // max(1, len(entries) * (3 if vary else 1))))
    for e in entries:
        e.setdefault("timeout", per_entry)
    variants: list[dict[str, Any]] = [{"name": "base"}]
    if vary:
        variants += [{"name": "ci", "env": {"CI": "true", "GITHUB_ACTIONS": "true", "GITHUB_RUN_ID": "8812345678", "RUNNER_OS": "Linux"}},
                     {"name": "later", "faketime": "+200d"}]
    plan.job = {
        "nonce": nonce, "marker": marker, "target_dir": TARGET_DIR, "home": honey.home, "user": honey.user, "hostname": honey.hostname,
        "lang": honey.lang, "tz": honey.tz, "uid": 1000, "gid": 1000, "honey_files": honey.files, "env": honey.env,
        "entries": entries, "variants": variants, "total_timeout": timeout,
    }
    return plan


__all__ = ["MAX_ENTRIES", "Plan", "TARGET_DIR", "build_plan", "tar_of"]
