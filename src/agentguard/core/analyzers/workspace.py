"""Workspace auto-execution (the WS family, spec/ecosystems.md §10).

Files next to agent files that make an editor, a shell or git run something
without being asked: VS Code tasks and settings, dev containers, ``.envrc`` and
tool-version manager hooks, git hooks, ``.gitattributes`` drivers, IDE start-up
tasks, and build scripts the instructions tell the agent to run.

Pure: reads the parsed documents and the tree; runs nothing.
"""

from __future__ import annotations

import json
import posixpath
from typing import Any, ClassVar

import regex

from ..inventory_surfaces import Doc, span_of
from ..models import Span
from ..models.enums import ArtifactRole, EvidenceKind, Severity
from ..parsers import parse_json, parse_toml
from ..textutil import TIMEOUT
from .base import Context
from .config_units import locate_value
from .heuristics import CREDENTIAL_PATH, ENV_DUMP
from .settings import _DYN_EXEC, _NET

_F = regex.IGNORECASE
LIFECYCLE = ("initializeCommand", "onCreateCommand", "updateContentCommand", "postCreateCommand", "postStartCommand",
             "postAttachCommand")
_AUTO_APPROVE_KEY = regex.compile(
    r"^(?:chat\.tools\.(?:global\.)?autoApprove|chat\.agent\.autoApprove|github\.copilot\.chat\.agent\.autoApprove"
    r"|chat\.tools\.terminal\.autoApprove|chat\.tools\.edits\.autoApprove|chat\.tools\.urls\.autoApprove"
    r"|chat\.agent\.terminal\.autoApprove|[\w.]*dangerouslySkipPermissions|[\w.]*\.yolo(?:Mode)?)$", _F)
_BROAD_PATTERN = regex.compile(r"^(?:\*{1,2}|\*\*/\*|/\.\*/\w*|\.\*|/\^?\.\*\$?/\w*|\.vscode/\*{1,2}.*|\.github/\*{1,2}.*|\.claude/\*{1,2}.*)$")
_SHELLISH = regex.compile(r"^(?:bash|sh|zsh|fish|pwsh|powershell|cmd|python3?|node|curl|wget|eval|sudo|npx|uvx|rm|git)$", _F)
_PERMISSIVE_MODE = regex.compile(r"^(?:bypassPermissions|dontAsk|acceptEdits|yolo|auto|unrestricted)$", _F)
_TERMINAL_KEY = regex.compile(r"^terminal\.integrated\.(?:(?:automation)?profiles?|automationProfile|defaultProfile|shell|shellArgs|env)\.(?:linux|osx|windows)$", _F)
_RISKY_ENV = regex.compile(r"^(?:PATH|LD_PRELOAD|LD_LIBRARY_PATH|DYLD_INSERT_LIBRARIES|BASH_ENV|ENV|ZDOTDIR|PROMPT_COMMAND|NODE_OPTIONS|PYTHONSTARTUP"
                           r"|PYTHONPATH|GIT_SSH_COMMAND|GIT_ASKPASS|EDITOR|VISUAL|PAGER)$", _F)
_INLINE_FLAG = regex.compile(r"^(?:-c|-lc|-ic|-Command|-EncodedCommand|-e|-enc|/c|/k|--init-file|--rcfile|-NoExit)$", _F)
_STD_SHELL = regex.compile(r"^(?:/(?:usr/)?(?:local/)?bin/(?:ba|z|fi|da|k|c)?sh|/bin/sh|/opt/homebrew/bin/(?:ba|z|fi)sh|(?:ba|z|fi)?sh|pwsh(?:\.exe)?"
                           r"|powershell(?:\.exe)?|cmd(?:\.exe)?|C:\\\\?Windows\\\\?System32\\\\?(?:cmd|WindowsPowerShell\\\\?v1\.0\\\\?powershell)\.exe"
                           r"|\$\{env:windir\}.*)$", _F)
_PRIV_ARG = regex.compile(r"--privileged\b|--cap-add[= ]+(?:ALL|SYS_ADMIN|SYS_PTRACE|NET_ADMIN|SYS_MODULE)\b|--pid[= ]+host\b|--network[= ]+host\b"
                          r"|--net[= ]+host\b|--ipc[= ]+host\b|--userns[= ]+host\b|seccomp[=:]unconfined|apparmor[=:]unconfined"
                          r"|docker\.sock|--device[= ]+/dev/", _F)
_HOST_MOUNT = regex.compile(r"docker\.sock|source=/(?:,|$)|source=\$\{localEnv:(?:HOME|USERPROFILE)\}(?:,|$)|^/:/|^\$\{localEnv:HOME\}:", _F)
# direnv's own helpers and plain assignments: nothing here runs code of the repository's choosing.
_ENVRC_SAFE = regex.compile(
    r"^\s*(?:#.*|$|(?:export\s+)?[A-Za-z_]\w*=(?:\"[^\"`$]*\"|'[^']*'|[^\s`$;&|()<>]*)\s*(?:#.*)?$"
    r"|(?:dotenv(?:_if_exists)?|layout|use|PATH_add|path_add|MANPATH_add|source_env(?:_if_exists)?|source_up(?:_if_exists)?|watch_file|watch_dir"
    r"|strict_env|unstrict_env|unset|env_vars_required|direnv_version|log_status|has)\b[^`$;&|()<>]*$)")
_SUBSTITUTION = regex.compile(r"\$\(|`[^`\n]+`|<\(|\beval\b|\bsource\s+<|\bexec\b")
_ATTR = regex.compile(r"(?<![\w-])(filter|diff|merge)=([A-Za-z0-9_.\-]+)")
_BUILTIN_DRIVERS = frozenset({
    "lfs", "text", "binary", "union", "ours", "ada", "bash", "bibtex", "cpp", "csharp", "css", "dts", "elixir", "fortran", "fountain",
    "golang", "html", "java", "kotlin", "markdown", "matlab", "objc", "pascal", "perl", "php", "python", "ruby", "rust", "scheme",
    "tex", "astextplain"})
_ENABLE_HOOKS = regex.compile(
    r"\bgit\s+config\s+(?:--\w+\s+)*core\.hooksPath\s+\S+|\b(?:npx\s+)?husky(?:\s+install)?\b|\bpre-commit\s+install\b|\blefthook\s+install\b"
    r"|\b(?:cp|ln\s+-s\w*|install)\s+[^\n]*\.githooks/[^\n]*\.git/hooks|\bchmod\s+\+x\s+[^\n]*(?:\.githooks|\.husky)/"
    r"|\b(?:enable|install|activate|set\s+up)\s+(?:the\s+)?(?:repo(?:sitory)?'?s?\s+|project'?s?\s+)?git\s+hooks\b", _F)
_RUN_SCRIPT = regex.compile(r"\b(npm|pnpm|yarn|bun)\s+(?:run\s+|run-script\s+)?([A-Za-z][\w:.\-]*)|\b(make)\s+([A-Za-z][\w.\-]*)?", _F)
_PKG_BUILTIN = frozenset({"install", "i", "ci", "add", "exec", "dlx", "init", "create", "publish", "audit", "outdated", "update", "x",
                          "remove", "uninstall", "link", "pack", "login", "view", "info", "why", "ls", "list", "config", "cache"})
_LIFECYCLE_SCRIPTS = ("preinstall", "install", "postinstall", "prepare")
_PROSE_ROLES = (ArtifactRole.skill_md, ArtifactRole.instruction_md, ArtifactRole.command_md)
_STARTUP_CFG = regex.compile(r"<component\s+name=\"ProjectStartup(?:Shared|Local)Configuration\"[\s\S]*?</component>", _F)
_STARTUP_NAME = regex.compile(r"<configuration\b[^>]*\bname=\"([^\"]{1,120})\"", _F)


def _search(rx: regex.Pattern[str], text: str) -> regex.Match[str] | None:
    try:
        return rx.search(text, timeout=TIMEOUT)
    except TimeoutError:
        return None


def _cmd_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return " ".join(str(v) for v in value if isinstance(v, (str, int, float)))
    if isinstance(value, dict):
        return "\n".join(_cmd_text(v) for v in value.values())
    return ""


def risky_command(text: str) -> str:
    """Why a build or lifecycle command is risky, or ""."""
    net, dyn = _search(_NET, text), _search(_DYN_EXEC, text)
    if net and dyn:
        return f"downloads content and runs it (`{net.group(0)}` … `{dyn.group(0).strip()}`)"
    cred = _search(CREDENTIAL_PATH, text)
    if cred and (net or _search(regex.compile(r"\b(?:cat|cp|tar|zip|base64|scp)\b"), text)):
        return f"touches credential files (`{cred.group(0)}`)"
    if _search(ENV_DUMP, text) and net:
        return "sends the environment to the network"
    return ""


class WorkspaceAnalyzer:
    id: ClassVar[str] = "workspace"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = tuple(f"AG-WS-{i:03d}" for i in range(1, 9))

    def run(self, ctx: Context) -> None:
        self.ctx = ctx
        inv = ctx.inventory
        for path in sorted(inv.docs):
            doc: Doc = inv.docs[path]
            if not isinstance(doc.value, dict):
                continue
            sid = doc.surface.id
            if sid == "ws.vscode_tasks":
                self._tasks(doc)
            elif sid == "ws.vscode_settings":
                self._settings(doc)
            elif sid == "ws.devcontainer":
                self._devcontainer(doc)
        for path in sorted(inv.surfaces):
            sid = inv.surfaces[path].id
            if sid == "ws.envrc":
                self._envrc(path)
            elif sid == "ws.toolversions":
                self._mise(path)
            elif sid == "ws.gitattributes":
                self._gitattributes(path)
        self._githooks()
        self._ide_startup()
        self._build_scripts()

    # -- helpers ----------------------------------------------------------------------------------
    def _cid(self, path: str) -> list[str]:
        art = self.ctx.inventory.artifacts.get(path)
        return [art.component_id] if art else []

    def _text(self, path: str) -> str:
        at = self.ctx.inventory.texts.get(path)
        if at is not None:
            return at.text
        tree = self.ctx.inventory.tree
        blob = tree.files.get(path) if tree is not None else None
        return blob.data.decode("utf-8", "replace") if blob is not None else ""

    def _flag(self, rule: str, doc: Doc, keys: tuple[str, ...], message: str, *, value: Any = None, severity: Severity | None = None,
              needle: str = "") -> None:
        text = value if isinstance(value, str) else ""
        if needle:
            span = span_of(doc.text, needle, path=doc.path)
        elif text:
            span = locate_value(doc, keys, text)
        else:
            span = span_of(doc.text, *[k for k in keys if not k.isdigit()][-2:], path=doc.path)
        shown = f"{keys[-1]}: {json.dumps(value, ensure_ascii=False)[:200]}" if value is not None else ".".join(keys)
        self.ctx.emit(rule, component_ids=self._cid(doc.path), span=span, snippet=shown[:300], kind=EvidenceKind.config,
                      match=f"{doc.path}:{'.'.join(keys)}={str(value)[:80]}", detail=f"key: {'.'.join(keys)}", message=message,
                      severity=severity)

    def _line(self, rule: str, path: str, text: str, offset: int, message: str, *, key: str, severity: Severity | None = None,
              related: list[Span] | None = None, end: int | None = None) -> None:
        ls = text.rfind("\n", 0, offset) + 1
        le = text.find("\n", offset)
        le = len(text) if le < 0 else le
        line = text.count("\n", 0, offset) + 1
        span = Span(path=path, start_line=line, start_col=offset - ls + 1, end_line=line,
                    end_col=(min(end, le) if end is not None else le) - ls + 1)
        self.ctx.emit(rule, component_ids=self._cid(path), span=span, snippet=text[ls:le].strip()[:300], kind=EvidenceKind.config,
                      match=f"{path}:{key}", message=message, severity=severity, related=related)

    # -- AG-WS-001: tasks that run when the folder opens ------------------------------------------------
    def _tasks(self, doc: Doc) -> None:
        tasks = doc.data.get("tasks")
        for i, task in enumerate(tasks if isinstance(tasks, list) else []):
            if not isinstance(task, dict):
                continue
            opts = task.get("runOptions")
            if isinstance(opts, dict) and str(opts.get("runOn", "")).lower() == "folderopen":
                cmd = _cmd_text(task.get("command"))
                if isinstance(task.get("args"), list):
                    cmd = (cmd + " " + _cmd_text(task["args"])).strip()
                label = str(task.get("label") or task.get("script") or f"#{i + 1}")[:60]
                why = risky_command(cmd)
                self._flag("AG-WS-001", doc, ("tasks", str(i), "runOptions", "runOn"),
                           f"Task '{label}' runs when the folder is opened (`runOn: folderOpen`)"
                           + (f": `{cmd[:100]}`" if cmd else "") + (f". It {why}." if why else
                                                                    ". Opening the repository in VS Code is enough to start it once "
                                                                    "automatic tasks are allowed."),
                           value="folderOpen", needle="folderOpen")

    # -- AG-WS-002: editor settings ---------------------------------------------------------------------
    def _settings(self, doc: Doc) -> None:
        for key, value in doc.data.items():
            k = str(key)
            if _search(_AUTO_APPROVE_KEY, k):
                broad = ""
                if value is True:
                    broad = "is on"
                elif isinstance(value, dict):
                    hit = next((str(p) for p, v in value.items() if v is True and (_search(_BROAD_PATTERN, str(p)) or _search(_SHELLISH, str(p)))),
                               None)
                    if hit is None:
                        hit = next((str(p) for p, v in value.items() if isinstance(v, dict) and v.get("approve") is True
                                    and (_search(_BROAD_PATTERN, str(p)) or _search(_SHELLISH, str(p)))), None)
                    if hit is not None:
                        broad = f"approves `{hit}` without asking"
                if broad:
                    self._flag("AG-WS-002", doc, (k,), f"`{k}` {broad}: the agent's tool calls in this workspace run without a "
                               "confirmation. A repository that ships this setting approves its own commands.", value=value, needle=k)
            elif k.lower() in ("claudecode.initialpermissionmode", "claude-code.initialpermissionmode") and isinstance(value, str) \
                    and _search(_PERMISSIVE_MODE, value):
                self._flag("AG-WS-002", doc, (k,), f"`{k}` is `{value}`: the agent starts in a mode that skips permission prompts.",
                           value=value, needle=k)
            elif k == "task.allowAutomaticTasks" and str(value).lower() == "on":
                self._flag("AG-WS-002", doc, (k,), "`task.allowAutomaticTasks` is `on`: tasks marked `runOn: folderOpen` start "
                           "without the one-time prompt.", value=value, needle=k)
            elif _search(_TERMINAL_KEY, k):
                why = self._terminal(k, value)
                if why:
                    self._flag("AG-WS-002", doc, (k,), f"`{k}` {why}. Every terminal the editor or the agent opens in this workspace "
                               "starts with it.", value=value if isinstance(value, str) else None, needle=k)

    def _terminal(self, key: str, value: Any) -> str:
        low = key.lower()
        if ".env." in low and isinstance(value, dict):
            bad = [str(n) for n in value if _search(_RISKY_ENV, str(n))]
            return f"sets {', '.join(bad[:3])} for every terminal" if bad else ""
        if ".shellargs." in low:
            args = [str(a) for a in value] if isinstance(value, list) else []
            return f"passes `{' '.join(args)[:80]}` to the shell" if any(_search(_INLINE_FLAG, a) for a in args) else ""
        if ".shell." in low and isinstance(value, str):
            return f"replaces the shell with `{value[:80]}`" if not _search(_STD_SHELL, value) else ""
        profiles: list[tuple[str, Any]] = []
        if ".automationprofile." in low and isinstance(value, dict):
            profiles = [("automation profile", value)]
        elif ".profiles." in low and isinstance(value, dict):
            profiles = [(str(n), p) for n, p in value.items() if isinstance(p, dict)]
        for name, prof in profiles:
            path = prof.get("path")
            paths = [str(p) for p in path] if isinstance(path, list) else [path] if isinstance(path, str) else []
            args = [str(a) for a in prof.get("args")] if isinstance(prof.get("args"), list) else []
            if any(_search(_INLINE_FLAG, a) for a in args):
                return f"defines the terminal profile '{name}' with an inline command (`{' '.join(args)[:80]}`)"
            odd = next((p for p in paths if not _search(_STD_SHELL, p)), None)
            if odd is not None:
                return f"defines the terminal profile '{name}' with the executable `{odd[:80]}`"
            env = prof.get("env")
            if isinstance(env, dict) and any(_search(_RISKY_ENV, str(n)) for n in env):
                return f"defines the terminal profile '{name}' with a changed {next(str(n) for n in env if _search(_RISKY_ENV, str(n)))}"
        return ""

    # -- AG-WS-003: dev containers -------------------------------------------------------------------------
    def _devcontainer(self, doc: Doc) -> None:
        d = doc.data
        for key in LIFECYCLE:
            if key not in d:
                continue
            cmd = _cmd_text(d[key])
            why = risky_command(cmd)
            if not why and key == "initializeCommand" and (_search(_NET, cmd) or _search(_DYN_EXEC, cmd)):
                why = "runs on the host machine, before any container exists, and reaches the network or evaluates code"
            if why:
                first = d[key] if isinstance(d[key], str) else cmd.split("\n", 1)[0]
                self._flag("AG-WS-003", doc, (key,), f"Dev container `{key}` {why}. It runs as soon as the container is created or "
                           "started, without a prompt for the command itself.", value=str(first)[:200],
                           severity=Severity.high if key == "initializeCommand" else None)
        if d.get("privileged") is True:
            self._flag("AG-WS-003", doc, ("privileged",), "The dev container runs privileged: processes in it can reach the host's "
                       "devices and kernel interfaces.", value=True, needle="privileged")
        args = " ".join(str(a) for a in d.get("runArgs")) if isinstance(d.get("runArgs"), list) else ""
        m = _search(_PRIV_ARG, args)
        if m:
            self._flag("AG-WS-003", doc, ("runArgs",), f"Dev container `runArgs` contains `{m.group(0)}`, which removes the "
                       "container's isolation from the host.", value=m.group(0), needle=m.group(0))
        caps = [str(c) for c in d.get("capAdd")] if isinstance(d.get("capAdd"), list) else []
        if any(c.upper() in ("ALL", "SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN", "SYS_MODULE") for c in caps):
            self._flag("AG-WS-003", doc, ("capAdd",), f"Dev container adds capabilities ({', '.join(caps[:4])}) that let it act on "
                       "the host.", value=caps[0], needle="capAdd")
        mounts = d.get("mounts") if isinstance(d.get("mounts"), list) else []
        for mnt in mounts:
            text = mnt if isinstance(mnt, str) else ",".join(f"{k}={v}" for k, v in mnt.items()) if isinstance(mnt, dict) else ""
            m = _search(_HOST_MOUNT, text)
            if m:
                self._flag("AG-WS-003", doc, ("mounts",), f"Dev container mounts `{text[:100]}`: the host's Docker socket or home "
                           "directory is available inside the container.", value=text if isinstance(mnt, str) else None,
                           needle="docker.sock" if "docker.sock" in text else "mounts")
                break

    # -- AG-WS-004: code that runs on entering the directory ---------------------------------------------------
    def _envrc(self, path: str) -> None:
        text = self._text(path)
        offset = 0
        for line in text.split("\n"):
            start = offset
            offset += len(line) + 1
            if _search(_ENVRC_SAFE, line):
                continue
            why = risky_command(line)
            sub = _search(_SUBSTITUTION, line)
            net = _search(_NET, line)
            if not (why or sub or net):
                continue
            what = why or (f"evaluates a command (`{sub.group(0)[:40]}`)" if sub else f"reaches the network (`{net.group(0)}`)")  # type: ignore[union-attr]
            self._line("AG-WS-004", path, text, start + (len(line) - len(line.lstrip())), key=f"envrc:{line.strip()[:60]}",
                       message=f"`.envrc` {what}. direnv runs this file each time a shell enters the directory once it has been "
                               "allowed, and agents' shells enter it constantly.",
                       severity=Severity.high if why else None)
            return

    def _mise(self, path: str) -> None:
        if not path.lower().endswith(".toml"):
            return
        text = self._text(path)
        parsed = parse_toml(text)
        data = parsed.value if isinstance(parsed.value, dict) else {}
        hooks = data.get("hooks") if isinstance(data.get("hooks"), dict) else {}
        for name in ("enter", "cd", "leave", "preinstall", "postinstall"):
            if name not in hooks:
                continue
            cmd = _cmd_text(hooks[name] if not isinstance(hooks[name], dict) else hooks[name].get("script") or hooks[name].get("run"))
            why = risky_command(cmd)
            at = text.find(name, max(text.find("[hooks]"), 0))
            self._line("AG-WS-004", path, text, max(at, 0), key=f"mise:{name}",
                       message=f"`{posixpath.basename(path)}` defines a `{name}` hook (`{cmd[:80]}`) that mise runs when a shell enters "
                               f"the directory{'. It ' + why if why else ''}.", severity=Severity.high if why else None)
            return
        m = _search(regex.compile(r"\{\{\s*exec\("), text)
        if m:
            self._line("AG-WS-004", path, text, m.start(), key="mise:exec",
                       message=f"`{posixpath.basename(path)}` computes a value with `exec(…)`, which mise runs when a shell enters "
                               "the directory.")

    # -- AG-WS-005: git hooks the instructions enable ------------------------------------------------------------
    def _githooks(self) -> None:
        inv = self.ctx.inventory
        hooks = sorted(p for p, s in inv.surfaces.items() if s.id == "ws.githook" and not p.endswith(".sample"))
        if not hooks:
            return
        enable: tuple[str, int, str] | None = None
        for at in self.ctx.texts(*(r.value for r in _PROSE_ROLES)):
            m = _search(_ENABLE_HOOKS, at.text)
            if m:
                enable = (at.path, at.index.line_col(m.start())[0], m.group(0))
                break
        for path in hooks:
            shipped = "/.git/hooks/" in "/" + path
            if not shipped and enable is None:
                continue
            body = self._text(path)
            why = risky_command(body)
            name = posixpath.basename(path)
            if shipped:
                msg = f"`{path}` is an active git hook shipped inside the package's own `.git/`: git runs it on the matching " \
                      "operation with no further step."
            else:
                msg = f"`{path}` is a git hook, and `{enable[0]}` tells the agent to enable the repository's hooks " \
                      f"(`{enable[2][:60]}`). After that git runs `{name}` on every matching operation."  # type: ignore[index]
            if why:
                msg += f" The hook {why}."
            self.ctx.emit("AG-WS-005", component_ids=self._cid(path), span=Span(path=path, start_line=1),
                          snippet=body.strip().split("\n", 1)[0][:200] or path, kind=EvidenceKind.config, match=f"githook:{path}",
                          message=msg, severity=Severity.high if why else None,
                          related=[Span(path=enable[0], start_line=enable[1])] if enable and not shipped else None)

    # -- AG-WS-006: .gitattributes drivers ----------------------------------------------------------------------
    def _gitattributes(self, path: str) -> None:
        inv = self.ctx.inventory
        text = self._text(path)
        wanted: dict[tuple[str, str], int] = {}
        for m in _ATTR.finditer(text):
            if m.group(2).lower() not in _BUILTIN_DRIVERS and not text[text.rfind("\n", 0, m.start()) + 1: m.start()].lstrip().startswith("#"):
                wanted.setdefault((m.group(1).lower(), m.group(2)), m.start())
        if not wanted:
            return
        tree = inv.tree
        sources: list[tuple[str, str]] = [(p, self._text(p)) for p in sorted(tree.files if tree is not None else [])
                                          if posixpath.basename(p).lower() in (".gitconfig", "gitconfig", ".lfsconfig")]
        sources += [(at.path, at.text) for at in self.ctx.texts() if at.artifact.role in (*_PROSE_ROLES, ArtifactRole.script,
                                                                                         ArtifactRole.repo_doc, ArtifactRole.reference)]
        for (kind, name), at_off in sorted(wanted.items(), key=lambda kv: kv[1]):
            section = regex.compile(rf"\[{kind}\s+\"{regex.escape(name)}\"\][^\[]*?\b(clean|smudge|process|textconv|command|driver)\s*=\s*([^\n]+)", _F)
            config = regex.compile(rf"\bgit\s+config\s+(?:--\w+\s+)*{kind}\.{regex.escape(name)}\.(clean|smudge|process|textconv|command|driver)\s+([^\n]+)", _F)
            for src, body in sources:
                m = _search(section, body) or _search(config, body)
                if not m:
                    continue
                cmd = m.group(2).strip().strip("\"'`")[:100]
                line = body.count("\n", 0, m.start()) + 1
                self._line("AG-WS-006", path, text, at_off, key=f"{kind}={name}", related=[Span(path=src, start_line=line)],
                           message=f"`.gitattributes` assigns the {kind} driver `{name}`, and `{src}` defines it as `{cmd}`. Once that "
                                   "configuration is applied, git runs the command on checkout, diff, add or merge of the matching "
                                   "files.", severity=Severity.high if risky_command(cmd) else None)
                break

    # -- AG-WS-007: IDE start-up tasks ---------------------------------------------------------------------------
    def _ide_startup(self) -> None:
        tree = self.ctx.inventory.tree
        if tree is None:
            return
        for path in sorted(tree.files):
            if not ("/" + path.lower()).endswith("/.idea/startup.xml"):
                continue
            text = self._text(path)
            block = _search(_STARTUP_CFG, text)
            if not block:
                continue
            names = _STARTUP_NAME.findall(block.group(0))
            if not names:
                continue
            first = _search(_STARTUP_NAME, block.group(0))
            self._line("AG-WS-007", path, text, block.start() + (first.start() if first else 0), key="startup",
                       message=f"The IDE project lists start-up tasks ({', '.join(names[:3])}): JetBrains IDEs run these run "
                               "configurations when the project is opened and trusted.")

    # -- AG-WS-008: build scripts the instructions tell the agent to run ---------------------------------------------
    def _build_scripts(self) -> None:
        inv = self.ctx.inventory
        tree = inv.tree
        if tree is None:
            return
        packages: dict[str, dict[str, Any]] = {}
        makefiles: dict[str, str] = {}
        for p in tree.files:
            base = posixpath.basename(p)
            if base == "package.json":
                parsed = parse_json(self._text(p))
                if isinstance(parsed.value, dict) and isinstance(parsed.value.get("scripts"), dict):
                    packages[p] = parsed.value["scripts"]
            elif base in ("Makefile", "makefile", "GNUmakefile"):
                makefiles[p] = self._text(p)
        if not packages and not makefiles:
            return
        seen: set[tuple[str, str]] = set()
        for at in self.ctx.texts(*(r.value for r in _PROSE_ROLES)):
            here = posixpath.dirname(at.path)
            for m in _RUN_SCRIPT.finditer(at.text):
                line = at.index.line_col(m.start())[0]
                origin = Span(path=at.path, start_line=line)
                if m.group(3):                                   # make [target]
                    target = m.group(4) or ""
                    mk = self._nearest(makefiles, here)
                    if mk is None or (mk, target) in seen:
                        continue
                    body, off = self._make_target(makefiles[mk], target)
                    why = risky_command(body)
                    if why:
                        seen.add((mk, target))
                        self._line("AG-WS-008", mk, makefiles[mk], off, key=f"make:{target}", related=[origin],
                                   message=f"`{at.path}` tells the agent to run `{m.group(0).strip()}`, and that Makefile target "
                                           f"{why}.")
                    continue
                name = m.group(2)
                pkg = self._nearest(packages, here)
                if pkg is None:
                    continue
                names = list(_LIFECYCLE_SCRIPTS) if name.lower() in ("install", "i", "ci") else \
                    [] if name.lower() in _PKG_BUILTIN else [f"pre{name}", name, f"post{name}"]
                for script in names:
                    cmd = packages[pkg].get(script)
                    if not isinstance(cmd, str) or (pkg, script) in seen:
                        continue
                    why = risky_command(cmd)
                    if not why:
                        continue
                    seen.add((pkg, script))
                    text = self._text(pkg)
                    off = text.find(json.dumps(script))
                    self._line("AG-WS-008", pkg, text, max(off, 0), key=f"npm:{script}", related=[origin],
                               message=f"`{at.path}` tells the agent to run `{m.group(0).strip()}`, and the `{script}` script in "
                                       f"`{pkg}` {why}.")

    @staticmethod
    def _nearest(files: dict[str, Any], here: str) -> str | None:
        """The file of ``files`` in ``here`` or the closest parent directory."""
        d = here
        while True:
            for p in files:
                if posixpath.dirname(p) == d:
                    return p
            if not d:
                return None
            d = posixpath.dirname(d)

    @staticmethod
    def _make_target(text: str, target: str) -> tuple[str, int]:
        """Recipe lines of a Makefile target (the first target when none is named), and its offset."""
        rx = regex.compile(rf"(?m)^{regex.escape(target)}\s*:(?!=)[^\n]*\n((?:\t[^\n]*\n?|[ \t]*\n)*)") if target else \
            regex.compile(r"(?m)^[A-Za-z][\w.\-]*\s*:(?!=)[^\n]*\n((?:\t[^\n]*\n?|[ \t]*\n)*)")
        m = _search(rx, text)
        return (m.group(1), m.start()) if m else ("", 0)


__all__ = ["LIFECYCLE", "WorkspaceAnalyzer", "risky_command"]
