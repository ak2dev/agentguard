"""Plugins, extensions, marketplaces and MCP bundles (the PLUG family, the
plugin-borne EXEC rules and the bundle rules of MCP; spec/ecosystems.md §2.7, §3.2, §3.3).

A plugin can ship hooks, MCP / LSP servers, monitors, workflow code, mods and a
``bin/`` directory added to ``PATH``. Every component type is read here; the
rules compare what a plugin ships with what its description says, check how a
marketplace pins its sources, and check what a bundle would launch.

Pure: works on ``inv.docs``, the inventory and recorded facts.
"""

from __future__ import annotations

import posixpath
from typing import Any, ClassVar

import regex

from ..inventory_surfaces import Doc, span_of
from ..mcp_config import exe_name
from ..models import Component, Span
from ..models.enums import ArtifactRole, ComponentKind, EvidenceKind, Severity
from ..textutil import sha256_hex
from .base import Context
from .config_units import ConfigCommand, locate_value
from .heuristics import EGRESS_CODE, EXEC_CODE, search
from .settings import _DYN_EXEC, _NET, _OFFICIAL_MARKETPLACE, _get, _host, _strs, is_local_host, is_repo_file, iter_hooks

_F = regex.IGNORECASE
_SHA40 = regex.compile(r"^[0-9a-f]{40}$")
_SHA256 = regex.compile(r"^(?:sha256:)?[0-9a-f]{64}$", _F)
_EXACT_VERSION = regex.compile(r"^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?$")
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "cmd", "powershell", "pwsh"}
_INTERPRETERS = {"python", "python3", "node", "deno", "bun", "perl", "ruby", "php", "osascript"}
_INLINE = {"-c", "-e", "--eval", "-p", "-command", "-encodedcommand", "-enc", "/c"}
_SHELL_META = regex.compile(r"[;&|`]|\$\(|>\s*\S")
# Commands a `bin/` entry must not shadow: the agent's Bash tool would run the plugin's file instead.
COMMON_COMMANDS = frozenset("""
git ls cat cp mv rm mkdir rmdir touch chmod chown ln find grep sed awk sort head tail cut tr wc xargs tee diff patch tar zip unzip
gzip curl wget ssh scp rsync sudo su env which whoami id ps kill echo printf test true false sh bash zsh python python3 pip pip3
uv uvx node npm npx pnpm yarn bun deno ruby gem perl php go cargo rustc java javac mvn gradle make cmake gcc clang docker podman
kubectl helm terraform aws gcloud az gh glab brew apt apt-get yum dnf pacman code claude codex gemini cursor jq yq openssl gpg
pytest ruff eslint prettier tsc vim nano less more date sleep df du mount systemctl crontab open xdg-open pbcopy pbpaste
""".split())
RESERVED_MARKETPLACES = frozenset({
    "claude-code-marketplace", "claude-code-plugins", "claude-plugins-official", "anthropic-marketplace", "anthropic-plugins",
    "agent-skills", "life-sciences",
})
_IMITATES = regex.compile(r"(?:^|[-_.\s])(?:official|verified|anthropic|anthropics)(?:$|[-_.\s])|claude[-_ ]?(?:code)?[-_ ]?(?:official|marketplace)"
                          r"|(?:openai|google|github|microsoft|cursor)[-_ ]official", _F)
_HOOK_WORDS = regex.compile(r"\bhooks?\b|\bautomatic(?:ally)?\b|\b(?:on|after|before)\s+(?:each|every)\b|\bintercepts?\b|\bSessionStart\b|\bPreToolUse\b|\bPostToolUse\b", _F)
_SERVER_WORDS = regex.compile(r"\bMCP\b|\bservers?\b|\bLSP\b|language[- ]server|\bmonitors?\b|\bbackground\b|\bdaemon\b|\bconnector\b|\bintegrat", _F)
_CODE_WORDS = regex.compile(r"\bworkflows?\b|\bmods?\b|\bCLI\b|command[- ]line|\bbinar(?:y|ies)\b|\bexecutables?\b|\bscripts?\b|\bbin/", _F)
_SECRET_NAME = regex.compile(r"api[-_ ]?key|token|secret|passw(?:or)?d|credential|private[-_ ]?key|bearer|client[-_ ]?secret", _F)
_PATH_FIELDS = ("commands", "agents", "skills", "hooks", "mcpServers", "lspServers", "outputStyles", "monitors", "themes", "workflows",
                "mods", "settings", "icon")
_SENDER_KEYS = regex.compile(r"allow(?:ed)?(?:From|Senders|Users|List)|allowlist|senders|trusted", _F)
_SIG_MARKERS = (b"MCPB_SIG_V1", b"DXT_SIG_V1", b"MCPB_SIG_END")
_DEFAULT_ON = ("enabledByDefault", "defaultEnabled", "enabled_by_default", "autoEnable")


def risky_launch(command: str, args: list[str] | None = None) -> str:
    """Why a launch command is more than "start this program", or ""."""
    args = args or []
    exe = exe_name(command)
    line = " ".join([command, *args])
    low = [a.lower() for a in args[:4]]
    if exe in _SHELLS and any(a in _INLINE for a in low):
        return "it is a shell command string"
    if exe.rstrip("0123456789.") in _INTERPRETERS and any(a in _INLINE for a in low):
        return "it runs inline code"
    if search(_DYN_EXEC, line):
        return "it evaluates or decodes content at start"
    if search(_NET, line) and exe not in ("npx", "uvx", "bunx", "pnpx", "docker", "podman"):
        return "it uses the network at start"
    if not args and search(_SHELL_META, command):
        return "it is a shell pipeline"
    return ""


def _is_path_like(value: str) -> bool:
    return bool(value) and not value.startswith(("http://", "https://")) and (
        "/" in value or "\\" in value or value.startswith((".", "~")) or regex.search(r"\.[A-Za-z0-9]{1,5}$", value) is not None)


def _escapes(value: str) -> bool:
    v = value.replace("\\", "/")
    v = regex.sub(r"^\$\{?(?:CLAUDE_PLUGIN_ROOT|CLAUDE_SKILL_DIR|__dirname|extensionPath)\}?/?", "", v)
    if v.startswith(("/", "~")) or regex.match(r"[A-Za-z]:/", v) or v.startswith(("$HOME", "${HOME}", "%USERPROFILE%")):
        return True
    return posixpath.normpath(v).startswith("..")


class PluginAnalyzer:
    id: ClassVar[str] = "plugins"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = (
        *(f"AG-PLUG-{n:03d}" for n in (*range(1, 17), *range(18, 24))),
        "AG-EXEC-016", "AG-EXEC-017", "AG-EXEC-018", "AG-EXEC-019", "AG-MCP-006", "AG-MCP-008", "AG-MCP-034",
        "AG-MCP-061", "AG-MCP-062", "AG-MCP-063", "AG-MCP-064", "AG-MCP-065",
    )

    def run(self, ctx: Context) -> None:
        self.ctx = ctx
        inv = ctx.inventory
        self.cmds: list[ConfigCommand] = ctx.data.get("config_commands", [])  # type: ignore[assignment]
        for path in sorted(inv.docs):
            doc: Doc = inv.docs[path]
            if doc.value is None or path not in inv.artifacts:
                continue
            sid = doc.surface.id
            if sid in ("claude.marketplace", "cursor.marketplace"):
                self._marketplace(doc)
            elif sid == "claude.settings":
                self._settings_marketplaces(doc)
            elif sid == "bundle.mcpb":
                self._bundle(doc)
        for comp in sorted(inv.of_kind(ComponentKind.plugin), key=lambda c: c.id):
            self._plugin(comp)
        self._helpers()
        self._server_paths()
        self._background_processes()
        self._registry_bundles()
        self._unsigned_bundles()
        self._icons()

    # -- helpers --------------------------------------------------------------------------------------
    def _cid(self, path: str) -> str:
        art = self.ctx.inventory.artifacts.get(path)
        return art.component_id if art else ""

    def flag(self, rule: str, doc: Doc, keys: tuple[str, ...], message: str, *, value: Any = None, severity: Severity | None = None,
             snippet: str | None = None, cid: str | None = None, related: list[Span] | None = None) -> None:
        text = value if isinstance(value, str) else ""
        named = [k for k in keys if not k.isdigit()]
        span = locate_value(doc, keys, text) if text else span_of(doc.text, *named[-2:], path=doc.path)
        owner = cid if cid is not None else self._cid(doc.path)
        shown = snippet if snippet is not None else (f"{keys[-1]}: {value!r}" if value is not None else ".".join(keys))
        self.ctx.emit(rule, component_ids=[owner] if owner else [], span=span, snippet=shown[:300], kind=EvidenceKind.config,
                      match=f"{doc.path}:{'.'.join(keys)}={str(value)[:80]}", detail=f"key: {'.'.join(keys)}", message=message,
                      severity=severity, related=related)

    # -- marketplaces (PLUG-001 to 006, 012, 013, 020, 023) ------------------------------------------------
    def _marketplace(self, doc: Doc) -> None:
        d = doc.data
        name = str(d.get("name") or "")
        tree = self.ctx.inventory.tree
        origin = (tree.source.locator if tree is not None and tree.source is not None else "") or ""
        official_origin = bool(regex.search(r"github\.com[/:]anthropics?/", origin, _F))
        if name and not official_origin and (name.lower() in RESERVED_MARKETPLACES or _IMITATES.search(name)):
            what = "is a name reserved for Anthropic's own marketplaces" if name.lower() in RESERVED_MARKETPLACES \
                else "imitates an official marketplace name"
            self.flag("AG-PLUG-013", doc, ("name",), f"The marketplace name '{name}' {what}; users may take it for the vendor's.",
                      value=name)
        if d.get("autoUpdate") is True and not official_origin:
            self.flag("AG-PLUG-006", doc, ("autoUpdate",), "The marketplace turns auto-update on: new plugin versions install "
                      "without anyone reviewing them.", value=True)
        if d.get("renames"):
            first = next(iter(d["renames"]), "") if isinstance(d["renames"], (dict, list)) else ""
            self.flag("AG-PLUG-020", doc, ("renames",), "The marketplace declares `renames`: an installed plugin can be replaced by "
                      "a differently named one on the next update.", value=None, snippet=f"renames: {str(first)[:80]}")
        if d.get("forceRemoveDeletedPlugins") is True:
            self.flag("AG-PLUG-020", doc, ("forceRemoveDeletedPlugins",), "`forceRemoveDeletedPlugins` removes installed plugins "
                      "when the marketplace drops them, which together with a new entry swaps one plugin for another.", value=True)
        plugins = d.get("plugins") if isinstance(d.get("plugins"), list) else []
        for i, entry in enumerate(plugins[:500]):
            if not isinstance(entry, dict):
                continue
            pname = str(entry.get("name") or i)
            keys = ("plugins", str(i))
            src = entry.get("source")
            if isinstance(src, dict):
                kind = str(src.get("source") or src.get("type") or "").lower()
                if kind in ("github", "url", "git", "git-subdir") and not _SHA40.match(str(src.get("sha") or "")):
                    ref = src.get("ref")
                    self.flag("AG-PLUG-001", doc, (*keys, "source"), f"Plugin '{pname}' is fetched from "
                              f"{src.get('repo') or src.get('url') or 'a git source'} "
                              + (f"at `{ref}`, a branch or tag that can be moved" if ref else "at the default branch")
                              + "; no commit `sha` pins what gets installed.", value=str(src.get("repo") or src.get("url") or ""),
                              snippet=f"{pname}: source {kind} {src.get('repo') or src.get('url') or ''} ref={ref}")
                elif kind == "npm" and not _EXACT_VERSION.match(str(src.get("version") or "")):
                    v = src.get("version")
                    self.flag("AG-PLUG-002", doc, (*keys, "source"), f"Plugin '{pname}' is the npm package `{src.get('package')}` "
                              + (f"at `{v}`, a range or dist-tag" if v else "with no version") + "; a later publish changes what is "
                              "installed.", value=str(src.get("package") or ""), snippet=f"{pname}: npm {src.get('package')}@{v}")
                elif kind == "archive" and not _SHA256.match(str(src.get("sha256") or "")):
                    self.flag("AG-PLUG-003", doc, (*keys, "source"), f"Plugin '{pname}' is an archive downloaded from "
                              f"`{str(src.get('url'))[:100]}` with no `sha256`; the file can change after review.",
                              value=str(src.get("url") or ""), snippet=f"{pname}: archive {src.get('url')}")
                elif kind == "command":
                    cmd = src.get("command")
                    text = cmd if isinstance(cmd, str) else " ".join(str(x) for x in cmd) if isinstance(cmd, list) else ""
                    self.flag("AG-PLUG-004", doc, (*keys, "source"), f"Plugin '{pname}' has a `command` source (`{text[:80]}`): the "
                              "command runs on install, on update and once per session.", value=text or None,
                              snippet=f"{pname}: command {text[:120]}")
            if entry.get("headersHelper"):
                self.flag("AG-PLUG-005", doc, (*keys, "headersHelper"), f"The marketplace entry for '{pname}' sets `headersHelper`, "
                          "a shell command run to produce request headers.", value=str(entry["headersHelper"]))
            if entry.get("strict") is False:
                self.flag("AG-PLUG-012", doc, (*keys, "strict"), f"The marketplace entry for '{pname}' has `strict: false`: its "
                          "own component definitions replace the plugin's manifest, so the plugin's repository does not show "
                          "what is installed.", value=False, snippet=f"{pname}: strict: false")
            if not official_origin and _IMITATES.search(pname):
                self.flag("AG-PLUG-013", doc, (*keys, "name"), f"The plugin name '{pname}' imitates an official or vendor name.",
                          value=pname, severity=Severity.medium)
            risky_parts = [k for k in ("hooks", "mcpServers", "lspServers", "monitors") if entry.get(k)]
            if any(entry.get(k) is True for k in _DEFAULT_ON) and risky_parts:
                self.flag("AG-PLUG-023", doc, (*keys, next(k for k in _DEFAULT_ON if entry.get(k) is True)), f"Plugin '{pname}' "
                          f"is enabled by default and ships {', '.join(risky_parts)}.", value=True, snippet=f"{pname}: enabled by default")

    def _settings_marketplaces(self, doc: Doc) -> None:
        markets = doc.data.get("extraKnownMarketplaces")
        for name, entry in (markets.items() if isinstance(markets, dict) else []):
            if isinstance(entry, dict) and entry.get("autoUpdate") is True and not _OFFICIAL_MARKETPLACE.search(str(name)):
                self.flag("AG-PLUG-006", doc, ("extraKnownMarketplaces", str(name), "autoUpdate"), f"Auto-update is on for the "
                          f"third-party marketplace '{name}': its plugins update without review.", value=True)

    # -- one plugin (PLUG-007 to 011, 014 to 016, 018, 019, 021 to 023; EXEC-016, 017) ------------------------
    def _plugin(self, comp: Component) -> None:
        ctx, inv = self.ctx, self.ctx.inventory
        root = comp.root
        prefix = root + "/" if root else ""
        manifest = inv.docs.get(comp.metadata.get("manifest", ""))
        agent = comp.metadata.get("agent", "claude-code")
        if manifest is None or manifest.value is None:
            return
        d = manifest.data
        description = " ".join(str(d.get(k) or "") for k in ("description", "summary", "long_description")) \
            + " " + " ".join(_strs(d.get("keywords")))
        under = [p for p in inv.surfaces if p.startswith(prefix)]
        surf = {p: inv.surfaces[p].id for p in under}
        hook_docs = [inv.docs[p] for p, s in surf.items() if s in ("plugin.hooks", "codex.hooks", "cursor.hooks") and p in inv.docs]
        has_hooks = bool(d.get("hooks")) or any(iter_hooks(h) for h in hook_docs)
        server_files = [p for p, s in surf.items() if s in ("claude.lsp", "claude.monitors")]
        mcp_cfgs = [c for c in inv.configs if c.path.startswith(prefix) and c.servers]
        has_servers = bool(server_files or mcp_cfgs or d.get("mcpServers") or d.get("lspServers") or d.get("monitors"))
        code_files = sorted(p for p, s in surf.items() if s in ("plugin.workflow", "plugin.mod", "plugin.bin"))
        native = agent == "openclaw"
        rule_x = "AG-PLUG-022" if agent in ("cursor", "codex", "gemini") else ""
        mspan = Span(path=manifest.path)

        def undeclared(rule: str, what: str, words: regex.Pattern[str], where: Span | None) -> None:
            if search(words, description):
                return
            said = f"its description (\"{description.strip()[:80]}\")" if description.strip() else "it has no description, so nothing"
            self.flag(rule_x or rule, manifest, ("description",) if "description" in d else ("name",),
                      f"The {agent} plugin '{comp.name}' ships {what}; {said} does not mention it.", value=None,
                      snippet=f"{comp.name}: {what}", cid=comp.id, related=[where] if where else None)

        if has_hooks:
            undeclared("AG-PLUG-007", "hooks that run automatically", _HOOK_WORDS, Span(path=hook_docs[0].path) if hook_docs else mspan)
        if has_servers:
            first = server_files[0] if server_files else (mcp_cfgs[0].path if mcp_cfgs else manifest.path)
            undeclared("AG-PLUG-008", "MCP, LSP or monitor servers", _SERVER_WORDS, Span(path=first))
        if code_files:
            kinds = sorted({surf[p].split(".", 1)[1] for p in code_files})
            undeclared("AG-PLUG-009", f"code that runs on its own ({', '.join(kinds)})", _CODE_WORDS, Span(path=code_files[0]))
        # PLUG-010: a dependency on a plugin from another marketplace.
        deps = d.get("dependencies")
        dep_items = list(deps.items()) if isinstance(deps, dict) else [(x, None) for x in deps] if isinstance(deps, list) else []
        for dep, spec in dep_items[:100]:
            name = dep.get("name") if isinstance(dep, dict) else str(dep)
            market = dep.get("marketplace") if isinstance(dep, dict) else (spec.get("marketplace") if isinstance(spec, dict) else None)
            if not market and isinstance(name, str) and "@" in name.lstrip("@"):
                name, _, market = name.rpartition("@")
            if market and not _OFFICIAL_MARKETPLACE.search(str(market)):
                self.flag("AG-PLUG-010", manifest, ("dependencies",), f"The plugin depends on '{name}' from the marketplace "
                          f"'{market}'; installing it pulls a second plugin from a source you did not choose.", value=str(name),
                          snippet=f"dependencies: {name}@{market}", cid=comp.id)
        # PLUG-011: a manifest path that leaves the plugin root.
        for key in _PATH_FIELDS:
            for value in _strs(d.get(key)):
                if _is_path_like(value) and _escapes(value):
                    self.flag("AG-PLUG-011", manifest, (key,), f"The manifest's `{key}` points at `{value}`, outside the plugin's "
                              "own directory.", value=value, cid=comp.id)
        # PLUG-014: plugin settings.json with a status-line command or a default agent.
        settings = inv.docs.get(f"{prefix}settings.json")
        if settings is not None and settings.value is not None and inv.surfaces.get(settings.path) is not None \
                and inv.surfaces[settings.path].id == "plugin.settings":
            line = settings.data.get("subagentStatusLine")
            cmd = line.get("command") if isinstance(line, dict) else line if isinstance(line, str) else None
            if cmd:
                self.flag("AG-PLUG-014", settings, ("subagentStatusLine",), f"The plugin's settings set a status-line command "
                          f"(`{str(cmd)[:80]}`) that runs repeatedly while subagents work.", value=str(cmd), cid=comp.id)
            if isinstance(settings.data.get("agent"), str):
                self.flag("AG-PLUG-014", settings, ("agent",), f"The plugin's settings make '{settings.data['agent']}' the default "
                          "agent for the whole session.", value=settings.data["agent"], cid=comp.id, severity=Severity.low)
        # PLUG-015 / MCP-065: a secret collected without `sensitive: true`.
        for field, rule in (("userConfig", "AG-PLUG-015"), ("user_config", "AG-PLUG-015")):
            self._user_config(manifest, d.get(field), field, rule, comp.id)
        # PLUG-016: findings on the plugin's own dependencies.
        dep_files = {f"{prefix}{n}" for n in ("package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "requirements.txt",
                                              "pyproject.toml", "uv.lock")}
        dep_findings = [r for r in ctx.raw if r.primary and r.primary.path in dep_files and r.rid.startswith("AG-SUPPLY-")
                        # Informational notes (a missing licence) are not a problem with the dependencies.
                        and (r.severity or ctx.pack.detector(r.rule_id).severity).rank > Severity.info.rank]
        if dep_findings:
            worst = max(dep_findings, key=lambda r: (r.severity or ctx.pack.detector(r.rule_id).severity).rank)
            sev = worst.severity or ctx.pack.detector(worst.rule_id).severity
            ctx.emit("AG-PLUG-016", component_ids=comp.id, span=worst.primary, snippet=", ".join(sorted({r.rid for r in dep_findings})),
                     kind=EvidenceKind.config, match=f"{root}:deps", severity=sev,
                     related=[r.primary for r in dep_findings[1:6] if r.primary],
                     message=f"The plugin's dependencies have {len(dep_findings)} supply-chain finding(s) "
                             f"({', '.join(sorted({r.rid for r in dep_findings})[:5])}); they are installed with the plugin.")
        # PLUG-018: an MCP bundle named by URL with no hash.
        servers = d.get("mcpServers")
        candidates: list[tuple[tuple[str, ...], Any]] = []
        if isinstance(servers, str):
            candidates.append((("mcpServers",), servers))
        elif isinstance(servers, list):
            candidates += [(("mcpServers", str(i)), v) for i, v in enumerate(servers)]
        elif isinstance(servers, dict):
            candidates += [(("mcpServers", str(k)), v) for k, v in servers.items()]
        for keys, value in candidates:
            url = value if isinstance(value, str) else (value.get("url") or value.get("bundle") or value.get("source")) if isinstance(value, dict) else None
            if isinstance(url, str) and regex.match(r"https?://", url) and regex.search(r"\.(?:mcpb|dxt)(?:[?#]|$)", url, _F):
                pinned = (isinstance(value, dict) and _SHA256.match(str(value.get("sha256") or value.get("fileSha256") or ""))) \
                    or regex.search(r"[#?&]sha256=[0-9a-f]{64}", url, _F)
                if not pinned:
                    self.flag("AG-PLUG-018", manifest, keys, f"The plugin loads an MCP bundle from `{url[:100]}` with no hash; "
                              "whatever that URL serves at install time is run.", value=url, cid=comp.id)
        # PLUG-019: something that starts with the session and uses the network.
        for hd in [manifest, *hook_docs]:
            for hook in iter_hooks(hd):
                cmd = str(hook.handler.get("command") or "")
                if hook.event.lower() in ("sessionstart", "setup", "workspaceopen") and cmd and search(_NET, cmd):
                    self.flag(rule_x or "AG-PLUG-019", hd, (*hook.keypath, "command"), f"The plugin's {hook.event} hook uses the "
                              "network every time a session starts.", value=cmd, cid=comp.id)
        for c in self.cmds:
            if c.path.startswith(prefix) and (c.surface == "claude.monitors" or "monitors" in c.keypath) and search(_NET, c.text):
                ctx.emit(rule_x or "AG-PLUG-019", component_ids=comp.id, span=c.span, snippet=c.text[:300], kind=EvidenceKind.config,
                         match=f"{c.path}:{c.text[:100]}", message="A monitor of this plugin starts with the session, runs in the "
                                                                   "background and uses the network.")
        # PLUG-021: a channel that accepts inbound messages from anyone.
        channels = d.get("channels")
        if channels:
            text = str(channels)
            if not _SENDER_KEYS.search(text):
                self.flag("AG-PLUG-021", manifest, ("channels",), "The plugin declares a channel that takes inbound messages and "
                          "does not restrict who may send them; each message reaches the agent as input.", value=None,
                          snippet="channels", cid=comp.id)
        # PLUG-022: Gemini / Cursor / Codex manifest specifics.
        if agent in ("cursor", "codex", "gemini"):
            if isinstance(d.get("migratedTo"), str):
                self.flag("AG-PLUG-022", manifest, ("migratedTo",), f"The extension redirects to `{d['migratedTo'][:100]}`: an "
                          "update replaces it with whatever that source holds.", value=d["migratedTo"], cid=comp.id)
            if d.get("autoUpdate") is True:
                self.flag("AG-PLUG-022", manifest, ("autoUpdate",), "The extension turns auto-update on for itself.", value=True,
                          cid=comp.id)
        # PLUG-023: risky and enabled by default.
        if any(d.get(k) is True for k in _DEFAULT_ON) and (has_hooks or has_servers or code_files):
            parts = [w for w, on in (("hooks", has_hooks), ("servers", has_servers), ("code", bool(code_files))) if on]
            self.flag("AG-PLUG-023", manifest, (next(k for k in _DEFAULT_ON if d.get(k) is True),), f"The plugin is enabled by "
                      f"default and ships {', '.join(parts)}.", value=True, cid=comp.id)
        # EXEC-016: a bin/ entry named like a common command.
        for p in code_files:
            if surf[p] != "plugin.bin":
                continue
            stem = regex.sub(r"\.(?:exe|cmd|bat|sh|ps1|py|js)$", "", posixpath.basename(p), flags=_F).lower()
            if stem in COMMON_COMMANDS:
                ctx.emit("AG-EXEC-016", component_ids=comp.id, span=Span(path=p), snippet=p, kind=EvidenceKind.config,
                         match=f"bin:{p}", message=f"`{posixpath.basename(p)}` in the plugin's `bin/` has the name of a common "
                                                   f"command. `bin/` is added to the Bash tool's PATH, so `{stem}` may run the "
                                                   "plugin's file instead of the real program.")
        # EXEC-017: in-process code that executes commands or talks to the network.
        in_process = [p for p in code_files if surf[p] in ("plugin.workflow", "plugin.mod")]
        if native:
            in_process += sorted(p for p in inv.texts if p.startswith(prefix) and inv.artifacts[p].role == ArtifactRole.script
                                 and regex.search(r"(?:^|/)(?:index|main|plugin|extension)\.(?:ts|js|mjs|cjs)$", p))
        for p in in_process:
            at = inv.texts.get(p)
            if at is None:
                continue
            m = search(EXEC_CODE, at.text) or search(EGRESS_CODE, at.text)
            if m:
                what = "runs commands" if search(EXEC_CODE, at.text) else "makes network requests"
                where = "inside the gateway process" if native else "inside the agent's own process"
                ctx.emit("AG-EXEC-017", component_ids=comp.id, span=at.span(m.start(), m.end()), kind=EvidenceKind.ast,
                         snippet=at.line_text(m.start()).strip()[:300], match=f"{p}:{m.group(0)}",
                         message=f"`{posixpath.basename(p)}` {what} and is loaded {where}, outside any sandbox and with no prompt.")

    def _user_config(self, doc: Doc, config: Any, field: str, rule: str, cid: str) -> None:
        if not isinstance(config, dict):
            return
        for key, spec in config.items():
            if not isinstance(spec, dict) or spec.get("sensitive") is True:
                continue
            text = " ".join(str(spec.get(k) or "") for k in ("title", "description", "name")) + " " + str(key)
            if _SECRET_NAME.search(text):
                self.flag(rule, doc, (field, str(key)), f"`{field}.{key}` asks the user for a secret and is not marked "
                          "`sensitive: true`, so the value is stored and shown as plain text.", value=None,
                          snippet=f"{field}.{key}", cid=cid)

    # -- helper commands (MCP-006, EXEC-019) ---------------------------------------------------------------------
    def _helpers(self) -> None:
        ctx, inv = self.ctx, self.ctx.inventory
        for cfg in inv.configs:
            for entry in cfg.servers:
                helper = entry.raw.get("headersHelper") or entry.raw.get("http_headers_helper")
                if not helper:
                    continue
                text = helper if isinstance(helper, str) else " ".join(str(x) for x in helper) if isinstance(helper, list) else str(helper)
                sid = inv.server_components.get((cfg.path, entry.project or "", entry.name))
                span = Span(path=cfg.path, start_line=entry.line)
                ctx.emit("AG-MCP-006", component_ids=[sid] if sid else [], span=span, snippet=f"headersHelper: {text[:200]}",
                         kind=EvidenceKind.config, match=f"{entry.name}:helper",
                         message=f"Server '{entry.name}' gets its request headers from a helper command (`{text[:80]}`), which "
                                 "runs on every connection.")
                self._shell_helper(cfg.path, sid or "", span, "headersHelper", text)
        for c in self.cmds:
            key = c.key.lower()
            if key in ("apikeyhelper", "awsauthrefresh", "awscredentialexport", "gcpauthrefresh", "otelheadershelper", "headershelper",
                       "http_headers_helper") or (key == "command" and len(c.keypath) >= 2 and c.keypath[-2].lower() in ("auth", "source")):
                self._shell_helper(c.path, c.component_id, c.span, ".".join(k for k in c.keypath if not k.isdigit())[-60:], c.text)

    def _shell_helper(self, path: str, cid: str, span: Span, key: str, text: str) -> None:
        parts = text.split()
        why = risky_launch(parts[0] if parts else "", parts[1:]) or ("it is a shell pipeline" if search(_SHELL_META, text) else "")
        if why:
            self.ctx.emit("AG-EXEC-019", component_ids=[cid] if cid else [], span=span, snippet=f"{key}: {text[:240]}",
                          kind=EvidenceKind.config, match=f"{path}:{key}:{text[:100]}",
                          message=f"The helper command in `{key}` is not a single program: {why}. It runs automatically and "
                                  "repeatedly with the user's permissions.")

    # -- a server launched from outside the package (MCP-008) -----------------------------------------------------
    def _server_paths(self) -> None:
        ctx, inv = self.ctx, self.ctx.inventory
        for cfg in inv.configs:
            if not is_repo_file(cfg.path) or cfg.scope == "user":
                continue
            base = posixpath.dirname(cfg.path)
            for entry in cfg.servers:
                if not entry.spec.command:
                    continue
                cands = [entry.spec.command, *entry.spec.args[:6]]
                for value in cands:
                    v = value.replace("\\", "/")
                    if not regex.search(r"\.(?:js|mjs|cjs|ts|py|sh|rb|pl|php|jar|exe|bin)$", v, _F) and value is not entry.spec.command:
                        continue
                    if regex.match(r"\$\{?(?:CLAUDE_PLUGIN_ROOT|CLAUDE_PROJECT_DIR|workspaceFolder|__dirname|PWD)", v):
                        continue
                    outside = False
                    if v.startswith(("~", "$HOME", "${HOME}", "%USERPROFILE%")) or regex.match(r"[A-Za-z]:/", v):
                        outside = True
                    elif v.startswith("/"):
                        outside = not regex.match(r"/(?:usr|bin|sbin|opt/homebrew|nix|snap)/", v) or value is not entry.spec.command
                    elif "/" in v and posixpath.normpath(posixpath.join(base, v)).startswith(".."):
                        outside = True
                    if outside:
                        sid = inv.server_components.get((cfg.path, entry.project or "", entry.name))
                        ctx.emit("AG-MCP-008", component_ids=[sid] if sid else [], span=Span(path=cfg.path, start_line=entry.line),
                                 snippet=" ".join(cands)[:300], kind=EvidenceKind.config, match=f"{entry.name}:{value}",
                                 message=f"Server '{entry.name}' is started from `{value}`, a path outside the repository or "
                                         "plugin: the code that runs is not part of what was scanned.")
                        break

    # -- LSP servers and monitors (EXEC-018) -----------------------------------------------------------------------
    def _background_processes(self) -> None:
        for c in self.cmds:
            keys = [k.lower() for k in c.keypath]
            if c.surface in ("claude.lsp", "claude.monitors") or any(k in ("lspservers", "monitors") for k in keys):
                parts = c.text.split()
                why = risky_launch(parts[0] if parts else "", parts[1:])
                if why:
                    kind = "monitor" if c.surface == "claude.monitors" or "monitors" in keys else "LSP server"
                    self.ctx.emit("AG-EXEC-018", component_ids=[c.component_id] if c.component_id else [], span=c.span,
                                  snippet=c.text[:300], kind=EvidenceKind.config, match=f"{c.path}:{c.text[:100]}",
                                  message=f"The {kind} entry does not start a {kind.split()[0].lower()} program: {why}. It "
                                          "starts with the session and keeps running in the background.")

    # -- MCPB bundles (MCP-062, 063, 065) ---------------------------------------------------------------------------
    def _bundle(self, doc: Doc) -> None:
        ctx, inv = self.ctx, self.ctx.inventory
        d = doc.data
        cid = self._cid(doc.path)
        comp = inv.components.get(cid)
        cfg = _get(d, "server", "mcp_config")
        if isinstance(cfg, dict):
            cmd = str(cfg.get("command") or "")
            args = [str(a) for a in cfg.get("args") or []] if isinstance(cfg.get("args"), list) else []
            why = risky_launch(cmd, args)
            if why:
                self.flag("AG-MCP-062", doc, ("mcp_config", "command"), f"The bundle's launch command (`{' '.join([cmd, *args])[:80]}`) "
                          f"is risky: {why}.", value=cmd, cid=cid)
            overrides = cfg.get("platform_overrides")
            if isinstance(overrides, dict):
                for plat, over in overrides.items():
                    if isinstance(over, dict) and isinstance(over.get("command"), str) and over["command"] != cmd:
                        o_args = [str(a) for a in over.get("args") or []] if isinstance(over.get("args"), list) else []
                        o_why = risky_launch(over["command"], o_args)
                        self.flag("AG-MCP-062", doc, ("platform_overrides", str(plat), "command"), f"On {plat} the bundle starts "
                                  f"`{over['command'][:60]}` instead of `{cmd[:60]}`"
                                  + (f", and that command is risky: {o_why}" if o_why else "") + ". Review each platform's command.",
                                  value=over["command"], cid=cid, severity=None if o_why else Severity.medium)
        self._user_config(doc, d.get("user_config"), "user_config", "AG-MCP-065", cid)
        if comp is None:
            return
        declared = {t.get("name") for t in d.get("tools") or [] if isinstance(t, dict) and isinstance(t.get("name"), str)}
        served = {t.name for t in comp.tools if t.origin in ("source_extraction", "live_list")}
        facts = ctx.options.facts.get("served_tools") if isinstance(ctx.options.facts, dict) else None
        if isinstance(facts, dict):
            listed = facts.get(comp.name) or facts.get(comp.root) or facts.get(doc.path)
            if isinstance(listed, list):
                served |= {str(x) for x in listed}
        if served and d.get("tools_generated") is not True:
            extra, missing = sorted(served - declared), sorted(declared - served)
            if extra or (missing and isinstance(facts, dict)):
                bits = []
                if extra:
                    bits.append(f"serves {', '.join(extra[:5])} which the manifest does not declare")
                if missing and isinstance(facts, dict):
                    bits.append(f"declares {', '.join(missing[:5])} which it does not serve")
                self.flag("AG-MCP-063", doc, ("tools",), f"The bundle {' and '.join(bits)}. What a user reviews in the manifest is "
                          "not the tool set the agent gets.", value=None, snippet="tools: " + ", ".join(sorted(declared)[:8]), cid=cid)

    # -- registry entries (MCP-061) ------------------------------------------------------------------------------------
    def _registry_bundles(self) -> None:
        ctx, inv = self.ctx, self.ctx.inventory
        tree = inv.tree
        recorded = ctx.options.facts.get("artifact_sha256") if isinstance(ctx.options.facts, dict) else None
        for path, manifest in sorted(inv.manifests.items()):
            art = inv.artifacts.get(path)
            if art is None or art.role != ArtifactRole.server_json or not isinstance(manifest, dict):
                continue
            text = tree.files[path].data.decode("utf-8", "replace") if tree is not None and path in tree.files else ""
            for pkg in manifest.get("packages") or []:
                if not isinstance(pkg, dict) or str(pkg.get("registryType") or pkg.get("registry_type") or "").lower() != "mcpb":
                    continue
                ident = str(pkg.get("identifier") or "")
                want = str(pkg.get("fileSha256") or pkg.get("file_sha256") or "").lower()
                span = span_of(text, ident or '"mcpb"', path=path)
                actual = ""
                if isinstance(recorded, dict) and isinstance(recorded.get(ident), str):
                    actual = recorded[ident].lower()
                elif tree is not None:
                    local = next((p for p in tree.files if ident and posixpath.basename(p) == posixpath.basename(ident.split("?")[0])
                                  and p.lower().endswith((".mcpb", ".dxt"))), None)
                    actual = tree.files[local].sha256 if local else ""
                if not want:
                    ctx.emit("AG-MCP-061", component_ids=art.component_id, span=span, snippet=ident[:200], kind=EvidenceKind.config,
                             match=f"{path}:{ident}:nohash", message=f"The registry entry names the bundle `{ident[:100]}` with no "
                                                                     "`fileSha256`. The registry does not check bundle hashes, so "
                                                                     "nothing ties the entry to the file that is downloaded.")
                elif actual and actual != want:
                    ctx.emit("AG-MCP-061", component_ids=art.component_id, span=span, snippet=f"{ident[:120]} sha256 {actual[:16]}…",
                             kind=EvidenceKind.config, match=f"{path}:{ident}:mismatch",
                             message=f"The bundle `{ident[:100]}` hashes to {actual[:16]}…, not the {want[:16]}… the registry entry "
                                     "declares: the file is not the one the entry describes.")

    def _unsigned_bundles(self) -> None:
        ctx, inv = self.ctx, self.ctx.inventory
        tree = inv.tree
        if tree is None:
            return
        for path in sorted(tree.files):
            if not path.lower().endswith((".mcpb", ".dxt")) or path not in inv.unpacked:
                continue
            data = tree.files[path].data
            if not any(marker in data[-65536:] for marker in _SIG_MARKERS):
                cid = self._cid(path)
                ctx.emit("AG-MCP-064", component_ids=[cid] if cid else [], span=Span(path=path), snippet=path, kind=EvidenceKind.config,
                         match=f"unsigned:{path}", message=f"The bundle `{posixpath.basename(path)}` carries no signature block; "
                                                           "its origin cannot be checked from the file.")

    # -- icons (MCP-034) -------------------------------------------------------------------------------------------------
    def _icons(self) -> None:
        ctx, inv = self.ctx, self.ctx.inventory
        tree = inv.tree
        sources: list[tuple[str, Any]] = [(p, v) for p, v in inv.manifests.items()]
        sources += [(p, d.value) for p, d in inv.docs.items() if d.surface.id in ("bundle.mcpb", "claude.plugin", "gemini.extension")]
        seen: set[tuple[str, str]] = set()
        for path, value in sorted(sources, key=lambda x: x[0]):
            text = tree.files[path].data.decode("utf-8", "replace") if tree is not None and path in tree.files else ""
            stack: list[Any] = [value]
            icons: list[Any] = []
            n = 0
            while stack and n < 20000:
                node = stack.pop()
                n += 1
                if isinstance(node, dict):
                    for k, v in node.items():
                        if k in ("icons", "icon"):
                            icons += v if isinstance(v, list) else [v]
                        elif isinstance(v, (dict, list)):
                            stack.append(v)
                elif isinstance(node, list):
                    stack.extend(x for x in node if isinstance(x, (dict, list)))
            for icon in icons[:200]:
                src = icon.get("src") or icon.get("url") if isinstance(icon, dict) else icon if isinstance(icon, str) else None
                if not isinstance(src, str) or (path, src) in seen:
                    continue
                seen.add((path, src))
                why = ""
                low = src.lower()
                if low.startswith(("http://", "https://")) and not is_local_host(_host(src)):
                    why = f"is loaded from `{_host(src)}` every time the client shows it, which tells that host who is using the server"
                elif low.startswith("data:image/svg") and regex.search(r"script|onload|onerror|foreignobject|javascript:|%3cscript", low):
                    why = "is an inline SVG that carries script"
                elif low.endswith(".svg") and tree is not None:
                    local = posixpath.normpath(posixpath.join(posixpath.dirname(path), src))
                    blob = tree.files.get(local)
                    if blob is not None and regex.search(rb"(?i)<script|\bon(?:load|error|click)\s*=|<foreignObject|javascript:", blob.data):
                        why = "is an SVG file that carries script or event handlers"
                if why:
                    cid = self._cid(path)
                    ctx.emit("AG-MCP-034", component_ids=[cid] if cid else [], span=span_of(text, src[:60], path=path),
                             snippet=src[:200], kind=EvidenceKind.config, match=f"{path}:icon:{sha256_hex(src)[:12]}",
                             message=f"An icon {why}.")


__all__ = ["COMMON_COMMANDS", "PluginAnalyzer", "RESERVED_MARKETPLACES", "risky_launch"]
