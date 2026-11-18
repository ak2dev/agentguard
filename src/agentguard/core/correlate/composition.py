"""Composition: the candidate evaluated together with what is already installed (engine I).

Each component of the scanned tree, and of the installed context
(``options.context``, an ``ArtifactTree``), gets a profile: the files it
writes, the files it runs or obeys, the environment variables it sets and
executes, the skills it invokes by name, the memory and instruction files it
writes, and its capability labels. Chains are then looked for across pairs of
components with at least one side in the candidate:

* AG-FLOW-004  sensitive data in one, external communication in the other
* AG-FLOW-005  one writes a file the other executes or obeys
* AG-FLOW-006  one sets an environment variable or state the other executes
* AG-FLOW-007  a skill invokes a sensitive skill by name
* AG-FLOW-008  one writes memory the other is given as instructions
* AG-FLOW-009  instructions route one server's tool output into another server's sink
* AG-FLOW-013  the candidate replaces, edits or redirects an installed component
* AG-META-013  the candidate's description nearly duplicates an installed skill's

Pure: both trees are data; nothing is executed.
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass, field
from typing import ClassVar

import regex

from ..analyzers.base import Context
from ..artifacts import ArtifactText
from ..inventory import Inventory, build_inventory
from ..models import Component, Span
from ..models.enums import ArtifactRole, CapLabel, ComponentKind, EvidenceKind, Severity
from ..textutil import TIMEOUT
from .flows import build_nodes

_F = regex.IGNORECASE
L = CapLabel
_PATH = r"(?:~|\$\{?HOME\}?|\$\{?TMPDIR\}?|\$\{?XDG_\w+\}?|/tmp|/var/tmp|/dev/shm|\.{1,2}|\.[\w-]+|[\w-]+)(?:/[\w.@+-]+)+"
_WRITE = regex.compile(
    r"(?:>>?|\btee\s+(?:-a\s+)?)\s*[\"']?(?P<a>" + _PATH + r")"
    r"|\bopen\(\s*(?:os\.path\.expanduser\(\s*)?[\"'](?P<b>" + _PATH + r")[\"']\s*\)?\s*,\s*[\"'][wax]"
    r"|\b(?:Path\(\s*[\"'](?P<c>" + _PATH + r")[\"']\s*\)(?:\.expanduser\(\))?\.write_(?:text|bytes)|(?:writeFile|appendFile)(?:Sync)?\(\s*[\"'`](?P<d>" + _PATH + r"))"
    r"|\b(?:write|save|store|append|put|record|dump|log|copy|export)s?\b[^.\n]{0,60}?\b(?:to|into|in|at|as)\s+(?:the\s+file\s+)?[`\"']?(?P<e>" + _PATH + r")", _F)
_RUN = regex.compile(
    r"\b(?:bash|sh|zsh|source|python3?|node|exec|chmod\s+\+x)\s+(?:-\w+\s+)*[\"']?(?P<a>" + _PATH + r")"
    r"|(?:^|[;&|]\s*|`)\s*\.\s+[\"']?(?P<b>" + _PATH + r")"
    r"|\b(?:run|execute|source|follow|obey|apply|load|import|carry\s+out|act\s+on)\b[^.\n]{0,60}?\b(?:in|from|at)?\s*[`\"']?(?P<c>" + _PATH + r")"
    r"|\bread\s+[`\"']?(?P<d>" + _PATH + r")[`\"']?\s+(?:and|then)\s+(?:follow|do|obey|execute|apply)", _F | regex.MULTILINE)
_ENV_SET = regex.compile(
    r"\bexport\s+(?P<a>[A-Z][A-Z0-9_]{2,})="
    r"|\bos\.environ\[\s*[\"'](?P<b>[A-Z][A-Z0-9_]{2,})[\"']\s*\]\s*="
    r"|\bprocess\.env\.(?P<c>[A-Z][A-Z0-9_]{2,})\s*=(?!=)"
    r"|\becho\s+[\"']?(?:export\s+)?(?P<d>[A-Z][A-Z0-9_]{2,})=[^\n]*>>"
    r"|\bset\s+(?:the\s+)?(?:environment\s+variable|env(?:ironment)?\s+var)\s+[`\"']?(?P<e>[A-Z][A-Z0-9_]{2,})")
_ENV_EXEC = regex.compile(
    r"\b(?:eval|source|exec|(?:ba|z)?sh\s+-c)\s+[\"']?\$\{?(?P<a>[A-Z][A-Z0-9_]{2,})\}?"
    r"|(?:^|[;&|]\s*|`)\s*\$\{?(?P<b>[A-Z][A-Z0-9_]{2,})\}?(?=[\s`;&|]|$)"
    r"|\b(?:curl|wget)\s+[^\n|;]*?\$\{?(?P<c>[A-Z][A-Z0-9_]{2,})\}?"
    r"|\b(?:os\.system|subprocess\.\w+|exec|eval)\(\s*os\.environ(?:\.get\(|\[)\s*[\"'](?P<d>[A-Z][A-Z0-9_]{2,})"
    r"|\b(?:run|execute|eval(?:uate)?)\s+(?:the\s+)?(?:command|contents?|value|script)\s+(?:in|of|from)\s+[`\"']?\$?\{?(?P<e>[A-Z][A-Z0-9_]{2,})", regex.MULTILINE)
_COMMON_ENV = regex.compile(r"^(?:PATH|HOME|USER|PWD|OLDPWD|SHELL|LANG|LC_\w+|TERM|TMPDIR|TEMP|TMP|CI|EDITOR|VISUAL|PAGER|GITHUB_\w+|CLAUDE_\w+"
                            r"|CODEX_\w+|GEMINI_\w+|XDG_\w+|NODE_ENV|PYTHONPATH|HOSTNAME|DISPLAY|SSH_\w+)$")
_INVOKE = regex.compile(
    r"\b(?:use|invoke|call|run|trigger|launch|activate|hand\s+off\s+to|delegate\s+to)\s+(?:the\s+)?[`\"']?/?(?P<a>[a-z0-9][a-z0-9-]{1,63})[`\"']?\s+"
    r"(?:skill|command|subagent|agent)\b"
    r"|\bSkill\(\s*[\"']?(?P<b>[a-z0-9][a-z0-9:-]{1,63})"
    r"|`/(?P<c>[a-z0-9][a-z0-9-]{2,63})`", _F)
_MEMORY_FILE = regex.compile(
    r"(?:^|/)(?:CLAUDE(?:\.local)?|AGENTS(?:\.override)?|GEMINI|MEMORY|SOUL|USER|IDENTITY|BOOT|BOOTSTRAP)\.md$|(?:^|/)\.cursorrules$"
    r"|(?:^|/)copilot-instructions\.md$|(?:^|/)\.claude/(?:rules|projects/[^/]+/memory)/[^/]+\.md$|(?:^|/)\.cursor/rules/[^/]+\.mdc?$"
    r"|(?:^|/)memory/[\w.-]+\.md$|(?:^|/)\.(?:windsurf|clinerules|roo|kiro)\w*(?:/|$)", _F)
_TOOL_REF = regex.compile(r"\bmcp__([A-Za-z0-9-]+)__([A-Za-z0-9_-]+)\b")
_SINK_TOOL = regex.compile(r"(?:^|_)(?:send|post|upload|publish|create|share|reply|comment|tweet|email|message|webhook|write|push|forward)(?:_|$)", _F)
_SOURCE_TOOL = regex.compile(r"(?:^|_)(?:read|get|list|search|query|fetch|export|download|find|dump)(?:_|$)", _F)
_REDIRECT = regex.compile(
    r"\b(?:when(?:ever)?|every\s+time|each\s+time|before|after|instead\s+of)\s+(?:you\s+)?(?:us(?:e|ing)|invok(?:e|ing)|call(?:ing)?|run(?:ning)?)\s+"
    r"(?:the\s+)?[`\"']?/?(?P<name>[A-Za-z0-9][A-Za-z0-9_-]{1,63})[`\"']?\s+(?:skill|tool|server|command|plugin|agent)\b"
    r"[^.\n]{0,100}\b(?:instead|also|first|always|never|do\s+not|don'?t|skip|ignore|replace|override|add|send|use)\b", _F)
_SENSITIVE_LABELS = frozenset({L.destructive, L.credential_access, L.external_egress, L.financial, L.shell, L.code_exec, L.host_elevated,
                               L.fs_write_outside, L.persistence})
_DATA_LABELS = frozenset({L.reads_private_data, L.credential_access})
_SKIP_KINDS = (ComponentKind.repository, ComponentKind.mcp_client_config)
_STOP = frozenset("a an the and or of to for in on with by from this that these those is are be it its your you use uses used using when "
                  "into as at any all can will helps help skill tool".split())
MAX_TEXT = 400_000


def _finditer(rx: regex.Pattern[str], text: str) -> list[regex.Match[str]]:
    try:
        return list(rx.finditer(text[:MAX_TEXT], timeout=TIMEOUT))
    except TimeoutError:
        return []


def norm_path(p: str) -> str:
    p = p.strip("\"'`").rstrip(".,;:)")
    p = regex.sub(r"^\$\{?HOME\}?", "~", p)
    p = regex.sub(r"^\$\{?TMPDIR\}?", "/tmp", p)
    return posixpath.normpath(p) if not p.startswith("~") else "~" + posixpath.normpath(p[1:])


def shared_path(p: str) -> bool:
    """A path two components can both reach: absolute, in the home directory, in a temp directory, or in a dot-directory
    of the workspace. Paths relative to a component's own folder are not shared."""
    return p.startswith(("~", "/tmp", "/var/tmp", "/dev/shm", "/")) or p.startswith(".") and not p.startswith(("./", "../"))


def tokens(text: str) -> set[str]:
    return {w for w in regex.findall(r"[a-z0-9]+", text.lower()) if len(w) > 2 and w not in _STOP}


@dataclass
class Profile:
    comp: Component
    installed: bool                       # from the installed context, not from the candidate
    labels: set[CapLabel] = field(default_factory=set)
    description: str = ""
    writes: dict[str, Span] = field(default_factory=dict)
    runs: dict[str, Span] = field(default_factory=dict)
    env_set: dict[str, Span] = field(default_factory=dict)
    env_exec: dict[str, Span] = field(default_factory=dict)
    invokes: dict[str, Span] = field(default_factory=dict)
    redirects: dict[str, Span] = field(default_factory=dict)
    tool_flows: list[tuple[str, str, str, str, Span]] = field(default_factory=list)   # (server a, tool a, server b, tool b, where)
    instruction_files: set[str] = field(default_factory=set)        # base names of the instruction files this component is

    @property
    def name(self) -> str:
        return self.comp.name

    def what(self) -> str:
        return f"{self.comp.kind.spec_type} '{self.comp.name}'" + (" (installed)" if self.installed else "")


def _span(at: ArtifactText, m: regex.Match[str], group: str | None = None) -> Span:
    s, e = (m.start(group), m.end(group)) if group else (m.start(), m.end())
    return at.span(s, e)


def _first_group(m: regex.Match[str]) -> tuple[str, str] | None:
    for name, value in m.groupdict().items():
        if value:
            return name, value
    return None


def profiles_of(inv: Inventory, labels: dict[str, set[CapLabel]], installed: bool) -> list[Profile]:
    by_comp: dict[str, list[ArtifactText]] = {}
    for at in inv.texts.values():
        by_comp.setdefault(at.artifact.component_id, []).append(at)
    out: list[Profile] = []
    for cid in sorted(inv.components):
        comp = inv.components[cid]
        if comp.kind in _SKIP_KINDS:
            continue
        prof = Profile(comp=comp, installed=installed, labels=set(labels.get(cid, set())) | comp.labels())
        for at in sorted(by_comp.get(cid, []), key=lambda t: t.path):
            role = at.artifact.role
            if role == ArtifactRole.skill_md and at.fm is not None and isinstance(at.fm.data, dict):
                prof.description = prof.description or str(at.fm.data.get("description") or "")
            if role == ArtifactRole.instruction_md:
                prof.instruction_files.add(posixpath.basename(at.path).lower())
            if role in (ArtifactRole.binary, ArtifactRole.archive, ArtifactRole.lockfile):
                continue
            text = at.text
            for m in _finditer(_WRITE, text):
                g = _first_group(m)
                if g and shared_path(norm_path(g[1])):
                    prof.writes.setdefault(norm_path(g[1]), _span(at, m, g[0]))
            for m in _finditer(_RUN, text):
                g = _first_group(m)
                if g and shared_path(norm_path(g[1])):
                    prof.runs.setdefault(norm_path(g[1]), _span(at, m, g[0]))
            for m in _finditer(_ENV_SET, text):
                g = _first_group(m)
                if g and not _COMMON_ENV.match(g[1]):
                    prof.env_set.setdefault(g[1], _span(at, m, g[0]))
            for m in _finditer(_ENV_EXEC, text):
                g = _first_group(m)
                if g and not _COMMON_ENV.match(g[1]):
                    prof.env_exec.setdefault(g[1], _span(at, m, g[0]))
            if role in (ArtifactRole.skill_md, ArtifactRole.instruction_md, ArtifactRole.command_md, ArtifactRole.reference):
                for m in _finditer(_INVOKE, text):
                    g = _first_group(m)
                    if g:
                        prof.invokes.setdefault(g[1].lower().split(":")[-1], _span(at, m, g[0]))
                for m in _finditer(_REDIRECT, text):
                    prof.redirects.setdefault(m.group("name").lower(), _span(at, m))
                for line_m in _finditer(regex.compile(r"[^\n]*mcp__[^\n]*"), text):
                    refs = list(_TOOL_REF.finditer(line_m.group(0)))
                    for a in refs:
                        for b in refs:
                            if a.group(1) != b.group(1) and a.start() < b.start() and _SOURCE_TOOL.search(a.group(2)) \
                                    and _SINK_TOOL.search(b.group(2)) and not _SOURCE_TOOL.match(b.group(2)):
                                prof.tool_flows.append((a.group(1), a.group(2), b.group(1), b.group(2),
                                                        at.span(line_m.start() + a.start(), line_m.start() + b.end())))
        out.append(prof)
    return out


def context_profiles(ctx: Context) -> list[Profile]:
    """Profiles of the installed components (``options.context``), built once per scan."""
    cached = ctx.data.get("_context_profiles")
    if cached is not None:
        return cached  # type: ignore[return-value]
    profiles: list[Profile] = []
    tree = ctx.options.context
    if tree is not None and getattr(tree, "files", None):
        from ..analyzers.capabilities import CapabilityAnalyzer
        from ..analyzers.code import CodeAnalyzer
        from ..analyzers.config_units import ConfigUnitsBuilder
        from ..analyzers.mcp import McpUnitsBuilder
        from ..analyzers.privilege import PrivilegeAnalyzer

        inv = build_inventory(tree, ctx.options.limits)
        sub = Context(inventory=inv, pack=ctx.pack, options=ctx.options.model_copy(update={"context": None}))
        for cls in (McpUnitsBuilder, ConfigUnitsBuilder, CodeAnalyzer, CapabilityAnalyzer, PrivilegeAnalyzer):
            sub.current, sub.allowed_rules = cls.id, frozenset(cls.rules)
            try:
                cls().run(sub)
            except Exception:  # noqa: BLE001 - a context component that cannot be labelled is still profiled from its text
                continue
        profiles = profiles_of(inv, _labels(sub), installed=True)
    ctx.data["_context_profiles"] = profiles
    return profiles


def _labels(ctx: Context) -> dict[str, set[CapLabel]]:
    out: dict[str, set[CapLabel]] = {}
    for node in build_nodes(ctx):
        out.setdefault(node.component.id, set()).update(node.labels)
    return out


class CompositionAnalyzer:
    id: ClassVar[str] = "composition"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = ("AG-FLOW-004", "AG-FLOW-005", "AG-FLOW-006", "AG-FLOW-007", "AG-FLOW-008", "AG-FLOW-009",
                                        "AG-FLOW-013", "AG-META-013")

    def run(self, ctx: Context) -> None:
        self.ctx = ctx
        mine = profiles_of(ctx.inventory, _labels(ctx), installed=False)
        theirs = context_profiles(ctx)
        if not mine:
            return
        everyone = [*mine, *theirs]
        for a in mine:
            self._tool_flows(a)
            for b in everyone:
                if b is a:
                    continue
                self._pair(a, b)
            self._installed(a, theirs)

    def _emit(self, rule: str, a: Profile, span: Span | None, key: str, message: str, *, snippet: str = "",
              related: list[Span] | None = None, severity: Severity | None = None) -> None:
        self.ctx.emit(rule, component_ids=a.comp.id, span=span, snippet=snippet or key, match=f"{a.comp.id}:{key}", kind=EvidenceKind.flow,
                      message=message, related=[r for r in (related or []) if r is not None], severity=severity)

    def _where(self, p: Profile, span: Span | None) -> list[Span]:
        """Spans of an installed component are outside the scanned tree: they are named in the message, not linked."""
        return [span] if span is not None and not p.installed else []

    # -- pairs --------------------------------------------------------------------------------------
    def _pair(self, a: Profile, b: Profile) -> None:
        # AG-FLOW-005: a writes, b runs (and the reverse when b is installed: the candidate runs what an installed one writes)
        for writer, reader in ((a, b), (b, a)) if b.installed else ((a, b),):
            for path in sorted(set(writer.writes) & set(reader.runs)):
                if _MEMORY_FILE.search(path):
                    continue
                span = writer.writes[path] if writer is a else reader.runs[path]
                other = reader if writer is a else writer
                self._emit("AG-FLOW-005", a, span, f"file:{path}:{other.comp.name}",
                           f"{writer.what().capitalize()} writes `{path}` and {reader.what()} runs or follows that file. Neither "
                           "does anything alarming alone; together the first one decides what the second one executes.",
                           snippet=path, related=self._where(other, other.runs.get(path) or other.writes.get(path)))
                break
            for var in sorted(set(writer.env_set) & set(reader.env_exec)):
                span = writer.env_set[var] if writer is a else reader.env_exec[var]
                other = reader if writer is a else writer
                self._emit("AG-FLOW-006", a, span, f"env:{var}:{other.comp.name}",
                           f"{writer.what().capitalize()} sets the environment variable `{var}` and {reader.what()} executes its "
                           "value. The variable is a channel between the two that no review of either one shows.",
                           snippet=var, related=self._where(other, other.env_exec.get(var) or other.env_set.get(var)))
                break
        # AG-FLOW-008: a writes a memory or instruction file that b is, or that b follows
        for path in sorted(a.writes):
            if not _MEMORY_FILE.search(path):
                continue
            base = posixpath.basename(path).lower()
            if base in b.instruction_files or path in b.runs:
                self._emit("AG-FLOW-008", a, a.writes[path], f"memory:{path}:{b.comp.name}",
                           f"{a.what().capitalize()} writes `{path}`, and {b.what()} is loaded from that file as instructions. What "
                           "the first one writes there is obeyed in every later session.", snippet=path,
                           related=self._where(b, b.runs.get(path)))
                break
        # AG-FLOW-007: a invokes b by name, and b is sensitive
        if b.comp.kind in (ComponentKind.skill, ComponentKind.command, ComponentKind.subagent) and b.name.lower() in a.invokes \
                and b.labels & _SENSITIVE_LABELS and a.comp.kind != ComponentKind.repository:
            caps = ", ".join(sorted(x.value for x in b.labels & _SENSITIVE_LABELS)[:4])
            self._emit("AG-FLOW-007", a, a.invokes[b.name.lower()], f"invoke:{b.name}",
                       f"{a.what().capitalize()} tells the agent to use {b.what()}, which can do sensitive things ({caps}). The "
                       "caller decides when that capability is used, with whatever input it supplies.", snippet=b.name)
        # AG-FLOW-004: sensitive data on one side, external communication on the other
        if a.comp.id < b.comp.id or b.installed:
            data_a, out_a = a.labels & _DATA_LABELS, L.external_egress in a.labels
            data_b, out_b = b.labels & _DATA_LABELS, L.external_egress in b.labels
            if not (data_a and out_a) and not (data_b and out_b) and ((data_a and out_b) or (data_b and out_a)):
                reader, sender = (a, b) if data_a and out_b else (b, a)
                self._emit("AG-FLOW-004", a, None, f"pair:{b.comp.name}",
                           f"{reader.what().capitalize()} reads sensitive data and {sender.what()} can send data out. Installed "
                           "together, an instruction that reaches the agent can chain them: read with the first, send with the "
                           "second.", snippet=f"{reader.name} + {sender.name}")

    # -- AG-FLOW-009 ----------------------------------------------------------------------------------
    def _tool_flows(self, a: Profile) -> None:
        seen: set[tuple[str, str]] = set()
        for src, tool_a, dst, tool_b, span in a.tool_flows:
            if (src, dst) in seen:
                continue
            seen.add((src, dst))
            self._emit("AG-FLOW-009", a, span, f"toolflow:{src}:{tool_a}:{dst}:{tool_b}",
                       f"{a.what().capitalize()} tells the agent to pass the result of `mcp__{src}__{tool_a}` to "
                       f"`mcp__{dst}__{tool_b}`: data read through one server leaves through another.",
                       snippet=f"mcp__{src}__{tool_a} -> mcp__{dst}__{tool_b}")

    # -- the candidate against what is installed -----------------------------------------------------------
    def _installed(self, a: Profile, theirs: list[Profile]) -> None:
        if not theirs:
            return
        kinds = (ComponentKind.skill, ComponentKind.command, ComponentKind.subagent, ComponentKind.plugin, ComponentKind.mcp_server)
        for b in theirs:
            if b.comp.kind not in kinds:
                continue
            same_kind = a.comp.kind == b.comp.kind
            if same_kind and a.name.lower() == b.name.lower():
                self._emit("AG-FLOW-013", a, self._name_span(a), f"same-name:{b.name}",
                           f"{a.what().capitalize()} has the same name as {b.what()}. Installing it replaces or shadows the one "
                           "you already use, and requests meant for that one go to this one.", snippet=a.name)
                continue
            root = b.comp.root.strip("/")
            hit = next((p for p in sorted(a.writes) if root and (p.lstrip("~/").startswith(root + "/") or ("/" + root + "/") in p)), None) \
                if root and "/" in root else None
            if hit is None and b.comp.kind in (ComponentKind.skill, ComponentKind.plugin):
                hit = next((p for p in sorted(a.writes)
                            if regex.search(rf"/(?:skills|plugins|commands|agents)/{regex.escape(b.name)}(?:/|$)", p, _F)), None)
            if hit is not None:
                self._emit("AG-FLOW-013", a, a.writes[hit], f"writes-into:{b.name}",
                           f"{a.what().capitalize()} writes `{hit}`, inside {b.what()}. It changes a component you installed and "
                           "reviewed separately.", snippet=hit)
                continue
            if b.name.lower() in a.redirects:
                self._emit("AG-FLOW-013", a, a.redirects[b.name.lower()], f"redirects:{b.name}",
                           f"{a.what().capitalize()} gives the agent rules for using {b.what()}. It changes how a component you "
                           "already installed behaves without touching that component's files.", snippet=b.name)
                continue
            if same_kind and a.comp.kind == ComponentKind.skill and a.description and b.description and a.name.lower() != b.name.lower():
                ta, tb = tokens(a.description), tokens(b.description)
                if len(ta) >= 5 and len(tb) >= 5 and len(ta & tb) / len(ta | tb) >= 0.8:
                    self._emit("AG-META-013", a, self._name_span(a, "description"), f"duplicate:{b.name}",
                               f"The description of {a.what()} is nearly the same as that of {b.what()}. The agent picks a skill "
                               "by its description, so requests meant for the installed one can be routed to this one.",
                               snippet=a.description[:200])

    def _name_span(self, a: Profile, key: str = "name") -> Span | None:
        inv = self.ctx.inventory
        for at in sorted(inv.texts.values(), key=lambda t: t.path):
            if at.artifact.component_id != a.comp.id:
                continue
            if at.fm is not None and at.fm.has_frontmatter:
                hit = at.text.find(f"{key}:")
                return at.span(hit if hit >= 0 else 0)
        if a.comp.server is not None and a.comp.server.config_span is not None:
            return a.comp.server.config_span
        first = next((p for p, art in sorted(inv.artifacts.items()) if art.component_id == a.comp.id), None)
        return Span(path=first) if first else None


__all__ = ["CompositionAnalyzer", "Profile", "context_profiles", "profiles_of"]
