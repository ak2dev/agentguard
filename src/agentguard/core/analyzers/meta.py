"""Metadata, identity and trigger checks that need more than a pattern (the META family).

AG-META-007 keyword stuffing · 009 inconsistent author, repository or version ·
010 a restriction one agent honours and another ignores · 011 reserved words in a
name · 012 the name of a built-in command or skill, placed where it wins ·
014 compatibility claims the purpose does not explain · 015 confusable
characters in a display name.
"""

from __future__ import annotations

import posixpath
from collections import Counter
from typing import Any, ClassVar

import regex

from ..artifacts import ArtifactText
from ..inventory_surfaces import Doc, span_of
from ..models import Span
from ..models.enums import ComponentKind, EvidenceKind, Severity
from ..normalize.unicode import _CONFUSABLES
from ..parsers import parse_json
from ..textutil import TIMEOUT
from .base import Context
from .skill import _fm_span

_F = regex.IGNORECASE
RESERVED_WORDS = ("anthropic", "claude")
_VENDOR_ORIGIN = regex.compile(r"(?:^|[/@.])github\.com[/:]anthropics/", regex.IGNORECASE)
# Locations more than one agent loads skills from (spec/ecosystems.md §4, §6, §7, §8).
_SHARED_SKILL_DIRS = (
    (regex.compile(r"(^|/)\.agents/skills/", _F), "Codex, Cursor, Copilot, Gemini CLI and OpenClaw"),
    (regex.compile(r"(^|/)\.claude/skills/", _F), "Cursor and GitHub Copilot"),
    (regex.compile(r"(^|/)\.codex/skills/", _F), "Cursor"),
)
_PRECEDENCE_DIR = regex.compile(r"(^|/)\.(?:claude|agents|codex|cursor|gemini)/(?:skills|commands)/|(^|/)\.github/skills/", _F)
_BROAD_COMPAT = regex.compile(
    r"\b(?:root|sudo|administrator|admin\s+(?:rights|privileges|access)|full\s+disk\s+access|unrestricted\s+(?:network|internet|access)"
    r"|(?:network|internet)\s+access|docker\s+socket|privileged|kernel|system-?wide|all\s+files)\b", _F)
_EXPLAINS = regex.compile(
    r"\b(?:network|internet|api|web|http|url|download|fetch|server|cloud|remote|online|deploy|install|system|admin|docker|container|"
    r"service|daemon|kernel|disk|backup|sync|upload|browser|email|search)\w*\b", _F)
_STOP = frozenset("the and for with from that this your you are can will use uses used using when into any all its not but also "
                  "have has was were then than them they their what which who how why where files file skill tool".split())


def _search(rx: regex.Pattern[str], text: str) -> regex.Match[str] | None:
    try:
        return rx.search(text, timeout=TIMEOUT)
    except TimeoutError:
        return None


def stuffing(description: str) -> str:
    """Why a description looks keyword-stuffed, or ""."""
    parts = [p.strip() for p in regex.split(r"[,;|/\n]", description) if p.strip()]
    short = [p for p in parts if len(p.split()) <= 3]
    if len(parts) >= 14 and len(short) / len(parts) >= 0.8:
        return f"it is a list of {len(parts)} short keywords"
    words = [w for w in regex.findall(r"[a-z][a-z0-9+#.-]{3,}", description.lower()) if w not in _STOP]
    if words:
        word, n = Counter(words).most_common(1)[0]
        if n >= 6 and n / len(words) >= 0.12:
            return f"the word '{word}' appears {n} times"
    return ""


class MetaAnalyzer:
    id: ClassVar[str] = "meta"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = ("AG-META-007", "AG-META-009", "AG-META-010", "AG-META-011", "AG-META-012", "AG-META-014",
                                        "AG-META-015")

    def run(self, ctx: Context) -> None:
        self.ctx = ctx
        inv = ctx.inventory
        builtin = {str(n).lower() for n in ctx.pack.data.get("builtin-names") or []}
        for at in ctx.texts():
            is_skill = at.artifact.role.value == "skill_md"
            surface = inv.surfaces.get(at.path)
            if not is_skill and at.artifact.role.value != "command_md" and not (surface is not None and surface.group == "command"):
                continue
            data: dict[Any, Any] = at.fm.data if at.fm is not None and isinstance(at.fm.data, dict) else {}
            comp = inv.components.get(at.artifact.component_id)
            if comp is None:
                continue
            name = str(data.get("name") or (comp.name if is_skill else posixpath.splitext(posixpath.basename(at.path))[0]))
            self._name(at, name, is_skill, builtin, "name" in data)
            if is_skill:
                self._skill(at, data, name)
        for comp in sorted(inv.components.values(), key=lambda c: c.id):
            if comp.kind in (ComponentKind.plugin, ComponentKind.mcp_server, ComponentKind.marketplace, ComponentKind.bundle,
                             ComponentKind.subagent):
                self._display_name(comp.id, comp.name, self._comp_span(comp), comp.kind.spec_type)
            if comp.kind == ComponentKind.plugin and any(w in comp.name.lower() for w in RESERVED_WORDS):
                self._reserved(comp.id, comp.name, self._comp_span(comp), "plugin")
        self._consistency()

    # -- helpers ------------------------------------------------------------------------------------
    def _comp_span(self, comp: Any) -> Span | None:
        if comp.server is not None and comp.server.config_span is not None:
            return comp.server.config_span
        manifest = comp.metadata.get("manifest") if isinstance(comp.metadata, dict) else None
        if manifest:
            doc = self.ctx.inventory.docs.get(manifest)
            return span_of(doc.text, '"name"', path=manifest) if doc is not None else Span(path=manifest)
        first = next((p for p, a in sorted(self.ctx.inventory.artifacts.items()) if a.component_id == comp.id), None)
        return Span(path=first) if first else None

    def _reserved(self, cid: str, name: str, span: Span | None, what: str) -> None:
        tree = self.ctx.inventory.tree
        origin = (tree.source.locator if tree is not None and tree.source is not None else "") or ""
        if _VENDOR_ORIGIN.search(origin):
            return                  # fetched from the vendor's own repository: the name is theirs to use
        low = name.lower()
        word = next(w for w in RESERVED_WORDS if w in low)
        leading = low == word or low.startswith((word + "-", word + "_", word + " ")) or low in ("claude-code", "anthropic-official")
        self.ctx.emit("AG-META-011", component_ids=cid, span=span, snippet=f"name: {name}", match=f"reserved:{what}:{low}",
                      kind=EvidenceKind.metadata, detail="key: name", severity=None if leading else Severity.medium,
                      message=f"The {what} name `{name}` contains the reserved word '{word}'. Names with a vendor's name in them read "
                              "as coming from that vendor; the skill specification reserves these words for that reason.")

    def _display_name(self, cid: str, name: str, span: Span | None, what: str) -> None:
        bad = [c for c in name if c in _CONFUSABLES]
        if not bad:
            return
        folded = "".join(_CONFUSABLES.get(c, c) for c in name)
        self.ctx.emit("AG-META-015", component_ids=cid, span=span, snippet=name, match=f"confusable-name:{what}:{name}",
                      kind=EvidenceKind.metadata, decoded=folded, detail="key: name",
                      message=f"The {what} name `{name}` contains {len(bad)} look-alike character(s) "
                              f"({', '.join(f'U+{ord(c):04X}' for c in bad[:3])}). It displays like `{folded}` but is a different name, "
                              "so it can sit beside the real one or pass for it.")

    # -- names (011, 012, 015) -----------------------------------------------------------------------------
    def _name(self, at: ArtifactText, name: str, is_skill: bool, builtin: set[str], declared: bool) -> None:
        cid = at.artifact.component_id
        what = "skill" if is_skill else "command"
        span = _fm_span(at, "name") if declared else Span(path=at.path)
        low = name.lower()
        if any(w in low for w in RESERVED_WORDS):
            self._reserved(cid, name, span, what)
        self._display_name(cid, name, span, what)
        if low in builtin and _search(_PRECEDENCE_DIR, at.path):
            self.ctx.emit("AG-META-012", component_ids=cid, span=span, snippet=f"name: {name}", match=f"builtin:{what}:{low}",
                          kind=EvidenceKind.metadata, detail="key: name",
                          message=f"This {what} is named `{name}`, the name of a command or skill the agent ships with, and it sits in "
                                  f"`{posixpath.dirname(at.path)}`, where project and personal definitions are loaded. A request for the "
                                  "built-in can reach this file instead.")

    # -- skill frontmatter (007, 010, 014) -------------------------------------------------------------------
    def _skill(self, at: ArtifactText, data: dict[Any, Any], name: str) -> None:
        cid = at.artifact.component_id
        desc = data.get("description") if isinstance(data.get("description"), str) else ""
        why = stuffing(desc) if desc else ""
        kw = data.get("keywords") if isinstance(data.get("keywords"), list) else data.get("tags") if isinstance(data.get("tags"), list) else []
        if not why and len(kw) >= 25:
            why = f"it lists {len(kw)} keywords"
        if why:
            self.ctx.emit("AG-META-007", component_ids=cid, span=_fm_span(at, "description"), snippet=desc[:240], match=f"stuffing:{name}",
                          kind=EvidenceKind.metadata, detail="key: description",
                          message=f"The description of '{name}' reads as keyword stuffing: {why}. Agents pick skills by matching the "
                                  "description, so a stuffed one is selected for requests it has nothing to do with.")
        compat = data.get("compatibility") if isinstance(data.get("compatibility"), str) else ""
        m = _search(_BROAD_COMPAT, compat) if compat else None
        if m and not _search(_EXPLAINS, desc):
            self.ctx.emit("AG-META-014", component_ids=cid, span=_fm_span(at, "compatibility"), snippet=compat[:240],
                          match=f"compat:{name}:{m.group(0).lower()}", kind=EvidenceKind.metadata, detail="key: compatibility",
                          message=f"`compatibility` says the skill needs {m.group(0)}, and nothing in its description "
                                  f"(\"{desc[:80]}\") explains why.")
        shared = next((who for rx, who in _SHARED_SKILL_DIRS if _search(rx, at.path)), None)
        if shared is None:
            return
        fields = [k for k, want in (("disable-model-invocation", True), ("user-invocable", False)) if data.get(k) is want]
        if data.get("disallowed-tools"):
            fields.append("disallowed-tools")
        if fields:
            self.ctx.emit("AG-META-010", component_ids=cid, span=_fm_span(at, fields[0]), snippet=", ".join(fields),
                          match=f"cross-agent:{name}:{fields}", kind=EvidenceKind.metadata, detail=f"key: {fields[0]}",
                          message=f"'{name}' limits itself with {', '.join('`' + f + '`' for f in fields)}, which only Claude Code reads. "
                                  f"The same file is loaded by {shared}, which ignore those fields, so the limit does not hold there.")
            return
        sidecar = posixpath.join(posixpath.dirname(at.path), "agents", "openai.yaml")
        doc = self.ctx.inventory.docs.get(sidecar)
        policy = doc.data.get("policy") if doc is not None and isinstance(doc.data.get("policy"), dict) else {}
        if policy.get("allow_implicit_invocation") is False and data.get("disable-model-invocation") is not True:
            self.ctx.emit("AG-META-010", component_ids=cid, span=_fm_span(at, "name"), snippet="allow_implicit_invocation: false",
                          match=f"cross-agent-sidecar:{name}", kind=EvidenceKind.metadata, related=[Span(path=sidecar)],
                          message=f"'{name}' turns implicit invocation off for Codex (`agents/openai.yaml`) but sets no "
                                  "`disable-model-invocation` for the other agents that load this folder, so they may still start it "
                                  "on their own.")

    # -- AG-META-009 ----------------------------------------------------------------------------------------
    def _consistency(self) -> None:
        inv = self.ctx.inventory
        tree = inv.tree
        if tree is None:
            return

        def package_json(root: str) -> tuple[str, dict[str, Any]] | None:
            path = posixpath.join(root, "package.json") if root else "package.json"
            blob = tree.files.get(path)
            if blob is None:
                return None
            parsed = parse_json(blob.data.decode("utf-8", "replace"))
            return (path, parsed.value) if isinstance(parsed.value, dict) else None

        def differ(a: Any, b: Any) -> bool:
            return isinstance(a, (str, int, float)) and isinstance(b, (str, int, float)) and str(a).strip() != str(b).strip()

        def emit(doc: Doc, key: str, mine: Any, other_path: str, theirs: Any) -> None:
            art = inv.artifacts.get(doc.path)
            self.ctx.emit("AG-META-009", component_ids=[art.component_id] if art else [],
                          span=span_of(doc.text, f'"{key}"', path=doc.path), snippet=f"{key}: {mine}", match=f"{doc.path}:{key}:{other_path}",
                          kind=EvidenceKind.metadata, detail=f"key: {key}", related=[Span(path=other_path)],
                          message=f"`{doc.path}` says {key} `{mine}`, and `{other_path}` says `{theirs}`. Two descriptions of the same "
                                  "component disagree about what it is.")

        for doc in inv.of_surface("claude.plugin", "codex.plugin", "cursor.plugin", "gemini.extension", "openclaw.plugin"):
            up = 1 if doc.surface.id in ("gemini.extension", "openclaw.plugin") else 2
            root = doc.path
            for _ in range(up):
                root = posixpath.dirname(root)
            pkg = package_json(root)
            if pkg and differ(doc.data.get("version"), pkg[1].get("version")):
                emit(doc, "version", doc.data.get("version"), pkg[0], pkg[1].get("version"))
        for doc in inv.of_surface("claude.marketplace", "cursor.marketplace"):
            base = posixpath.dirname(posixpath.dirname(doc.path))
            for entry in doc.data.get("plugins") if isinstance(doc.data.get("plugins"), list) else []:
                src = entry.get("source") if isinstance(entry, dict) else None
                if not isinstance(src, str) or not src.startswith("."):
                    continue
                root = posixpath.normpath(posixpath.join(base, src))
                for manifest in (f"{root}/.claude-plugin/plugin.json", f"{root}/.cursor-plugin/plugin.json"):
                    other = inv.docs.get(manifest)
                    if other is None:
                        continue
                    for key in ("version", "name"):
                        if differ(entry.get(key), other.data.get(key)):
                            emit(doc, key, entry.get(key), manifest, other.data.get(key))
                            break
        for path in sorted(p for p in tree.files if posixpath.basename(p).lower() == "server.json"):
            parsed = parse_json(tree.files[path].data.decode("utf-8", "replace"))
            data = parsed.value if isinstance(parsed.value, dict) else {}
            pkg = package_json(posixpath.dirname(path))
            if pkg and "name" in data and differ(data.get("version"), pkg[1].get("version")):
                doc = Doc(path=path, surface=inv.surfaces.get(path) or next(iter(inv.surfaces.values()), None),  # type: ignore[arg-type]
                          value=data, fmt="json", text=tree.files[path].data.decode("utf-8", "replace"))
                emit(doc, "version", data.get("version"), pkg[0], pkg[1].get("version"))


__all__ = ["MetaAnalyzer", "RESERVED_WORDS", "stuffing"]
