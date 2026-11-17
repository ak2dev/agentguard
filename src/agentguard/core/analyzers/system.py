"""Coverage findings: what the scanner could not read, parse or fetch, and
content placed where scanners commonly do not look.

* loader limit events → AG-EVADE-001, 004, 005, 018;
* files that should parse and do not → AG-EVADE-002;
* git LFS pointers and submodules whose content is not in the tree → AG-EVADE-018;
* content in `.git/`, build output and hidden directories of a package → AG-EVADE-006.
"""

from __future__ import annotations

import posixpath
from typing import ClassVar

import regex

from ..artifacts import binary_kind
from ..models import LimitEvent, Span
from ..models.enums import ArtifactRole, ComponentKind, EvidenceKind, Severity
from ..textutil import TIMEOUT
from .base import Context

NOT_FETCHED_KINDS = ("submodule", "lfs_pointer", "not_fetched", "listing_truncated")


def rule_for(ev: LimitEvent) -> str | None:
    if ev.kind == "archive_bomb":
        return "AG-EVADE-004"
    if ev.kind in ("symlink", "hardlink", "path_escape"):
        return "AG-EVADE-005"
    if ev.kind in ("too_large", "too_many_files", "too_deep", "total_bytes_exceeded", "encrypted_member",
                   "special_file", "unreadable", "archive_error", "windows_hazard"):
        return "AG-EVADE-001"
    if ev.kind in NOT_FETCHED_KINDS:
        return "AG-EVADE-018"
    return None


class LimitsAnalyzer:
    id: ClassVar[str] = "sys.limits"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = ("AG-EVADE-001", "AG-EVADE-005", "AG-EVADE-004")

    def run(self, ctx: Context) -> None:
        events: list[LimitEvent] = ctx.data.get("limit_events", [])  # type: ignore[assignment]
        for ev in sorted(events, key=lambda e: (e.kind, e.path)):
            rid = rule_for(ev)
            if rid is None or rid == "AG-EVADE-018":
                continue
            comp = ctx.inventory.component_for(ev.path)
            ctx.emit(rid, component_ids=[comp.id] if comp else [], span=Span(path=ev.path), snippet=ev.path,
                     match=f"{ev.kind}:{ev.path}", kind=EvidenceKind.loader, detail=f"{ev.kind}: {ev.detail}".strip(": "),
                     message={
                         "AG-EVADE-001": f"Not scanned ({ev.kind.replace('_', ' ')}): {ev.path}",
                         "AG-EVADE-005": f"Link or path escape blocked ({ev.kind}): {ev.path}",
                         "AG-EVADE-004": f"Archive exceeded decompression limits: {ev.path}",
                     }[rid])


_LFS_POINTER = regex.compile(r"\Aversion https://git-lfs\.github\.com/spec/v1\r?\noid sha256:[0-9a-f]{64}\r?\nsize (\d+)\r?\n?\Z")
_SUBMODULE = regex.compile(r'(?m)^\s*\[submodule\s+"([^"\n]{1,200})"\]\s*$')
_KV = regex.compile(r"(?m)^\s*(path|url|branch)\s*=\s*(.+?)\s*$")
# Directories that belong to an agent or to tooling; a hidden directory outside this list is unusual in a package.
_KNOWN_DOT_DIRS = frozenset({
    ".claude", ".claude-plugin", ".codex", ".codex-plugin", ".cursor", ".cursor-plugin", ".gemini", ".github", ".vscode",
    ".agents", ".clawhub", ".devcontainer", ".husky", ".githooks", ".openclaw", ".well-known", ".continue", ".windsurf",
    ".roo", ".kiro", ".junie", ".aiassistant", ".idea", ".run", ".mise", ".config", ".copilot",
})
_BUILD_DIRS = frozenset({"build", "dist", "out", "target", ".cache", "tmp", "temp", ".tmp"})
_PACKAGE_KINDS = (ComponentKind.skill, ComponentKind.plugin, ComponentKind.bundle)
_PAYLOAD_ROLES = (ArtifactRole.script, ArtifactRole.binary, ArtifactRole.archive)


def _git_inner(path: str) -> str | None:
    """Path below a `.git/` directory, or None."""
    parts = path.split("/")
    if ".git" in parts[:-1]:
        return "/".join(parts[parts.index(".git") + 1:])
    return None


def submodules(text: str) -> list[dict[str, str]]:
    """Entries of a `.gitmodules` file: name, path, url, branch, line."""
    out: list[dict[str, str]] = []
    heads = list(_SUBMODULE.finditer(text))
    for i, m in enumerate(heads):
        body = text[m.end(): heads[i + 1].start() if i + 1 < len(heads) else len(text)]
        entry = {"name": m.group(1), "line": str(text.count("\n", 0, m.start()) + 1)}
        for kv in _KV.finditer(body):
            entry[kv.group(1)] = kv.group(2)
        out.append(entry)
    return out


class CoverageAnalyzer:
    id: ClassVar[str] = "coverage"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = ("AG-EVADE-002", "AG-EVADE-006", "AG-EVADE-018")

    def run(self, ctx: Context) -> None:
        inv = ctx.inventory
        tree = inv.tree
        # -- AG-EVADE-002: a file of a known format that does not parse -------------------------
        for path, error, surface in sorted(inv.parse_failures):
            comp = inv.component_for(path)
            line = 1
            m = regex.search(r"line (\d+)", error)
            if m:
                line = max(1, int(m.group(1)))
            ctx.emit("AG-EVADE-002", component_ids=[comp.id] if comp else [], span=Span(path=path, start_line=line),
                     snippet=error[:200], match=f"parse:{path}", kind=EvidenceKind.loader, detail=f"surface {surface}",
                     message=f"{path} is read by an agent as {surface} but does not parse ({error[:120]}); "
                             "its settings were not analysed.")
        # -- AG-EVADE-018: content that exists and was not fetched -------------------------------
        events: list[LimitEvent] = ctx.data.get("limit_events", [])  # type: ignore[assignment]
        for ev in sorted(events, key=lambda e: (e.kind, e.path)):
            if ev.kind in NOT_FETCHED_KINDS:
                comp = inv.component_for(ev.path)
                ctx.emit("AG-EVADE-018", component_ids=[comp.id] if comp else [], span=Span(path=ev.path), snippet=ev.path,
                         match=f"{ev.kind}:{ev.path}", kind=EvidenceKind.loader, detail=f"{ev.kind}: {ev.detail}".strip(": "),
                         message=f"Not fetched ({ev.kind.replace('_', ' ')}): {ev.path}. {ev.detail}".strip())
        if tree is None:
            return
        reported = {ev.path for ev in events if ev.kind in NOT_FETCHED_KINDS}
        for path in sorted(tree.files):
            blob = tree.files[path]
            if blob.size > 200 or path in reported:
                continue
            m = _LFS_POINTER.match(blob.data.decode("utf-8", "replace"))
            if m:
                comp = inv.component_for(path)
                ctx.emit("AG-EVADE-018", component_ids=[comp.id] if comp else [], span=Span(path=path),
                         snippet=blob.data.decode("utf-8", "replace")[:160], match=f"lfs:{path}", kind=EvidenceKind.loader,
                         message=f"{path} is a Git LFS pointer; the {m.group(1)}-byte object it stands for was not fetched "
                                 "and was not analysed.")
        for path in sorted(p for p in tree.files if posixpath.basename(p) == ".gitmodules"):
            base = posixpath.dirname(path)
            text = tree.files[path].data.decode("utf-8", "replace")
            comp = inv.component_for(path)
            for sub in submodules(text):
                sub_path = sub.get("path", "").strip("/")
                if not sub_path:
                    continue
                root = posixpath.normpath(posixpath.join(base, sub_path))
                if root in reported or any(p.startswith(root + "/") for p in tree.files):
                    continue
                ctx.emit("AG-EVADE-018", component_ids=[comp.id] if comp else [],
                         span=Span(path=path, start_line=int(sub["line"])), snippet=f'[submodule "{sub["name"]}"] path = {sub_path}',
                         match=f"submodule:{root}", kind=EvidenceKind.loader,
                         message=f"Submodule '{sub['name']}' ({sub_path}) is declared but its content is not in the scanned "
                                 "tree, so it was not analysed.")
        # -- AG-EVADE-006: content where scanners commonly do not look ------------------------------
        referenced = {dst for _src, _line, _ref, dst, _kind in inv.references if dst}
        for path in sorted(inv.artifacts):
            art = inv.artifacts[path]
            comp = inv.components.get(art.component_id)
            if comp is None:
                continue
            inner = _git_inner(path)
            if inner is not None:
                if inner.startswith("hooks/"):
                    continue                              # repository git hooks are AG-WS-005's
                ctx.emit("AG-EVADE-006", component_ids=comp.id, span=Span(path=path), snippet=path, match=f"git:{path}",
                         kind=EvidenceKind.loader, severity=Severity.high,
                         message=f"{path} is not one of git's own files. Content placed inside `.git/` is skipped by most "
                                 "scanners and reviewers.")
                continue
            if comp.kind not in _PACKAGE_KINDS:
                continue
            rel = path[len(comp.root) + 1:] if comp.root and path.startswith(comp.root + "/") else path
            dirs = rel.split("/")[:-1]
            hidden = next((d for d in dirs if d.startswith(".") and len(d) > 1 and d.lower() not in _KNOWN_DOT_DIRS), None)
            build = next((d for d in dirs if d.lower() in _BUILD_DIRS), None)
            docs = next((d for d in dirs if d.lower() in ("docs", "doc", "documentation")), None)
            opaque = art.role in (ArtifactRole.binary, ArtifactRole.archive) or (
                art.role not in (ArtifactRole.image, ArtifactRole.document, ArtifactRole.media)
                and binary_kind(tree.files[path].data) is not None) if path in tree.files else False
            payload = art.role in _PAYLOAD_ROLES or opaque
            where = ""
            if hidden and payload:
                where = f"hidden directory `{hidden}/`"
            elif build and payload:
                where = f"build output directory `{build}/`"
            elif docs and (opaque or (art.role == ArtifactRole.script and path in referenced)):
                where = f"documentation directory `{docs}/`"
            if not where:
                continue
            try:
                what = "an opaque file" if opaque else "a script"
                if regex.search(r"\.(?:md|txt|rst)$", path, regex.IGNORECASE, timeout=TIMEOUT):
                    continue
            except TimeoutError:
                continue
            ctx.emit("AG-EVADE-006", component_ids=comp.id, span=Span(path=path), snippet=path, match=f"skipdir:{path}",
                     kind=EvidenceKind.loader, severity=Severity.medium if not (path in referenced or opaque) else None,
                     message=f"{what.capitalize()} sits in the {where} of {comp.kind.spec_type} '{comp.name}'"
                             f"{' and is referenced for use' if path in referenced else ''}. Scanners commonly skip this "
                             "location; packed skills hide their payload there.")
