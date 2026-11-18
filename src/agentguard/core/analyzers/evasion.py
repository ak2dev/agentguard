"""Evasion techniques that need more than a pattern (the EVADE family).

* AG-EVADE-007: a script kept under a harmless extension (``notes.txt``,
  ``logo.png``) that instructions or commands run with an interpreter.
* AG-EVADE-014: a short, harmless cover page (``SKILL.md``) that hands the agent
  to a second file holding the real workflow.

Pure: reads prepared text and the tree.
"""

from __future__ import annotations

import posixpath
from typing import ClassVar

import regex

from ..models import Span
from ..models.enums import ArtifactRole, EvidenceKind
from ..scriptshape import RUN_AS_SCRIPT, script_shape
from ..textutil import TIMEOUT
from .base import Context
from .heuristics import EXECUTABLE_COMMANDS, search, word_count

_F = regex.IGNORECASE
_RUN_AS_SCRIPT = RUN_AS_SCRIPT
_HANDOFF = regex.compile(
    r"\b(?:follow|execute|run|obey|perform|carry\s+out|do|complete|apply|load|read\s+and\s+follow)\s+(?:exactly\s+|all\s+(?:of\s+)?|every\s+)?"
    r"(?:the\s+|each\s+)?(?:steps?|instructions?|workflow|procedure|directions|commands?|playbook|guide|rules)\s+(?:in|from|at|inside|listed\s+in|"
    r"described\s+in|found\s+in)\s+[`\"']?(?P<file>[\w./-]+\.(?:md|markdown|txt|mdc))[`\"']?"
    r"|\b(?:see|open|read|load|consult)\s+[`\"']?(?P<file2>[\w./-]+\.(?:md|markdown|txt|mdc))[`\"']?\s+(?:and|then)\s+(?:follow|do|execute|run|obey)\b", _F)
_PROSE = (ArtifactRole.skill_md, ArtifactRole.instruction_md, ArtifactRole.command_md, ArtifactRole.reference)
_CODE = (ArtifactRole.script, ArtifactRole.source_code, ArtifactRole.hook_config, ArtifactRole.workflow)
COVER_MAX_WORDS = 80
WORKFLOW_MIN_WORDS = 120


def _finditer(rx: regex.Pattern[str], text: str) -> list[regex.Match[str]]:
    try:
        return list(rx.finditer(text, timeout=TIMEOUT))
    except TimeoutError:
        return []


class EvasionAnalyzer:
    id: ClassVar[str] = "evasion"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = ("AG-EVADE-007", "AG-EVADE-014")

    def run(self, ctx: Context) -> None:
        self.ctx = ctx
        inv = ctx.inventory
        tree = inv.tree
        if tree is None:
            return
        by_base: dict[str, list[str]] = {}
        for p in tree.files:
            by_base.setdefault(posixpath.basename(p).lower(), []).append(p)
        self.by_base = by_base
        for at in ctx.texts():
            if at.artifact.role in _PROSE or at.artifact.role in _CODE:
                self._disguised(at)
        for at in ctx.texts("skill_md"):
            self._cover(at)

    def _resolve(self, src: str, ref: str) -> str | None:
        """The tree file a reference written in ``src`` names (same directory first, then by trailing path)."""
        tree = self.ctx.inventory.tree
        assert tree is not None
        clean = regex.sub(r"\$\{?\w+\}?/", "", ref).lstrip("./~").strip("/")
        if not clean:
            return None
        here = posixpath.dirname(src)
        cand = posixpath.normpath(posixpath.join(here, clean)) if here else clean
        if cand in tree.files:
            return cand
        matches = [p for p in self.by_base.get(posixpath.basename(clean).lower(), []) if p == clean or p.endswith("/" + clean)]
        if not matches:
            return None
        comp = self.ctx.inventory.artifacts.get(src)
        same = [p for p in matches if comp and self.ctx.inventory.artifacts.get(p) and
                self.ctx.inventory.artifacts[p].component_id == comp.component_id]
        return sorted(same or matches, key=len)[0]

    # -- AG-EVADE-007 ---------------------------------------------------------------------------------
    def _disguised(self, at) -> None:  # noqa: ANN001 - ArtifactText
        tree = self.ctx.inventory.tree
        assert tree is not None
        seen: set[str] = set()
        for m in _finditer(_RUN_AS_SCRIPT, at.text)[:40]:
            ref = m.group("file") or m.group("file2") or m.group("file3")
            how = (m.group("how") or m.group("how2") or m.group("how3") or "").strip()
            target = self._resolve(at.path, ref)
            if target is None or target == at.path or target in seen:
                continue
            shebang, lines = script_shape(tree.files[target].data)
            if not shebang and lines < 2:
                continue
            if target.lower().endswith((".md", ".markdown", ".rst")) and not shebang and how.lower() in ("source", "."):
                continue
            seen.add(target)
            ext = posixpath.splitext(target)[1]
            self.ctx.emit("AG-EVADE-007", component_ids=at.artifact.component_id, span=at.span(m.start(), m.end()),
                          snippet=at.line_text(m.start())[:200], match=f"disguised:{target}", kind=EvidenceKind.regex,
                          related=[Span(path=target)],
                          message=f"`{target}` is run with `{how}`, but it is stored as a `{ext}` file"
                                  + (" and starts with an interpreter line" if shebang else f" and holds {lines} lines of script")
                                  + ". Scanners and reviewers treat that extension as data, so the code in it is not looked at.")

    # -- AG-EVADE-014 ---------------------------------------------------------------------------------
    def _cover(self, at) -> None:  # noqa: ANN001 - ArtifactText
        tree = self.ctx.inventory.tree
        assert tree is not None
        body = at.fm.body if at.fm is not None else at.text
        words = word_count(body)
        if words > COVER_MAX_WORDS:
            return
        base = at.fm.body_offset if at.fm is not None else 0
        for m in _finditer(_HANDOFF, body):
            ref = m.group("file") or m.group("file2")
            target = self._resolve(at.path, ref)
            if target is None or target == at.path:
                continue
            other = tree.files[target].data.decode("utf-8", "replace")
            n = word_count(other)
            if n < WORKFLOW_MIN_WORDS or n < 3 * max(words, 1) or not search(EXECUTABLE_COMMANDS, other):
                continue
            self.ctx.emit("AG-EVADE-014", component_ids=at.artifact.component_id, span=at.span(base + m.start(), base + m.end()),
                          snippet=at.line_text(base + m.start())[:200], match=f"cover:{target}", kind=EvidenceKind.regex,
                          related=[Span(path=target)],
                          message=f"`{at.path}` is {words} words long and hands the agent to `{target}` ({n} words, with commands) "
                                  "for the actual steps. Review the second file as the skill; the page that listings and quick "
                                  "reviews show says nothing about what it does.")
            return


__all__ = ["EvasionAnalyzer"]
