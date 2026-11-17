"""Attack chains: findings linked along graph edges, instruction → script →
source → sink (PLAN §5.5).

A chain is reported one severity level above its strongest part. A *confirmed*
chain (two or more linked findings ending in a sink) produces a BLOCK verdict;
a chain whose last step is only a heuristic is recorded without a sink, so it
corroborates its members without blocking on its own.
"""

from __future__ import annotations

import posixpath
from typing import TYPE_CHECKING

from .models import Chain, Finding
from .models.enums import ArtifactRole, Category, Confidence, Lane, Severity

if TYPE_CHECKING:
    from .analyzers.base import Context
    from .inventory import Inventory

# What a chain can end in, by rule.
_SINKS: dict[str, tuple[str, ...]] = {
    "network": ("AG-EXF-001", "AG-EXF-002", "AG-EXF-003", "AG-EXF-004", "AG-EXF-005", "AG-EXF-006", "AG-EXF-008",
                "AG-EXF-009", "AG-EXF-011", "AG-EXF-013", "AG-EXF-014"),
    "exec": ("AG-EXEC-001", "AG-EXEC-003", "AG-EXEC-004", "AG-EXEC-010", "AG-EXEC-014"),
    "persistence": ("AG-PERSIST-002", "AG-PERSIST-004", "AG-PERSIST-005", "AG-PERSIST-006", "AG-PERSIST-010",
                    "AG-PERSIST-014"),
    "destruction": ("AG-IMPACT-001", "AG-IMPACT-002"),
}
_SINK_OF = {rule: sink for sink, rules in _SINKS.items() for rule in rules}
_SOURCES = ("AG-CRED-002", "AG-CRED-003", "AG-CRED-004", "AG-CRED-005", "AG-EXF-002", "AG-EXF-011", "AG-EXF-012",
            "AG-EXF-013")
_INSTRUCTION_FAMILIES = ("INJ", "OBF", "MM", "MANIP")
# Correlators that already proved the link between a source and a sink.
_CORRELATED = {"AG-EXF-001": "network", "AG-EXEC-003": "exec"}
_MARKDOWN = (ArtifactRole.skill_md, ArtifactRole.instruction_md, ArtifactRole.reference, ArtifactRole.command_md)
_CODE = (ArtifactRole.script, ArtifactRole.source_code)
MAX_CHAINS_PER_COMPONENT = 5


def _strongest(findings: list[Finding]) -> Finding:
    return max(findings, key=lambda f: (f.severity.rank, f.confidence.rank, f.lane == Lane.block, f.fingerprint))


def _at(f: Finding) -> set[tuple[str, int]]:
    return {(f.location.file, f.location.start.line)} if f.location else set()


def _mentions(inv: Inventory, md_path: str, script_path: str, root: str) -> bool:
    at = inv.texts.get(md_path)
    if at is None:
        return False
    rel = script_path[len(root) + 1:] if root and script_path.startswith(root + "/") else script_path
    return rel in at.text or posixpath.basename(script_path) in at.text


def build_chains(findings: list[Finding], inv: Inventory, ctx: Context) -> list[Chain]:
    by_comp: dict[str, list[Finding]] = {}
    for f in findings:
        if f.suppressed or f.category == Category.hygiene:
            continue
        for cid in f.component_ids:
            by_comp.setdefault(cid, []).append(f)
    candidates: list[tuple[list[Finding], str, str]] = []   # (steps, sink, narrative)

    for cid in sorted(by_comp):
        group = sorted(by_comp[cid], key=Finding.sort_key)
        comp = inv.components.get(cid)
        if comp is None:
            continue
        found = 0
        used: set[str] = set()
        # 1. A correlator proved source → sink: collect the findings at its evidence locations.
        # Two correlator findings over the same members are one chain, not two.
        proved: dict[tuple[str, tuple[str, ...]], tuple[list[Finding], list[Finding]]] = {}
        for f in group:
            sink = _CORRELATED.get(f.id)
            if sink is None:
                continue
            spots = {(e.location.path, e.location.start_line) for e in f.evidence.items if e.location}
            spots |= {(s.path, s.start_line) for s in f.related}
            members = [g for g in group if g is not f and g.id not in _CORRELATED and _at(g) & spots]
            if not members:
                continue
            members.sort(key=lambda g: (g.id not in _SOURCES, g.id in _SINK_OF, g.sort_key()))
            members = members[:4]
            key = (sink, tuple(sorted(g.fingerprint for g in members)))
            proved.setdefault(key, (members, []))[1].append(f)
        for (sink, _), (members, ends) in sorted(proved.items()):
            if found >= MAX_CHAINS_PER_COMPONENT:
                break
            ends.sort(key=Finding.sort_key)
            steps = [*members, *ends]
            confirmed = any(f.lane == Lane.block and f.confidence.rank >= Confidence.medium.rank for f in ends)
            candidates.append((steps, sink if confirmed else "",
                               f"{len(members)} linked finding(s) lead to {ends[0].title.lower()}."))
            used.update(s.fingerprint for s in steps)
            found += 1
        # 2. An instruction in a Markdown file that names a script, and a sink in that script.
        role_of = {a.path: a.role for a in inv.artifacts.values() if a.component_id == cid}
        instr = [f for f in group if f.family in _INSTRUCTION_FAMILIES and f.location
                 and role_of.get(f.location.file) in _MARKDOWN]
        sinks = [f for f in group if f.id in _SINK_OF and f.location and role_of.get(f.location.file) in _CODE]
        sources = [f for f in group if f.id in _SOURCES and f.location and role_of.get(f.location.file) in _CODE]
        for script in sorted({f.location.file for f in sinks if f.location}):
            if found >= MAX_CHAINS_PER_COMPONENT:
                break
            here = [f for f in sinks if f.location and f.location.file == script]
            pointing = [f for f in instr if f.location and _mentions(inv, f.location.file, script, comp.root)]
            if not pointing:
                continue
            sink_f = _strongest(here)
            steps = [_strongest(pointing)]
            src_here = [f for f in sources if f.location and f.location.file == script and f is not sink_f]
            if src_here:
                steps.append(_strongest(src_here))
            steps.append(sink_f)
            if all(s.fingerprint in used for s in steps):
                continue
            sink = _SINK_OF[sink_f.id]
            confirmed = sink_f.lane == Lane.block and sink_f.confidence.rank >= Confidence.medium.rank
            candidates.append((steps, sink if confirmed else "",
                               f"Instructions in {posixpath.basename(steps[0].location.file)} lead to "  # type: ignore[union-attr]
                               f"{posixpath.basename(script)}, which ends in {sink}."))
            used.update(s.fingerprint for s in steps)
            found += 1

    chains: list[Chain] = []
    seen: set[tuple[str, ...]] = set()
    candidates.sort(key=lambda c: tuple(s.fingerprint for s in c[0]))
    for steps, sink, narrative in candidates:
        fps = tuple(dict.fromkeys(s.fingerprint for s in steps))
        if len(fps) < 2 or fps in seen:
            continue
        seen.add(fps)
        top = max(steps, key=lambda s: s.severity.rank).severity
        chain = Chain(id=f"chain-{len(chains) + 1}", severity=top.bump(1) if top != Severity.critical else top,
                      steps=list(fps), narrative=narrative, sink=sink)
        chains.append(chain)
        for s in steps:
            if s.chain is None:
                s.chain = chain.id
    return chains
