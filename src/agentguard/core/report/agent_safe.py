"""Agent-safe output (spec/interfaces.md §11).

A scanner that returns hostile text to the agent calling it becomes an
injection path. In this mode the agent receives rule ids, fixed rule wording,
file and line, verdict and fix summary. Evidence snippets and decoded payloads
are withheld, and every string that came from the target (names, paths) is
length-limited and stripped of control and invisible characters. The full
report is written to disk for the human.
"""

from __future__ import annotations

import unicodedata

from ..models import EvidenceSummary, Finding, Report, Span
from ..models.finding import Chain, Location, Position, TraceStep
from ..models.report import ArtifactSummary, Coverage, TargetInfo, UnanalysedItem
from ..textutil import is_invisible

MAX_NAME = 120
_DROP = ("Cc", "Cf", "Co", "Cs", "Cn", "Zl", "Zp")


def clean(text: str | None, limit: int = MAX_NAME) -> str:
    """Target-derived strings: no control or invisible characters, one line, bounded length."""
    if not text:
        return ""
    out = []
    for ch in text:
        if is_invisible(ch) or unicodedata.category(ch) in _DROP:
            continue
        out.append(" " if ch.isspace() else ch)
    cleaned = " ".join("".join(out).split())
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 1] + "…"


def _location(loc: Location | None) -> Location | None:
    if loc is None:
        return None
    return Location(artifact=clean(loc.artifact), file=clean(loc.file, 200), container=clean(loc.container, 200) or None,
                    start=Position(line=loc.start.line, column=loc.start.column, byte=loc.start.byte), end=loc.end)


def _span(s: Span) -> Span:
    return Span(path=clean(s.path, 200), start_line=s.start_line, start_col=s.start_col, end_line=s.end_line, end_col=s.end_col)


def scrub_finding(f: Finding) -> Finding:
    return f.model_copy(update={
        "risk": f.title,                              # fixed rule wording, not the per-match text
        "location": _location(f.location),
        "related": [_span(s) for s in f.related[:10]],
        "evidence": EvidenceSummary(derivation=[clean(d, 40) for d in f.evidence.derivation]),
        "trace": [TraceStep(file=clean(t.file, 200), line=t.line, role=clean(t.role, 20)) for t in f.trace],
        "fix": f.fix.model_copy(update={"patch": None}),
        "adjudication": f.adjudication.model_copy(update={"rationale": ""}) if f.adjudication else None,
        "flow": None,
        "references": [],
    })


def scrub_report(report: Report) -> Report:
    by_fp = {f.fingerprint: f for f in report.findings}

    def reason(text: str) -> str:
        return clean(text, 240)

    chains = [Chain(id=c.id, severity=c.severity, steps=c.steps, sink=c.sink,
                    narrative=" → ".join(by_fp[s].id for s in c.steps if s in by_fp)) for c in report.chains]
    cov = report.coverage
    return report.model_copy(update={
        "target": TargetInfo(source=clean(report.target.source, 200), kind=report.target.kind, commit=report.target.commit,
                             tree_sha256=report.target.tree_sha256),
        "coverage": Coverage(files_total=cov.files_total, files_analysed=cov.files_analysed, bytes_total=cov.bytes_total,
                             bytes_analysed=cov.bytes_analysed, analyzability=cov.analyzability,
                             unanalysed=[UnanalysedItem(path=clean(u.path, 200), reason=clean(u.reason, 60), bytes=u.bytes)
                                         for u in cov.unanalysed[:20]]),
        "verdict_reasons": [reason(r) for r in report.verdict_reasons],
        "artifacts": [ArtifactSummary(id=clean(a.id), type=a.type, ecosystem=clean(a.ecosystem, 40), name=clean(a.name),
                                      version=clean(a.version, 40) or None, root=clean(a.root, 200),
                                      component_id=a.component_id, capabilities=a.capabilities, risk_tier=a.risk_tier,
                                      verdict=a.verdict, findings=a.findings) for a in report.artifacts],
        "findings": [scrub_finding(f) for f in report.findings],
        "suppressed_findings": [scrub_finding(f) for f in report.suppressed_findings],
        "chains": chains,
        "inventory": [],
        "files": [],
        "flows": [],
        "network_hosts": [clean(h, 100) for h in report.network_hosts],
    })
