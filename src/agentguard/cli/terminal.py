"""Terminal rendering (Rich). All scanned text is escaped for Rich markup and
control characters are already rendered visible by the redaction layer.

Findings are grouped by their effect on the verdict, then by severity. Each
one gives the risk, the cause (file, line, column and the trace when the
problem spans files) and the fix.
"""

from __future__ import annotations

from rich.console import Console
from rich.markup import escape

from ..core import verdict as verdicts
from ..core.models import Finding, Report
from ..core.models.enums import FixKind, Severity, Verdict
from ..core.report.render import ALLOW_NOTE, FIX_LABEL, FRAMEWORK_LABEL
from ..core.textutil import visible_escape

SEV_STYLE = {
    Severity.critical: "bold white on red",
    Severity.high: "bold red",
    Severity.medium: "yellow",
    Severity.low: "cyan",
    Severity.info: "dim",
}
VERDICT_STYLE = {Verdict.block: "bold white on red", Verdict.review: "bold black on yellow", Verdict.allow: "bold black on green"}
EFFECT_TITLE = {
    "block": "Blocks: these decide the BLOCK verdict",
    "review": "Needs review",
    "info": "Does not affect the verdict",
}


def _e(text: str) -> str:
    return escape(visible_escape(text))


def _where(f: Finding) -> str:
    loc = f.location
    if loc is None:
        return "-"
    text = f"{loc.file}:{loc.start.line}:{loc.start.column}"
    if loc.end and (loc.end.line, loc.end.column) != (loc.start.line, loc.start.column):
        text += f" → {loc.end.line}:{loc.end.column}"
    if loc.container:
        text = f"{loc.container} » {text}"
    return text


def _maps(f: Finding) -> str:
    parts = []
    for key, ids in f.mappings.items():
        label = FRAMEWORK_LABEL.get(key, key)
        parts += [i if key == "cwe" else f"{label} {i}" for i in ids]
    return " · ".join(parts[:8])


def _print_finding(console: Console, f: Finding, *, verbose: bool) -> None:
    sev = f.severity.value.upper()
    note = "" if f.corroborated else "  [dim](not corroborated)[/dim]"
    console.print(f"[{SEV_STYLE[f.severity]}]{sev:<8}[/]  [bold]{f.id}[/bold]  {_e(f.title)}"
                  f"  [dim]confidence: {f.confidence.value}[/dim]{note}")
    console.print(f"  [dim]{_e(_where(f))}[/dim]" + (f"  [dim]{_e(f.location.artifact)}[/dim]" if f.location and f.location.artifact else ""))
    if f.risk and f.risk.strip().rstrip(".").casefold() != f.title.strip().rstrip(".").casefold():
        console.print(f"  [bold]Risk[/bold]   {_e(f.risk)}")
    elif f.explanation:
        console.print(f"  [bold]Risk[/bold]   {_e(f.explanation)}")
    if f.trace:
        steps = " → ".join(f"{t.file}:{t.line}" + (f" ({t.role})" if t.role and t.role != "step" else "") for t in f.trace[:6])
        console.print(f"  [bold]Trace[/bold]  {_e(steps)}")
    if verbose and str(f.evidence.decoded):
        console.print(f"  [bold]Hidden[/bold] {_e(str(f.evidence.decoded))}"
                      + (f"  [dim]via {_e(', '.join(f.evidence.derivation))}[/dim]" if f.evidence.derivation else ""))
    if verbose and str(f.evidence.snippet):
        console.print(f"  [dim]›      {_e(str(f.evidence.snippet))}[/dim]")
    fix = f.fix.summary or FIX_LABEL[f.fix.kind]
    console.print(f"  [green]Fix[/green]    {_e(fix)}")
    if f.fix.kind == FixKind.auto:
        console.print(f"         [dim]Auto-fix available: agentguard fix --finding {f.fingerprint[:12]}[/dim]")
    elif f.fix.kind == FixKind.remove:
        console.print("         [dim]No edit makes this safe: do not install it, or remove it.[/dim]")
    if verbose:
        maps = _maps(f)
        if maps:
            console.print(f"  [dim]Maps   {_e(maps)}[/dim]")
        if f.adjudication and f.adjudication.status != "not_run":
            console.print(f"  [dim]Model  {f.adjudication.status} ({_e(f.adjudication.model)})[/dim]")
    console.print()


def print_report(report: Report, console: Console, *, verbose: bool = False, show_info: bool = False) -> None:
    cov = report.coverage
    console.print(f"[bold]Agent Guard[/bold] {report.engine_version} · rule pack {report.tool.rule_pack}"
                  f" · profile {report.profile} · policy {report.policy}"
                  f" · {report.stats.components} component{'' if report.stats.components == 1 else 's'}"
                  f" · {report.stats.files_scanned} file{'' if report.stats.files_scanned == 1 else 's'}")
    if report.network_features_used:
        console.print(f"[yellow]Network features used:[/yellow] {', '.join(report.network_features_used)}")
    else:
        console.print("[dim]Offline scan (no network features used).[/dim]")
    console.print()
    findings = [f for f in report.findings if show_info or f.severity != Severity.info]
    groups: dict[str, list[Finding]] = {"block": [], "review": [], "info": []}
    for f in findings:
        groups[verdicts.effect(f, report.chains)].append(f)
    for effect in ("block", "review", "info"):
        group = groups[effect]
        if not group:
            continue
        console.print(f"[bold underline]{EFFECT_TITLE[effect]}[/bold underline] ({len(group)})")
        console.print()
        for f in sorted(group, key=Finding.sort_key):
            _print_finding(console, f, verbose=verbose)
    if report.chains:
        by_fp = {f.fingerprint: f for f in report.findings}
        console.print("[bold underline]Attack chains[/bold underline]")
        for ch in report.chains:
            path = " → ".join(dict.fromkeys(by_fp[s].id for s in ch.steps if s in by_fp))
            console.print(f"  {ch.id} [{SEV_STYLE[ch.severity]}]{ch.severity.value}[/]"
                          + (f" ends in {ch.sink}" if ch.sink else "") + f": {path}")
        console.print()
    notes = [a for a in report.analyzers if a.status != "ran" and a.reason != "not selected"]
    if notes or cov.unanalysed:
        console.print("[dim]Coverage notes:[/dim]")
        for a in notes:
            console.print(f"[dim]  - {escape(a.id)}: {a.status} ({escape(a.reason)})[/dim]")
        for u in cov.unanalysed[:10]:
            console.print(f"[dim]  - not analysed: {_e(u.path)} ({_e(u.reason)})[/dim]")
        if len(cov.unanalysed) > 10:
            console.print(f"[dim]  - …and {cov.files_total - cov.files_analysed - 10} more files not analysed[/dim]")
    if report.stats.suppressed:
        console.print(f"[dim]{report.stats.suppressed} finding(s) suppressed by configuration.[/dim]")
    for reason in report.verdict_reasons[:5]:
        console.print(f"[dim]  because: {_e(reason)}[/dim]")
    console.print(
        f"[{VERDICT_STYLE[report.verdict]}] {report.verdict.value} [/]  score {report.score}  ·  tier {report.risk_tier.value}"
        f"  ·  coverage {cov.files_analysed}/{cov.files_total} files ({round(cov.analyzability * 100)}%)"
        f"  ·  {len(report.findings)} finding(s)")
    if report.verdict == Verdict.allow:
        console.print(f"[dim]{ALLOW_NOTE}[/dim]")
