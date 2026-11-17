"""`agentguard explain <id>`: a rule, or one finding of a report."""

from __future__ import annotations

import json

from rich.console import Console
from rich.markup import escape

from ..core import verdict as verdicts
from ..core.models import Finding, Report, RuleDef
from ..core.report.render import FIX_LABEL, FRAMEWORK_LABEL
from ..core.rules.export import export_rule
from ..core.rules.pack import RulePack
from ..core.textutil import visible_escape

LANE_TEXT = {
    "block": "block: high precision; can produce a BLOCK verdict alone",
    "evidence": "evidence: counts towards the verdict only when another engine, a chain or the adjudicator backs it up",
    "hunt": "hunt: advisory; off in the balanced policy, on in strict",
}
STATUS_TEXT = {
    "planned": "planned: in the catalogue, no detector in this rule pack yet",
    "experimental": "experimental: has a detector and fixtures",
    "stable": "stable: at least five positive and five negative fixtures",
    "deprecated": "deprecated",
}


def _e(text: str) -> str:
    return escape(visible_escape(text or ""))


def explain_rule(pack: RulePack, rule: RuleDef, ident: str, console: Console, json_out: bool = False) -> None:
    data = export_rule(pack, rule)
    key = pack.resolve_key(ident)
    if json_out:
        console.file.write(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
        return
    console.print(f"[bold]{rule.id}[/bold]  {_e(rule.title)}")
    console.print(f"family {rule.family} · category {rule.category.value} · severity {rule.severity.value}"
                  + (" (from the matched content)" if rule.severity_from_content else "")
                  + f" · confidence floor {rule.confidence.value} · engine {rule.engine}")
    console.print(f"lane    {LANE_TEXT[rule.lane.value]}")
    console.print(f"status  {STATUS_TEXT[rule.status.value]}")
    if rule.blocks_allow:
        console.print("coverage rule: a finding prevents an ALLOW verdict")
    if data["aliases"]:
        console.print(f"[dim]also known as: {', '.join(data['aliases'])}[/dim]")
    if data["description"]:
        console.print(f"\n[bold]Detects[/bold]\n{_e(data['description'])}")
    if data["why"]:
        console.print(f"\n[bold]Risk[/bold]\n{_e(data['why'])}")
    fix = FIX_LABEL[rule.fix]
    console.print(f"\n[bold]Fix[/bold] ({fix})\n{_e(data['remediation'] or 'See the rule description.')}")
    if data["variants"]:
        console.print("\n[bold]Variants[/bold]")
        for v in data["variants"]:
            mark = "→ " if key == f"{rule.id}/{v['key']}" else "  "
            console.print(f"{mark}{rule.id}/{v['key']}  [{v['severity']}, {v['lane']}]  {_e(v['title'])}")
            if key == f"{rule.id}/{v['key']}":
                console.print(f"    {_e(v['description'])}")
                if v["remediation"]:
                    console.print(f"    Fix: {_e(v['remediation'])}")
    maps = [f"{FRAMEWORK_LABEL.get(k, k)} {', '.join(ids)}" for k, ids in data["mapping_ids"].items() if ids]
    if maps:
        console.print("\n[bold]Standards[/bold]\n" + "\n".join(f"  {_e(m)}" for m in maps))
    for ref in data["references"]:
        console.print(f"  ref: {_e(ref)}")
    n = data["fixtures"]
    console.print(f"\n[dim]fixtures: {n['positive']} positive, {n['negative']} negative[/dim]")


def explain_finding(pack: RulePack, report: Report, f: Finding, console: Console, json_out: bool = False) -> None:
    if json_out:
        console.file.write(f.model_dump_json(indent=2, exclude_none=True) + "\n")
        return
    effect = verdicts.effect(f, report.chains)
    loc = f.location
    console.print(f"[bold]{f.id}[/bold]{'/' + f.variant if f.variant else ''}  {_e(f.title)}")
    console.print(f"fingerprint {f.fingerprint}")
    console.print(f"severity {f.severity.value} · confidence {f.confidence.value} · category {f.category.value} · "
                  f"lane {f.lane.value} · engines {', '.join(f.engines) or '-'}")
    if loc is not None:
        where = f"{loc.file}:{loc.start.line}:{loc.start.column}"
        if loc.end is not None:
            where += f" → {loc.end.line}:{loc.end.column}"
        console.print(f"\n[bold]Cause[/bold]  {_e(where)}" + (f"  ({_e(loc.artifact)})" if loc.artifact else ""))
    if str(f.evidence.snippet):
        console.print(f"  [dim]›[/dim] {_e(str(f.evidence.snippet))}")
    if str(f.evidence.decoded):
        console.print(f"  [dim]decoded ({_e(', '.join(f.evidence.derivation) or 'hidden')}):[/dim] {_e(str(f.evidence.decoded))}")
    for step in f.trace:
        console.print(f"  [dim]trace[/dim] {_e(step.file)}:{step.line} {_e(step.role)}")
    console.print(f"\n[bold]Risk[/bold]   {_e(f.risk or f.explanation)}")
    if f.explanation and f.explanation != f.risk:
        console.print(f"         [dim]{_e(f.explanation)}[/dim]")
    console.print(f"\n[bold]Fix[/bold]    ({FIX_LABEL[f.fix.kind]}) {_e(f.fix.summary)}")
    if f.fix.patch:
        console.print(_e(f.fix.patch))
    why = {"block": "it is one of the findings that decide the BLOCK verdict",
           "review": "it requires a review",
           "info": "it does not affect the verdict" + ("" if f.corroborated else " (not corroborated by another engine)")}[effect]
    console.print(f"\n[bold]Verdict[/bold] {report.verdict.value}: {why}.")
    if f.chain:
        ch = next((c for c in report.chains if c.id == f.chain), None)
        if ch is not None:
            by_fp = {x.fingerprint: x for x in report.findings}
            console.print(f"  part of {ch.id}: " + " → ".join(by_fp[s].id for s in ch.steps if s in by_fp)
                          + (f" (ends in {ch.sink})" if ch.sink else ""))
    if f.adjudication is not None and f.adjudication.status != "not_run":
        console.print(f"  model: {f.adjudication.status} by {_e(f.adjudication.model)}: {_e(f.adjudication.rationale)}")
    if f.suppression is not None:
        console.print(f"  suppression: {f.suppression.status}, expires {f.suppression.expires}: {_e(f.suppression.reason)}")
    console.print(f"\n[dim]Rule details: agentguard explain {f.id}[/dim]")
