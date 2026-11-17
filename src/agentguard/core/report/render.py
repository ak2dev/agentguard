"""Pure renderers: Report → bytes/str. Identical output across CLI and web.

All scanned text reaching an output already went through ``redact_snippet``
(Evidence.snippet is a RedactedText). Renderers additionally neutralize
format-specific injection: Markdown control characters, @mentions, #refs,
remote images, HTML and XML.

Formats: JSON (the report itself), SARIF 2.1.0, Markdown, JUnit, CycloneDX
(AI-BOM) and trust cards. The HTML report is in ``html.py``.
"""

from __future__ import annotations

import hashlib
import html
import json
import uuid
from typing import Any

import regex

from ..models import Finding, Report
from ..models.enums import Category, FixKind, Severity, Verdict
from ..redact import redact_secrets

TOOL_NAME = "Agent Guard"
INFO_URI = "https://github.com/ak2dev/agentguard"
# spec/interfaces.md §9: critical 9.5, high 8.0, medium 5.5, low 3.0, info 0.
SEVERITY_SCORE = {Severity.critical: "9.5", Severity.high: "8.0", Severity.medium: "5.5", Severity.low: "3.0",
                  Severity.info: "0.0"}
SARIF_LEVEL = {Severity.critical: "error", Severity.high: "error", Severity.medium: "warning", Severity.low: "note",
               Severity.info: "note"}
FRAMEWORK_LABEL = {
    "owasp_asi": "OWASP Agentic", "owasp_mcp": "OWASP MCP", "owasp_ast": "OWASP Skills", "owasp_llm": "OWASP LLM",
    "nsa_csi_mcp": "NSA MCP CSI", "cwe": "CWE", "skilltrustbench": "SkillTrustBench", "malskillbench": "MalSkillBench",
    "mitre_atlas": "MITRE ATLAS",
}
FIX_LABEL = {
    FixKind.auto: "Auto-fix available", FixKind.patch: "Proposed patch", FixKind.guidance: "Guidance",
    FixKind.remove: "Do not install", FixKind.none: "No fix",
}
CATEGORY_TITLE = {Category.malice: "Malice", Category.vulnerability: "Vulnerabilities", Category.hygiene: "Hygiene"}
ALLOW_NOTE = "ALLOW means nothing that counts towards the verdict matched. It does not mean safe."


def mapping_ids(f: Finding) -> list[str]:
    return [i for ids in f.mappings.values() for i in ids]


def agent_safe(report: Report) -> Report:
    """A copy of the report with nothing an agent could be injected by:
    evidence snippets and decoded payloads are withheld, and every string that
    came from the target (names, paths) is length-limited and stripped of
    control and invisible characters. Rule ids, fixed rule wording, file and
    line, verdict and fix summary remain (spec/interfaces.md §11)."""
    from .agent_safe import scrub_report

    return scrub_report(report)


# ---------------------------------------------------------------- JSON ------
def render_json(report: Report) -> str:
    return report.model_dump_json(indent=2, exclude_none=True) + "\n"


# ---------------------------------------------------------------- SARIF -----
def _sarif_rule(f: Finding) -> dict[str, Any]:
    tags = ["security", "agent-guard", f.family, f.category.value, f"lane:{f.lane.value}", *mapping_ids(f)[:12]]
    props: dict[str, Any] = {"tags": tags[:20], "precision": f.confidence.value,
                             "security-severity": SEVERITY_SCORE[f.severity]}
    fix = f"{FIX_LABEL[f.fix.kind]}: {f.fix.summary}" if f.fix.summary else FIX_LABEL[f.fix.kind]
    help_md = f"**{f.title}**\n\n{f.explanation}\n\n**Fix.** {fix}"
    return {
        "id": f.id,
        "name": regex.sub(r"[^A-Za-z0-9]+", "", f.title.title())[:64] or f.id,
        "shortDescription": {"text": f.title},
        "fullDescription": {"text": f.explanation or f.title},
        "help": {"text": f"{f.explanation}\n\nFix. {fix}", "markdown": help_md},
        "helpUri": f"{INFO_URI}/blob/main/docs/rules/{f.id}.md",
        "defaultConfiguration": {"level": SARIF_LEVEL[f.severity]},
        "properties": props,
    }


def _sarif_location(path: str, line: int, col: int = 1, end_line: int | None = None, end_col: int | None = None,
                    uri_base: str | None = None, snippet: str = "") -> dict[str, Any]:
    region: dict[str, Any] = {"startLine": max(1, line), "startColumn": max(1, col)}
    if end_line and end_line >= line:
        region["endLine"] = end_line
        if end_col:
            region["endColumn"] = max(1, end_col)
    if snippet:
        region["snippet"] = {"text": snippet}
    art: dict[str, Any] = {"uri": path}
    if uri_base:
        art["uriBaseId"] = uri_base
    return {"physicalLocation": {"artifactLocation": art, "region": region}}


def _sarif_result(f: Finding, rule_index: dict[str, int], uri_base: str | None) -> dict[str, Any]:
    locs = []
    p = f.primary
    if p:
        locs.append(_sarif_location(p.path, p.start_line, p.start_col, p.end_line, p.end_col, uri_base,
                                    str(f.evidence.snippet)))
    result: dict[str, Any] = {
        "ruleId": f.id,
        "ruleIndex": rule_index[f.id],
        "level": SARIF_LEVEL[f.severity],
        "message": {"text": f.risk or f.title},
        "locations": locs,
        "partialFingerprints": {"primaryLocationLineHash": f.fingerprint, "agentguard/v1": f.fingerprint},
        "properties": {
            "severity": f.severity.value,
            "confidence": f.confidence.value,
            "category": f.category.value,
            "lane": f.lane.value,
            "countsTowardsVerdict": f.corroborated,
            "engines": f.engines,
            **({"variant": f.variant} if f.variant else {}),
            **({"chain": f.chain} if f.chain else {}),
            **({"aivss": f.aivss.value} if f.aivss else {}),
            "tags": f.tags,
        },
    }
    if f.related:
        result["relatedLocations"] = [
            {"id": i + 1, **_sarif_location(s.path, s.start_line, uri_base=uri_base)} for i, s in enumerate(f.related[:50])
        ]
    if f.trace:
        result["codeFlows"] = [{"threadFlows": [{"locations": [
            {"location": {**_sarif_location(t.file, t.line, uri_base=uri_base), "message": {"text": t.role or "step"}}}
            for t in f.trace
        ]}]}]
    if f.fix.patch and p:
        result["fixes"] = [{
            "description": {"text": f.fix.summary or FIX_LABEL[f.fix.kind]},
            "artifactChanges": [{
                "artifactLocation": {"uri": p.path, **({"uriBaseId": uri_base} if uri_base else {})},
                "replacements": [{"deletedRegion": {"startLine": max(1, p.start_line)},
                                  "insertedContent": {"text": f.fix.patch}}],
            }],
        }]
    if f.suppression is not None and f.suppression.status == "active":
        result["suppressions"] = [{"kind": "inSource" if f.suppression.kind == "inline" else "external",
                                   "justification": f.suppression.reason, "status": "accepted"}]
    return result


def render_sarif(report: Report, uri_base: str | None = None) -> str:
    everything = [*report.findings, *report.suppressed_findings]
    rules: dict[str, dict[str, Any]] = {}
    for f in everything:
        if f.id not in rules:
            rules[f.id] = _sarif_rule(f)
    rule_index = {rid: i for i, rid in enumerate(sorted(rules))}
    results = [_sarif_result(f, rule_index, uri_base) for f in everything]
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "informationUri": INFO_URI,
                        "semanticVersion": report.engine_version,
                        "version": report.engine_version,
                        "rules": [rules[r] for r in sorted(rules)],
                        "properties": {"rulePack": report.tool.rule_pack, "rulePackDigest": report.tool.rule_pack_digest,
                                       "intel": report.tool.intel},
                    }
                },
                "automationDetails": {"id": "agentguard/"},
                "invocations": [{"executionSuccessful": not any(a.status == "errored" for a in report.analyzers)}],
                "results": results,
                "properties": {
                    "verdict": report.verdict.value,
                    "verdictReasons": report.verdict_reasons,
                    "score": report.score,
                    "riskTier": report.risk_tier.value,
                    "coverage": report.coverage.model_dump(exclude={"unanalysed"}),
                    "profile": report.profile,
                    "policy": report.policy,
                    "summary": report.summary,
                    "networkFeaturesUsed": report.network_features_used,
                },
            }
        ],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False) + "\n"


# ------------------------------------------------------------- Markdown -----
_MD_SPECIAL = regex.compile(r"([\\`*_{}\[\]()#+!|<>~])")


def md_escape(text: str) -> str:
    t = _MD_SPECIAL.sub(r"\\\1", text)
    t = regex.sub(r"@(?=\w)", "@​", t)          # neutralize @mentions
    t = regex.sub(r"(?<=\s|^)#(?=\d)", "#​", t)  # neutralize #123 refs
    return t.replace("\n", " ")


def _md_code(text: str) -> str:
    return "`" + text.replace("`", "ˋ").replace("\n", " ") + "`"


def render_markdown(report: Report, max_findings: int = 50) -> str:
    sev = report.stats.findings_by_severity
    cov = report.coverage
    lines = [
        "## Agent Guard scan",
        "",
        f"**Verdict: {report.verdict.value}** · score {report.score} · risk tier {report.risk_tier.value} · "
        f"coverage {cov.files_analysed}/{cov.files_total} files ({round(cov.analyzability * 100)}%)",
        "",
    ]
    if report.verdict_reasons:
        lines += [f"- {md_escape(r)}" for r in report.verdict_reasons[:6]] + [""]
    lines += [
        "| critical | high | medium | low | info |",
        "|---:|---:|---:|---:|---:|",
        f"| {sev.get('critical', 0)} | {sev.get('high', 0)} | {sev.get('medium', 0)} | {sev.get('low', 0)} | {sev.get('info', 0)} |",
        "",
    ]
    if report.network_features_used:
        lines += [f"Network features used: {', '.join(report.network_features_used)}", ""]
    skipped = [a for a in report.analyzers if a.status != "ran" and a.reason != "not selected"]
    if skipped or cov.unanalysed:
        lines += ["<details><summary>Coverage notes</summary>", ""]
        lines += [f"- `{a.id}`: {a.status} — {md_escape(a.reason)}" for a in skipped]
        lines += [f"- not analysed: {_md_code(u.path)} ({md_escape(u.reason)})" for u in cov.unanalysed[:20]]
        lines += ["", "</details>", ""]
    left = max_findings
    hidden = 0
    for cat in Category:
        group = [f for f in report.findings if f.category == cat and f.severity != Severity.info]
        if not group:
            continue
        lines += [f"### {CATEGORY_TITLE[cat]} ({len(group)})", "", "| Severity | Rule | Location | Risk | Fix |", "|---|---|---|---|---|"]
        for f in group[:max(left, 0)]:
            loc = _md_code(f"{f.primary.path}:{f.primary.start_line}") if f.primary else ""
            fix = f"{FIX_LABEL[f.fix.kind]}. {md_escape(f.fix.summary)[:200]}"
            lines.append(f"| {f.severity.value} | `{f.id}` | {loc} | {md_escape(f.risk)[:300]} | {fix} |")
        hidden += max(0, len(group) - max(left, 0))
        left -= len(group)
        lines.append("")
    if hidden > 0:
        lines += [f"…and {hidden} more. See the full report artifact.", ""]
    if report.chains:
        lines += ["### Attack chains", ""]
        by_fp = {f.fingerprint: f for f in report.findings}
        for ch in report.chains[:10]:
            path = " → ".join(by_fp[s].id for s in ch.steps if s in by_fp)
            lines.append(f"- `{ch.id}` ({ch.severity.value}{', ends in ' + ch.sink if ch.sink else ''}): {path}")
        lines.append("")
    lines += [f"<sub>Agent Guard {report.engine_version} · rule pack {report.tool.rule_pack} · profile {report.profile} · "
              f"policy {report.policy}. {ALLOW_NOTE}</sub>", ""]
    return "\n".join(lines)


# ---------------------------------------------------------------- JUnit -----
def _xml(text: str) -> str:
    # XML 1.0 forbids most control characters even when escaped.
    cleaned = regex.sub(r"[^\x09\x0A\x0D\x20-퟿-�\U00010000-\U0010FFFF]", "", text)
    return html.escape(cleaned, quote=True)


def render_junit(report: Report) -> str:
    """One test case per rule that ran into a finding, with failures as
    findings, plus one passing case for the verdict when nothing failed."""
    by_rule: dict[str, list[Finding]] = {}
    for f in report.findings:
        by_rule.setdefault(f.id, []).append(f)
    failures = sum(1 for fs in by_rule.values() if any(f.corroborated and f.category != Category.hygiene for f in fs))
    out = ['<?xml version="1.0" encoding="UTF-8"?>',
           f'<testsuites name="agentguard" tests="{max(len(by_rule), 1)}" failures="{failures}">',
           f'  <testsuite name="agentguard.{_xml(report.verdict.value)}" tests="{max(len(by_rule), 1)}" failures="{failures}">',
           "    <properties>",
           f'      <property name="verdict" value="{_xml(report.verdict.value)}"/>',
           f'      <property name="score" value="{report.score}"/>',
           f'      <property name="risk_tier" value="{report.risk_tier.value}"/>',
           f'      <property name="coverage" value="{report.coverage.analyzability}"/>',
           f'      <property name="rule_pack" value="{_xml(report.tool.rule_pack)}"/>',
           "    </properties>"]
    if not by_rule:
        out.append(f'    <testcase classname="agentguard" name="{_xml(report.summary)}"/>')
    for rid in sorted(by_rule):
        fs = by_rule[rid]
        first = fs[0]
        out.append(f'    <testcase classname="agentguard.{_xml(first.family)}" name="{_xml(rid + " " + first.title)}">')
        counting = [f for f in fs if f.corroborated and f.category != Category.hygiene]
        body = "\n".join(
            f"{f.severity.value} {f.primary.path + ':' + str(f.primary.start_line) if f.primary else '-'} {f.risk}" for f in fs)
        if counting:
            top = max(counting, key=lambda f: f.severity.rank)
            out.append(f'      <failure type="{_xml(top.severity.value)}" message="{_xml(top.risk[:300])}">{_xml(body)}</failure>')
        else:
            out.append(f"      <system-out>{_xml(body)}</system-out>")
        out.append("    </testcase>")
    out += ["  </testsuite>", "</testsuites>", ""]
    return "\n".join(out)


# ------------------------------------------------------------ CycloneDX -----
_BOM_KINDS = ("skill", "mcp_server", "package", "instruction_file", "subagent", "command", "plugin", "hook",
              "settings", "bundle", "connector", "container", "marketplace", "ci_workflow")


def render_cyclonedx(report: Report, serial: str | None = None) -> str:
    """CycloneDX 1.6 AI-BOM: one component per skill, plugin, server, hook and
    instruction file, with version, hash, source, capabilities, risk tier and
    scan status. Deterministic: no timestamp, serial derived from content."""
    summaries = {a.component_id: a for a in report.artifacts}
    comps = []
    for c in report.inventory:
        if c.kind.value not in _BOM_KINDS:
            continue
        props = [{"name": "agentguard:kind", "value": c.kind.value}]
        summary = summaries.get(c.id)
        if summary is not None:
            props += [
                {"name": "agentguard:ecosystem", "value": summary.ecosystem},
                {"name": "agentguard:risk_tier", "value": summary.risk_tier.value},
                {"name": "agentguard:verdict", "value": summary.verdict.value},
                {"name": "agentguard:findings", "value": str(summary.findings)},
            ]
            props += [{"name": "agentguard:capability", "value": cap} for cap in summary.capabilities]
        if c.server:
            props += [
                {"name": "agentguard:transport", "value": c.server.transport.value},
                {"name": "agentguard:client", "value": c.server.client},
                {"name": "agentguard:scope", "value": c.server.scope},
                {"name": "agentguard:pinned", "value": str(c.server.pinned).lower()},
            ]
            if c.server.pin_detail:
                props.append({"name": "agentguard:pin_detail", "value": c.server.pin_detail})
            if c.server.command:
                props.append({"name": "agentguard:command", "value": c.server.command})
            if c.server.url:
                props.append({"name": "agentguard:url", "value": redact_secrets(c.server.url)})
            for n in c.server.env_names:
                props.append({"name": "agentguard:env_name", "value": n})
        entry: dict[str, Any] = {
            "type": "application" if c.kind.value in ("mcp_server", "package", "plugin", "bundle", "container") else "data",
            "bom-ref": c.id,
            "name": c.name,
            "properties": props,
        }
        if c.version:
            entry["version"] = c.version
        if c.publisher:
            entry["publisher"] = c.publisher
        if c.content_hash:
            entry["hashes"] = [{"alg": "SHA-256", "content": c.content_hash}]
        if c.root:
            entry["properties"].append({"name": "agentguard:source", "value": c.root})
        comps.append(entry)
    digest = hashlib.sha256(json.dumps(comps, sort_keys=True).encode()).digest()
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": serial or f"urn:uuid:{uuid.UUID(bytes=digest[:16], version=5)}",
        "version": 1,
        "metadata": {
            "tools": {"components": [{"type": "application", "name": TOOL_NAME, "version": report.engine_version}]},
            "properties": [
                {"name": "agentguard:rule_pack", "value": report.tool.rule_pack},
                {"name": "agentguard:verdict", "value": report.verdict.value},
                {"name": "agentguard:score", "value": str(report.score)},
            ],
        },
        "components": comps,
    }
    return json.dumps(bom, indent=2, ensure_ascii=False) + "\n"


# ----------------------------------------------------------- Trust card -----
_TIER_TEXT = {
    "L0": "only adds instructions", "L1": "writes files inside the workspace",
    "L2": "uses shell, network or credentials", "L3": "makes persistent or system-level changes",
}


def trust_cards(report: Report) -> list[dict[str, Any]]:
    """A short summary per component: what it is, what it can do, where it came
    from, verdict, and what would change the verdict."""
    by_comp: dict[str, list[Finding]] = {}
    for f in report.findings:
        for cid in f.component_ids:
            by_comp.setdefault(cid, []).append(f)
    cards = []
    for a in report.artifacts:
        mine = sorted(by_comp.get(a.component_id, []), key=Finding.sort_key)
        counting = [f for f in mine if f.corroborated and f.category != Category.hygiene]
        if a.verdict == Verdict.allow:
            change = "A finding at high severity, a malice finding, or content that cannot be analysed would move it to REVIEW."
        else:
            top = counting[:3] or mine[:3]
            change = "Resolving " + ", ".join(f"{f.id} ({f.fix.kind.value})" for f in top) + " would improve the verdict." if top else ""
        cards.append({
            "id": a.id, "what": f"{a.type} for {a.ecosystem}", "name": a.name, "version": a.version,
            "can_do": a.capabilities, "risk_tier": a.risk_tier.value, "risk_tier_meaning": _TIER_TEXT[a.risk_tier.value],
            "source": report.target.source, "commit": report.target.commit, "verdict": a.verdict.value,
            "findings": len(mine), "top_findings": [{"id": f.id, "severity": f.severity.value, "title": f.title} for f in counting[:5]],
            "what_would_change_it": change, "rule_pack": report.tool.rule_pack,
            "least_privilege": a.least_privilege.model_dump(mode="json") if a.least_privilege else None,
            "triage": a.triage,
            "date": report.generated_at.date().isoformat() if report.generated_at else None,
        })
    return cards


def _grant_line(plan: dict[str, Any] | None) -> str:
    """The least-privilege proposal as one Markdown bullet (rule text and tool names only, in code spans)."""
    if not plan or not plan.get("allowed_tools"):
        return ""
    tools = ", ".join(f"`{md_escape(t)}`" for t in plan["allowed_tools"][:12])
    domains = (plan.get("sandbox") or {}).get("network", {}).get("allowedDomains") or []
    net = "network to " + ", ".join(f"`{md_escape(d)}`" for d in domains[:8]) if domains else "no network"
    return f"- **Smallest grant that covers what it does:** {tools}; sandbox with {net}"


def render_trust_cards(report: Report) -> str:
    lines = ["## Trust cards", ""]
    for card in trust_cards(report):
        lines += [
            f"### {md_escape(card['id'])} — {card['verdict']}",
            "",
            f"- **What it is:** {md_escape(card['what'])}" + (f", version {md_escape(card['version'])}" if card["version"] else ""),
            f"- **What it can do:** tier {card['risk_tier']} ({card['risk_tier_meaning']})"
            + (": " + ", ".join(card["can_do"]) if card["can_do"] else ""),
            f"- **Where it came from:** {md_escape(card['source'] or 'local')}" + (f" at {card['commit'][:12]}" if card["commit"] else ""),
            f"- **Findings:** {card['findings']}" + ("".join(f"\n  - `{t['id']}` {t['severity']}: {md_escape(t['title'])}"
                                                           for t in card["top_findings"])),
            f"- **What would change the verdict:** {md_escape(card['what_would_change_it'])}" if card["what_would_change_it"] else "",
            _grant_line(card["least_privilege"]),
            (f"- **Triage model:** {card['triage']:.2f} probability of malice (advisory; it never decides the verdict alone)"
             if card["triage"] is not None else ""),
            "",
        ]
    lines.append(f"<sub>{ALLOW_NOTE}</sub>")
    return "\n".join(ln for ln in lines if ln is not None) + "\n"


def html_escape(text: str) -> str:
    return html.escape(text, quote=True)
