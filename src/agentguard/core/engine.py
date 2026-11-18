"""The scan pipeline: inventory → text units → analyzers → correlation →
finalize (severity invariants, dedupe) → suppressions → chains → adjudication →
corroboration → verdict, score, tier → report.

``scan`` is pure: no filesystem, no network, no wall clock (unless
``options.include_timestamps``). Same tree + same rule pack → identical report.
"""

from __future__ import annotations

import datetime as dt
import posixpath
import time
from collections import Counter

from . import triage as triage_model
from . import verdict as verdicts
from .analyzers.base import Context, RawFinding
from .analyzers.registry import ANALYZERS, CORRELATORS, native_available
from .chains import build_chains
from .coverage import compute_coverage
from .inventory import NESTED, Inventory, build_inventory
from .models import (
    Adjudication,
    AnalyzerMatch,
    AnalyzerRun,
    ArtifactSummary,
    Component,
    DynamicLimits,
    Evidence,
    EvidenceSummary,
    Finding,
    Fix,
    LeastPrivilege,
    LimitEvent,
    Limits,
    LlmLimits,
    Location,
    ProgressEvent,
    Report,
    ReportStats,
    ScanOptions,
    Span,
    TargetInfo,
    ToolInfo,
    TraceStep,
)
from .models.enums import (
    ArtifactRole,
    Category,
    ComponentKind,
    Confidence,
    EvidenceKind,
    FindingSource,
    Lane,
    RiskTier,
    Severity,
    Verdict,
)
from .models.finding import mapping_dict
from .models.rule import Detector
from .policy.apply import apply_baseline, apply_inline_suppressions, apply_suppressions
from .redact import RedactedText
from .rules.pack import RulePack
from .scoring.aivss import DEFAULT_SCORER, Scorer
from .textutil import sha256_hex, visible_escape
from .tree import ArtifactTree

ENGINE_VERSION = "0.2.0.dev0"

# Findings that are *about* hidden content are not escalated for sitting in it.
_NO_HIDDEN_ESCALATION_FAMILIES = ("OBF", "EVADE", "MM")
_NO_HIDDEN_ESCALATION_KEYS = ("AG-MCP-020/hidden-unicode", "AG-CFG-092", "AG-META-015")

# Which engine (PLAN §5.4) an analyzer belongs to. Regex rules are placed by the text they matched.
ANALYZER_ENGINE: dict[str, str] = {
    "sys.limits": "coverage", "coverage": "coverage", "skill.bundle": "coverage",
    "mcp.units": "config", "skill.spec": "config", "skill.exec": "config", "mcp.config": "config",
    "mcp.meta": "config", "settings": "config", "plugins": "config", "ci": "config", "workspace": "config",
    "descriptors": "config", "hooks": "config", "hygiene": "config",
    "text.hidden": "text-integrity", "text.integrity": "text-integrity",
    "code": "code", "code.ts": "code", "mcp.client_auth": "code", "skill.staged": "code", "yara": "code",
    "code.patterns": "code",
    "skill.privilege": "privilege", "capabilities": "privilege", "privilege": "privilege",
    "skill.typosquat": "supply", "supply.offline": "supply", "supply.drift": "supply", "supply.provenance": "supply",
    "supply.osv": "supply", "supply.age": "supply", "supply.hijack": "supply", "supply.deps": "supply",
    "supply.intel": "intel",
    "auth": "live", "live": "live",
    "judge": "judge", "triage": "triage",
    "corr.cred_egress": "flow", "flows": "flow", "composition": "flow",
    "media": "media", "image": "image", "containers": "image",
    "policy": "policy", "engine": "coverage", "dynamic": "dynamic",
}

_ARTIFACT_PREFIX = {
    ComponentKind.skill: "skill", ComponentKind.mcp_server: "mcp", ComponentKind.plugin: "plugin",
    ComponentKind.instruction_file: "instructions", ComponentKind.subagent: "agent", ComponentKind.command: "command",
    ComponentKind.mcp_client_config: "config", ComponentKind.package: "package", ComponentKind.settings: "settings",
    ComponentKind.hook: "hook", ComponentKind.ci_workflow: "ci", ComponentKind.workspace: "workspace",
    ComponentKind.container: "image", ComponentKind.connector: "connector", ComponentKind.bundle: "bundle",
    ComponentKind.marketplace: "marketplace", ComponentKind.repository: "repo", ComponentKind.agent_host: "host",
}
_ECOSYSTEM_PATHS = (
    (".claude-plugin/", "claude-code"), (".claude/", "claude-code"), ("claude.md", "claude-code"),
    ("claude.local.md", "claude-code"), (".mcp.json", "claude-code"),
    (".codex-plugin/", "codex"), (".codex/", "codex"), ("agents/openai.yaml", "codex"),
    (".cursor-plugin/", "cursor"), (".cursor/", "cursor"), (".cursorrules", "cursor"),
    (".gemini/", "gemini"), ("gemini.md", "gemini"), ("gemini-extension.json", "gemini"),
    (".github/", "copilot"), (".vscode/", "copilot"), (".copilot/", "copilot"),
    (".openclaw/", "openclaw"), ("openclaw.plugin.json", "openclaw"), ("openclaw.json", "openclaw"),
)


TIMED_OUT = "scan time limit reached"
# Ecosystems `--ecosystem` can select. Everything else (agent-skills, mcp, generic, …) is agent-neutral.
AGENT_ECOSYSTEMS = ("claude-code", "codex", "cursor", "gemini", "copilot", "openclaw")


def _progress(options: ScanOptions, stage: str, done: int, total: int) -> None:
    if options.on_progress is not None:
        options.on_progress(ProgressEvent(stage=stage, done=done, total=total))


def scan(tree: ArtifactTree, options: ScanOptions | None = None, pack: RulePack | None = None,
         scorer: Scorer | None = None) -> Report:
    started = time.perf_counter()
    options = options or ScanOptions()
    pack = pack or RulePack.default()
    scorer = scorer or DEFAULT_SCORER
    policy = options.effective_policy

    inv = build_inventory(tree, options.limits)
    ctx = Context(inventory=inv, pack=pack, options=options)
    ctx.data["limit_events"] = list(tree.limit_events)

    runs: list[AnalyzerRun] = []
    stages = [*ANALYZERS, *CORRELATORS]
    for i, analyzer_cls in enumerate(stages):
        _progress(options, analyzer_cls.id, i, len(stages))
        analyzer = analyzer_cls()
        reason = _skip_reason(analyzer_cls, options)
        if not reason and options.deadline_s is not None and time.perf_counter() - started > options.deadline_s:
            reason = TIMED_OUT
        if reason:
            runs.append(AnalyzerRun(id=analyzer_cls.id, status="skipped", reason=reason))
            continue
        ctx.current = analyzer_cls.id
        ctx.allowed_rules = frozenset(analyzer_cls.rules)
        try:
            analyzer.run(ctx)
            runs.append(AnalyzerRun(id=analyzer_cls.id, status="ran"))
        except Exception as exc:  # noqa: BLE001 — isolate analyzer failures; never fail open
            runs.append(AnalyzerRun(id=analyzer_cls.id, status="errored", reason=f"{type(exc).__name__}: {str(exc)[:200]}"))
            ctx.current = "engine"
            ctx.allowed_rules = frozenset()
            ctx.emit(
                "AG-EVADE-002/analyzer-error",
                component_ids=[],
                span=None,
                snippet="",
                detail=f"analyzer {analyzer_cls.id} failed: {type(exc).__name__}",
                message=f"Analyzer '{analyzer_cls.id}' failed; coverage is reduced.",
                kind=EvidenceKind.loader,
            )
    _progress(options, "finalize", len(stages), len(stages))
    ctx.current = "engine"
    ctx.allowed_rules = frozenset()
    timed_out = [r.id for r in runs if r.reason == TIMED_OUT]
    if timed_out:
        ctx.emit("AG-EVADE-002/analyzer-error", component_ids=[], span=None, snippet="", kind=EvidenceKind.loader,
                 detail="time limit", match="deadline",
                 message=f"The scan reached its time limit of {options.deadline_s:g} s; {len(timed_out)} analyzer(s) did "
                         f"not run ({', '.join(timed_out[:6])}{'…' if len(timed_out) > 6 else ''}). Coverage is reduced.")
    _emit_dynamic(ctx)
    _emit_model_limits(ctx)
    coverage = compute_coverage(tree, inv, ctx)
    _emit_coverage_threshold(ctx, coverage, policy.require.min_analyzability)

    ran = {r.id for r in runs if r.status == "ran"}
    evaluated = {
        d.rule_id for d in pack.detectors.values()
        if d.enabled and d.match is not None and ctx.rule_enabled(d.key)
        and ((isinstance(d.match, AnalyzerMatch) and (d.match.analyzer in ran or d.match.analyzer == "engine"))
             or (not isinstance(d.match, AnalyzerMatch) and d.match.type in ran))  # "regex" / "yara" analyzers
    }

    raw = ctx.raw
    if options.ecosystems is not None:
        raw = _ecosystem_filter(raw, inv, options.ecosystems)
    if options.changed_paths is not None:
        raw = _pr_filter(raw, ctx, options.changed_paths)
    labels = _artifact_labels(inv)
    findings = _finalize(raw, ctx, pack, options, labels)

    # Hunt-lane findings are advisory: dropped unless the policy turns the lane on. The triage model still reads
    # them (a hunt-lane hit is one of its inputs), so they are kept aside for it.
    hunt_hidden = 0
    hunt_aside: list[Finding] = []
    if not policy.lanes.hunt:
        kept = [f for f in findings if f.lane != Lane.hunt]
        hunt_aside = [f for f in findings if f.lane == Lane.hunt]
        hunt_hidden = len(findings) - len(kept)
        findings = kept

    all_suppressions = [*options.suppressions, *policy.suppressions]
    findings, suppressed, problems = apply_suppressions(findings, options, pack, all_suppressions)
    if options.own_repo:
        findings, inline = apply_inline_suppressions(findings, inv, options, pack)
        suppressed += inline
    for s, why in problems:
        if "AG-POL-006" in pack.detectors:
            findings.append(_synthetic(pack, "AG-POL-006", f"Suppression for {s.rule_id or s.fingerprint or s.path_glob} ignored: {why}.",
                                       key=f"{s.rule_id}|{s.fingerprint}|{s.path_glob}"))
    for f in list(findings):
        if f.suppression and f.suppression.status == "expired" and "AG-POL-005" in pack.detectors:
            findings.append(_synthetic(pack, "AG-POL-005", f"Suppression of {f.id} expired on {f.suppression.expires}; "
                                       "the finding is reported again.", key=f.fingerprint, primary=f.primary))

    chains = build_chains(findings, inv, ctx)
    _apply_adjudications(findings, pack, options)
    verdicts.raise_for_agreement(findings)
    triage, agrees, triage_run = _triage(inv, [*findings, *hunt_aside], options, pack)
    runs.append(triage_run)
    # A package's tests are not what it ships to an agent, unless an agent-facing file runs or names one
    # (the inventory then holds it as a script or reference, and it counts like any other).
    aside = frozenset(p for p, a in inv.artifacts.items()
                      if a.role in (ArtifactRole.repo_code, ArtifactRole.repo_doc, ArtifactRole.source_code, ArtifactRole.other)
                      and verdicts.is_test_path(p))
    verdicts.corroborate(findings, hunt=policy.lanes.hunt, triage=triage, aside=aside, agrees=agrees)

    for f in [*findings, *suppressed]:
        comps = [inv.components[c] for c in f.component_ids if c in inv.components]
        f.aivss = scorer.score(f, pack.detector(f.key), comps)
    for f in suppressed:
        f.suppressed = True
    findings = apply_baseline(findings, options)
    findings.sort(key=Finding.sort_key)
    suppressed.sort(key=Finding.sort_key)

    score_value = verdicts.score(findings)
    verdict, reasons = verdicts.decide(findings, chains, score_value=score_value)
    # A component whose configuration runs commands (hooks, editor tasks, lifecycle and CI steps) runs code.
    commands = {getattr(c, "component_id", "") for c in ctx.data.get("config_commands", [])}  # type: ignore[union-attr]
    artifacts = _artifact_summaries(inv, findings, chains, labels, ctx.data.get("least_privilege", {}),  # type: ignore[arg-type]
                                    triage, commands)
    tier = max((a.risk_tier for a in artifacts), key=lambda t: t.rank, default=RiskTier.L0)

    by_sev = Counter(f.severity.value for f in findings)
    by_cat = Counter(f.category.value for f in findings)
    stats = ReportStats(
        files_scanned=len(tree.files),
        bytes_scanned=tree.total_bytes,
        components=len(inv.components),
        rules_evaluated=len(evaluated),
        findings_by_severity={s.value: by_sev.get(s.value, 0) for s in Severity},
        findings_by_category={c.value: by_cat.get(c.value, 0) for c in Category},
        suppressed=len(suppressed),
        limit_events=sorted(ctx.data["limit_events"], key=lambda e: (e.kind, e.path)),  # type: ignore[arg-type]
    )
    intel_version = getattr(options.intel, "version", "") if options.intel is not None else ""
    report = Report(
        tool=ToolInfo(version=ENGINE_VERSION, rule_pack=pack.version, rule_pack_digest=pack.digest,
                      rule_count=len(pack.rules), rules_implemented=len(pack.implemented), intel=str(intel_version or "")),
        target=_target(tree),
        profile=options.profile,
        policy=policy.name,
        coverage=coverage,
        verdict=verdict,
        verdict_reasons=reasons,
        score=score_value,
        risk_tier=tier,
        artifacts=artifacts,
        findings=findings,
        suppressed_findings=suppressed,
        chains=chains,
        limits=Limits(
            llm=LlmLimits(tokens=options.llm_tokens, cost_usd=round(options.llm_cost_usd, 4), calls=options.llm_calls,
                          complete=options.llm_complete, model=options.llm_model, sent=sorted(options.llm_sent)),
            dynamic=DynamicLimits(ran=options.dynamic_ran, level=options.dynamic_level,
                                  not_reached=sorted(options.dynamic_not_reached)),
        ),
        timings_ms={"total": int((time.perf_counter() - started) * 1000)} if options.include_timestamps else {},
        network_features_used=options.network.enabled(),
        network_hosts=sorted(set(options.network_hosts)),
        analyzers=runs,
        inventory=sorted(inv.components.values(), key=lambda c: (c.kind.value, c.root, c.name, c.id)),
        files=sorted(inv.artifacts.values(), key=lambda a: a.path),
        flows=[f.flow for f in findings if f.flow is not None],
        stats=stats,
        fail_on=policy.fail_on if (options.fail_on == "block" and policy.fail_on) else options.fail_on,
        require_full_coverage=policy.require.full_coverage,
        summary=_summary(findings, verdict, score_value, len(evaluated), pack.version, hunt_hidden),
        generated_at=dt.datetime.now(dt.UTC).replace(microsecond=0) if options.include_timestamps else None,
    )
    return report


def _skip_reason(analyzer_cls, options: ScanOptions) -> str:
    if options.analyzers is not None and analyzer_cls.id not in options.analyzers:
        return "not selected"
    needs = analyzer_cls.requires
    if "network" in needs:
        feature = getattr(analyzer_cls, "network_feature", None)
        if not feature or not getattr(options.network, feature, False):
            return "network feature not enabled (opt-in)"
    if "native" in needs and not native_available(analyzer_cls):
        return "optional native dependency not installed"
    if "lock" in needs and options.lock is None:
        return "no lockfile supplied"
    if "intel" in needs and options.intel is None:
        return "no IOC feed loaded"
    if "standard" in needs and options.profile == "quick":
        return "runs in the standard and deep profiles"
    if "deep" in needs and options.profile != "deep":
        return "runs in the deep profile"
    return ""


def _summary(findings: list[Finding], verdict: Verdict, score_value: int, n_rules: int, pack_version: str,
             hunt_hidden: int) -> str:
    tail = f" {hunt_hidden} advisory (hunt-lane) finding(s) not shown." if hunt_hidden else ""
    if not findings:
        return f"{verdict.value} · no findings from {n_rules} rules (rule pack v{pack_version}).{tail}"
    c = Counter(f.severity.value for f in findings)
    parts = ", ".join(f"{c[s.value]} {s.value}" for s in Severity if c.get(s.value))
    return (f"{verdict.value} · score {score_value} · {len(findings)} findings ({parts}) "
            f"from {n_rules} rules (rule pack v{pack_version}).{tail}")


def _target(tree: ArtifactTree) -> TargetInfo:
    src = tree.source
    tree_hash = sha256_hex("\n".join(f"{p}\0{tree.files[p].sha256}" for p in sorted(tree.files)))
    if src is None:
        return TargetInfo(source=tree.display_root or "", kind="local", tree_sha256=tree_hash)
    return TargetInfo(source=src.locator, kind=src.kind.value, commit=getattr(src, "resolved", None),
                      tree_sha256=tree_hash, ref=src)


def ecosystem_for(comp: Component) -> str:
    # What discovery recorded for the surface wins over a guess from the path.
    agent = (comp.metadata.get("agent") or "").lower()
    if agent and agent not in ("generic", "unknown"):
        return agent
    client = (comp.metadata.get("client") or (comp.server.client if comp.server else "") or "").lower()
    if client and client != "unknown":
        return {"claude": "claude-code", "claude_code": "claude-code", "claude-desktop": "claude-desktop",
                "vscode": "copilot", "gemini-cli": "gemini"}.get(client, client)
    eco = comp.metadata.get("ecosystem")
    hay = f"/{comp.root.lower()}"
    for needle, name in _ECOSYSTEM_PATHS:
        if f"/{needle}" in hay or hay.endswith(f"/{needle.rstrip('/')}"):
            return name
    if comp.kind in (ComponentKind.mcp_server, ComponentKind.bundle, ComponentKind.package):
        return "mcp"
    if comp.kind == ComponentKind.skill:
        return "agent-skills"
    return eco or "generic"


def _artifact_labels(inv: Inventory) -> dict[str, str]:
    """``component id -> "skill:pdf-helper"``; the root is appended when two components share a label."""
    labels: dict[str, str] = {}
    seen: Counter[str] = Counter()
    base: dict[str, str] = {}
    for cid, c in inv.components.items():
        name = visible_escape(c.name)[:80].replace(" ", "-") or "(unnamed)"
        base[cid] = f"{_ARTIFACT_PREFIX.get(c.kind, c.kind.value)}:{name}"
        seen[base[cid]] += 1
    for cid, c in inv.components.items():
        labels[cid] = base[cid] if seen[base[cid]] == 1 else f"{base[cid]}@{c.root or cid[:8]}"
    return labels


_CODE_ROLES = {ArtifactRole.script, ArtifactRole.source_code, ArtifactRole.binary}


def _triage(inv: Inventory, findings: list[Finding], options: ScanOptions,
            pack: RulePack) -> tuple[dict[str, float], float, AnalyzerRun]:
    """The triage model's probability per component (engine K), in the ``standard`` and ``deep`` profiles.

    Returns the probabilities, the threshold at which the model agrees with a rule, and the run record.
    ``options.on_triage_features`` receives the feature vectors in any profile (the trainer uses it)."""
    wanted = options.profile in ("standard", "deep")
    if not wanted and options.on_triage_features is None:
        return {}, triage_model.DEFAULT_AGREES, AnalyzerRun(id="triage", status="skipped", reason="quick profile")
    features = triage_model.component_features(findings, inv)
    if options.on_triage_features is not None:
        options.on_triage_features(features)
    if not wanted:
        return {}, triage_model.DEFAULT_AGREES, AnalyzerRun(id="triage", status="skipped", reason="quick profile")
    model = triage_model.load_model(pack.data.get("triage-model"))
    if model is None:
        return {}, triage_model.DEFAULT_AGREES, AnalyzerRun(id="triage", status="skipped",
                                                            reason="the rule pack carries no triage model")
    return triage_model.score(model, features), model.agrees, AnalyzerRun(id="triage", status="ran")


def _artifact_summaries(inv: Inventory, findings: list[Finding], chains, labels: dict[str, str],
                        plans: dict[str, dict] | None = None, triage: dict[str, float] | None = None,
                        commands: set[str] | None = None) -> list[ArtifactSummary]:
    by_comp: dict[str, list[Finding]] = {}
    for f in findings:
        for cid in f.component_ids:
            by_comp.setdefault(cid, []).append(f)
    roles_by_comp: dict[str, set[ArtifactRole]] = {}
    for a in inv.artifacts.values():
        roles_by_comp.setdefault(a.component_id, set()).add(a.role)
    out: list[ArtifactSummary] = []
    for cid, c in inv.components.items():
        if c.kind in (ComponentKind.mcp_client_config, ComponentKind.repository) and cid not in by_comp:
            continue
        observed = {cap.label for cap in c.capabilities if cap.observed or cap.declared}
        runs_code = bool(roles_by_comp.get(cid, set()) & _CODE_ROLES) or bool(commands and cid in commands) or (
            c.kind in (ComponentKind.mcp_server, ComponentKind.hook, ComponentKind.bundle, ComponentKind.container)
            and (c.server is None or bool(c.server.command))
        )
        mine = by_comp.get(cid, [])
        fps = {f.fingerprint for f in mine}
        verdict, _ = verdicts.decide(mine, [ch for ch in chains if set(ch.steps) & fps])
        out.append(ArtifactSummary(
            id=labels[cid], type=c.kind.spec_type, ecosystem=ecosystem_for(c), name=visible_escape(c.name)[:128],
            version=c.version, root=c.root, component_id=cid,
            capabilities=sorted({lab.spec_name for lab in observed}),
            risk_tier=verdicts.risk_tier(observed, runs_code=runs_code), verdict=verdict, findings=len(mine),
            least_privilege=LeastPrivilege.model_validate(plans[cid]) if plans and cid in plans else None,
            triage=triage.get(cid) if triage else None,
        ))
    out.sort(key=lambda a: (a.type, a.root, a.id))
    return out


def _source_line(inv: Inventory, span: Span | None) -> str:
    if span is None:
        return ""
    at = inv.texts.get(span.path)
    if at is None:
        return ""
    return at.line_text(at.index.line_start(span.start_line))[:400]


def _trace(r: RawFinding) -> list[TraceStep]:
    if r.trace:
        return r.trace[:20]
    for ev in r.evidence:
        if ev.taint_path:
            last = len(ev.taint_path) - 1
            return [TraceStep(file=s.path, line=s.start_line,
                              role="source" if i == 0 else ("sink" if i == last else "propagator"))
                    for i, s in enumerate(ev.taint_path[:20])]
    if r.related and r.primary:
        steps = [TraceStep(file=r.primary.path, line=r.primary.start_line, role="step")]
        steps += [TraceStep(file=s.path, line=s.start_line, role="step") for s in r.related[:19]]
        return steps
    return []


def _engine_of(r: RawFinding, det: Detector) -> str:
    name = r.engine
    if name in ("instruction", "code", "text-integrity", "media"):
        return name
    return ANALYZER_ENGINE.get(name, det.engine)


def _finalize(raw: list[RawFinding], ctx: Context, pack: RulePack, options: ScanOptions,
              labels: dict[str, str]) -> list[Finding]:
    merged: dict[str, Finding] = {}
    policy = options.effective_policy
    overrides: dict[str, Severity] = {}
    for selector, sev in policy.severity_overrides.items():
        for rid in pack.canonical_ids(selector):
            overrides[rid] = sev
    denied = {rid for selector in policy.deny.rules for rid in pack.canonical_ids(selector)}
    inv = ctx.inventory
    for r in raw:
        det = pack.detector(r.rule_id)
        severity = r.severity or det.severity
        confidence = r.confidence or det.confidence
        tags = set(r.tags) | set(det.tags)
        if det.blocks_allow:
            tags.add("coverage")
        if r.hidden and det.family not in _NO_HIDDEN_ESCALATION_FAMILIES and det.key not in _NO_HIDDEN_ESCALATION_KEYS:
            severity = severity.bump(1)
            tags.add("hidden")
        if det.rule_id in overrides:
            severity = overrides[det.rule_id]
        if det.rule_id in denied:
            tags.add("policy-deny")
        # Invariants: CRITICAL needs high confidence + deterministic evidence;
        # model-sourced findings cap at HIGH.
        if r.source == FindingSource.llm and severity == Severity.critical:
            severity = Severity.high
        if severity == Severity.critical and confidence != Confidence.high:
            severity = Severity.high
            tags.add("capped-by-confidence")
        comp_key = ",".join(r.component_ids)
        path = r.primary.path if r.primary else ""
        # Rule + artifact + path + matched text. Line numbers are excluded, so a
        # finding keeps its fingerprint when the file shifts.
        fp = sha256_hex(f"{det.key}|{comp_key}|{path}|{r.match_key}")[:32]
        engines = [_engine_of(r, det)]
        # A static finding the detonation confirmed was seen by the dynamic engine too.
        if "dynamic" not in engines and any(e.kind == EvidenceKind.dynamic for e in r.evidence):
            engines.append("dynamic")
        existing = merged.get(fp)
        if existing is not None:
            if r.primary and r.primary != existing.primary and r.primary not in existing.related and len(existing.related) < 20:
                existing.related.append(r.primary)
            if len(existing.evidence.items) < 10:
                existing.evidence.items.extend(r.evidence)
            if severity.rank > existing.severity.rank:
                existing.severity = severity
            existing.tags = sorted(set(existing.tags) | tags)
            existing.engines.extend(e for e in engines if e not in existing.engines)
            continue
        first = r.evidence[0] if r.evidence else None
        snippet = first.snippet if first else RedactedText.of("")
        decoded = RedactedText.of(r.decoded) if r.decoded else RedactedText.of("")
        derivation = list(first.decode_path) if first else []
        if r.hidden and first is not None and not r.decoded:
            # The matched text came out of hidden or decoded content: show it as
            # the decoded payload, and the original source line as the snippet.
            decoded = snippet
            original = _source_line(inv, r.primary)
            snippet = RedactedText.of(original) if original else snippet
        rendered = str(snippet) if "⟨U+" in str(snippet) else ""
        artifact = labels.get(r.component_ids[0], "") if r.component_ids else ""
        risk = visible_escape(r.message or det.why or det.description or det.title)[:500]
        merged[fp] = Finding(
            id=det.rule_id,
            variant=det.variant,
            rule_version=det.version,
            fingerprint=fp,
            title=det.title,
            family=det.family,
            category=det.category,
            severity=severity,
            confidence=confidence,
            # A mention (a downgraded match) is weak evidence whatever the rule's lane: it never counts alone.
            lane=Lane.evidence if "mention" in tags and det.lane == Lane.block else det.lane,
            risk=risk,
            explanation=det.why or det.description,
            location=Location.of(r.primary, artifact=artifact, container=_container(r.primary.path)) if r.primary else None,
            related=list(r.related),
            evidence=EvidenceSummary(snippet=snippet, rendered=rendered, decoded=decoded, derivation=derivation,
                                     items=list(r.evidence)),
            trace=_trace(r),
            fix=Fix(kind=det.fix, summary=det.remediation, action=det.fix_action, patch=r.fix_patch),
            mappings=mapping_dict(det.mappings),
            engines=engines,
            source=r.source,
            component_ids=r.component_ids,
            references=list(det.references),
            tags=sorted(tags),
            flow=r.flow,
        )
    return list(merged.values())


def _ecosystem_filter(raw: list[RawFinding], inv: Inventory, selected: set[str]) -> list[RawFinding]:
    """``--ecosystem``: drop findings on components that belong only to an agent
    that was not selected. Agent-neutral surfaces (skills, MCP, the repository)
    always stay."""
    eco = {cid: ecosystem_for(c) for cid, c in inv.components.items()}
    out = []
    for r in raw:
        names = {eco.get(cid, "generic") for cid in r.component_ids}
        if not names or any(n in selected or n not in AGENT_ECOSYSTEMS for n in names):
            out.append(r)
    return out


def _pr_filter(raw: list[RawFinding], ctx: Context, changed: set[str]) -> list[RawFinding]:
    """PR mode: keep findings for every component that contains a changed file
    (whole component, so payloads split into unchanged files are still seen),
    plus findings whose primary location changed, plus policy findings."""
    touched = {a.component_id for a in ctx.inventory.artifacts.values() if a.path in changed}
    for c in ctx.inventory.components.values():
        if c.server and c.server.config_path in changed:
            touched.add(c.id)
    out = []
    for r in raw:
        if r.rid.startswith("AG-POL-") or r.rule_id == "AG-EVADE-002/analyzer-error":
            out.append(r)
        elif set(r.component_ids) & touched or (r.primary and r.primary.path in changed):
            out.append(r)
    return out


def _synthetic(pack: RulePack, rule_id: str, message: str, *, key: str, primary=None) -> Finding:
    det = pack.detector(rule_id)
    return Finding(
        id=det.rule_id,
        variant=det.variant,
        rule_version=det.version,
        fingerprint=sha256_hex(f"{rule_id}|{key}")[:32],
        title=det.title,
        family=det.family,
        category=det.category,
        severity=det.severity,
        confidence=det.confidence,
        lane=det.lane,
        risk=visible_escape(message)[:500],
        explanation=det.why or det.description,
        location=Location.of(primary) if primary else None,
        fix=Fix(kind=det.fix, summary=det.remediation),
        mappings=mapping_dict(det.mappings),
        engines=["policy"],
        source=FindingSource.policy,
        references=list(det.references),
    )


def _emit_dynamic(ctx: Context) -> None:
    """Observations from the detonation tier become findings. They add to static
    findings and never clear them: a static finding of the same rule in the same
    file is marked confirmed instead of being reported twice."""
    options = ctx.options
    static = {(r.rid, r.primary.path) for r in ctx.raw if r.primary}
    for ev in options.dynamic_evidence:
        key = ctx.pack.resolve_key(ev.rule)
        if key is None or not ctx.rule_enabled(key):
            continue
        rid = key.partition("/")[0]
        if (rid, ev.path) in static:
            for r in ctx.raw:
                if r.rid == rid and r.primary and r.primary.path == ev.path:
                    r.tags = sorted({*r.tags, "dynamic-confirmed"})
                    r.evidence.append(Evidence(kind=EvidenceKind.dynamic, location=Span(path=ev.path, start_line=ev.line),
                                               snippet=RedactedText.of("\n".join(ev.trace[:6])), detail=ev.detail, engine="dynamic"))
            continue
        comp = ctx.inventory.component_for(ev.path)
        ctx.current = "dynamic"
        ctx.emit(key, component_ids=[comp.id] if comp else [], span=Span(path=ev.path or ".", start_line=max(1, ev.line)),
                 snippet="\n".join(ev.trace[:6]), detail=ev.detail, kind=EvidenceKind.dynamic,
                 match=f"dynamic|{ev.path}|{ev.detail}", message=ev.detail or None, source=FindingSource.dynamic,
                 tags=["dynamic-confirmed"] if ev.confirmed else [])
    if options.dynamic_ran and options.dynamic_not_reached and ctx.rule_enabled("AG-EVADE-017"):
        ctx.current = "dynamic"
        for path in sorted(options.dynamic_not_reached)[:50]:
            comp = ctx.inventory.component_for(path)
            ctx.emit("AG-EVADE-017", component_ids=[comp.id] if comp else [], span=Span(path=path), snippet=path,
                     kind=EvidenceKind.dynamic, match=f"not-reached|{path}",
                     message=f"Dynamic analysis did not reach {path}; a clean detonation does not clear it.")
    ctx.current = "engine"


def _container(path: str) -> str | None:
    """The outermost archive, bundle or image a nested path sits in
    (``outer.zip!/inner/file`` → ``outer.zip``); ``Location.file`` keeps the whole path."""
    return path.split(NESTED, 1)[0] if NESTED in path else None


def _emit_coverage_threshold(ctx: Context, coverage, minimum: float) -> None:
    """AG-EVADE-021: the share of content that was analysed is below what the policy asks for."""
    if minimum <= 0.0 or coverage.analyzability >= minimum or not ctx.rule_enabled("AG-EVADE-021"):
        return
    biggest = max(coverage.unanalysed, key=lambda u: (u.bytes, u.path), default=None)
    where = Span(path=biggest.path) if biggest is not None else None
    comp = ctx.inventory.component_for(biggest.path) if biggest is not None else None
    listed = ", ".join(f"{u.path} ({u.reason})" for u in sorted(coverage.unanalysed, key=lambda u: (-u.bytes, u.path))[:3])
    ctx.emit("AG-EVADE-021", component_ids=[comp.id] if comp else [], span=where, snippet=biggest.path if biggest else "",
             kind=EvidenceKind.loader, match="analyzability",
             detail=f"analysed {coverage.bytes_analysed} of {coverage.bytes_total} bytes in "
                    f"{coverage.files_analysed} of {coverage.files_total} files",
             message=f"Only {coverage.analyzability:.0%} of the content could be analysed; the policy requires "
                     f"{minimum:.0%}. Largest part not analysed: {listed or 'see coverage.unanalysed'}.")


def _emit_model_limits(ctx: Context) -> None:
    """No silent degradation: when a model budget ran out, say so (spec/interfaces.md §14)."""
    if not ctx.options.llm_complete and ctx.rule_enabled("AG-EVADE-016"):
        ctx.emit("AG-EVADE-016", component_ids=[], span=None, snippet="", kind=EvidenceKind.llm,
                 match="model-incomplete",
                 message="Model-based analysis did not finish (budget, timeout or refusal); "
                         "the candidates it did not review keep their deterministic result.")


def _apply_adjudications(findings: list[Finding], pack: RulePack, options: ScanOptions) -> None:
    """The adjudicator is bounded: it may raise; it may lower by one level at
    most; it cannot touch deterministic block-lane findings; and an answer that
    cites no valid span from the evidence it was given is discarded."""
    by_fp = {f.fingerprint: f for f in findings}
    for adj in options.adjudications:
        f = by_fp.get(adj.fingerprint)
        if f is None:
            continue
        valid = _valid_citations(f)
        if not any(c in valid for c in adj.cited_spans):
            f.adjudication = Adjudication(status="not_run", runs=adj.runs, model=adj.model,
                                          rationale="Answer discarded: it cited no span from the evidence it was given.")
            continue
        det = pack.detector(f.key)
        rationale = visible_escape(adj.rationale)[:600]
        deterministic_block = f.lane == Lane.block and f.source != FindingSource.llm
        if adj.status == "confirmed":
            if adj.raise_severity is not None and adj.raise_severity.rank > f.severity.rank:
                target = f.severity.bump(1)
                if target == Severity.critical and f.confidence != Confidence.high:
                    target = Severity.high
                f.severity = target
            order = [Confidence.low, Confidence.medium, Confidence.high]
            f.confidence = order[min(order.index(f.confidence) + 1, 2)]
            f.adjudication = Adjudication(status="confirmed", runs=adj.runs, model=adj.model, rationale=rationale)
            if "judge" not in f.engines:
                f.engines.append("judge")
        elif deterministic_block:
            # Recorded, never applied: a model cannot lower or dismiss these.
            f.adjudication = Adjudication(status=adj.status, runs=adj.runs, model=adj.model,
                                          rationale=rationale + " (not applied: deterministic block-lane finding)")
            f.tags = sorted({*f.tags, "adjudicator-overruled"})
        else:
            lowered = f.confidence.lower()
            f.confidence = lowered if lowered.rank >= det.confidence.rank else det.confidence
            if adj.status == "dismissed":
                f.severity = f.severity.bump(-1)
                f.tags = sorted({*f.tags, "dismissed"})
            f.adjudication = Adjudication(status=adj.status, runs=adj.runs, model=adj.model, rationale=rationale)


def _valid_citations(f: Finding) -> set[str]:
    out: set[str] = set()
    spans = [f.primary, *f.related, *(e.location for e in f.evidence.items)]
    for s in spans:
        if s is None:
            continue
        for line in range(s.start_line, (s.end_line or s.start_line) + 1):
            out.add(f"{s.path}:{line}")
            out.add(f"{posixpath.basename(s.path)}:{line}")
    for step in f.trace:
        out.add(f"{step.file}:{step.line}")
    return out


def limit_event_rule(ev: LimitEvent) -> str | None:
    from .analyzers.system import rule_for

    return rule_for(ev)
