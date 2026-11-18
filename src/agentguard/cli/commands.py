"""Every command besides `scan`, `explain`, `report` and `schema`
(spec/interfaces.md §2). Imported by ``app.py``; registers itself on ``app``."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.markup import escape
from rich.table import Table

from ..core.engine import ENGINE_VERSION
from ..core.models import NetworkOptions
from ..core.models.report import EXIT_BLOCK, EXIT_OK, EXIT_REVIEW
from ..core.report.render import render_cyclonedx, render_json, render_trust_cards
from ..core.rules.pack import RulePack
from ..runner import ScanRequest, UsageError, run_scan
from .app import (
    _console,
    _formats,
    app,
    emit,
    load_report,
    print_notes,
    render,
    save_last_report,
    write_outputs,
)
from .config import LOCK_NAME

baseline_app = typer.Typer(help="The baseline lockfile: what was approved. create | verify | update | diff.", no_args_is_help=True)
rules_app = typer.Typer(help="The rule pack: list | new | test | validate | import.", no_args_is_help=True)
mcp_app = typer.Typer(help="MCP servers: inspect | probe.", no_args_is_help=True)
intel_app = typer.Typer(help="The local, signed indicator feed (see also `agentguard update`).", no_args_is_help=True)
app.add_typer(baseline_app, name="baseline")
app.add_typer(rules_app, name="rules")
app.add_typer(mcp_app, name="mcp")
app.add_typer(intel_app, name="intel")

DRIFT_RULES = ("AG-PLUG-017", "AG-MCP-012", "AG-MCP-027", "AG-MCP-028", "AG-CONN-008")


def _static_request(target: Optional[str], *, machine: bool = False, no_user: bool = False, policy: Optional[str] = None,
                    baseline: Optional[Path] = None, lock_in_use: Optional[Path] = None, profile: str = "quick",
                    context: str = "none", llm: str = "off") -> ScanRequest:
    targets = [] if (machine and not target) else [target or "."]
    return ScanRequest(targets=targets, machine=machine, profile=profile, llm=llm, context=context, policy=policy,
                       baseline=baseline, include_user=not no_user, lock_in_use=lock_in_use, cwd=Path.cwd())


# --------------------------------------------------------------------- fix --
@app.command("fix")
def fix_cmd(
    target: Annotated[str, typer.Argument(help="A local path (your own files; a fix is never applied to a remote target).")] = ".",
    finding: Annotated[Optional[str], typer.Option("--finding", help="Fix only this finding (a fingerprint or its first characters).")] = None,
    rule: Annotated[Optional[str], typer.Option("--rule", help="Fix only findings of this rule, alias or family.")] = None,
    safe_only: Annotated[bool, typer.Option("--safe-only", help="Only deterministic safe fixes; no model-drafted patch.")] = False,
    apply: Annotated[bool, typer.Option("--apply", help="Write the changes. Without it the command prints a unified diff.")] = False,
    policy: Annotated[Optional[str], typer.Option("--policy")] = None,
    network: Annotated[bool, typer.Option("--network", help="NETWORK: look up the commit, version or hash a pinning fix needs.")] = False,
    llm: Annotated[Optional[str], typer.Option("--llm", envvar="AGENTGUARD_LLM", help="off · auto · always: let a configured model draft a patch where no deterministic fix exists. The draft is kept only after a clean re-scan. Default: auto.")] = None,
    emit_policy: Annotated[Optional[Path], typer.Option("--emit-policy", help="Write the least-privilege policy (smallest allowed-tools, permission rules and sandbox profile per component) to this JSON file, for the agent to enforce.")] = None,
    json_out: Annotated[bool, typer.Option("--json", help="JSON output.")] = False,
) -> None:
    """Show or apply fixes. Every applied fix is followed by a re-scan of the
    touched files; a fix that leaves its finding in place, adds a finding or
    breaks parsing is rolled back. --emit-policy writes the least-privilege
    policy (what each component needs, nothing more) for the agent to enforce."""
    from ..fix import run_fix

    root = Path(target)
    if not root.exists():
        raise UsageError(f"path not found: {target}")
    mode = (llm or "auto").lower()
    if mode not in ("off", "auto", "always"):
        raise UsageError("--llm must be off, auto or always")
    result = run_fix(root, finding=finding, rule=rule, safe_only=safe_only, apply=apply, policy=policy, cwd=Path.cwd(),
                     network=network, llm=mode, emit_policy=emit_policy)
    if apply and result.applied:
        _audit("fix", "", target, {"files": sorted(result.files)[:100],
                                   "fixed": [f"{i.finding_id} {i.fingerprint[:12]}" for i in result.applied][:200],
                                   "rolled_back": len(result.rolled_back),
                                   "verdict_before": result.before.verdict.value if result.before else None,
                                   "verdict_after": result.after.verdict.value if result.after else None})
    if json_out:
        emit(json.dumps(result.to_dict(), indent=2) + "\n", None)
    else:
        con = _console(stderr=True)
        if not apply:
            sys.stdout.write(result.diff)
        for item in result.applied:
            con.print(f"[green]fixed[/green]       {item.finding_id} {escape(item.path)}:{item.line}  {escape(item.summary)}")
        for item in result.proposed:
            con.print(f"[cyan]would fix[/cyan]   {item.finding_id} {escape(item.path)}:{item.line}  {escape(item.summary)}")
        for item in result.rolled_back:
            con.print(f"[red]rolled back[/red] {item.finding_id} {escape(item.path)}:{item.line}  {escape(item.reason)}")
        for item in result.skipped:
            con.print(f"[dim]no auto-fix {item.finding_id} {escape(item.path)}:{item.line}  {escape(item.reason)}[/dim]")
        con.print(escape(result.summary))
    raise typer.Exit(EXIT_REVIEW if result.rolled_back else EXIT_OK)


# ----------------------------------------------------------------- install --
@app.command("install")
def install_cmd(
    source: Annotated[str, typer.Argument(help="What to install: any scan target (a GitHub URL, a package, an archive, a path).")],
    agent: Annotated[str, typer.Option("--agent", help="claude-code, codex, cursor, gemini, copilot or openclaw.")] = "claude-code",
    scope: Annotated[str, typer.Option("--scope", help="project (this directory) or user (your home directory).")] = "project",
    dest: Annotated[Optional[Path], typer.Option("--dest", help="Install root to use instead of the agent's default location.")] = None,
    accept: Annotated[bool, typer.Option("--accept", help="Install a REVIEW verdict (a BLOCK is never installed).")] = False,
    plan: Annotated[bool, typer.Option("--plan", help="Show the receipt and the verdict; write nothing.")] = False,
    policy: Annotated[Optional[str], typer.Option("--policy")] = None,
    profile: Annotated[Optional[str], typer.Option("--profile")] = None,
    context: Annotated[Optional[str], typer.Option("--context", envvar="AGENTGUARD_CONTEXT")] = None,
    llm: Annotated[Optional[str], typer.Option("--llm", envvar="AGENTGUARD_LLM")] = None,
    offline: Annotated[bool, typer.Option("--offline")] = False,
    approved_by: Annotated[str, typer.Option("--approved-by", help="Recorded in agentguard.lock.")] = "",
    json_out: Annotated[bool, typer.Option("--json", help="Machine-readable receipt (agent-safe: no scanned text).")] = False,
) -> None:
    """Scan, show the install receipt, then install.

    The source is fetched to quarantine at a pinned identifier and scanned with
    the installed context. The receipt lists every file that would be written
    and every setting, hook, MCP entry or instruction file that would change.
    On ALLOW (or REVIEW with --accept) the scanned bytes, not a fresh download,
    are copied into place and agentguard.lock is updated."""
    from ..install import perform_install, plan_install, render_receipt

    req = ScanRequest(targets=[source], profile=profile, llm=(llm or "auto").lower(), context=context, policy=policy,
                      offline=offline, cwd=Path.cwd())
    planned = plan_install(req, agent=agent, scope=scope, dest=dest)
    save_last_report(planned.outcome.report)
    if json_out:
        emit(json.dumps(planned.to_dict(), indent=2) + "\n", None)
    else:
        print_notes(planned.outcome)
        render_receipt(planned, _console())
    verdict = planned.outcome.report.verdict.value
    if plan:
        raise typer.Exit({"ALLOW": EXIT_OK, "REVIEW": EXIT_REVIEW}.get(verdict, EXIT_BLOCK))
    report = planned.outcome.report
    components = [a.id for a in report.artifacts][:50]
    if verdict == "BLOCK" or (verdict == "REVIEW" and not accept):
        why = "BLOCK is never installed" if verdict == "BLOCK" else "REVIEW needs --accept"
        _audit("install-refused", approved_by, source, {"agent": agent, "scope": scope, "verdict": verdict, "score": report.score,
                                                         "why": why, "components": components})
        _console(stderr=True).print(f"[bold red]Not installed:[/bold red] {why}. Nothing was written.")
        raise typer.Exit(EXIT_BLOCK if verdict == "BLOCK" else EXIT_REVIEW)
    done = perform_install(planned, approved_by=approved_by)
    _audit("install", approved_by, source, {"agent": agent, "scope": scope, "verdict": verdict, "score": report.score,
                                            "accepted_review": verdict == "REVIEW", "files": len(done.written),
                                            "root": str(done.root), "lock": str(done.lock_path), "components": components,
                                            "commit": report.target.commit or ""})
    _console(stderr=True).print(f"[green]Installed[/green] {len(done.written)} file(s) under {escape(str(done.root))}; "
                                f"{escape(str(done.lock_path))} updated.")


def _audit(action: str, actor: str, target: str, details: dict) -> None:
    """Append to the audit log; a log that cannot be written is said, never fatal."""
    from ..audit import note_failure, record

    problem = note_failure(record(action, actor=actor, target=target, details=details))
    if problem:
        _console(stderr=True).print(f"[yellow]{escape(problem)}[/yellow]")


# ---------------------------------------------------------------- baseline --
def _create_lock(target: Optional[str], output: Path, *, machine: bool, no_user: bool, approved_by: str, review_by: str,
                 accept_findings: bool):
    import datetime as dt

    from ..core.lock import build_lock, dump_lock

    outcome = run_scan(_static_request(target, machine=machine, no_user=no_user, lock_in_use=output))
    approved_at = dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z") if approved_by else ""
    lock = build_lock(outcome.report, approved_by=approved_by, approved_at=approved_at, review_by=review_by,
                      accept_findings=accept_findings)
    return outcome, lock, dump_lock(lock)


@baseline_app.command("create")
def baseline_create(
    target: Annotated[Optional[str], typer.Argument(help="What to record (default: the current directory).")] = None,
    output: Annotated[Path, typer.Option("--output", "-o", help="Lockfile path.")] = Path(LOCK_NAME),
    machine: Annotated[bool, typer.Option("--machine", help="Record every agent component installed on this machine.")] = False,
    no_user: Annotated[bool, typer.Option("--no-user")] = False,
    approved_by: Annotated[str, typer.Option("--approved-by", help="Who approved what the lock records.")] = "",
    review_by: Annotated[str, typer.Option("--review-by", help="Date (YYYY-MM-DD) the approval should be looked at again.")] = "",
    accept_findings: Annotated[bool, typer.Option("--accept-findings", help="Record the current findings as reviewed and accepted: later scans against this lock do not report them again.")] = False,
) -> None:
    """Write agentguard.lock: file hashes, server launch commands, a hash per
    tool definition, capabilities, risk tier and verdict of what is there now."""
    outcome, lock, text = _create_lock(target, output, machine=machine, no_user=no_user, approved_by=approved_by,
                                       review_by=review_by, accept_findings=accept_findings)
    emit(text, output)
    _audit("baseline-create", approved_by, target or ("--machine" if machine else "."),
           {"lock": str(output), "components": len(lock.artifacts), "verdict": outcome.report.verdict.value,
            "accepted_findings": sum(len(e.accepted_findings) for e in lock.artifacts), "review_by": review_by})
    con = _console(stderr=True)
    con.print(f"Locked {len(lock.artifacts)} component(s) → {escape(str(output))} (verdict at lock time: {outcome.report.verdict.value})")
    if outcome.report.findings and not accept_findings:
        con.print(f"[dim]{len(outcome.report.findings)} finding(s) are not accepted by this lock; "
                  "re-run with --accept-findings after reviewing them.[/dim]")


@baseline_app.command("verify")
def baseline_verify(
    target: Annotated[Optional[str], typer.Argument()] = None,
    baseline: Annotated[Path, typer.Option("--baseline", "--lock", help="Lockfile to compare against.")] = Path(LOCK_NAME),
    machine: Annotated[bool, typer.Option("--machine")] = False,
    no_user: Annotated[bool, typer.Option("--no-user")] = False,
    fail_on: Annotated[str, typer.Option("--fail-on", help="Lowest severity of drift that fails the command.")] = "low",
    format: Annotated[Optional[list[str]], typer.Option("--format", "-f")] = None,
    output: Annotated[Optional[Path], typer.Option("--output", "-o")] = None,
) -> None:
    """Re-scan what the lock records with the current rules and report what
    changed: file content, versions, launch commands, tool definitions, tool
    sets and capabilities (rug pulls and update drift)."""
    from ..core.models.enums import Severity

    if not baseline.is_file():
        raise UsageError(f"lockfile not found: {baseline} (run `agentguard baseline create` first)")
    outcome = run_scan(_static_request(target, machine=machine, no_user=no_user, baseline=baseline))
    report = outcome.report
    level = Severity.parse(fail_on)
    drift = [f for f in report.findings if f.id in DRIFT_RULES]
    n_locked = len(outcome.options.lock.artifacts) if outcome.options.lock else 0
    summary = (f"{len(drift)} drift finding(s) against {baseline}." if drift
               else f"No drift from {baseline} ({n_locked} locked component(s)).")
    formats = _formats(format)
    if formats == ["terminal"]:
        con = _console()
        for f in drift:
            con.print(f"[bold]{f.key}[/bold] {escape('[' + f.severity.value + ']')} {escape(f.message)}")
            for ev in f.evidence.items[1:]:
                if ev.detail.startswith("definition diff"):
                    con.print(escape(str(ev.snippet)), highlight=False)
        if report.verdict.value != "ALLOW" and not drift:
            con.print(f"[dim]Verdict with the current rules: {report.verdict.value} "
                      f"({len(report.findings)} finding(s) not accepted by the lock).[/dim]")
        con.print(escape(summary))
    else:
        report.findings = drift
        report.summary = summary
        write_outputs(report, formats, output)
    raise typer.Exit(EXIT_REVIEW if any(f.severity.at_least(level) for f in drift) else EXIT_OK)


@baseline_app.command("update")
def baseline_update(
    target: Annotated[Optional[str], typer.Argument()] = None,
    baseline: Annotated[Path, typer.Option("--baseline", "--lock", "-o")] = Path(LOCK_NAME),
    machine: Annotated[bool, typer.Option("--machine")] = False,
    no_user: Annotated[bool, typer.Option("--no-user")] = False,
    approved_by: Annotated[str, typer.Option("--approved-by")] = "",
    review_by: Annotated[str, typer.Option("--review-by")] = "",
    accept_findings: Annotated[bool, typer.Option("--accept-findings")] = False,
) -> None:
    """Record the current state as approved, and print what changed since the
    previous lock. Entries that did not change keep their approval record."""
    from ..core.lock import diff_locks, dump_lock, load_lock

    old = load_lock(baseline.read_text(encoding="utf-8")) if baseline.is_file() else None
    _, lock, _ = _create_lock(target, baseline, machine=machine, no_user=no_user, approved_by=approved_by,
                              review_by=review_by, accept_findings=accept_findings)
    rows = diff_locks(old, lock) if old is not None else []
    if old is not None:
        changed = {r["artifact"] for r in rows}
        previous = {e.key: e for e in old.artifacts}
        for e in lock.artifacts:
            prev = previous.get(e.key)
            if prev is not None and (e.id or e.key) not in changed:
                if not approved_by:
                    e.approved_by, e.approved_at = prev.approved_by, prev.approved_at
                e.review_by = review_by or prev.review_by
                if not accept_findings:
                    e.accepted_findings = list(prev.accepted_findings)
    emit(dump_lock(lock), baseline)
    _audit("baseline-update", approved_by, target or ("--machine" if machine else "."),
           {"lock": str(baseline), "components": len(lock.artifacts), "changes": len(rows),
            "changed": sorted({r["artifact"] for r in rows})[:50],
            "accepted_findings": sum(len(e.accepted_findings) for e in lock.artifacts), "review_by": review_by})
    con = _console(stderr=True)
    for r in rows:
        con.print(f"{escape(r['artifact'])}: {r['change']} {escape(r['detail'])}")
    con.print(f"{len(rows)} change(s); {len(lock.artifacts)} component(s) locked → {escape(str(baseline))}")


@baseline_app.command("diff")
def baseline_diff(
    old: Annotated[Path, typer.Argument(help="A lockfile.")] = Path(LOCK_NAME),
    new: Annotated[Optional[str], typer.Argument(help="Another lockfile, or a target to compare the lock with (default: the current directory).")] = None,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """What differs between two locks, or between a lock and what is there now."""
    from ..core.lock import build_lock, diff_locks, load_lock

    if not old.is_file():
        raise UsageError(f"lockfile not found: {old}")
    a = load_lock(old.read_text(encoding="utf-8"))
    if new is not None and Path(new).is_file() and Path(new).suffix in (".lock", ".json"):
        b = load_lock(Path(new).read_text(encoding="utf-8"))
    else:
        b = build_lock(run_scan(_static_request(new, lock_in_use=old)).report)
    rows = diff_locks(a, b)
    if json_out:
        emit(json.dumps(rows, indent=2) + "\n", None)
    else:
        con = _console()
        for r in rows:
            con.print(f"{escape(r['artifact'])}: {r['change']} {escape(r['detail'])}")
        con.print(f"{len(rows)} difference(s).")
    raise typer.Exit(EXIT_REVIEW if rows else EXIT_OK)


@app.command("lock", hidden=True)
def lock_cmd(
    target: Annotated[Optional[str], typer.Argument()] = None,
    output: Annotated[Path, typer.Option("--output", "-o")] = Path(LOCK_NAME),
    no_user: Annotated[bool, typer.Option("--no-user")] = False,
) -> None:
    """Alias of `baseline create`."""
    baseline_create(target, output, False, no_user, "", "", False)


@app.command("verify", hidden=True)
def verify_cmd(
    target: Annotated[Optional[str], typer.Argument()] = None,
    lock: Annotated[Path, typer.Option("--lock", "--baseline")] = Path(LOCK_NAME),
    fail_on: Annotated[str, typer.Option("--fail-on")] = "low",
    format: Annotated[Optional[list[str]], typer.Option("--format", "-f")] = None,
    output: Annotated[Optional[Path], typer.Option("--output", "-o")] = None,
    no_user: Annotated[bool, typer.Option("--no-user")] = False,
) -> None:
    """Alias of `baseline verify`."""
    baseline_verify(target, lock, False, no_user, fail_on, format, output)


# --------------------------------------------------------------- inventory --
def _inventory(format: str, output: Optional[Path], no_user: bool, project: Optional[Path], cards: bool) -> None:
    from ..acquire.machine import user_home
    from ..core.engine import scan as core_scan
    from ..core.models import ScanOptions
    from ..io.discovery import discover

    disc = discover((project or Path.cwd()), include_user=not no_user, home=user_home())
    report = core_scan(disc.tree, ScanOptions())
    if format == "cyclonedx":
        emit(render_cyclonedx(report), output)
        return
    if format == "json":
        data = {
            "locations": [r.__dict__ for r in disc.records],
            "artifacts": [a.model_dump(mode="json") for a in report.artifacts],
            "components": [json.loads(c.model_dump_json(exclude_none=True, exclude={"capabilities"})) for c in report.inventory],
        }
        emit(json.dumps(data, indent=2, ensure_ascii=False) + "\n", output)
        return
    if format != "table":
        raise UsageError("--format must be table, json or cyclonedx")
    con = _console()
    t = Table(title="Checked locations", title_justify="left")
    for col in ("Agent", "Scope", "Kind", "Path", "Found", "Path verified"):
        t.add_column(col)
    for r in disc.records:
        t.add_row(r.client, r.scope, r.kind, escape(r.path), "yes" if r.exists else "-",
                  "yes" if r.verified else escape(f"no ({r.note})" if r.note else "no"))
    con.print(t)
    a = Table(title="Agent components", title_justify="left")
    for col in ("Component", "Type", "Ecosystem", "Tier", "Verdict", "Findings", "Capabilities", "Location"):
        a.add_column(col, overflow="fold")
    for art in report.artifacts:
        a.add_row(escape(art.id), art.type, art.ecosystem, art.risk_tier.value, art.verdict.value, str(art.findings),
                  escape(", ".join(art.capabilities)), escape(art.root))
    con.print(a)
    s = Table(title="MCP servers", title_justify="left")
    for col in ("Name", "Agent", "Transport", "Command / URL", "Pinned", "Env vars (names)"):
        s.add_column(col, overflow="fold")
    for c in report.inventory:
        if c.server:
            target = c.server.url or " ".join([c.server.command or "", *c.server.args])
            s.add_row(escape(c.name), c.server.client, c.server.transport.value, escape(target[:120]),
                      "yes" if c.server.pinned else f"no ({escape(c.server.pin_detail or '')})", escape(", ".join(c.server.env_names)))
    con.print(s)
    if cards:
        con.print(escape(render_trust_cards(report)), markup=False)


@app.command("inventory")
def inventory_cmd(
    format: Annotated[str, typer.Option("--format", "-f", help="table, json or cyclonedx (the AI-BOM).")] = "table",
    output: Annotated[Optional[Path], typer.Option("--output", "-o")] = None,
    no_user: Annotated[bool, typer.Option("--no-user", help="Skip home-directory locations.")] = False,
    project: Annotated[Optional[Path], typer.Option("--project", help="Project root (default: current directory).")] = None,
    cards: Annotated[bool, typer.Option("--trust-cards", help="Also print a trust card per component.")] = False,
) -> None:
    """List the agent components on this machine and in this project, with
    their capabilities and risk tier; emit an AI-BOM with --format cyclonedx."""
    _inventory(format, output, no_user, project, cards)


@app.command("discover", hidden=True)
def discover_cmd(
    format: Annotated[str, typer.Option("--format", "-f")] = "table",
    output: Annotated[Optional[Path], typer.Option("--output", "-o")] = None,
    no_user: Annotated[bool, typer.Option("--no-user")] = False,
    project: Annotated[Optional[Path], typer.Option("--project")] = None,
) -> None:
    """Alias of `inventory`."""
    _inventory(format, output, no_user, project, False)


# --------------------------------------------------------------------- mcp --
@mcp_app.command("inspect")
def mcp_inspect(
    endpoint: Annotated[str, typer.Argument(help="mcp+https://… / https://… for a remote server, or mcp+stdio:<command> for a local one (started only inside the sandbox).")],
    json_out: Annotated[bool, typer.Option("--json")] = False,
    output: Annotated[Optional[Path], typer.Option("--output", "-o")] = None,
    scan_too: Annotated[bool, typer.Option("--scan/--no-scan", help="Run the definition rules on what the server serves.")] = True,
    two_identities: Annotated[bool, typer.Option("--two-identities/--one-identity", help="List twice with different client identities to detect cloaked tool lists.")] = True,
) -> None:
    """List a server's tools, prompts and resources without calling them, hash
    each definition for the baseline, and run the definition rules on them."""
    from ..acquire.mcp_live import inspect_endpoint

    result = inspect_endpoint(endpoint, two_identities=two_identities, scan=scan_too, cwd=Path.cwd())
    if json_out:
        emit(json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n", output)
    else:
        result.print(_console())
    if result.report is not None:
        save_last_report(result.report)
        raise typer.Exit(result.report.exit_code())


@mcp_app.command("probe")
def mcp_probe(
    url: Annotated[str, typer.Argument(help="The remote endpoint (https://… or mcp+https://…).")],
    format: Annotated[Optional[list[str]], typer.Option("--format", "-f")] = None,
    output: Annotated[Optional[Path], typer.Option("--output", "-o")] = None,
) -> None:
    """Read-only posture check of a remote endpoint: TLS, the unauthenticated
    response and its challenge, protected-resource and authorization-server
    metadata, advertised grant types and PKCE. No tool is listed or called."""
    target = url if url.lower().startswith("mcp+") else f"mcp+{url}"
    req = ScanRequest(targets=[target], profile="quick", llm="off", context="none", cwd=Path.cwd(), probe_only=True,
                      network=NetworkOptions(auth_checks=True))
    outcome = run_scan(req)
    print_notes(outcome)
    save_last_report(outcome.report)
    write_outputs(outcome.report, _formats(format), output)
    raise typer.Exit(outcome.report.exit_code())


# ---------------------------------------------------------------- detonate --
@app.command("detonate")
def detonate_cmd(
    target: Annotated[str, typer.Argument(help="What to detonate (any scan target that can be fetched to disk).")],
    timeout: Annotated[Optional[int], typer.Option("--timeout", help="Seconds for the whole run (default 900).")] = None,
    adapter: Annotated[Optional[str], typer.Option("--agent-adapter", help="claude-code, opencode or none (direct execution only).")] = None,
    format: Annotated[Optional[list[str]], typer.Option("--format", "-f")] = None,
    output: Annotated[Optional[Path], typer.Option("--output", "-o")] = None,
    keep_trace: Annotated[Optional[Path], typer.Option("--keep-trace", help="Directory for the trace, the file diff and the network log.")] = None,
) -> None:
    """Dynamic analysis only: run the target in a disposable container with no
    route to the internet and no real credentials, and report what it did.
    Fails if the sandbox is not available; it never falls back to the host."""
    from ..sandbox import SandboxUnavailable, detonate_target

    try:
        outcome = detonate_target(target, timeout=timeout, adapter=adapter, keep_trace=keep_trace, cwd=Path.cwd())
    except SandboxUnavailable as exc:
        raise UsageError(f"the sandbox is not available, so nothing was run: {exc}") from exc
    print_notes(outcome)
    save_last_report(outcome.report)
    write_outputs(outcome.report, _formats(format), output)
    raise typer.Exit(outcome.report.exit_code())


# ------------------------------------------------------------------- serve --
@app.command("serve")
def serve_cmd(
    mcp: Annotated[bool, typer.Option("--mcp", help="Speak MCP over stdio (tools: agentguard_scan, agentguard_check_install, agentguard_explain, agentguard_inventory).")] = False,
    http: Annotated[bool, typer.Option("--http", help="Serve the local HTTP API.")] = False,
    host: Annotated[str, typer.Option("--host", help="HTTP bind address (loopback only unless you change it).")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port")] = 8765,
    policy: Annotated[Optional[str], typer.Option("--policy")] = None,
    profile: Annotated[str, typer.Option("--profile")] = "quick",
    reports: Annotated[Optional[Path], typer.Option("--reports", help="Where full reports for the human are written.")] = None,
) -> None:
    """Run as an MCP server or local HTTP API for agents. Output is agent-safe:
    rule ids, fixed rule wording, file and line, verdict and fix summary; never
    text from the target."""
    from ..serve import ServeConfig, serve_http, serve_mcp

    if mcp == http:
        raise UsageError("choose one of --mcp or --http")
    cfg = ServeConfig(policy=policy, profile=profile, reports_dir=reports, cwd=Path.cwd())
    if mcp:
        serve_mcp(cfg)
    else:
        serve_http(cfg, host, port)


# ------------------------------------------------------------------- rules --
@rules_app.command("list")
def rules_list(
    family: Annotated[Optional[str], typer.Option("--family", help="One family, e.g. INJ.")] = None,
    status: Annotated[Optional[str], typer.Option("--status", help="planned, experimental, stable or deprecated.")] = None,
    format: Annotated[str, typer.Option("--format", "-f", help="table or json.")] = "table",
    json_out: Annotated[bool, typer.Option("--json", help="Same as --format json.")] = False,
) -> None:
    """List the rules of the catalogue with their status in this rule pack
    (detectors from imported community packs are included)."""
    from ..runner import load_pack

    pack = load_pack([])
    rules = [r for r in pack.rules.values()
             if (not family or r.family == family.upper()) and (not status or r.status.value == status.lower())]
    if json_out or format == "json":
        emit(json.dumps([{"id": r.id, "title": r.title, "family": r.family, "category": r.category.value,
                          "severity": r.severity.value, "confidence": r.confidence.value, "lane": r.lane.value,
                          "fix": r.fix.value, "status": r.status.value,
                          "detectors": sorted(d.key for d in pack.detectors.values() if d.rule_id == r.id)}
                         for r in rules], indent=2) + "\n", None)
        return
    t = Table(title=f"Rule pack {pack.version}: {len(pack.implemented)} of {len(pack.rules)} rules implemented, "
                    f"{len(pack.detectors)} detectors", title_justify="left")
    for col in ("ID", "Sev", "Lane", "Fix", "Status", "Title"):
        t.add_column(col, overflow="fold")
    for r in rules:
        t.add_row(r.id, r.severity.value, r.lane.value, r.fix.value, r.status.value, escape(r.title))
    _console().print(t)


@rules_app.command("explain", hidden=True)
def rules_explain(rule_id: Annotated[str, typer.Argument()]) -> None:
    """Alias of `agentguard explain <rule id>`."""
    from .explain import explain_rule

    pack = RulePack.default()
    explain_rule(pack, pack.rule(rule_id), rule_id, _console())


@rules_app.command("export", hidden=True)
def rules_export(
    format: Annotated[str, typer.Option("--format")] = "json",
    output: Annotated[Optional[Path], typer.Option("--output", "-o")] = None,
) -> None:
    """The rule pack with mappings and fixture examples, as JSON (used by the website)."""
    if format != "json":
        raise UsageError("only --format json is supported")
    from ..core.rules.export import export_rules

    emit(json.dumps(export_rules(RulePack.default()), indent=2, ensure_ascii=False) + "\n", output)


@rules_app.command("new")
def rules_new(
    rule_id: Annotated[str, typer.Argument(help="A catalogue rule id, e.g. AG-INJ-011.")],
    variant: Annotated[Optional[str], typer.Option("--variant", help="Add a narrower detector under a rule that already has one.")] = None,
    out: Annotated[Path, typer.Option("--out", help="Pack directory to write into (rules/ and fixtures/ are created).")] = Path("."),
) -> None:
    """Scaffold a detection entry and a positive and a negative fixture."""
    from ..rules_dev import scaffold

    try:
        written = scaffold(RulePack.default(), rule_id.upper(), variant, out)
    except ValueError as exc:
        raise UsageError(str(exc)) from exc
    for p in written:
        _console().print(f"wrote {escape(str(p))}")


@rules_app.command("test")
def rules_test(
    selector: Annotated[Optional[str], typer.Argument(help="A rule id, id/variant, alias or family (default: every detector).")] = None,
    fixtures: Annotated[Optional[Path], typer.Option("--fixtures", help="Fixture root (default: the repository's fixtures/rules).")] = None,
    rule_pack: Annotated[Optional[list[Path]], typer.Option("--rule-pack")] = None,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Run the positive and negative fixtures of the selected detectors."""
    from ..rules_dev import run_fixtures
    from ..runner import load_pack

    results = run_fixtures(load_pack(list(rule_pack or [])), fixtures, selector)
    bad = [r for r in results if r.status in ("failed", "error")]
    if json_out:
        emit(json.dumps([r.__dict__ for r in results], indent=2) + "\n", None)
    else:
        con = _console()
        for r in bad:
            con.print(f"[red]{r.status}[/red] {escape(r.case)}: {escape(r.detail)}")
        counts = {s: sum(1 for r in results if r.status == s) for s in ("passed", "failed", "error", "skipped")}
        con.print(", ".join(f"{n} {s}" for s, n in counts.items() if n) or "no fixtures found")
    raise typer.Exit(EXIT_REVIEW if bad or not results else EXIT_OK)


@rules_app.command("validate")
def rules_validate(
    rule_pack: Annotated[Optional[list[Path]], typer.Option("--rule-pack", help="Extra pack directories to load with the built-in pack.")] = None,
    fixtures: Annotated[Optional[Path], typer.Option("--fixtures")] = None,
) -> None:
    """Load the pack with the strict loader and check detectors, fixtures and mappings."""
    from ..core.rules.pack import RulePackError, data_dirs, strict_pack_check
    from ..rules_dev import validate_pack
    from ..runner import load_pack

    problems: list[str] = []
    try:
        strict_pack_check(*data_dirs())
        pack = load_pack(list(rule_pack or []))
        problems += validate_pack(pack, fixtures)
    except RulePackError as exc:
        problems.append(str(exc))
        pack = None
    con = _console()
    for p in problems:
        con.print(f"[red]problem[/red] {escape(p)}")
    if pack is not None:
        core = [r for r in pack.rules.values() if not r.extension]
        con.print(f"{len(core)} catalogue rules, {sum(1 for r in core if r.implemented)} implemented, "
                  f"{len(pack.detectors)} detectors; {len(problems)} problem(s)")
    raise typer.Exit(EXIT_REVIEW if problems else EXIT_OK)


@rules_app.command("import")
def rules_import(
    source: Annotated[Path, typer.Argument(help="A community pack: an Agent Threat Rules directory or file (YAML), or YARA files.")],
    format: Annotated[Optional[str], typer.Option("--format", help="atr or yara (default: detected).")] = None,
    name: Annotated[Optional[str], typer.Option("--name", help="Name of the installed pack.")] = None,
    lane: Annotated[str, typer.Option("--lane", help="Lane the imported rules run in. Community rules default to the advisory lane.")] = "hunt",
    licence: Annotated[Optional[str], typer.Option("--licence", "--license", help="Licence of the pack, recorded with it.")] = None,
    out: Annotated[Optional[Path], typer.Option("--out", help="Write the pack here instead of installing it.")] = None,
) -> None:
    """Import a community rule pack. Each imported rule becomes a variant of
    the catalogue rule it corresponds to, in the advisory (hunt) lane."""
    from ..rules_import import import_pack

    result = import_pack(source, fmt=format, name=name, lane=lane, licence=licence, out_dir=out)
    if result.get("installed"):
        _audit("rules-import", "", str(source), {"pack": result["name"], "imported": result["imported"],
                                                 "skipped": result["skipped"], "lane": lane, "licence": licence or ""})
    con = _console()
    con.print(f"Imported {result['imported']} rule(s) as pack '{escape(result['name'])}' → {escape(result['dir'])} "
              f"({result['skipped']} skipped).")
    for reason, n in sorted(result.get("skip_reasons", {}).items()):
        con.print(f"[dim]  skipped {n}: {escape(reason)}[/dim]")
    for note in result.get("notes", []):
        con.print(escape(note))
    if result.get("installed"):
        con.print("Imported rules are advisory: they are reported when the policy turns the hunt lane on (the strict preset does).")


# ------------------------------------------------------------------ update --
@app.command("update")
def update_cmd(
    source: Annotated[Optional[str], typer.Option("--from", help="A local update bundle (air-gapped use), or an https:// URL. Default: the configured source.")] = None,
    check: Annotated[bool, typer.Option("--check", help="Verify the bundle and show what it holds; install nothing.")] = False,
) -> None:
    """Refresh the rule pack and the intelligence bundle. A bundle is used only
    after its signature verifies against a trusted release key; a bundle older
    than the installed one is refused."""
    from ..update import UpdateError, run_update

    try:
        result = run_update(source, check_only=check, cwd=Path.cwd())
    except UpdateError as exc:
        raise UsageError(str(exc)) from exc
    if result.installed:
        _audit("update", "", source or "configured source", {"serial": result.serial, "rule_pack": result.rule_pack,
                                                             "intel": result.intel, "key_id": result.key_id})
    con = _console()
    for line in result.lines:
        con.print(escape(line))
    if result.installed:
        con.print("Run `agentguard baseline verify` to re-scan approved components against the new rules.")


@intel_app.command("status")
def intel_status() -> None:
    """Show which indicator feed is active."""
    from ..io.intel_store import load_active_feed

    feed, note = load_active_feed()
    _console().print(escape(note))
    if feed:
        e = feed.entries
        _console().print(f"{len(e.hashes)} hashes · {len(e.domains)} domains · {len(e.ips)} IPs · {len(e.publishers)} publishers")


@intel_app.command("update")
def intel_update(
    source: Annotated[str, typer.Option("--from", help="Path to feed.json (a feed.json.sig must sit next to it), or an https:// URL (NETWORK).")],
) -> None:
    """Install a newer signed indicator feed (signature and rollback checks enforced)."""
    from ..core.intel.feed import FeedError
    from ..io.intel_store import install_feed

    try:
        if source.startswith("https://"):
            from ..net.safe_http import SafeHttpClient

            client = SafeHttpClient()
            feed_bytes = client.get(source).body
            sig_bytes = client.get(source + ".sig").body
        else:
            p = Path(source)
            feed_bytes, sig_bytes = p.read_bytes(), Path(str(p) + ".sig").read_bytes()
        feed = install_feed(feed_bytes, sig_bytes)
    except (FeedError, OSError, ValueError) as exc:
        raise UsageError(str(exc)) from exc
    _console().print(f"Installed {escape(feed.describe())}")


# ------------------------------------------------------------------- bench --
@app.command("bench")
def bench_cmd(
    suite: Annotated[str, typer.Argument(help="corpus · evasion · incidents · perf · malskillbench · skilltrustbench · all (the suites that need no download).")] = "corpus",
    corpus: Annotated[Path, typer.Option("--corpus", help="Benchmark root containing manifest.yaml and corpus/.")] = Path("bench"),
    data: Annotated[Optional[Path], typer.Option("--data", help="Local copy of a public benchmark (never redistributed with Agent Guard).")] = None,
    split: Annotated[str, typer.Option("--split", help="Corpus suite: all | dev | heldout. skilltrustbench: subset (the fixed 556 cases) | full.")] = "all",
    profile: Annotated[str, typer.Option("--profile")] = "quick",
    limit: Annotated[Optional[int], typer.Option("--limit", help="Scan at most this many cases.")] = None,
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Write the scorecard JSON here.")] = None,
    perf: Annotated[bool, typer.Option("--perf/--no-perf", help="Corpus suite: also time 100 skills + 20 configs.")] = True,
) -> None:
    """Run benchmark and regression suites and print a scorecard."""
    from ..bench.suites import SUITES, print_scorecard, run_suite

    if suite not in (*SUITES, "all"):
        raise UsageError(f"unknown suite {suite!r}; choose from {', '.join((*SUITES, 'all'))}")
    results = run_suite(suite, corpus=corpus, data=data, split=split, profile=profile, limit=limit, perf=perf)
    if output:
        emit(json.dumps(results, indent=2, default=str) + "\n", output)
    print_scorecard(results, _console())
    raise typer.Exit(EXIT_OK if results.get("ok", True) else EXIT_REVIEW)


# ------------------------------------------------------------------ doctor --
@app.command("doctor")
def doctor_cmd(json_out: Annotated[bool, typer.Option("--json")] = False) -> None:
    """Check the environment and report what each tier can use."""
    from ..doctor import diagnose

    info = diagnose()
    if json_out:
        emit(json.dumps(info, indent=2) + "\n", None)
        return
    con = _console()
    con.print(f"[bold]Agent Guard[/bold] engine {ENGINE_VERSION} · rule pack {info['rule_pack']['version']} "
              f"({info['rule_pack']['implemented']} of {info['rule_pack']['rules']} rules implemented) · "
              f"Python {info['python']} on {info['platform']}")
    t = Table(title="What each profile can use", title_justify="left")
    for col in ("Capability", "Status", "Used by", "Detail"):
        t.add_column(col, overflow="fold")
    for row in info["checks"]:
        style = {"ok": "green", "missing": "yellow", "error": "red"}.get(row["status"], "white")
        t.add_row(row["name"], f"[{style}]{row['status']}[/{style}]", row["used_by"], escape(row["detail"]))
    con.print(t)
    for name, text in info["profiles"].items():
        con.print(f"[bold]{name}[/bold]: {escape(text)}")


__all__ = ["DRIFT_RULES", "render", "load_report", "render_json"]
