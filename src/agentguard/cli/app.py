"""agentguard command-line interface (spec/interfaces.md §1–§3).

    agentguard scan <target>...     Scan and report
    agentguard fix <target>         Show or apply fixes
    agentguard explain <id>         Explain a rule or a finding
    agentguard install <source>     Scan, show the install receipt, then install
    agentguard baseline <action>    create | verify | update | diff
    agentguard inventory            List agent components; emit an AI-BOM
    agentguard mcp inspect <ep>     List a server's tools, prompts and resources without calling them
    agentguard mcp probe <url>      Read-only posture check of a remote endpoint
    agentguard detonate <target>    Dynamic analysis only
    agentguard serve                Run as an MCP server or local HTTP API for agents
    agentguard rules <action>       list | new | test | validate | import
    agentguard update               Refresh rule packs and intelligence
    agentguard bench <suite>        Run benchmark and regression suites
    agentguard doctor               Check the environment and report what each tier can use

Exit codes: 0 ALLOW (or below the --fail-on threshold) · 1 REVIEW at or above
the threshold · 2 BLOCK · 3 scan incomplete and policy requires full coverage ·
64 usage or configuration error · 70 internal error.

The static tier never executes what it scans: an audit hook blocks process
creation for the whole run.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Annotated, Any, Optional

import typer
from rich.console import Console
from rich.markup import escape
from typer.core import TyperGroup

from .. import __version__
from ..acquire import AcquireError, TargetError
from ..core.engine import ENGINE_VERSION
from ..core.models import NetworkOptions, Report
from ..core.models.report import EXIT_INTERNAL, EXIT_USAGE
from ..core.report.render import (
    agent_safe,
    render_cyclonedx,
    render_json,
    render_junit,
    render_markdown,
    render_sarif,
)
from ..core.rules.pack import RulePack, RulePackError
from ..io import guard
from ..runner import ScanOutcome, ScanRequest, UsageError, run_scan
from .config import ConfigError
from .terminal import print_report

_ClickException = next(c for c in typer.BadParameter.__mro__ if c.__name__ == "ClickException")
USAGE_ERRORS = (UsageError, ConfigError, TargetError, AcquireError, RulePackError)
FORMATS = {"terminal": "", "json": "json", "sarif": "sarif", "md": "md", "markdown": "md", "html": "html",
           "junit": "xml", "cyclonedx": "cdx.json"}
REPORT_BASENAME = "agentguard-report"


def _console(stderr: bool = False) -> Console:
    return Console(stderr=stderr, highlight=False, soft_wrap=False)


def _utf8_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


def _error(kind: str, msg: str) -> None:
    _console(stderr=True).print(f"[bold red]{kind}:[/bold red] {escape(msg)}")


class _Group(TyperGroup):
    """Maps every way a run can end to the documented exit codes."""

    def main(self, args: Any = None, prog_name: Any = None, complete_var: Any = None, standalone_mode: bool = True,
             windows_expand_args: bool = True, **extra: Any) -> Any:
        try:
            rv = super().main(args=args, prog_name=prog_name, complete_var=complete_var, standalone_mode=False,
                              windows_expand_args=windows_expand_args, **extra)
            code = rv if isinstance(rv, int) and not isinstance(rv, bool) else 0
        except typer.Abort:
            code = 130
        except _ClickException as exc:
            exc.show()
            code = EXIT_USAGE
        except USAGE_ERRORS as exc:
            _error("error", str(exc))
            code = EXIT_USAGE
        except guard.ExecutionBlocked as exc:
            _error("internal error", str(exc))
            code = EXIT_INTERNAL
        except Exception as exc:  # noqa: BLE001 - the last line of defence: an internal error, never a silent pass
            _error("internal error", f"{type(exc).__name__}: {str(exc)[:300]}")
            if os.environ.get("AGENTGUARD_DEBUG"):
                raise
            code = EXIT_INTERNAL
        if standalone_mode:
            sys.exit(code)
        return code


app = typer.Typer(
    name="agentguard",
    cls=_Group,
    help="Security scanner for agent extensions: skills, plugins, instruction files, agent settings and hooks, "
         "MCP servers and connectors. It reports the risk, the cause (file and line) and the fix, and ends in one "
         "verdict: ALLOW, REVIEW or BLOCK. The static tier never executes what it scans.",
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_enable=False,
)


def _version(value: bool) -> None:
    if value:
        pack = RulePack.default()
        typer.echo(f"agentguard {__version__} (engine {ENGINE_VERSION}, rule pack {pack.version}, "
                   f"{len(pack.implemented)} of {len(pack.rules)} rules implemented)")
        raise typer.Exit(0)


@app.callback()
def _main(
    version: Annotated[bool, typer.Option("--version", help="Show version and exit.", is_eager=True,
                                          callback=_version)] = False,
) -> None:
    guard.install()
    _utf8_stdio()
    from ..update import activate

    activate()      # use a rule pack installed by `agentguard update`, if it still verifies


# ------------------------------------------------------------------ output --
def render(report: Report, fmt: str) -> str:
    fmt = FORMATS_CANON.get(fmt, fmt)
    if fmt == "json":
        return render_json(report)
    if fmt == "sarif":
        return render_sarif(report)
    if fmt == "md":
        return render_markdown(report)
    if fmt == "junit":
        return render_junit(report)
    if fmt == "cyclonedx":
        return render_cyclonedx(report)
    if fmt == "html":
        from ..core.report.html import render_html

        return render_html(report)
    raise UsageError(f"unknown format {fmt!r} (choose from terminal, json, sarif, md, html, junit, cyclonedx)")


FORMATS_CANON = {"markdown": "md"}


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))


def emit(text: str, output: Optional[Path]) -> None:
    if output:
        _write(output, text)
    else:
        sys.stdout.write(text)


def _formats(values: list[str] | None) -> list[str]:
    out: list[str] = []
    for raw in values or ["terminal"]:
        for name in (v.strip().lower() for v in raw.split(",")):
            if not name:
                continue
            if name not in FORMATS:
                raise UsageError(f"--format: unknown format {name!r} (choose from terminal, json, sarif, md, html, junit, cyclonedx)")
            name = FORMATS_CANON.get(name, name)
            if name not in out:
                out.append(name)
    return out or ["terminal"]


def write_outputs(report: Report, formats: list[str], output: Optional[Path], *, shown: Report | None = None,
                  verbose: bool = False, show_info: bool = False) -> list[Path]:
    """Write every requested format. ``shown`` is what goes to stdout (the
    agent-safe copy when asked for); files always hold the full report."""
    shown = shown or report
    files = [f for f in formats if f != "terminal"]
    written: list[Path] = []
    as_dir = output is not None and (output.is_dir() or len(files) > 1 or str(output).endswith(("/", "\\")))
    if output is None and len(files) > 1:
        raise UsageError("several --format values need --output <directory>")
    for fmt in files:
        if output is None:
            sys.stdout.write(render(shown, fmt))
        elif as_dir:
            target = output / f"{REPORT_BASENAME}.{FORMATS[fmt]}"
            _write(target, render(report, fmt))
            written.append(target)
        else:
            _write(output, render(report, fmt))
            written.append(output)
    if "terminal" in formats:
        if output is not None and not files:
            target = output / f"{REPORT_BASENAME}.json" if output.is_dir() else output
            _write(target, render_json(report))
            written.append(target)
        print_report(shown, _console(), verbose=verbose, show_info=show_info)
    return written


def last_report_path() -> Path:
    from ..io.intel_store import data_home

    return data_home() / "last-report.json"


def save_last_report(report: Report) -> Path | None:
    """Keep the full report of the last scan for `explain <fingerprint>` and `fix --finding`."""
    try:
        path = last_report_path()
        _write(path, render_json(report))
        return path
    except OSError:
        return None


def load_report(path: Optional[Path]) -> Report:
    src = path or last_report_path()
    if not src.is_file():
        raise UsageError(f"no report at {src}: run a scan first, or pass --report <file.json>")
    try:
        return Report.model_validate_json(src.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise UsageError(f"cannot read report {src}: {str(exc)[:200]}") from exc


def print_notes(outcome: ScanOutcome, quiet: bool = False) -> None:
    if quiet:
        return
    con = _console(stderr=True)
    for note in outcome.notes:
        con.print(f"[dim]{escape(note)}[/dim]")


# -------------------------------------------------------------------- scan --
def _on_off(value: Optional[str], flag: str) -> Optional[bool]:
    if value is None:
        return None
    v = value.strip().lower()
    if v in ("on", "true", "yes", "1"):
        return True
    if v in ("off", "false", "no", "0"):
        return False
    raise UsageError(f"{flag} must be on or off")


@app.command("scan")
def scan_cmd(
    targets: Annotated[Optional[list[str]], typer.Argument(
        help="What to scan: a path, a GitHub URL (optionally @ref, or …/pull/N), pkg:npm/… or pkg:pypi/…, oci://…, "
             "an archive or bundle, mcp:<registry name>, mcp+https://… or mcp+stdio:<command>, or an OpenAPI / A2A "
             "descriptor. Several targets are scanned together. Default: the current directory.")] = None,
    machine: Annotated[bool, typer.Option("--machine", help="Scan every agent component installed on this machine.")] = False,
    profile: Annotated[Optional[str], typer.Option("--profile", help="quick (deterministic static) · standard (adds the triage model and a gated adjudicator) · deep (adds dynamic analysis). Default: standard.")] = None,
    llm: Annotated[Optional[str], typer.Option("--llm", envvar="AGENTGUARD_LLM", help="off · auto (use a model when one is configured) · always. Default: auto.")] = None,
    dynamic: Annotated[Optional[str], typer.Option("--dynamic", help="off · on: detonate the target in the sandbox (needs Docker). Default: off, on in the deep profile.")] = None,
    context: Annotated[Optional[str], typer.Option("--context", envvar="AGENTGUARD_CONTEXT", help="What the target is composed with: installed (the agent components on this machine) · none · a path. Default: installed.")] = None,
    policy: Annotated[Optional[str], typer.Option("--policy", help="A preset (strict, balanced, permissive) or a policy file. Default: balanced.")] = None,
    format: Annotated[Optional[list[str]], typer.Option("--format", "-f", help="terminal, json, sarif, md, html, junit, cyclonedx. Repeatable.")] = None,
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="A file, or a directory when several formats are written. Default: stdout.")] = None,
    fail_on: Annotated[Optional[str], typer.Option("--fail-on", help="block · review · severity:<level>. Default: block.")] = None,
    baseline: Annotated[Optional[Path], typer.Option("--baseline", "--lock", help="A lockfile of what was approved (default: agentguard.lock here, if present). A previous JSON report also works: only new findings are reported.")] = None,
    diff: Annotated[Optional[str], typer.Option("--diff", help="<base>..<head>: scan the changed files in full, the rest as context, and report only new findings.")] = None,
    ref: Annotated[Optional[str], typer.Option("--ref", help="Branch, tag or commit to scan (git and GitHub targets).")] = None,
    all_refs: Annotated[bool, typer.Option("--all-refs", help="Scan every branch and tag head.")] = False,
    history: Annotated[Optional[str], typer.Option("--history", help="<n|all>: also scan agent-facing files from the last n commits, including ones later removed.")] = None,
    submodules: Annotated[Optional[str], typer.Option("--submodules", help="on · off: read git submodules at their pinned commits. Default: on.")] = None,
    ecosystem: Annotated[Optional[list[str]], typer.Option("--ecosystem", help="Comma list: claude-code, codex, cursor, gemini, copilot, openclaw. Default: all.")] = None,
    rules: Annotated[Optional[list[str]], typer.Option("--rules", help="Only these rules: ids, aliases, families (INJ) or prefixes (AG-INJ-). Comma list, repeatable.")] = None,
    exclude_rules: Annotated[Optional[list[str]], typer.Option("--exclude-rules", help="Rules to leave out (same selectors).")] = None,
    rule_pack: Annotated[Optional[list[Path]], typer.Option("--rule-pack", help="An additional rule pack directory. Repeatable.")] = None,
    offline: Annotated[bool, typer.Option("--offline", help="Forbid all network use; fail if a selected engine or target needs it.")] = False,
    max_llm_cost: Annotated[Optional[float], typer.Option("--max-llm-cost", help="Model budget for this scan, in USD.")] = None,
    max_llm_tokens: Annotated[Optional[int], typer.Option("--max-llm-tokens", help="Model token budget for this scan.")] = None,
    estimate: Annotated[bool, typer.Option("--estimate", help="Print the expected model cost and stop.")] = False,
    agent_safe_out: Annotated[bool, typer.Option("--agent-safe", help="Never echo scanned text: rule ids, fixed wording, file and line, verdict and fix only.")] = False,
    jobs: Annotated[Optional[int], typer.Option("--jobs", help="Parallel fetches. Default: CPU count.")] = None,
    timeout: Annotated[Optional[int], typer.Option("--timeout", help="Seconds before the scan stops and reports what it did not reach. Default: 600.")] = None,
    config: Annotated[Optional[Path], typer.Option("--config", help="Configuration file (default: .agentguard.yaml in the directory you run from; never one inside the target).")] = None,
    no_user: Annotated[bool, typer.Option("--no-user", help="With --machine or --context installed: skip home-directory locations.")] = False,
    live_metadata: Annotated[bool, typer.Option("--live-metadata", help="NETWORK: read tool lists from the remote MCP servers a config names (read-only; no tool is called).")] = False,
    auth_checks: Annotated[bool, typer.Option("--auth-checks", help="NETWORK: check remote servers' TLS and OAuth posture.")] = False,
    osv: Annotated[bool, typer.Option("--osv", help="NETWORK: look up dependencies in OSV.")] = False,
    provenance: Annotated[bool, typer.Option("--provenance", help="NETWORK: verify package provenance attestations.")] = False,
    registry: Annotated[bool, typer.Option("--registry", help="NETWORK: registry existence and package-age checks.")] = False,
    check_hijackable: Annotated[bool, typer.Option("--check-hijackable", help="NETWORK: check that referenced GitHub owners, packages and domains still exist. Uses $AGENTGUARD_GITHUB_TOKEN or $GITHUB_TOKEN for api.github.com only.")] = False,
    changed_since: Annotated[Optional[str], typer.Option("--changed-since", hidden=True, help="Same as --diff <ref>..HEAD.")] = None,
    show_info: Annotated[bool, typer.Option("--show-info", help="Show info-level findings in terminal output.")] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Show evidence, decoded content and standards mappings.")] = False,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="No progress notes on stderr.")] = False,
    timestamps: Annotated[bool, typer.Option("--timestamps", help="Include a generation timestamp and timings (output is then not reproducible).")] = False,
) -> None:
    """Scan and report. Ends in one verdict: ALLOW, REVIEW or BLOCK."""
    formats = _formats(format)
    cwd = Path.cwd()
    req = ScanRequest(
        targets=list(targets or ([] if machine else ["."])), machine=machine, profile=profile, llm=(llm or "auto").lower(),
        dynamic=None if dynamic is None else ("on" if _on_off(dynamic, "--dynamic") else "off"),
        context=context, policy=policy, fail_on=fail_on, baseline=baseline,
        diff=diff or (f"{changed_since}..HEAD" if changed_since else None), ref=ref, all_refs=all_refs, history=history,
        submodules=_on_off(submodules, "--submodules") is not False, ecosystems=list(ecosystem or []),
        rules=list(rules or []), exclude_rules=list(exclude_rules or []), rule_packs=list(rule_pack or []),
        offline=offline, max_llm_cost=max_llm_cost, max_llm_tokens=max_llm_tokens, estimate=estimate,
        agent_safe=agent_safe_out, jobs=jobs, timeout=timeout, config=config, include_user=not no_user,
        network=NetworkOptions(live_metadata=live_metadata, auth_checks=auth_checks, osv=osv, provenance=provenance,
                               registry=registry, hijackable=check_hijackable),
        timestamps=timestamps, cwd=cwd,
    )
    outcome = run_scan(req)
    print_notes(outcome, quiet)
    if estimate:
        emit(json.dumps(outcome.estimate or {}, indent=2, sort_keys=True) + "\n", output)
        raise typer.Exit(0)
    report = outcome.report
    saved = save_last_report(report)
    shown = agent_safe(report) if agent_safe_out else report
    write_outputs(report, formats, output, shown=shown, verbose=verbose, show_info=show_info)
    if agent_safe_out and saved is not None and not quiet:
        _console(stderr=True).print(f"[dim]Full report for a human: {escape(str(saved))}[/dim]")
    raise typer.Exit(report.exit_code())


# ----------------------------------------------------------------- explain --
@app.command("explain")
def explain_cmd(
    ident: Annotated[str, typer.Argument(help="A rule id (AG-EXEC-001), an id/variant, an old alias, or a finding fingerprint (or its first characters).")],
    report: Annotated[Optional[Path], typer.Option("--report", help="JSON report to look a finding up in (default: the last scan).")] = None,
    json_out: Annotated[bool, typer.Option("--json", help="JSON output.")] = False,
) -> None:
    """Explain a rule or a finding: the risk, the cause and the fix."""
    from .explain import explain_finding, explain_rule

    pack = RulePack.default()
    try:
        rule = pack.rule(ident)
    except RulePackError:
        rule = None
    if rule is not None:
        explain_rule(pack, rule, ident, _console(), json_out)
        return
    rep = load_report(report)
    matches = [f for f in [*rep.findings, *rep.suppressed_findings] if f.fingerprint.startswith(ident.lower())]
    if not matches:
        raise UsageError(f"{ident!r} is neither a rule id nor the fingerprint of a finding in the report")
    if len(matches) > 1 and len({f.fingerprint for f in matches}) > 1:
        raise UsageError(f"{ident!r} matches {len(matches)} findings; give more characters of the fingerprint")
    explain_finding(pack, rep, matches[0], _console(), json_out)


# ------------------------------------------------------------------ report --
@app.command("report")
def report_cmd(
    input: Annotated[Path, typer.Option("--input", "-i", help="An Agent Guard JSON report.")],
    format: Annotated[Optional[list[str]], typer.Option("--format", "-f")] = None,
    output: Annotated[Optional[Path], typer.Option("--output", "-o")] = None,
    agent_safe_out: Annotated[bool, typer.Option("--agent-safe")] = False,
) -> None:
    """Re-render a JSON report in another format (no rescan)."""
    rep = load_report(input)
    write_outputs(rep, _formats(format or ["sarif"]), output, shown=agent_safe(rep) if agent_safe_out else rep)


@app.command("schema")
def schema_cmd(
    name: Annotated[str, typer.Argument(help="report | rule | lock | policy | config")] = "report",
) -> None:
    """Print a JSON Schema for one of Agent Guard's data formats."""
    from ..core.schemas import SCHEMAS

    if name not in SCHEMAS:
        raise UsageError(f"unknown schema {name}; choose from {', '.join(SCHEMAS)}")
    emit(json.dumps(SCHEMAS[name](), indent=2) + "\n", None)


def main() -> None:
    app()


from . import commands as _commands  # noqa: E402,F401 - registers the remaining commands on `app`

if __name__ == "__main__":
    main()
