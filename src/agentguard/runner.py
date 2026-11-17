"""Host-side scan orchestration, shared by the CLI, the library entry point,
the install gate and the agent-facing server.

    request → configuration and policy (from where the user runs, never from
    the target) → acquire → installed context → opt-in network facts →
    model stage (standard, deep) → dynamic stage (deep) → the pure engine.

Everything that touches the filesystem, the network, a model or Docker happens
here; ``agentguard.core.engine.scan`` then evaluates plain data.
"""

from __future__ import annotations

import datetime as dt
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .acquire import AcquireContext, AcquireError, Acquired, TargetError, acquire, merge_facts, merge_trees, parse_target
from .cli.config import (
    LOCK_NAME,
    ConfigError,
    load_baseline,
    load_user_config,
    load_user_level_config,
    parse_project_config,
    resolve_policy,
)
from .core.engine import scan as core_scan
from .core.models import Lockfile, NetworkOptions, Policy, ProjectConfig, Report, ScanOptions
from .core.models.config import LoadLimits
from .core.rules.pack import RulePack, RulePackError
from .core.tree import ArtifactTree

GITHUB_TOKEN_VARS = ("AGENTGUARD_GITHUB_TOKEN", "GITHUB_TOKEN")
MCP_TOKEN_VAR = "AGENTGUARD_MCP_TOKEN"     # a bearer token for the one live MCP endpoint being scanned
PROFILES = ("quick", "standard", "deep")
ECOSYSTEMS = ("claude-code", "codex", "cursor", "gemini", "copilot", "openclaw")
_ECOSYSTEM_ALIASES = {"claude": "claude-code", "gemini-cli": "gemini", "vscode": "copilot", "github-copilot": "copilot"}


class UsageError(ValueError):
    """A usage or configuration error (exit code 64)."""


@dataclass
class ScanRequest:
    targets: list[str] = field(default_factory=list)
    machine: bool = False
    profile: str | None = None            # quick | standard | deep
    llm: str = "auto"                     # off | auto | always
    dynamic: str | None = None            # off | on (None: on in the deep profile)
    context: str | None = None            # installed | none | path
    policy: str | None = None             # preset or file
    fail_on: str | None = None            # block | review | severity:<level>
    baseline: Path | None = None
    diff: str | None = None               # <base>..<head>
    ref: str | None = None
    all_refs: bool = False
    history: str | None = None
    submodules: bool = True
    ecosystems: list[str] = field(default_factory=list)
    rules: list[str] = field(default_factory=list)
    exclude_rules: list[str] = field(default_factory=list)
    rule_packs: list[Path] = field(default_factory=list)
    offline: bool = False
    max_llm_cost: float | None = None
    max_llm_tokens: int | None = None
    estimate: bool = False
    probe_only: bool = False              # mcp probe: posture checks only
    mcp_identities: bool = True           # list a live MCP server a second time as a different client
    agent_safe: bool = False
    jobs: int | None = None
    timeout: int | None = None
    config: Path | None = None
    network: NetworkOptions = field(default_factory=NetworkOptions)
    include_user: bool = True
    timestamps: bool = False
    cwd: Path = field(default_factory=Path.cwd)
    env: dict[str, str] | None = None     # None: os.environ
    today: dt.date | None = None
    # Hooks for tests and embedders.
    http: Any = None                      # a SafeHttpClient-like object
    provider: Any = None                  # a judge Provider
    sandbox: Any = None                   # a sandbox runtime
    lock_in_use: Path | None = None       # a lockfile this run writes (dropped from the scanned tree)
    # The dynamic tier (`agentguard detonate`, `--dynamic on`).
    dynamic_timeout: int | None = None    # seconds for the whole detonation (default: dynamic.timeout_seconds, 900)
    agent_adapter: str | None = None      # claude-code | opencode | none
    keep_trace: Path | None = None        # directory for the trace, the file diff and the network log
    dynamic_only: bool = False            # report what was observed in the sandbox; no static analyzers


@dataclass
class ScanOutcome:
    report: Report
    tree: ArtifactTree
    options: ScanOptions
    pack: RulePack
    config: ProjectConfig | None = None
    config_path: Path | None = None
    lock_path: Path | None = None
    acquired: list[Acquired] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    estimate: dict[str, Any] | None = None


def _env(req: ScanRequest) -> dict[str, str]:
    return dict(os.environ) if req.env is None else req.env


def is_own_repo(local_root: Path | None, cwd: Path) -> bool:
    """Inline ``agentguard-ignore`` comments are honoured only in the user's own
    repository: the directory the user runs from, or a path inside it when that
    directory is a git repository. Anything fetched, unpacked or outside it is
    third-party."""
    if local_root is None:
        return False
    try:
        root, here = local_root.resolve(), cwd.resolve()
    except OSError:
        return False
    if root == here:
        return True
    return (here / ".git").exists() and root.is_relative_to(here)


PACK_NOTES: list[str] = []          # what the last `load_pack` had to say (an installed update that was refused)


def load_pack(extra: list[Path]) -> RulePack:
    """The built-in pack, plus any ``--rule-pack`` directories and the packs
    installed by ``agentguard rules import`` / ``agentguard update``."""
    from .packs import installed_pack_files, pack_dir_files
    from .update import activate

    # A rule pack installed by `agentguard update` replaces the bundled one, if it still verifies.
    PACK_NOTES[:] = [note] if (note := activate()) else []
    files = installed_pack_files()
    for d in extra:
        if not d.is_dir():
            raise UsageError(f"--rule-pack: not a directory: {d}")
        files.update(pack_dir_files(d))
    if not files:
        return RulePack.default()
    from .core.rules.pack import data_dirs

    rules_dir, mappings_dir = data_dirs()
    base: dict[str, bytes] = {}
    for root, prefix in ((rules_dir, "rules"), (mappings_dir, "mappings")):
        for p in sorted(root.rglob("*")):
            if p.is_file() and not p.name.startswith("."):
                base[f"{prefix}/{p.relative_to(root).as_posix()}"] = p.read_bytes()
    base.update(files)
    return RulePack.from_files(base)


def rule_filter(pack: RulePack, include: list[str], exclude: list[str]) -> set[str] | None:
    def expand(selectors: list[str], flag: str) -> set[str]:
        out: set[str] = set()
        for raw in selectors:
            for sel in (s.strip() for s in raw.split(",")):
                if not sel:
                    continue
                ids = pack.canonical_ids(sel)
                if not ids:
                    raise UsageError(f"{flag}: {sel!r} is not a rule id, an alias, a family or a prefix")
                out |= ids
        return out

    if not include and not exclude:
        return None
    selected = expand(include, "--rules") if include else set(pack.rules)
    return selected - expand(exclude, "--exclude-rules")


def _ecosystems(values: list[str]) -> set[str] | None:
    out: set[str] = set()
    for raw in values:
        for name in (v.strip().lower() for v in raw.split(",")):
            if not name or name == "all":
                continue
            name = _ECOSYSTEM_ALIASES.get(name, name)
            if name not in ECOSYSTEMS:
                raise UsageError(f"--ecosystem: unknown ecosystem {name!r} (choose from {', '.join(ECOSYSTEMS)})")
            out.add(name)
    return out or None


def _limits(pconf: ProjectConfig | None) -> LoadLimits:
    if pconf is None:
        return LoadLimits()
    over = {k: v for k, v in pconf.limits.model_dump().items() if v is not None and k != "timeout_seconds"}
    return LoadLimits(**over) if over else LoadLimits()


def _without(tree: ArtifactTree, base: Path | None, path: Path | None) -> None:
    """Drop the lockfile this run reads or writes from the scanned tree: it is
    Agent Guard's own state, not component content. Only the file in use is
    dropped, so a target cannot hide a file by naming it agentguard.lock."""
    if base is None or path is None:
        return
    root = base if base.is_dir() else base.parent
    try:
        rel = path.resolve().relative_to(root.resolve()).as_posix()
    except (ValueError, OSError):
        return
    for key in (rel, f"./{rel}"):
        tree.files.pop(key, None)
        tree.hints.pop(key, None)


def _outside_skipped(changed: set[str], tree: ArtifactTree) -> set[str]:
    """The changed paths that are part of the scan. A change inside a directory the walk skipped (an ``exclude`` of
    the configuration, version-control storage) touches no component, and a lockfile there is a sample, not the
    lockfile this scan reads."""
    skipped = tuple(f"{e.path}/" for e in tree.limit_events if e.kind == "excluded_dir")
    return {p for p in changed if not p.startswith(skipped)} if skipped else changed


def _context_tree(mode: str, req: ScanRequest, limits: LoadLimits, parts: list[Acquired]) -> tuple[ArtifactTree | None, str]:
    """What the candidate is composed with: the components already installed on
    this machine (``installed``), a directory of them, or nothing."""
    if mode == "none":
        return None, ""
    if mode == "installed":
        if any(p.target.kind == "machine" for p in parts):
            return None, ""          # the machine is the target
        from .acquire.machine import user_home
        from .io.discovery import discover

        disc = discover(None, include_user=req.include_user, limits=limits, home=user_home())
        if not disc.tree.files:
            return None, ""
        return disc.tree, f"context: {len(disc.tree.files)} file(s) from the agent components installed on this machine"
    path = Path(mode) if Path(mode).is_absolute() else req.cwd / mode
    if not path.exists():
        raise UsageError(f"--context: {mode!r} is not 'installed', 'none' or an existing path")
    from .io.fs_loader import load_path

    return load_path(path, limits), f"context: {mode}"


def _github_token(req: ScanRequest) -> tuple[str | None, str | None]:
    env = _env(req)
    var = next((v for v in GITHUB_TOKEN_VARS if env.get(v)), None)
    return (env[var], var) if var else (None, None)


def _config_at_diff_base(req: ScanRequest) -> tuple[bool, str | None, str]:
    """In diff mode, when the configuration would be read from the repository
    being diffed, it is read as it was at the base commit: a change set cannot
    relax the policy it is scanned with. Returns (applies, text or None, origin)."""
    if not req.diff or req.config is not None or len(req.targets) != 1:
        return False, None, ""
    root = Path(req.targets[0]) if Path(req.targets[0]).is_absolute() else req.cwd / req.targets[0]
    try:
        if not root.is_dir() or root.resolve() != req.cwd.resolve():
            return False, None, ""
    except OSError:
        return False, None, ""
    from .acquire.diff import config_at_base

    got = config_at_base(root, req.diff)
    return True, (got[0] if got else None), (got[1] if got else "")


def prepare(req: ScanRequest) -> tuple[ProjectConfig | None, Path | None, Policy, RulePack, ScanOptions]:
    """Configuration, policy, rule pack and options for a request (no target is read)."""
    try:
        from_base, base_text, base_origin = _config_at_diff_base(req)
        if from_base:
            pconf, cfg_path = ((parse_project_config(base_text, base_origin), None) if base_text is not None
                               else load_user_level_config())
        else:
            pconf, cfg_path = load_user_config(req.cwd, req.config)
        policy = resolve_policy(req.policy, pconf, req.cwd)
        pack = load_pack(req.rule_packs)
    except (ConfigError, RulePackError, TargetError) as exc:
        raise UsageError(str(exc)) from exc
    profile = req.profile or (pconf.profile if pconf and pconf.profile else "standard")
    if profile not in PROFILES:
        raise UsageError(f"--profile: {profile!r} is not one of {', '.join(PROFILES)}")
    if req.llm not in ("off", "auto", "always"):
        raise UsageError("--llm must be off, auto or always")
    fail_on = req.fail_on or (pconf.fail_on if pconf and pconf.fail_on else None) or policy.fail_on or "block"
    try:
        options = ScanOptions(
            profile=profile, fail_on=fail_on, policy=policy,
            limits=_limits(pconf),
            suppressions=list(pconf.suppressions) if pconf else [],
            popular_skills=list(pconf.popular_skills) if pconf else [],
            rule_filter=rule_filter(pack, req.rules, req.exclude_rules),
            ecosystems=_ecosystems(req.ecosystems or (pconf.ecosystems if pconf else [])),
            network=req.network.model_copy(), include_timestamps=req.timestamps, agent_safe=req.agent_safe,
            today=req.today,
        )
    except ValueError as exc:
        raise UsageError(str(exc)) from exc
    timeout = req.timeout or (pconf.limits.timeout_seconds if pconf else None)
    if timeout:
        options.deadline_s = float(timeout)
    from .io.intel_store import load_active_feed

    options.intel, _ = load_active_feed(req.today)
    if req.offline and options.network.enabled():
        raise UsageError(f"--offline forbids network features ({', '.join(options.network.enabled())})")
    return pconf, cfg_path, policy, pack, options


def run_scan(req: ScanRequest) -> ScanOutcome:
    """Scan the request's targets. Raises UsageError for anything the user got
    wrong; every other exception is an internal error."""
    if not req.targets and not req.machine:
        raise UsageError("nothing to scan: give a target, or --machine")
    pconf, cfg_path, policy, pack, options = prepare(req)
    notes: list[str] = list(PACK_NOTES)
    token, token_var = _github_token(req)
    want_dynamic = not req.estimate and ((req.dynamic == "on") or (req.dynamic is None and options.profile == "deep"))
    sandbox = req.sandbox
    if want_dynamic and sandbox is None and any(t.strip().lower().startswith("mcp+stdio:") for t in req.targets):
        # A local server given by its command is started only inside the sandbox, so the sandbox is needed to list it.
        from .sandbox import SandboxUnavailable
        from .sandbox.runtime import default_runtime

        try:
            sandbox = default_runtime()
        except SandboxUnavailable as exc:
            raise UsageError(f"dynamic analysis needs its sandbox and will not run without it: {exc}") from exc
    actx = AcquireContext(
        limits=options.limits, offline=req.offline, github_token=token, ref=req.ref, all_refs=req.all_refs,
        history=req.history, submodules=req.submodules, excludes=tuple(pconf.exclude) if pconf else (),
        include_user=req.include_user, cwd=req.cwd, http=req.http, probe_only=req.probe_only, sandbox=sandbox,
        osv=req.network.osv, mcp_token=_env(req).get(MCP_TOKEN_VAR) or None, mcp_identities=req.mcp_identities,
    )
    specs: list[Any] = []
    try:
        specs = [parse_target(t) for t in req.targets]
        if req.machine:
            from .acquire.targets import Target

            specs.append(Target(kind="machine", raw="--machine"))
        parts = _acquire_all(specs, actx, req.jobs)
    except TargetError as exc:
        raise UsageError(str(exc)) from exc
    except AcquireError as exc:
        raise UsageError(str(exc)) from exc
    tree = merge_trees(parts, options.limits)
    merge_facts(options.facts, parts)
    for part in parts:
        notes += part.notes
        options.remote_probes += part.probes
        options.network_hosts += part.hosts
        for feature in part.network:
            setattr(options.network, feature, True)
    local_roots = [p.local_root for p in parts]
    options.own_repo = len(parts) == 1 and is_own_repo(local_roots[0], req.cwd)

    # Baseline: what was approved before. Defaults to agentguard.lock where the user runs.
    lock_path = req.baseline
    if lock_path is None and (req.cwd / LOCK_NAME).is_file():
        lock_path = req.cwd / LOCK_NAME
    if lock_path is not None:
        try:
            lock, known = load_baseline(lock_path)
        except ConfigError as exc:
            raise UsageError(str(exc)) from exc
        options.lock, options.baseline = lock, known
        if len(parts) == 1:
            _without(tree, local_roots[0], lock_path)
    if req.lock_in_use is not None and len(parts) == 1:
        _without(tree, local_roots[0], req.lock_in_use)

    # Pull-request / diff mode.
    changed: set[str] | None = None
    for part in parts:
        if part.changed_paths is not None:
            changed = (changed or set()) | part.changed_paths
    if req.diff:
        if len(parts) != 1 or parts[0].local_root is None or not parts[0].local_root.is_dir():
            raise UsageError("--diff needs exactly one local repository as the target")
        from .acquire.diff import diff_local

        d_changed, base_fps, d_notes = diff_local(parts[0].local_root, req.diff, options, pack, excludes=actx.excludes)
        changed = (changed or set()) | d_changed
        notes += d_notes
        if base_fps is not None:
            options.baseline = (options.baseline or set()) | base_fps
    else:
        for part in parts:
            if part.base_tree is not None:
                base_report = core_scan(part.base_tree, options.model_copy(update={"changed_paths": None, "baseline": None,
                                                                                    "lock": None, "remote_probes": []}), pack)
                options.baseline = (options.baseline or set()) | {f.fingerprint for f in base_report.findings}
    options.changed_paths = _outside_skipped(changed, tree) if changed else changed

    mode = req.context or (pconf.context if pconf and pconf.context else "installed")
    ctx_tree, ctx_note = _context_tree(mode, req, options.limits, parts)
    options.context = ctx_tree
    if ctx_note:
        notes.append(ctx_note)

    if options.network.enabled():
        notes.append(f"network features enabled: {', '.join(options.network.enabled())}")
    if req.network.enabled():
        from .net.collect import collect

        use_token = token if options.network.hijackable else None
        if use_token:
            notes.append(f"GitHub owner lookups authenticated with ${token_var} (sent to api.github.com only)")
        collect(tree, options, req.http, github_token=use_token, features=req.network)

    # Text inside images and rendered PDF pages, with the OCR engine when it is installed (local; no network).
    from .media_host import gather as gather_media
    from .media_host import unread_note

    gather_media(tree, options, notes)

    estimate = None
    if options.profile != "quick" and req.llm != "off":
        from .judge.stage import ModelBudget, run_model_stage

        budget = ModelBudget.from_config(pconf, max_cost=req.max_llm_cost, max_tokens=req.max_llm_tokens)
        estimate = run_model_stage(tree, options, pack, mode=req.llm, config=pconf, budget=budget, provider=req.provider,
                                   offline=req.offline, env=_env(req), estimate_only=req.estimate, notes=notes)
    elif req.estimate:
        estimate = {"calls": 0, "tokens": 0, "cost_usd": 0.0, "note": "no model is used in this configuration"}
    if req.estimate:
        return ScanOutcome(report=Report(), tree=tree, options=options, pack=pack, config=pconf, config_path=cfg_path,
                           lock_path=lock_path, acquired=parts, notes=notes, estimate=estimate)

    if want_dynamic:
        from .sandbox import SandboxUnavailable, detonate_into

        try:
            detonate_into(tree, options, config=pconf, runtime=sandbox, notes=notes, timeout=req.dynamic_timeout,
                          adapter=req.agent_adapter, keep_trace=req.keep_trace, pack=pack)
        except SandboxUnavailable as exc:
            raise UsageError(f"dynamic analysis needs its sandbox and will not run without it: {exc}") from exc
    if req.dynamic_only:
        options.analyzers = set()         # `agentguard detonate`: what was observed, without the static analyzers
    note = unread_note(tree, options)
    if note:
        notes.append(note)

    report = core_scan(tree, options, pack)
    return ScanOutcome(report=report, tree=tree, options=options, pack=pack, config=pconf, config_path=cfg_path,
                       lock_path=lock_path, acquired=parts, notes=notes, estimate=estimate)


def _acquire_all(specs: list[Any], actx: AcquireContext, jobs: int | None) -> list[Acquired]:
    if len(specs) <= 1 or (jobs or 1) <= 1:
        return [acquire(s, actx) for s in specs]
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=min(jobs or os.cpu_count() or 4, len(specs), 16)) as pool:
        return list(pool.map(lambda s: acquire(s, actx), specs))


def scan(target: Any = None, options: ScanOptions | None = None, pack: RulePack | None = None, **kwargs: Any) -> Report:
    """Library entry point (spec/interfaces.md §12).

        from agentguard import scan, ScanOptions
        report = scan("./skills/pdf-helper", ScanOptions(profile="standard", policy="strict"))

    ``target`` is a path or any other target string (or a list of them), or an
    ``ArtifactTree`` for a pure in-memory scan. With a string target the scan
    is static and offline unless the options ask for more: no configuration
    file is read, no installed context is added and no model is called."""
    if isinstance(target, ArtifactTree):
        return core_scan(target, options, pack, **kwargs)
    if target is None:
        raise UsageError("scan() needs a target")
    options = options.model_copy(deep=False) if options is not None else ScanOptions()
    pack = pack or RulePack.default()
    actx = AcquireContext(limits=options.limits, offline=not options.network.enabled())
    targets = [target] if isinstance(target, (str, os.PathLike)) else list(target)
    try:
        specs = [parse_target(os.fspath(t)) for t in targets]
        actx.offline = all(not s.remote for s in specs) and not options.network.enabled()
        parts = [acquire(s, actx) for s in specs]
    except (TargetError, AcquireError) as exc:
        raise UsageError(str(exc)) from exc
    tree = merge_trees(parts, options.limits)
    options.facts = dict(options.facts)
    merge_facts(options.facts, parts)
    requested = options.network
    implied = sorted({f for part in parts for f in part.network})
    if implied:
        options.network = requested.model_copy(update={f: True for f in implied})
    for part in parts:
        options.remote_probes = [*options.remote_probes, *part.probes]
        options.network_hosts = [*options.network_hosts, *part.hosts]
    if requested.enabled() and not actx.offline:
        from .net.collect import collect

        collect(tree, options, features=requested)
    return core_scan(tree, options, pack)


__all__ = ["ScanOutcome", "ScanRequest", "UsageError", "is_own_repo", "load_pack", "prepare", "rule_filter", "run_scan",
           "scan", "Lockfile"]
