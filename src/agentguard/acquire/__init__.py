"""Acquire: turn a target into an in-memory ArtifactTree (PLAN §5.2).

Nothing fetched is ever executed, installed or imported. Remote content is
read into memory (never unpacked onto the host disk) and every remote target
is resolved to an immutable identifier that the report records.

The engine (``agentguard.core``) never calls this package; it is the host side.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..core.archive import ArchiveError, from_archive, sniff_format
from ..core.models import ImmutableRef, LimitEvent, LoadLimits, RemoteProbe, SourceRef
from ..core.models.enums import SourceKind
from ..core.tree import ArtifactTree
from ..io.fs_loader import load_path
from .targets import Target, TargetError, is_archive_name, parse_target

__all__ = ["AcquireContext", "AcquireError", "Acquired", "Target", "TargetError", "acquire", "merge_facts", "merge_trees",
           "parse_target"]


class AcquireError(RuntimeError):
    """The target could not be fetched or read."""


@dataclass
class AcquireContext:
    limits: LoadLimits = field(default_factory=LoadLimits)
    offline: bool = False
    github_token: str | None = None
    ref: str | None = None            # --ref
    all_refs: bool = False            # --all-refs
    history: str | None = None        # --history <n|all>
    submodules: bool = True
    excludes: tuple[str, ...] = ()
    include_user: bool = True         # machine scans: include home-directory locations
    cwd: Path = field(default_factory=Path.cwd)
    home: Path | None = None
    http: object | None = None        # a SafeHttpClient (tests pass a fake)
    mcp_identities: bool = True       # list a live server twice, as two client identities
    probe_only: bool = False          # `mcp probe`: posture checks only; no tool, prompt or resource is listed
    compare_source: bool = True       # packages: compare the published files with the source repository
    osv: bool = False                 # images: look the packages inside up in OSV
    sandbox: object | None = None     # a sandbox runtime, for targets that are started only inside it
    mcp_token: str | None = None      # a bearer token for the live MCP endpoint being scanned; sent to that endpoint only


@dataclass
class Acquired:
    target: Target
    tree: ArtifactTree
    local_root: Path | None = None            # set for a local directory or file
    probes: list[RemoteProbe] = field(default_factory=list)
    changed_paths: set[str] | None = None     # pull requests: files the change touches
    base_tree: ArtifactTree | None = None     # pull requests: the base commit, for "new since base"
    hosts: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    network: list[str] = field(default_factory=list)   # network features this acquisition implies
    # Facts recorded while fetching (ScanOptions.facts): {"images": {ref: {...}}, "packages": {...}, "endpoints": {...}}.
    facts: dict[str, dict] = field(default_factory=dict)


def _need_network(target: Target, ctx: AcquireContext) -> None:
    if ctx.offline:
        raise AcquireError(f"--offline forbids fetching {target.raw}")


def _local(target: Target, ctx: AcquireContext) -> Acquired:
    path = Path(target.raw)
    if not path.is_absolute():
        path = ctx.cwd / path
    if not path.exists():
        raise TargetError(f"path not found: {target.raw}")
    if path.is_file():
        head = b""
        try:
            with open(path, "rb") as fh:
                head = fh.read(512)
        except OSError as exc:
            raise AcquireError(f"cannot read {target.raw}: {type(exc).__name__}") from exc
        if is_archive_name(path.name) or sniff_format(head) == "zip":
            data = path.read_bytes()
            if len(data) > ctx.limits.max_total_bytes:
                raise AcquireError(f"{target.raw} is larger than the {ctx.limits.max_total_bytes}-byte scan limit")
            source = SourceRef(kind=SourceKind.local, locator=path.name)
            try:
                tree = from_archive(data, None, ctx.limits, source=source)
            except (ArchiveError, ValueError, OSError) as exc:
                # Not an archive after all (or a broken one): scan the file as it is.
                tree = load_path(path, ctx.limits)
                tree.limit_events.append(LimitEvent(kind="archive_error", path=path.name, detail=str(exc)[:200]))
                return Acquired(target=target, tree=tree, local_root=path)
            tree.display_root = str(path)
            return Acquired(target=Target(kind="archive", raw=target.raw), tree=tree)
    tree = load_path(path, ctx.limits, extra_excludes=ctx.excludes)
    return Acquired(target=target, tree=tree, local_root=path)


def acquire(raw: str | Target, ctx: AcquireContext | None = None) -> Acquired:
    """Fetch one target. Raises TargetError (bad syntax, exit 64) or AcquireError."""
    ctx = ctx or AcquireContext()
    target = raw if isinstance(raw, Target) else parse_target(raw)
    if target.kind == "local":
        return _local(target, ctx)
    if target.kind == "machine":
        from .machine import acquire_machine

        return acquire_machine(target, ctx)
    if target.kind == "mcp_stdio":
        from .mcp_live import acquire_stdio_config

        return acquire_stdio_config(target, ctx)
    _need_network(target, ctx)
    if target.kind in ("github", "pull_request"):
        from .github import acquire_github

        return acquire_github(target, ctx)
    if target.kind == "package":
        from .package import acquire_package

        return acquire_package(target, ctx)
    if target.kind == "oci":
        from .oci import acquire_image

        return acquire_image(target, ctx)
    if target.kind == "registry":
        from .registry import acquire_registry_entry

        return acquire_registry_entry(target, ctx)
    if target.kind == "mcp_remote":
        from .mcp_live import acquire_remote

        return acquire_remote(target, ctx)
    if target.kind == "url":
        from .descriptor import acquire_url

        return acquire_url(target, ctx)
    raise TargetError(f"unsupported target: {target.raw}")


def merge_trees(parts: list[Acquired], limits: LoadLimits) -> ArtifactTree:
    """One tree for several targets: each sits under its label so paths cannot collide."""
    if len(parts) == 1:
        return parts[0].tree
    out = ArtifactTree(source=SourceRef(kind=SourceKind.local, locator=" + ".join(p.target.raw for p in parts)[:300]))
    used: dict[str, int] = {}
    for part in parts:
        label = part.target.label
        used[label] = used.get(label, 0) + 1
        prefix = label if used[label] == 1 else f"{label}-{used[label]}"
        for path, blob in part.tree.files.items():
            vpath = f"{prefix}/{path}"
            if out.add(vpath, blob.data, limits) and path in part.tree.hints:
                out.hints[vpath] = dict(part.tree.hints[path])
        for ev in part.tree.limit_events:
            out.limit_events.append(LimitEvent(kind=ev.kind, path=f"{prefix}/{ev.path}", detail=ev.detail, bytes=ev.bytes))
        if part.changed_paths is not None:
            part.changed_paths = {f"{prefix}/{p}" for p in part.changed_paths}
        for probe in part.probes:
            if probe.config_path:
                probe.config_path = f"{prefix}/{probe.config_path}"
        for fact in (part.facts.get("images") or {}).values():
            if isinstance(fact, dict) and isinstance(fact.get("root"), str):
                fact["root"] = f"{prefix}/{fact['root']}".rstrip("/")
    return out


def merge_facts(into: dict, parts: list[Acquired]) -> None:
    """Fold the facts each acquisition recorded into ``ScanOptions.facts`` (one level deep)."""
    for part in parts:
        for key, value in part.facts.items():
            if isinstance(value, dict) and isinstance(into.get(key), dict):
                into[key] = {**into[key], **value}
            else:
                into.setdefault(key, value)


def immutable(kind: SourceKind, locator: str, resolved: str, **kw: str | None) -> ImmutableRef:
    return ImmutableRef(kind=kind, locator=locator[:300], resolved=resolved[:200], **kw)  # type: ignore[arg-type]
