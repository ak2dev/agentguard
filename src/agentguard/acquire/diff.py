"""`--diff <base>..<head>`: pull-request mode on a local checkout.

Changed files are scanned in full and the rest of the repository supplies
context; only findings whose fingerprints are new since the base are reported.
What could approve the change (the configuration, the lockfile, inline ignore
comments) is taken from the base commit. The base tree is read straight from
the object database (``gitread``), so the repository's own git configuration
never runs.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..core.artifacts import decode_text
from ..core.engine import scan as core_scan
from ..core.models import LimitEvent, LoadLimits, ScanOptions, SourceRef
from ..core.models.enums import SourceKind
from ..core.policy.apply import inline_keys
from ..core.rules.pack import RulePack
from ..core.tree import ArtifactTree
from .gitread import GitReadError, Repo
from .targets import TargetError

CONFIG_NAMES = (".agentguard.yaml", ".agentguard.yml", "agentguard.yml", "agentguard.yaml")


def split_range(spec: str) -> tuple[str, str]:
    for sep in ("...", ".."):
        if sep in spec:
            base, head = spec.split(sep, 1)
            return base.strip() or "HEAD", head.strip() or "HEAD"
    return spec.strip(), "HEAD"


def tree_at(repo: Repo, commit: str, limits: LoadLimits, prefix: str = "", label: str = "",
            excludes: tuple[str, ...] = ()) -> ArtifactTree:
    """The files of a commit as an ArtifactTree. Submodule links and symlinks are
    recorded as limit events; nothing is checked out. ``excludes`` are the
    configuration's directory names, skipped as the file walk skips them."""
    tree = ArtifactTree(source=SourceRef(kind=SourceKind.local, locator=label or commit[:12]))
    c = repo.commit(commit)
    excluded = set(limits.excluded_dirs) | set(excludes)
    for path, entry in sorted(repo.walk(c.tree).items()):
        if any(seg in excluded for seg in path.split("/")[:-1]):
            continue
        vpath = f"{prefix}{path}"
        if entry.is_submodule:
            tree.limit_events.append(LimitEvent(kind="submodule", path=vpath, detail=f"pinned to {entry.sha[:12]}; not fetched"))
            continue
        if entry.is_symlink:
            tree.limit_events.append(LimitEvent(kind="symlink", path=vpath))
            continue
        try:
            data = repo.blob(entry.sha, limits.max_file_bytes)
        except GitReadError as exc:
            tree.limit_events.append(LimitEvent(kind="unreadable", path=vpath, detail=str(exc)[:120]))
            continue
        if data is None:
            tree.limit_events.append(LimitEvent(kind="too_large", path=vpath))
            continue
        tree.add(vpath, data, limits)
    return tree


def base_commit(root: Path, spec: str) -> tuple[Repo, str, str]:
    """(repo, the commit changes are measured from, head commit) for a ``base..head`` range."""
    try:
        repo = Repo(root)
        base_name, head_name = split_range(spec)
        base, head = repo.resolve(base_name), repo.resolve(head_name)
    except (GitReadError, OSError) as exc:
        raise TargetError(f"--diff {spec}: {exc}") from exc
    return repo, repo.merge_base(base, head) or base, head


def file_at_base(root: Path, spec: str, names: tuple[str, ...], max_bytes: int = 1 << 20) -> tuple[str, str] | None:
    """(text, origin) of the first of ``names`` (paths from the repository root) as it was at the base commit."""
    repo, base, _ = base_commit(root, spec)
    try:
        files = repo.walk(repo.commit(base).tree)
        for name in names:
            if name in files:
                data = repo.blob(files[name].sha, max_bytes)
                if data is not None:
                    return data.decode("utf-8", "replace"), f"{base[:12]}:{name}"
    except GitReadError:
        return None
    finally:
        repo.close()
    return None


def config_at_base(root: Path, spec: str) -> tuple[str, str] | None:
    """The scanner configuration as it was at the base commit: a change set cannot relax its own policy."""
    return file_at_base(root, spec, CONFIG_NAMES)


@dataclass
class DiffResult:
    changed: set[str]
    base_fingerprints: set[str] | None          # None when the base tree could not be read
    # The ignore comments the base commit had, by path (policy.apply.inline_key); empty when the base was unreadable,
    # so that no inline suppression counts.
    inline_at_base: dict[str, frozenset[tuple[str, str | None]]]
    notes: list[str]


def diff_local(root: Path, spec: str, options: ScanOptions, pack: RulePack, excludes: tuple[str, ...] = ()) -> DiffResult:
    """What changed from the base, and what the base already had: its findings' fingerprints and its inline ignore
    comments. The base is read with the same directory exclusions as the working tree."""
    repo, base, head = base_commit(root, spec)
    notes = [f"diff mode: changes from {base[:12]} to {head[:12]}"]
    inline: dict[str, frozenset[tuple[str, str | None]]] = {}
    try:
        changed = set(repo.changed_paths(base, head))
        head_now = repo.head()[1]
        if head_now and head_now != head:
            notes.append(f"the working tree is at {head_now[:12]}, not {head[:12]}; findings are located in the working tree")
        base_fps: set[str] | None = None
        try:
            base_tree = tree_at(repo, base, options.limits, excludes=excludes)
            base_opts = options.model_copy(update={"changed_paths": None, "baseline": None, "lock": None,
                                                   "remote_probes": [], "context": None, "inline_at_base": None})
            base_fps = {f.fingerprint for f in core_scan(base_tree, base_opts, pack).findings}
            for path, blob in base_tree.files.items():
                if b"agentguard-ignore" in blob.data:
                    text, _ = decode_text(blob.data)
                    if text is not None and (keys := inline_keys(text)):
                        inline[path] = keys
        except GitReadError as exc:
            notes.append(f"the base tree could not be read ({exc}); every finding in a changed component is reported")
    except GitReadError as exc:
        raise TargetError(f"--diff {spec}: {exc}") from exc
    finally:
        repo.close()
    return DiffResult(changed=changed, base_fingerprints=base_fps, inline_at_base=inline, notes=notes)
