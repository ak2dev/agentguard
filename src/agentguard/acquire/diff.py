"""`--diff <base>..<head>`: pull-request mode on a local checkout.

Changed files are scanned in full and the rest of the repository supplies
context; only findings whose fingerprints are new since the base are reported.
The base tree is read straight from the object database (``gitread``), so the
repository's own git configuration never runs.
"""

from __future__ import annotations

from pathlib import Path

from ..core.engine import scan as core_scan
from ..core.models import LimitEvent, LoadLimits, ScanOptions, SourceRef
from ..core.models.enums import SourceKind
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


def tree_at(repo: Repo, commit: str, limits: LoadLimits, prefix: str = "", label: str = "") -> ArtifactTree:
    """The files of a commit as an ArtifactTree. Submodule links and symlinks are
    recorded as limit events; nothing is checked out."""
    tree = ArtifactTree(source=SourceRef(kind=SourceKind.local, locator=label or commit[:12]))
    c = repo.commit(commit)
    excluded = set(limits.excluded_dirs)
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


def config_at_base(root: Path, spec: str) -> tuple[str, str] | None:
    """The scanner configuration as it was at the base commit: a change set cannot relax its own policy."""
    repo, base, _ = base_commit(root, spec)
    try:
        files = repo.walk(repo.commit(base).tree)
        for name in CONFIG_NAMES:
            if name in files:
                data = repo.blob(files[name].sha, 1 << 20)
                if data is not None:
                    return data.decode("utf-8", "replace"), f"{base[:12]}:{name}"
    except GitReadError:
        return None
    finally:
        repo.close()
    return None


def diff_local(root: Path, spec: str, options: ScanOptions, pack: RulePack) -> tuple[set[str], set[str] | None, list[str]]:
    """(changed paths, fingerprints present at the base, notes)."""
    repo, base, head = base_commit(root, spec)
    notes = [f"diff mode: changes from {base[:12]} to {head[:12]}"]
    try:
        changed = set(repo.changed_paths(base, head))
        head_now = repo.head()[1]
        if head_now and head_now != head:
            notes.append(f"the working tree is at {head_now[:12]}, not {head[:12]}; findings are located in the working tree")
        base_fps: set[str] | None = None
        try:
            base_tree = tree_at(repo, base, options.limits)
            base_opts = options.model_copy(update={"changed_paths": None, "baseline": None, "lock": None,
                                                   "remote_probes": [], "context": None})
            base_fps = {f.fingerprint for f in core_scan(base_tree, base_opts, pack).findings}
        except GitReadError as exc:
            notes.append(f"the base tree could not be read ({exc}); every finding in a changed component is reported")
    except GitReadError as exc:
        raise TargetError(f"--diff {spec}: {exc}") from exc
    finally:
        repo.close()
    return changed, base_fps, notes
