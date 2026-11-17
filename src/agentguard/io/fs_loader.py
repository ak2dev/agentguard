"""Safe real-filesystem → ArtifactTree loading (host only; not used in Pyodide).

* Never follows symlinks or Windows junctions/reparse points; they are
  recorded as limit events instead.
* Only regular files are read (FIFOs, sockets and devices would block or be
  infinite).
* Every path is confined to the scan root.
* Files are read with a hard size cap.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from ..core.models import LimitEvent, LoadLimits, SourceRef
from ..core.models.enums import SourceKind
from ..core.tree import ArtifactTree

_REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
# Git's own files. Anything else inside `.git/` was put there by someone, so it is read (AG-EVADE-006);
# hooks that are not the shipped samples are read too (AG-WS-005).
_GIT_FILES = frozenset({
    "HEAD", "config", "config.worktree", "description", "index", "packed-refs", "ORIG_HEAD", "FETCH_HEAD", "MERGE_HEAD",
    "CHERRY_PICK_HEAD", "REVERT_HEAD", "REBASE_HEAD", "BISECT_LOG", "BISECT_START", "BISECT_EXPECTED_REV",
    "COMMIT_EDITMSG", "MERGE_MSG", "MERGE_MODE", "MERGE_RR", "SQUASH_MSG", "TAG_EDITMSG", "AUTO_MERGE", "shallow",
    "gitk.cache", "index.lock", "HEAD.lock", "commondir", "gitdir", "NOTES_MERGE_REF", "fsmonitor--daemon.ipc",
})
_GIT_DIRS = frozenset({
    "objects", "refs", "logs", "info", "modules", "lfs", "worktrees", "rebase-merge", "rebase-apply", "branches",
    "rr-cache", "svn", "annex", "reftable", "sequencer", "fsmonitor--daemon", "filter-repo",
})
# A directory holding one of these is an agent package: its dependency directories are part of what
# gets installed, so they are walked instead of skipped.
_PACKAGE_MARKERS = frozenset({"skill.md", ".claude-plugin", ".codex-plugin", ".cursor-plugin", "gemini-extension.json",
                              "openclaw.plugin.json"})
_VCS_DIRS = frozenset({".git", ".hg", ".svn"})

_O_FLAGS = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)


def _is_link_like(st: os.stat_result) -> bool:
    if stat.S_ISLNK(st.st_mode):
        return True
    attrs = getattr(st, "st_file_attributes", 0)
    return bool(attrs & _REPARSE)


def _read_file(path: str, cap: int) -> bytes | None:
    fd = os.open(path, _O_FLAGS)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, 1 << 16)
            if not chunk:
                break
            total += len(chunk)
            if total > cap:
                return None
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def load_path(
    target: str | os.PathLike[str],
    limits: LoadLimits | None = None,
    extra_excludes: tuple[str, ...] = (),
) -> ArtifactTree:
    """Load a directory or a single file into an ArtifactTree."""
    limits = limits or LoadLimits()
    target_path = Path(target)
    st = os.lstat(target_path)
    if _is_link_like(st):
        tree = ArtifactTree(source=SourceRef(kind=SourceKind.local, locator=str(target_path)))
        tree.limit_events.append(LimitEvent(kind="symlink", path=target_path.name, detail="scan target is a link"))
        return tree
    if stat.S_ISREG(st.st_mode):
        root = target_path.resolve().parent
        tree = ArtifactTree(
            source=SourceRef(kind=SourceKind.local, locator=str(target_path)),
            display_root=str(root),
        )
        data = _read_file(str(target_path), limits.max_file_bytes)
        if data is None:
            tree.limit_events.append(LimitEvent(kind="too_large", path=target_path.name))
        else:
            tree.add(target_path.name, data, limits)
        return tree
    if not stat.S_ISDIR(st.st_mode):
        raise ValueError(f"not a regular file or directory: {target_path}")

    root = target_path.resolve()
    tree = ArtifactTree(source=SourceRef(kind=SourceKind.local, locator=str(target_path)), display_root=str(root))
    excluded = set(limits.excluded_dirs) | set(extra_excludes)
    # (directory, path relative to the root, depth, inside an agent package, position inside `.git`)
    stack: list[tuple[Path, str, int, bool, str]] = [(root, "", 0, False, "")]
    while stack:
        dir_path, rel_dir, depth, in_package, git_pos = stack.pop()
        if depth > limits.max_depth:
            tree.limit_events.append(LimitEvent(kind="too_deep", path=rel_dir))
            continue
        try:
            entries = sorted(os.scandir(dir_path), key=lambda e: e.name)
        except OSError as exc:
            tree.limit_events.append(LimitEvent(kind="unreadable", path=rel_dir or ".", detail=type(exc).__name__))
            continue
        if not in_package and not git_pos and any(e.name.lower() in _PACKAGE_MARKERS for e in entries):
            in_package = True
        subdirs: list[tuple[Path, str, int, bool, str]] = []
        for entry in entries:
            rel = f"{rel_dir}/{entry.name}" if rel_dir else entry.name
            try:
                est = entry.stat(follow_symlinks=False)
            except OSError:
                tree.limit_events.append(LimitEvent(kind="unreadable", path=rel))
                continue
            if _is_link_like(est) or (hasattr(entry, "is_junction") and entry.is_junction()):
                tree.limit_events.append(LimitEvent(kind="symlink", path=rel))
                continue
            if stat.S_ISDIR(est.st_mode):
                if git_pos:
                    if git_pos == "top" and entry.name in _GIT_DIRS:
                        continue                     # git's own storage; `.git` is already listed as excluded
                    subdirs.append((Path(entry.path), rel, depth + 1, in_package, "hooks" if git_pos == "top" and entry.name == "hooks" else "other"))
                    continue
                if entry.name in excluded:
                    if entry.name in extra_excludes or entry.name in _VCS_DIRS or not in_package:
                        tree.limit_events.append(LimitEvent(kind="excluded_dir", path=rel, detail="not walked"))
                        if entry.name == ".git":
                            subdirs.append((Path(entry.path), rel, depth + 1, in_package, "top"))
                        continue
                subdirs.append((Path(entry.path), rel, depth + 1, in_package, ""))
                continue
            if git_pos == "top" and entry.name in _GIT_FILES:
                continue
            if git_pos == "hooks" and entry.name.endswith(".sample"):
                continue
            if not stat.S_ISREG(est.st_mode):
                tree.limit_events.append(LimitEvent(kind="special_file", path=rel))
                continue
            # Defence in depth: confirm the entry is still inside the root.
            try:
                resolved = Path(entry.path).resolve(strict=True)
            except OSError:
                continue
            if not resolved.is_relative_to(root):
                tree.limit_events.append(LimitEvent(kind="path_escape", path=rel))
                continue
            if est.st_size > limits.max_file_bytes:
                tree.limit_events.append(LimitEvent(kind="too_large", path=rel, detail=f"{est.st_size} bytes"))
                continue
            if len(tree.files) >= limits.max_files:
                tree.limit_events.append(LimitEvent(kind="too_many_files", path=rel))
                return tree
            try:
                data = _read_file(entry.path, limits.max_file_bytes)
            except OSError:
                tree.limit_events.append(LimitEvent(kind="unreadable", path=rel))
                continue
            if data is None:
                tree.limit_events.append(LimitEvent(kind="too_large", path=rel))
                continue
            tree.add(rel, data, limits)
        stack.extend(reversed(subdirs))
    return tree
