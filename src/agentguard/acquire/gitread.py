"""A read-only git object reader in pure Python.

Agent Guard reads repository history, refs and submodule pins through this
module so that no repository-supplied git configuration, hook, filter, alias
or external diff driver can ever run: the ``git`` binary is never invoked on a
scanned repository. Only the object database and the ref files are read.

Supported: loose objects, packfiles (index v2, OFS and REF deltas), packed
refs, annotated tags, worktree / submodule ``gitdir:`` files, alternates are
ignored. SHA-1 repositories only (SHA-256 repositories are reported as
unsupported rather than misread).
"""

from __future__ import annotations

import os
import re
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path

MAX_OBJECT = 64 * 1024 * 1024
MAX_DELTA_DEPTH = 64
MAX_TREE_ENTRIES = 200_000
_SHA = re.compile(r"^[0-9a-f]{40}$")
_HEX = re.compile(r"^[0-9a-f]{4,40}$")
_TYPES = {1: "commit", 2: "tree", 3: "blob", 4: "tag"}


class GitReadError(RuntimeError):
    pass


@dataclass(frozen=True)
class Commit:
    sha: str
    tree: str
    parents: tuple[str, ...]
    author: str = ""
    time: int = 0
    message: str = ""


@dataclass(frozen=True)
class TreeEntry:
    mode: int
    path: str
    sha: str

    @property
    def is_submodule(self) -> bool:
        return self.mode == 0o160000

    @property
    def is_symlink(self) -> bool:
        return self.mode == 0o120000


class _Pack:
    def __init__(self, idx: Path, pack: Path) -> None:
        self.idx_path, self.pack_path = idx, pack
        data = idx.read_bytes()
        if data[:8] != b"\xfftOc\x00\x00\x00\x02":
            raise GitReadError(f"unsupported pack index version: {idx.name}")
        self.fanout = struct.unpack(">256I", data[8:8 + 1024])
        n = self.fanout[255]
        base = 8 + 1024
        self.names = data[base:base + 20 * n]
        off32 = base + 20 * n + 4 * n
        self.off32 = data[off32:off32 + 4 * n]
        self.off64 = data[off32 + 4 * n:]
        self.count = n
        self._fh = None

    def find(self, sha: bytes) -> int | None:
        lo = self.fanout[sha[0] - 1] if sha[0] else 0
        hi = self.fanout[sha[0]]
        while lo < hi:
            mid = (lo + hi) // 2
            cur = self.names[20 * mid:20 * mid + 20]
            if cur == sha:
                off = struct.unpack(">I", self.off32[4 * mid:4 * mid + 4])[0]
                if off & 0x80000000:
                    i = off & 0x7FFFFFFF
                    return struct.unpack(">Q", self.off64[8 * i:8 * i + 8])[0]
                return off
            if cur < sha:
                lo = mid + 1
            else:
                hi = mid
        return None

    def prefix(self, hexpfx: str) -> list[str]:
        out = []
        first = int(hexpfx[:2], 16)
        lo = self.fanout[first - 1] if first else 0
        for i in range(lo, self.fanout[first]):
            name = self.names[20 * i:20 * i + 20].hex()
            if name.startswith(hexpfx):
                out.append(name)
        return out

    def read_at(self, offset: int, n: int) -> bytes:
        if self._fh is None:
            self._fh = open(self.pack_path, "rb")  # noqa: SIM115 - kept open for the life of the reader
        self._fh.seek(offset)
        return self._fh.read(n)

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None


def _inflate(read, offset: int, size: int) -> bytes:
    """Inflate one zlib stream that starts at ``offset`` and expands to ``size`` bytes."""
    if size > MAX_OBJECT:
        raise GitReadError("object larger than the read limit")
    d = zlib.decompressobj()
    out = bytearray()
    pos = offset
    while not d.eof:
        # 16 KiB of deflate expands to at most ~16 MiB, so one step stays bounded.
        chunk = read(pos, 16384)
        if not chunk:
            break
        pos += len(chunk)
        out += d.decompress(chunk)
        if len(out) > size:
            raise GitReadError("object larger than its header says")
    if len(out) != size:
        raise GitReadError("truncated object")
    return bytes(out)


def _apply_delta(base: bytes, delta: bytes) -> bytes:
    def varint(pos: int) -> tuple[int, int]:
        value = shift = 0
        while True:
            b = delta[pos]
            pos += 1
            value |= (b & 0x7F) << shift
            shift += 7
            if not b & 0x80:
                return value, pos

    src_size, pos = varint(0)
    dst_size, pos = varint(pos)
    if src_size != len(base) or dst_size > MAX_OBJECT:
        raise GitReadError("bad delta")
    out = bytearray()
    while pos < len(delta):
        op = delta[pos]
        pos += 1
        if op & 0x80:
            off = size = 0
            for i in range(4):
                if op & (1 << i):
                    off |= delta[pos] << (8 * i)
                    pos += 1
            for i in range(3):
                if op & (1 << (4 + i)):
                    size |= delta[pos] << (8 * i)
                    pos += 1
            size = size or 0x10000
            out += base[off:off + size]
        elif op:
            out += delta[pos:pos + op]
            pos += op
        else:
            raise GitReadError("bad delta opcode")
    if len(out) != dst_size:
        raise GitReadError("delta result has the wrong size")
    return bytes(out)


class Repo:
    """Read-only access to one repository's objects and refs."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.worktree = Path(path)
        self.gitdir = self._find_gitdir(self.worktree)
        self.common = self.gitdir
        cd = self.gitdir / "commondir"
        if cd.is_file():
            self.common = (self.gitdir / cd.read_text(encoding="utf-8").strip()).resolve()
        fmt = self._config_value("extensions", "objectformat")
        if fmt and fmt.lower() != "sha1":
            raise GitReadError(f"unsupported object format {fmt!r} (only SHA-1 repositories are read)")
        self._packs: list[_Pack] | None = None

    # -- layout ---------------------------------------------------------------
    @staticmethod
    def _find_gitdir(path: Path) -> Path:
        dot = path / ".git"
        if dot.is_dir():
            return dot
        if dot.is_file():
            text = dot.read_text(encoding="utf-8", errors="replace").strip()
            if text.startswith("gitdir:"):
                target = Path(text[7:].strip())
                return target if target.is_absolute() else (path / target).resolve()
        if (path / "objects").is_dir() and (path / "HEAD").is_file():
            return path      # a bare repository
        raise GitReadError(f"not a git repository: {path}")

    def _config_value(self, section: str, key: str) -> str | None:
        cfg = self.common / "config"
        if not cfg.is_file():
            return None
        current = ""
        for line in cfg.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line.startswith("["):
                current = line.strip("[]").split()[0].lower()
            elif current == section and "=" in line:
                k, _, v = line.partition("=")
                if k.strip().lower() == key:
                    return v.strip()
        return None

    def packs(self) -> list[_Pack]:
        if self._packs is None:
            self._packs = []
            pdir = self.common / "objects" / "pack"
            if pdir.is_dir():
                for idx in sorted(pdir.glob("*.idx")):
                    pack = idx.with_suffix(".pack")
                    if pack.is_file():
                        try:
                            self._packs.append(_Pack(idx, pack))
                        except (GitReadError, OSError, struct.error):
                            continue
        return self._packs

    def close(self) -> None:
        for p in self._packs or []:
            p.close()

    # -- objects --------------------------------------------------------------
    def read_object(self, sha: str, _depth: int = 0) -> tuple[str, bytes]:
        if not _SHA.match(sha):
            raise GitReadError(f"not an object id: {sha!r}")
        loose = self.common / "objects" / sha[:2] / sha[2:]
        if loose.is_file():
            if loose.stat().st_size > MAX_OBJECT:
                raise GitReadError("object larger than the read limit")
            d = zlib.decompressobj()
            raw = d.decompress(loose.read_bytes(), MAX_OBJECT + 64)
            head, _, body = raw.partition(b"\x00")
            kind, _, size = head.partition(b" ")
            if not size.isdigit() or int(size) != len(body):
                raise GitReadError(f"corrupt loose object {sha[:12]}")
            return kind.decode("ascii", "replace"), body
        raw_sha = bytes.fromhex(sha)
        for pack in self.packs():
            off = pack.find(raw_sha)
            if off is not None:
                return self._read_packed(pack, off, _depth)
        raise GitReadError(f"object {sha[:12]} not found")

    def _read_packed(self, pack: _Pack, offset: int, depth: int) -> tuple[str, bytes]:
        if depth > MAX_DELTA_DEPTH:
            raise GitReadError("delta chain too deep")
        head = pack.read_at(offset, 32)
        b = head[0]
        kind = (b >> 4) & 7
        size = b & 0x0F
        shift, i = 4, 1
        while b & 0x80:
            b = head[i]
            size |= (b & 0x7F) << shift
            shift += 7
            i += 1
        if kind in _TYPES:
            return _TYPES[kind], _inflate(pack.read_at, offset + i, size)
        if kind == 6:       # OFS_DELTA
            b = head[i]
            i += 1
            rel = b & 0x7F
            while b & 0x80:
                b = head[i]
                i += 1
                rel = ((rel + 1) << 7) | (b & 0x7F)
            base_kind, base = self._read_packed(pack, offset - rel, depth + 1)
            return base_kind, _apply_delta(base, _inflate(pack.read_at, offset + i, size))
        if kind == 7:       # REF_DELTA
            base_sha = head[i:i + 20].hex()
            base_kind, base = self.read_object(base_sha, depth + 1)
            return base_kind, _apply_delta(base, _inflate(pack.read_at, offset + i + 20, size))
        raise GitReadError(f"unknown packed object type {kind}")

    def commit(self, sha: str) -> Commit:
        kind, body = self.read_object(sha)
        while kind == "tag":         # peel annotated tags
            m = re.search(rb"^object ([0-9a-f]{40})$", body, re.M)
            if not m:
                raise GitReadError("tag without an object")
            sha = m.group(1).decode()
            kind, body = self.read_object(sha)
        if kind != "commit":
            raise GitReadError(f"{sha[:12]} is a {kind}, not a commit")
        head, _, message = body.partition(b"\n\n")
        tree, parents, author, when = "", [], "", 0
        for line in head.split(b"\n"):
            if line.startswith(b"tree "):
                tree = line[5:].decode()
            elif line.startswith(b"parent "):
                parents.append(line[7:].decode())
            elif line.startswith(b"author "):
                text = line[7:].decode("utf-8", "replace")
                m2 = re.search(r"^(.*) (\d+) [+-]\d{4}$", text)
                author, when = (m2.group(1), int(m2.group(2))) if m2 else (text, 0)
        return Commit(sha=sha, tree=tree, parents=tuple(parents), author=author, time=when,
                      message=message.decode("utf-8", "replace")[:2000])

    def tree(self, sha: str) -> list[TreeEntry]:
        kind, body = self.read_object(sha)
        if kind != "tree":
            raise GitReadError(f"{sha[:12]} is a {kind}, not a tree")
        out, pos = [], 0
        while pos < len(body):
            sp = body.index(b" ", pos)
            nul = body.index(b"\x00", sp)
            out.append(TreeEntry(mode=int(body[pos:sp], 8), path=body[sp + 1:nul].decode("utf-8", "replace"),
                                 sha=body[nul + 1:nul + 21].hex()))
            pos = nul + 21
        return out

    def walk(self, tree_sha: str, prefix: str = "") -> dict[str, TreeEntry]:
        """Every file under a tree: ``path -> entry`` (submodules and symlinks included, not followed)."""
        out: dict[str, TreeEntry] = {}
        stack = [(tree_sha, prefix)]
        while stack:
            sha, pre = stack.pop()
            for e in self.tree(sha):
                path = f"{pre}{e.path}"
                if e.mode == 0o40000:
                    stack.append((e.sha, path + "/"))
                else:
                    out[path] = TreeEntry(mode=e.mode, path=path, sha=e.sha)
                if len(out) > MAX_TREE_ENTRIES:
                    raise GitReadError("tree has too many entries")
        return out

    def blob(self, sha: str, max_bytes: int = MAX_OBJECT) -> bytes | None:
        kind, body = self.read_object(sha)
        if kind != "blob":
            raise GitReadError(f"{sha[:12]} is a {kind}, not a blob")
        return body if len(body) <= max_bytes else None

    # -- refs -----------------------------------------------------------------
    def refs(self) -> dict[str, str]:
        """Every ref: ``refs/heads/main -> sha`` (loose refs win over packed ones)."""
        out: dict[str, str] = {}
        packed = self.common / "packed-refs"
        if packed.is_file():
            for line in packed.read_text(encoding="utf-8", errors="replace").splitlines():
                if line and line[0] not in "#^" and " " in line:
                    sha, _, name = line.partition(" ")
                    if _SHA.match(sha):
                        out[name.strip()] = sha
        base = self.common / "refs"
        if base.is_dir():
            for root, _dirs, names in os.walk(base):
                for name in names:
                    p = Path(root) / name
                    try:
                        text = p.read_text(encoding="utf-8", errors="replace").strip()
                    except OSError:
                        continue
                    if _SHA.match(text):
                        out["refs/" + p.relative_to(base).as_posix()] = text
        return dict(sorted(out.items()))

    def head(self) -> tuple[str | None, str | None]:
        """(``refs/heads/<branch>`` or None when detached, commit sha or None for an unborn branch)."""
        text = (self.gitdir / "HEAD").read_text(encoding="utf-8", errors="replace").strip()
        if text.startswith("ref:"):
            name = text[4:].strip()
            return name, self.refs().get(name)
        return None, text if _SHA.match(text) else None

    def resolve(self, rev: str) -> str:
        """A commit id for ``HEAD``, a branch, a tag, a remote branch, a full or
        abbreviated id, optionally followed by ``~n`` / ``^``."""
        m = re.fullmatch(r"(.+?)((?:~\d*|\^)*)", rev.strip())
        if not m:
            raise GitReadError(f"cannot read revision {rev!r}")
        name, suffix = m.group(1), m.group(2)
        sha = self._resolve_name(name)
        sha = self.commit(sha).sha
        for step in re.findall(r"~\d*|\^", suffix):
            n = 1 if step in ("^", "~") else int(step[1:])
            for _ in range(n):
                parents = self.commit(sha).parents
                if not parents:
                    raise GitReadError(f"{rev!r} goes past the first commit")
                sha = parents[0]
        return sha

    def _resolve_name(self, name: str) -> str:
        if name == "HEAD":
            _, sha = self.head()
            if sha is None:
                raise GitReadError("HEAD has no commit yet")
            return sha
        refs = self.refs()
        for cand in (name, f"refs/{name}", f"refs/heads/{name}", f"refs/tags/{name}", f"refs/remotes/{name}",
                     f"refs/remotes/origin/{name}"):
            if cand in refs:
                return refs[cand]
        if _SHA.match(name):
            return name
        if _HEX.match(name):
            found = set()
            d = self.common / "objects" / name[:2]
            if d.is_dir():
                found |= {name[:2] + f.name for f in d.iterdir() if f.name.startswith(name[2:]) and len(f.name) == 38}
            for pack in self.packs():
                found |= set(pack.prefix(name))
            if len(found) == 1:
                return found.pop()
            if len(found) > 1:
                raise GitReadError(f"{name!r} is ambiguous")
        raise GitReadError(f"unknown revision {name!r}")

    # -- history --------------------------------------------------------------
    def ancestors(self, sha: str, limit: int = 100_000) -> list[str]:
        """Commits reachable from ``sha``, newest first by commit time."""
        import heapq

        seen = {sha}
        heap = [(-self.commit(sha).time, sha)]
        out = []
        while heap and len(out) < limit:
            _, cur = heapq.heappop(heap)
            out.append(cur)
            for p in self.commit(cur).parents:
                if p not in seen:
                    seen.add(p)
                    try:
                        heapq.heappush(heap, (-self.commit(p).time, p))
                    except GitReadError:
                        continue       # shallow clone: history ends here
        return out

    def merge_base(self, a: str, b: str, limit: int = 20_000) -> str | None:
        mine = set(self.ancestors(a, limit))
        for sha in self.ancestors(b, limit):
            if sha in mine:
                return sha
        return None

    def changed_paths(self, base: str, head: str) -> list[str]:
        """Paths that differ between two commits (added, removed or modified)."""
        a = self.walk(self.commit(base).tree)
        b = self.walk(self.commit(head).tree)
        return sorted(p for p in a.keys() | b.keys() if (a.get(p) and a[p].sha, a.get(p) and a[p].mode)
                      != (b.get(p) and b[p].sha, b.get(p) and b[p].mode))

    def submodules(self, commit_sha: str) -> list[dict[str, str]]:
        """``.gitmodules`` entries at a commit, each with the commit it is pinned to (the gitlink)."""
        files = self.walk(self.commit(commit_sha).tree)
        entry = files.get(".gitmodules")
        if entry is None:
            return []
        text = (self.blob(entry.sha, 1 << 20) or b"").decode("utf-8", "replace")
        out = []
        for mod in parse_gitmodules(text):
            link = files.get(mod.get("path", ""))
            mod["commit"] = link.sha if link is not None and link.is_submodule else ""
            out.append(mod)
        return out


def parse_gitmodules(text: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    cur: dict[str, str] | None = None
    for raw in text.splitlines():
        line = raw.strip()
        m = re.match(r'^\[submodule\s+"(.*)"\]$', line)
        if m:
            cur = {"name": m.group(1)}
            out.append(cur)
        elif cur is not None and "=" in line and not line.startswith(("#", ";")):
            k, _, v = line.partition("=")
            cur[k.strip().lower()] = v.strip()
    return out


def is_repo(path: str | os.PathLike[str]) -> bool:
    try:
        Repo(path)
        return True
    except (GitReadError, OSError):
        return False
