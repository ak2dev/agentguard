"""GitHub repositories and pull requests (PLAN §5.2).

A ref is resolved to a commit first, and the tarball of that commit is read
through the API into memory. Nothing is cloned and git never runs, so no
repository-supplied configuration, hook or filter can execute. Submodules are
fetched at the commits they are pinned to (depth 3); branches, tags and history
are added on request (``--all-refs``, ``--history``).

The token, when one is set, is sent to api.github.com only: the HTTP client
drops credentials on a redirect to another host.
"""

from __future__ import annotations

import base64
import hashlib
import re
import urllib.parse
from typing import Any

from ..core.archive import ArchiveError, from_archive
from ..core.discover import surface_for
from ..core.models import ImmutableRef, LimitEvent
from ..core.models.enums import SourceKind
from ..core.tree import ArtifactTree
from . import AcquireContext, AcquireError, Acquired
from .gitread import parse_gitmodules
from .targets import Target

API = "https://api.github.com"
MAX_SUBMODULE_DEPTH = 3
MAX_REFS = 20
MAX_HISTORY = 300
MAX_PR_FILE_PAGES = 30
_SHA = re.compile(r"^[0-9a-f]{40}$")
_GH_URL = re.compile(r"^(?:https://github\.com/|git@github\.com:|ssh://git@github\.com/|git://github\.com/)([\w.-]+)/([\w.-]+?)(?:\.git)?/?$")


def http_client(ctx: AcquireContext, *, big: bool = False) -> Any:
    """The caller's client (tests pass a fake), or a hardened one sized for downloads."""
    if ctx.http is not None:
        return ctx.http
    from ..net.safe_http import SafeHttpClient

    if big:
        return SafeHttpClient(timeout=30, deadline_s=300, max_redirects=5, max_bytes=ctx.limits.max_total_bytes)
    return SafeHttpClient(timeout=15, deadline_s=60, max_bytes=16 * 1024 * 1024)


def fetch(http: Any, url: str, headers: dict[str, str] | None = None, what: str = "") -> Any:
    """GET with the failures turned into AcquireError."""
    from ..net.safe_http import BlockedRequest, FetchError

    try:
        return http.get(url, headers=headers or {})
    except BlockedRequest as exc:
        raise AcquireError(f"{what or url}: refused ({exc})") from exc
    except FetchError as exc:
        raise AcquireError(f"{what or url}: {exc}") from exc


class _GitHub:
    def __init__(self, ctx: AcquireContext) -> None:
        self.ctx = ctx
        self.api = http_client(ctx)
        self.big = http_client(ctx, big=True)
        self.hosts: list[str] = ["api.github.com", "codeload.github.com"]

    def headers(self) -> dict[str, str]:
        h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if self.ctx.github_token:
            h["Authorization"] = f"Bearer {self.ctx.github_token}"
        return h

    def json(self, path: str, what: str) -> Any:
        resp = fetch(self.api, f"{API}{path}", self.headers(), what)
        if resp.status == 404:
            raise AcquireError(f"{what}: not found. A private repository needs a token in $AGENTGUARD_GITHUB_TOKEN or $GITHUB_TOKEN")
        if resp.status in (403, 429):
            hint = "" if self.ctx.github_token else " Set $GITHUB_TOKEN (read-only scope) for a higher limit."
            raise AcquireError(f"{what}: GitHub refused the request (HTTP {resp.status}; usually the API rate limit).{hint}")
        if resp.status != 200:
            raise AcquireError(f"{what}: GitHub answered HTTP {resp.status}")
        try:
            return resp.json()
        except ValueError as exc:
            raise AcquireError(f"{what}: GitHub sent something that is not JSON") from exc

    def commit(self, owner: str, repo: str, ref: str) -> str:
        if _SHA.match(ref):
            return ref
        data = self.json(f"/repos/{owner}/{repo}/commits/{urllib.parse.quote(ref or 'HEAD', safe='')}", f"{owner}/{repo}@{ref or 'HEAD'}")
        sha = str(data.get("sha", "")) if isinstance(data, dict) else ""
        if not _SHA.match(sha):
            raise AcquireError(f"{owner}/{repo}@{ref or 'HEAD'}: could not resolve the ref to a commit")
        return sha

    def tree(self, owner: str, repo: str, sha: str, subpath: str = "") -> ArtifactTree:
        resp = fetch(self.big, f"{API}/repos/{owner}/{repo}/tarball/{sha}", self.headers(), f"{owner}/{repo}@{sha[:12]}")
        if resp.status != 200:
            raise AcquireError(f"{owner}/{repo}@{sha[:12]}: the tarball download answered HTTP {resp.status}")
        try:
            tree = from_archive(resp.body, "tgz", self.ctx.limits, strip_components=1)
        except ArchiveError as exc:
            raise AcquireError(f"{owner}/{repo}@{sha[:12]}: the tarball could not be read ({exc})") from exc
        if subpath:
            pre = subpath.strip("/") + "/"
            kept = {p[len(pre):]: b for p, b in tree.files.items() if p.startswith(pre)}
            if not kept:
                raise AcquireError(f"{owner}/{repo}: no files under {subpath!r} at {sha[:12]}")
            sub = ArtifactTree(limit_events=[ev for ev in tree.limit_events if ev.path.startswith(pre) or ev.path.startswith("(")])
            for p in sorted(kept):
                sub.add(p, kept[p].data, self.ctx.limits)
            tree = sub
        return tree

    # -- submodules -----------------------------------------------------------------------
    def submodules(self, tree: ArtifactTree, owner: str, repo: str, sha: str, notes: list[str], prefix: str = "", depth: int = 1) -> None:
        blob = tree.files.get(f"{prefix}.gitmodules")
        if blob is None:
            return
        for mod in parse_gitmodules(blob.data.decode("utf-8", "replace")):
            path, url = mod.get("path", "").strip("/"), mod.get("url", "")
            if not path or ".." in path.split("/"):
                continue
            vpath = f"{prefix}{path}"
            if depth > MAX_SUBMODULE_DEPTH:
                tree.limit_events.append(LimitEvent(kind="submodule", path=vpath, detail="not fetched: nested deeper than 3 levels"))
                continue
            m = _GH_URL.match(url)
            if url.startswith(("../", "./")):       # relative to the parent repository's URL
                stack: list[str] = [owner, repo]
                for part in url.split("/"):
                    if part == "..":
                        if stack:
                            stack.pop()
                    elif part not in ("", "."):
                        stack.append(part)
                m = _GH_URL.match("https://github.com/" + "/".join(stack)) if len(stack) == 2 else None
            if m is None:
                tree.limit_events.append(LimitEvent(kind="submodule", path=vpath, detail=f"not fetched: {url[:120] or 'no url'} is not on GitHub"))
                continue
            try:
                link = self.json(f"/repos/{owner}/{repo}/contents/{urllib.parse.quote(path)}?ref={sha}", f"submodule {vpath}")
                pinned = str(link.get("sha", "")) if isinstance(link, dict) and link.get("type") == "submodule" else ""
                if not _SHA.match(pinned):
                    raise AcquireError("no pinned commit")
                sub = self.tree(m.group(1), m.group(2), pinned)
            except AcquireError as exc:
                tree.limit_events.append(LimitEvent(kind="submodule", path=vpath, detail=f"not fetched: {str(exc)[:160]}"))
                continue
            for p in sorted(sub.files):
                tree.add(f"{vpath}/{p}", sub.files[p].data, self.ctx.limits)
            for ev in sub.limit_events:
                tree.limit_events.append(LimitEvent(kind=ev.kind, path=f"{vpath}/{ev.path}", detail=ev.detail, bytes=ev.bytes))
            notes.append(f"submodule {vpath}: {m.group(1)}/{m.group(2)} at {pinned[:12]}")
            self.submodules(tree, m.group(1), m.group(2), pinned, notes, prefix=f"{vpath}/", depth=depth + 1)

    # -- other refs and history ---------------------------------------------------------------
    def _agent_facing(self, path: str, data: bytes) -> bool:
        return surface_for(path, data[:8192]) is not None

    def all_refs(self, tree: ArtifactTree, owner: str, repo: str, head: str, notes: list[str]) -> None:
        refs: dict[str, str] = {}
        for kind in ("branches", "tags"):
            listing = self.json(f"/repos/{owner}/{repo}/{kind}?per_page=100", f"{owner}/{repo} {kind}")
            for item in listing if isinstance(listing, list) else []:
                sha = str((item.get("commit") or {}).get("sha", ""))
                if _SHA.match(sha) and sha != head and sha not in refs.values():
                    refs[f"{kind}/{item.get('name')}"] = sha
        names = sorted(refs)
        for name in names[:MAX_REFS]:
            other = self.tree(owner, repo, refs[name])
            added = 0
            for p in sorted(other.files):
                blob = other.files[p]
                same = tree.files.get(p)
                if (same is None or same.sha256 != blob.sha256) and self._agent_facing(p, blob.data):
                    added += tree.add(f"git-ref/{_label(name)}!/{p}", blob.data, self.ctx.limits)
            notes.append(f"ref {name} at {refs[name][:12]}: {added} agent-facing file(s) that differ from the scanned commit")
        if len(names) > MAX_REFS:
            tree.limit_events.append(LimitEvent(kind="not_fetched", path="git-ref", detail=f"{len(names) - MAX_REFS} more ref(s) were not read"))

    def history(self, tree: ArtifactTree, owner: str, repo: str, head: str, spec: str, notes: list[str]) -> None:
        want = MAX_HISTORY if spec == "all" else max(1, min(int(spec), MAX_HISTORY))
        seen = {_blob_sha(b.data) for b in tree.files.values()}
        commits: list[str] = []
        page = 1
        while len(commits) < want:
            got = self.json(f"/repos/{owner}/{repo}/commits?sha={head}&per_page=100&page={page}", f"{owner}/{repo} history")
            if not isinstance(got, list) or not got:
                break
            commits += [str(c.get("sha", "")) for c in got]
            page += 1
        added = 0
        for sha in commits[1:want]:           # the first is the scanned commit itself
            detail = self.json(f"/repos/{owner}/{repo}/commits/{sha}", f"{owner}/{repo}@{sha[:12]}")
            for f in detail.get("files") or [] if isinstance(detail, dict) else []:
                path, blob_sha = str(f.get("filename", "")), str(f.get("sha", ""))
                if not path or blob_sha in seen or f.get("status") == "removed" or not _SHA.match(blob_sha):
                    continue
                if surface_for(path) is None:
                    continue
                seen.add(blob_sha)
                blob = self.json(f"/repos/{owner}/{repo}/git/blobs/{blob_sha}", f"blob {blob_sha[:12]}")
                try:
                    data = base64.b64decode(blob.get("content", "")) if blob.get("encoding") == "base64" else b""
                except (ValueError, AttributeError):
                    data = b""
                if data:
                    added += tree.add(f"git-history/{sha[:12]}!/{path}", data, self.ctx.limits)
        if spec == "all" and len(commits) >= MAX_HISTORY:
            tree.limit_events.append(LimitEvent(kind="not_fetched", path="git-history", detail=f"history beyond {MAX_HISTORY} commits was not read"))
        notes.append(f"history: {min(len(commits), want)} commit(s) read, {added} earlier version(s) of agent-facing files added")


def _label(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-") or "ref"


def _blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data, usedforsecurity=False).hexdigest()


def _source(owner: str, repo: str, sha: str, subpath: str, locator: str) -> ImmutableRef:
    pre = f"{subpath.strip('/')}/" if subpath else ""
    return ImmutableRef(kind=SourceKind.github, locator=locator[:300], resolved=sha,
                        source_url_template=f"https://github.com/{owner}/{repo}/blob/{{resolved}}/{pre}{{path}}#L{{line}}")


def acquire_github(target: Target, ctx: AcquireContext) -> Acquired:
    gh = _GitHub(ctx)
    owner, repo = target.owner, target.repo
    notes: list[str] = []
    if target.kind == "pull_request":
        pr = gh.json(f"/repos/{owner}/{repo}/pulls/{target.number}", f"{owner}/{repo}#{target.number}")
        try:
            head_sha, base_sha = str(pr["head"]["sha"]), str(pr["base"]["sha"])
            head_repo = str((pr["head"].get("repo") or {}).get("full_name") or f"{owner}/{repo}")
        except (KeyError, TypeError) as exc:
            raise AcquireError(f"{owner}/{repo}#{target.number}: unexpected pull request data") from exc
        if not (_SHA.match(head_sha) and _SHA.match(base_sha)) or head_repo.count("/") != 1:
            raise AcquireError(f"{owner}/{repo}#{target.number}: unexpected pull request data")
        h_owner, h_repo = head_repo.split("/")
        tree = gh.tree(h_owner, h_repo, head_sha)
        base_tree = gh.tree(owner, repo, base_sha)
        changed: set[str] = set()
        for page in range(1, MAX_PR_FILE_PAGES + 1):
            files = gh.json(f"/repos/{owner}/{repo}/pulls/{target.number}/files?per_page=100&page={page}", "pull request files")
            if not isinstance(files, list) or not files:
                break
            for f in files:
                if isinstance(f, dict) and f.get("filename"):
                    changed.add(str(f["filename"]))
            if len(files) < 100:
                break
        if ctx.submodules:
            gh.submodules(tree, h_owner, h_repo, head_sha, notes)
        tree.source = _source(h_owner, h_repo, head_sha, "", target.raw)
        tree.display_root = target.raw
        notes.insert(0, f"pull request {owner}/{repo}#{target.number}: head {head_repo}@{head_sha[:12]}, base {base_sha[:12]}, "
                        f"{len(changed)} changed file(s)")
        return Acquired(target=target, tree=tree, changed_paths=changed, base_tree=base_tree, hosts=gh.hosts, notes=notes)

    ref = ctx.ref or target.ref
    sha = gh.commit(owner, repo, ref)
    tree = gh.tree(owner, repo, sha, target.subpath)
    if ctx.submodules and not target.subpath:
        gh.submodules(tree, owner, repo, sha, notes)
    if ctx.all_refs:
        gh.all_refs(tree, owner, repo, sha, notes)
    if ctx.history:
        if ctx.history != "all" and not ctx.history.isdigit():
            raise AcquireError("--history takes a number of commits, or 'all'")
        gh.history(tree, owner, repo, sha, ctx.history, notes)
    tree.source = _source(owner, repo, sha, target.subpath, target.raw)
    tree.display_root = target.raw
    notes.insert(0, f"{owner}/{repo}: {ref or 'default branch'} resolved to commit {sha}")
    return Acquired(target=target, tree=tree, hosts=gh.hosts, notes=notes)
