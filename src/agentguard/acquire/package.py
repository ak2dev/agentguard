"""npm and PyPI packages (PLAN §5.2).

The published archive is downloaded, checked against the hash the registry
records for it, and unpacked in memory. Lifecycle scripts never run and
nothing is installed. The published files are then compared with the source
repository at the commit the release names, because a package can ship files
its repository never held (AG-SUPPLY-016).
"""

from __future__ import annotations

import base64
import hashlib
import re
import urllib.parse
from typing import Any

from ..core.archive import ArchiveError, from_archive
from ..core.models import ImmutableRef, LimitEvent
from ..core.models.enums import SourceKind
from ..core.tree import ArtifactTree
from . import AcquireContext, AcquireError, Acquired
from .github import _GH_URL, _GitHub, fetch, http_client
from .targets import Target

NPM = "https://registry.npmjs.org"
PYPI = "https://pypi.org/pypi"
_REPO_URL = re.compile(r"github\.com[/:]([\w.-]+)/([\w.-]+?)(?:\.git)?(?:[/#?].*)?$")
# Build output and generated files a package legitimately has and its repository does not.
_GENERATED = re.compile(r"(?:^|/)(?:dist|build|lib|out|esm|cjs|umd|types|node_modules|__pycache__|[\w.-]+\.egg-info|[\w.-]+\.dist-info)/"
                        r"|\.(?:map|min\.js|min\.css|d\.ts|d\.mts|d\.cts|pyc|tsbuildinfo)$|(?:^|/)(?:PKG-INFO|RECORD|WHEEL|METADATA|setup\.cfg)$")
_COMPARED = re.compile(r"\.(?:md|mdc|markdown|txt|sh|bash|zsh|ps1|bat|cmd|py|js|mjs|cjs|ts|json|ya?ml|toml)$", re.I)
_NEVER_COMPARED = frozenset({"package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"})


def _json(http: Any, url: str, what: str) -> Any:
    resp = fetch(http, url, {"Accept": "application/json"}, what)
    if resp.status == 404:
        raise AcquireError(f"{what}: not found in the registry")
    if resp.status != 200:
        raise AcquireError(f"{what}: the registry answered HTTP {resp.status}")
    try:
        return resp.json()
    except ValueError as exc:
        raise AcquireError(f"{what}: the registry sent something that is not JSON") from exc


def _download(http: Any, url: str, what: str, hosts: tuple[str, ...]) -> bytes:
    host = (urllib.parse.urlsplit(url).hostname or "").lower()
    if urllib.parse.urlsplit(url).scheme != "https" or not any(host == h or host.endswith("." + h) for h in hosts):
        raise AcquireError(f"{what}: the registry points at an unexpected download host ({host or url[:60]})")
    resp = fetch(http, url, None, what)
    if resp.status != 200:
        raise AcquireError(f"{what}: the download answered HTTP {resp.status}")
    return resp.body


def source_diff(pkg: ArtifactTree, repo: ArtifactTree, subdir: str = "") -> dict[str, Any]:
    """Files of a published package that its source repository does not hold, or holds with other
    content. Build output is expected to differ and is left out; so are manifests the registry rewrites."""
    pre = subdir.strip("/") + "/" if subdir.strip("/") else ""
    by_path = {p[len(pre):]: b for p, b in repo.files.items() if p.startswith(pre)}
    only, changed = [], []
    for path in sorted(pkg.files):
        base = path.rsplit("/", 1)[-1]
        if "!/" in path or base in _NEVER_COMPARED or _GENERATED.search(path) or not _COMPARED.search(path):
            continue
        theirs = by_path.get(path)
        if theirs is None:
            only.append(path)
        elif theirs.sha256 != pkg.files[path].sha256 and \
                theirs.data.replace(b"\r\n", b"\n").strip() != pkg.files[path].data.replace(b"\r\n", b"\n").strip():
            changed.append(path)
    return {"only_in_package": only, "changed": changed}


def _compare(ctx: AcquireContext, pkg: ArtifactTree, repo_url: str, refs: list[str], subdir: str, notes: list[str],
             label: str) -> dict[str, Any] | None:
    m = _REPO_URL.search(repo_url or "")
    if m is None or not ctx.compare_source:
        if ctx.compare_source:
            notes.append(f"{label}: no GitHub source repository is named, so the package was not compared with its source")
        return None
    gh = _GitHub(ctx)
    for ref in refs:
        if not ref:
            continue
        try:
            sha = gh.commit(m.group(1), m.group(2), ref)
            repo = gh.tree(m.group(1), m.group(2), sha)
        except AcquireError:
            continue
        diff = source_diff(pkg, repo, subdir)
        diff["ref"] = f"{m.group(1)}/{m.group(2)}@{sha[:12]}"
        notes.append(f"{label}: compared with {diff['ref']}: {len(diff['only_in_package'])} file(s) only in the package, "
                     f"{len(diff['changed'])} changed")
        return diff
    notes.append(f"{label}: no commit or tag of {m.group(1)}/{m.group(2)} matches this release, so it was not compared with its source")
    return None


def _npm(target: Target, ctx: AcquireContext) -> Acquired:
    http, big = http_client(ctx), http_client(ctx, big=True)
    name = target.name
    label = f"pkg:npm/{name}"
    doc = _json(http, f"{NPM}/{urllib.parse.quote(name, safe='@')}/{urllib.parse.quote(target.version or 'latest', safe='')}", label)
    version, dist = str(doc.get("version", "")), doc.get("dist") or {}
    tarball = str(dist.get("tarball", ""))
    if not version or not tarball:
        raise AcquireError(f"{label}: the registry entry names no version or tarball")
    data = _download(big, tarball, label, ("registry.npmjs.org",))
    integrity = str(dist.get("integrity", ""))
    if integrity.startswith("sha512-"):
        if base64.b64encode(hashlib.sha512(data).digest()).decode() != integrity[7:]:
            raise AcquireError(f"{label}@{version}: the tarball does not match the integrity hash the registry records")
    elif dist.get("shasum"):
        if hashlib.sha1(data, usedforsecurity=False).hexdigest() != str(dist["shasum"]):
            raise AcquireError(f"{label}@{version}: the tarball does not match the checksum the registry records")
        integrity = f"sha1-{dist['shasum']}"
    else:
        raise AcquireError(f"{label}@{version}: the registry records no hash for the tarball")
    try:
        tree = from_archive(data, "tgz", ctx.limits, strip_components=1)
    except ArchiveError as exc:
        raise AcquireError(f"{label}@{version}: the tarball could not be read ({exc})") from exc
    tree.source = ImmutableRef(kind=SourceKind.npm, locator=f"{label}@{version}", resolved=version, integrity=integrity)
    tree.display_root = f"{label}@{version}"
    notes = [f"{label}: version {version}, {integrity[:24]}…, {len(tree.files)} file(s); lifecycle scripts were not run"]
    repo = doc.get("repository")
    repo_url = repo.get("url", "") if isinstance(repo, dict) else (repo if isinstance(repo, str) else "")
    subdir = repo.get("directory", "") if isinstance(repo, dict) else ""
    fact: dict[str, Any] = {"version": version, "integrity": integrity, "repository": str(repo_url)[:300]}
    diff = _compare(ctx, tree, str(repo_url), [str(doc.get("gitHead") or ""), f"v{version}", version], str(subdir), notes, label)
    if diff is not None:
        fact["source_diff"] = diff
    return Acquired(target=target, tree=tree, notes=notes, hosts=["registry.npmjs.org"], facts={"packages": {f"npm/{name}": fact}})


def _pypi(target: Target, ctx: AcquireContext) -> Acquired:
    http, big = http_client(ctx), http_client(ctx, big=True)
    name = target.name
    label = f"pkg:pypi/{name}"
    quoted = urllib.parse.quote(name, safe="")
    doc = _json(http, f"{PYPI}/{quoted}/{urllib.parse.quote(target.version, safe='')}/json" if target.version else f"{PYPI}/{quoted}/json", label)
    info = doc.get("info") or {}
    version = str(info.get("version", ""))
    files = [f for f in doc.get("urls") or [] if isinstance(f, dict) and f.get("url") and (f.get("digests") or {}).get("sha256")]
    if not version or not files:
        raise AcquireError(f"{label}: the registry lists no files for this release")
    wheels = sorted((f for f in files if f.get("packagetype") == "bdist_wheel"),
                    key=lambda f: (not str(f.get("filename", "")).endswith("none-any.whl"), str(f.get("filename", ""))))
    sdists = [f for f in files if f.get("packagetype") == "sdist"]
    primary = wheels[0] if wheels else sdists[0] if sdists else files[0]

    def load(f: dict[str, Any]) -> tuple[ArtifactTree, str]:
        data = _download(big, str(f["url"]), label, ("files.pythonhosted.org", "pypi.org"))
        digest = hashlib.sha256(data).hexdigest()
        if digest != str(f["digests"]["sha256"]).lower():
            raise AcquireError(f"{label}@{version}: {f.get('filename')} does not match the hash the registry records")
        try:
            return from_archive(data, None, ctx.limits, strip_components=0 if f.get("packagetype") == "bdist_wheel" else 1), digest
        except ArchiveError as exc:
            raise AcquireError(f"{label}@{version}: {f.get('filename')} could not be read ({exc})") from exc

    tree, digest = load(primary)
    comparable: ArtifactTree | None = tree if primary in sdists else None
    notes = [f"{label}: version {version}, {primary.get('filename')} sha256 {digest[:16]}…, {len(tree.files)} file(s); "
             "nothing was installed and no setup script was run"]
    if primary in wheels and sdists:
        # pip installs the wheel, but the source distribution is published too and is what is built when no wheel fits.
        try:
            sdist, _ = load(sdists[0])
            comparable = sdist
            for p in sorted(sdist.files):
                tree.add(f"sdist!/{p}", sdist.files[p].data, ctx.limits)
            for ev in sdist.limit_events:
                tree.limit_events.append(LimitEvent(kind=ev.kind, path=f"sdist!/{ev.path}", detail=ev.detail, bytes=ev.bytes))
            notes.append(f"{label}: the source distribution {sdists[0].get('filename')} was read as well")
        except AcquireError as exc:
            tree.limit_events.append(LimitEvent(kind="not_fetched", path="sdist", detail=str(exc)[:200]))
    tree.source = ImmutableRef(kind=SourceKind.pypi, locator=f"{label}@{version}", resolved=version, integrity=f"sha256-{digest}")
    tree.display_root = f"{label}@{version}"
    urls = info.get("project_urls") or {}
    repo_url = next((str(v) for k, v in sorted(urls.items()) if isinstance(v, str) and _REPO_URL.search(v)
                     and k.lower() in ("source", "source code", "repository", "homepage", "code", "github")), "")
    if not repo_url and isinstance(info.get("home_page"), str) and _REPO_URL.search(info["home_page"]):
        repo_url = info["home_page"]
    fact: dict[str, Any] = {"version": version, "integrity": f"sha256-{digest}", "repository": repo_url[:300]}
    if comparable is not None:
        diff = _compare(ctx, comparable, repo_url, [f"v{version}", version], "", notes, label)
        if diff is not None:
            fact["source_diff"] = diff
    elif ctx.compare_source:
        notes.append(f"{label}: only a wheel is published (built output), so the release was not compared with its source")
    return Acquired(target=target, tree=tree, notes=notes, hosts=["pypi.org", "files.pythonhosted.org"],
                    facts={"packages": {f"pypi/{name}": fact}})


def acquire_package(target: Target, ctx: AcquireContext) -> Acquired:
    if target.ecosystem == "npm":
        return _npm(target, ctx)
    if target.ecosystem == "pypi":
        return _pypi(target, ctx)
    raise AcquireError(f"unsupported package type {target.ecosystem!r}")


__all__ = ["acquire_package", "source_diff", "_GH_URL"]
