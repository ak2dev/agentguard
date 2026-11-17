"""Target syntax (spec/interfaces.md §1). Pure parsing: nothing is fetched here.

| Target              | Form                                  |
|---------------------|---------------------------------------|
| Local path          | path                                  |
| GitHub repository   | https://github.com/o/r[@ref]          |
| Pull request        | https://github.com/o/r/pull/N         |
| Package             | pkg:npm/name@v, pkg:pypi/name@v       |
| Container image     | oci://registry/repo[:tag][@sha256:…]  |
| Bundle or archive   | path or URL (.zip .tgz .mcpb .dxt …)  |
| Registry entry      | mcp:namespace/server[@version]        |
| Live MCP server     | mcp+https://…, mcp+stdio:<command>    |
| Descriptor          | path or URL of an OpenAPI / A2A file  |
| This machine        | the --machine flag                    |
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field

ARCHIVE_SUFFIXES = (".zip", ".tar", ".tgz", ".tar.gz", ".mcpb", ".dxt", ".whl", ".skill", ".vsix", ".crate", ".nupkg")
_OWNER = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})"
_REPO = r"[A-Za-z0-9._-]{1,100}"
_GITHUB = re.compile(rf"^https?://(?:www\.)?github\.com/({_OWNER})/({_REPO}?)(?:\.git)?(?:/(.*?))?/?(?:@([^/@\s][^@\s]*))?$")
_SHA = re.compile(r"^[0-9a-f]{40}$")
_NPM = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$")
_PYPI = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_!-]{0,63}$")
_REGISTRY_NAME = re.compile(r"^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+/[A-Za-z0-9._-]+$")
_OCI = re.compile(r"^oci://((?:[a-z0-9.-]+(?::\d+)?/)?[a-z0-9._/-]+?)(?::([A-Za-z0-9._-]{1,128}))?(?:@(sha256:[0-9a-f]{64}))?$")
_REF = re.compile(r"^(?!-)[A-Za-z0-9._/~^+\-]{1,200}$")


class TargetError(ValueError):
    """The target is not one of the forms this tool accepts."""


@dataclass(frozen=True)
class Target:
    kind: str            # local | archive | github | pull_request | package | oci | registry | mcp_remote | mcp_stdio | url | machine
    raw: str
    # github / pull_request
    owner: str = ""
    repo: str = ""
    ref: str = ""        # branch, tag or commit; "" = default branch
    subpath: str = ""
    number: int = 0
    # package
    ecosystem: str = ""  # npm | pypi
    name: str = ""
    version: str = ""
    # oci
    image: str = ""
    tag: str = ""
    digest: str = ""
    # mcp / url
    url: str = ""
    command: tuple[str, ...] = field(default_factory=tuple)

    @property
    def remote(self) -> bool:
        return self.kind not in ("local", "archive", "machine", "mcp_stdio")

    @property
    def label(self) -> str:
        """A short name for the target, used as a path prefix when several are scanned together."""
        if self.kind in ("github", "pull_request"):
            return f"{self.owner}-{self.repo}" + (f"-pr{self.number}" if self.number else "")
        if self.kind == "package":
            return re.sub(r"[^A-Za-z0-9._-]+", "-", self.name).strip("-")
        if self.kind == "oci":
            return re.sub(r"[^A-Za-z0-9._-]+", "-", self.image).strip("-")
        if self.kind == "registry":
            return re.sub(r"[^A-Za-z0-9._-]+", "-", self.name).strip("-")
        if self.kind in ("mcp_remote", "url"):
            return re.sub(r"[^A-Za-z0-9._-]+", "-", urllib.parse.urlsplit(self.url).netloc).strip("-") or "remote"
        if self.kind == "mcp_stdio":
            return "stdio-server"
        if self.kind == "machine":
            return "machine"
        name = self.raw.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
        return re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-") or "target"


def _split_ref_path(rest: str) -> tuple[str, str]:
    """``tree/<ref>/<path>`` / ``blob/<ref>/<path>``: the first segment is taken
    as the ref (a ref with slashes must be given with ``@ref`` instead)."""
    parts = [p for p in rest.split("/") if p]
    if len(parts) >= 2 and parts[0] in ("tree", "blob"):
        return parts[1], "/".join(parts[2:])
    return "", ""


def _github(m: re.Match[str], raw: str) -> Target:
    owner, repo, rest, at_ref = m.group(1), m.group(2), m.group(3) or "", m.group(4) or ""
    if repo in (".", ".."):
        raise TargetError(f"not a GitHub repository: {raw}")
    pr = re.fullmatch(r"pull/(\d{1,9})(?:/.*)?", rest)
    if pr:
        return Target(kind="pull_request", raw=raw, owner=owner, repo=repo, number=int(pr.group(1)))
    ref, subpath = _split_ref_path(rest)
    if rest and not ref:
        raise TargetError(f"unsupported GitHub URL (use the repository URL, …/tree/<ref>/<path>, or …/pull/<n>): {raw}")
    ref = at_ref or ref
    if ref and not _REF.match(ref):
        raise TargetError(f"unusual git ref {ref!r}")
    if ".." in subpath.split("/"):
        raise TargetError("path escapes the repository")
    return Target(kind="github", raw=raw, owner=owner, repo=repo, ref=ref, subpath=subpath)


def _package(spec: str, raw: str) -> Target:
    # pkg:npm/@scope/name@1.2.3   pkg:pypi/name@0.9.0   (purl; %40 for a scope's @ is accepted)
    eco, _, rest = spec.partition("/")
    eco = eco.lower()
    rest = urllib.parse.unquote(rest)
    name, sep, version = rest.rpartition("@")
    if not sep or not name:           # no version, or only the scope's @
        name, version = rest, ""
    if eco not in ("npm", "pypi"):
        raise TargetError(f"unsupported package type {eco!r} (npm and pypi are supported)")
    if not (_NPM if eco == "npm" else _PYPI).match(name):
        raise TargetError(f"not a valid {eco} package name: {name!r}")
    if version and not _VERSION.match(version):
        raise TargetError(f"not a valid version: {version!r}")
    return Target(kind="package", raw=raw, ecosystem=eco, name=name, version=version)


def parse_target(raw: str) -> Target:
    text = raw.strip()
    if not text or len(text) > 2048 or any(ord(c) < 32 for c in text):
        raise TargetError("empty, over-long or malformed target")
    low = text.lower()
    if low.startswith("mcp+stdio:"):
        import shlex

        argv = tuple(shlex.split(text[len("mcp+stdio:"):], posix=True))
        if not argv:
            raise TargetError("mcp+stdio: needs a command")
        return Target(kind="mcp_stdio", raw=text, command=argv)
    if low.startswith(("mcp+https://", "mcp+http://")):
        url = text[4:]
        if not urllib.parse.urlsplit(url).netloc:
            raise TargetError(f"not a URL: {url}")
        return Target(kind="mcp_remote", raw=text, url=url)
    if low.startswith("mcp:"):
        name, _, version = text[4:].partition("@")
        if not _REGISTRY_NAME.match(name):
            raise TargetError(f"not a registry name (namespace/server): {name!r}")
        if version and not _VERSION.match(version):
            raise TargetError(f"not a valid version: {version!r}")
        return Target(kind="registry", raw=text, name=name, version=version)
    if low.startswith("pkg:"):
        return _package(text[4:], text)
    if low.startswith(("npm:", "pypi:")):
        eco, _, rest = text.partition(":")
        return _package(f"{eco}/{rest}", text)
    if low.startswith("oci://"):
        m = _OCI.match(text)
        if not m:
            raise TargetError(f"not an image reference: {text}")
        return Target(kind="oci", raw=text, image=m.group(1), tag=m.group(2) or "", digest=m.group(3) or "")
    if low.startswith(("https://", "http://")):
        m = _GITHUB.match(text)
        if m:
            return _github(m, text)
        if not urllib.parse.urlsplit(text).netloc:
            raise TargetError(f"not a URL: {text}")
        return Target(kind="url", raw=text, url=text)
    if re.match(r"^[a-z][a-z0-9+.-]*://", low):
        raise TargetError(f"unsupported target scheme: {text.split(':', 1)[0]}")
    return Target(kind="local", raw=text)


def is_archive_name(name: str) -> bool:
    return name.lower().endswith(ARCHIVE_SUFFIXES)


def is_sha(ref: str) -> bool:
    return bool(_SHA.match(ref))
