"""A target given as a plain URL: an archive or bundle, an OpenAPI action
descriptor, an A2A agent card, a ``server.json``, or a single agent-facing file.

The response is read once, hashed, and that hash is the immutable identifier
recorded in the report. An archive is unpacked in memory with the usual limits.
"""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
import urllib.parse

from ..core.archive import ArchiveError, from_archive, sniff_format
from ..core.models import ImmutableRef, LimitEvent
from ..core.models.enums import SourceKind
from ..core.tree import ArtifactTree
from . import AcquireContext, AcquireError, Acquired
from .github import fetch, http_client
from .targets import Target, is_archive_name

_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def name_for(url: str, body: bytes, content_type: str) -> str:
    """A file name the discovery step recognises, from the URL and, failing that, the content."""
    path = urllib.parse.urlsplit(url).path
    base = _SAFE.sub("-", posixpath.basename(path.rstrip("/"))).strip("-")
    if "/.well-known/agent" in path:
        return "agent-card.json"
    head = body[:4096].lstrip(b"\xef\xbb\xbf \t\r\n")
    looks_json = head[:1] in (b"{", b"[")
    if looks_json:
        try:
            doc = json.loads(body)
        except ValueError:
            doc = None
        if isinstance(doc, dict):
            if "openapi" in doc or "swagger" in doc:
                return base if re.match(r"(?i)(openapi|swagger)", base) else "openapi.json"
            if "skills" in doc and ("url" in doc or "capabilities" in doc or "protocolVersion" in doc):
                return "agent-card.json"
            if "schema_version" in doc and "api" in doc and "name_for_model" in doc:
                return "ai-plugin.json"
            if "mcpServers" in doc or "servers" in doc:
                return base if base.endswith(".json") else "mcp.json"
            if "packages" in doc or "remotes" in doc:
                return "server.json"
    if re.search(rb"(?m)^\s*(openapi|swagger)\s*:", head):
        return base if re.match(r"(?i)(openapi|swagger).*\.ya?ml$", base) else "openapi.yaml"
    if not base or "." not in base:
        ext = ".json" if looks_json or "json" in content_type else ".yaml" if "yaml" in content_type else \
            ".md" if "markdown" in content_type or head.startswith(b"---") or head.startswith(b"#") else ".txt"
        return (base or "download") + ext
    return base


def acquire_url(target: Target, ctx: AcquireContext) -> Acquired:
    url = target.url
    if urllib.parse.urlsplit(url).scheme != "https":
        raise AcquireError(f"{url}: only https:// URLs are fetched")
    resp = fetch(http_client(ctx, big=True), url, {"Accept": "*/*"}, url)
    if resp.status != 200:
        raise AcquireError(f"{url}: the server answered HTTP {resp.status}")
    body = resp.body
    digest = hashlib.sha256(body).hexdigest()
    final = resp.url or url
    hosts = sorted({urllib.parse.urlsplit(u).hostname or "" for u in (url, final, *getattr(resp, "redirects", []))} - {""})
    notes = [f"{url}: {len(body)} bytes, sha256 {digest}"]
    if final != url:
        notes.append(f"{url}: redirected to {final}")
    source = ImmutableRef(kind=SourceKind.raw_url, locator=url[:300], resolved=f"sha256:{digest}", integrity=f"sha256-{digest}")
    fmt = sniff_format(body[:512])
    base = posixpath.basename(urllib.parse.urlsplit(final).path)
    if fmt is not None and (fmt == "zip" or is_archive_name(base) or fmt in ("tgz", "tar")):
        try:
            tree = from_archive(body, fmt, ctx.limits, source=source)
            tree.display_root = url
            notes.append(f"{url}: unpacked in memory ({len(tree.files)} file(s)); nothing was written to disk")
            return Acquired(target=target, tree=tree, hosts=hosts, notes=notes)
        except ArchiveError as exc:
            notes.append(f"{url}: looks like an archive but could not be unpacked ({exc}); scanned as a single file")
    tree = ArtifactTree(source=source, display_root=url)
    name = name_for(final, body, (resp.header("content-type") or "").lower())
    if not tree.add(name, body, ctx.limits):
        tree.limit_events.append(LimitEvent(kind="too_large", path=name, detail=f"{len(body)} bytes", bytes=len(body)))
    return Acquired(target=target, tree=tree, hosts=hosts, notes=notes)
