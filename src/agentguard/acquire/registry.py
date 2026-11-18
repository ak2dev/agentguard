"""MCP registry entries: ``mcp:<namespace>/<server>[@version]`` (PLAN §5.2).

The entry (``server.json``) is read from the official registry and scanned as
it is. The registry does not validate bundle hashes or scan what its entries
point at, so each package the entry names is then fetched and scanned too:
npm and PyPI packages, container images and MCPB bundles. Remote endpoints the
entry names get the read-only posture probe.
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
from typing import Any

from ..core.archive import ArchiveError, from_archive
from ..core.models import ImmutableRef, LimitEvent
from ..core.models.enums import SourceKind
from ..core.tree import ArtifactTree
from . import AcquireContext, AcquireError, Acquired
from .github import fetch, http_client
from .targets import Target, TargetError, parse_target

REGISTRY = "https://registry.modelcontextprotocol.io"
MAX_PACKAGES = 6
_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def _package_target(pkg: dict[str, Any]) -> tuple[str, Target | None, str]:
    """(label, target or None, why not) for one ``packages[]`` entry of a server.json."""
    kind = str(pkg.get("registryType") or pkg.get("registry_type") or pkg.get("registry_name") or "").lower()
    ident = str(pkg.get("identifier") or pkg.get("name") or "")
    version = str(pkg.get("version") or "")
    label = f"{kind}:{ident}" + (f"@{version}" if version else "")
    try:
        if kind == "npm":
            return label, parse_target(f"pkg:npm/{ident}" + (f"@{version}" if version else "")), ""
        if kind == "pypi":
            return label, parse_target(f"pkg:pypi/{ident}" + (f"@{version}" if version else "")), ""
        if kind in ("oci", "docker"):
            ref = ident if (":" in ident.rsplit("/", 1)[-1] or "@" in ident) or not version else f"{ident}:{version}"
            return label, parse_target(f"oci://{ref}"), ""
        if kind == "mcpb":
            return label, parse_target(ident), ""
    except TargetError as exc:
        return label, None, str(exc)
    return label, None, f"registry type {kind or '?'} is not fetched"


def acquire_registry_entry(target: Target, ctx: AcquireContext) -> Acquired:
    http = http_client(ctx)
    name, version = target.name, target.version or "latest"
    url = f"{REGISTRY}/v0/servers/{urllib.parse.quote(name, safe='')}/versions/{urllib.parse.quote(version, safe='')}"
    resp = fetch(http, url, {"Accept": "application/json"}, f"mcp:{name}")
    if resp.status == 404:
        raise AcquireError(f"mcp:{name}: no such server (or version {version}) in the registry")
    if resp.status != 200:
        raise AcquireError(f"mcp:{name}: the registry answered HTTP {resp.status}")
    try:
        doc = resp.json()
    except ValueError as exc:
        raise AcquireError(f"mcp:{name}: the registry sent something that is not JSON") from exc
    server = doc.get("server") if isinstance(doc, dict) and isinstance(doc.get("server"), dict) else doc
    if not isinstance(server, dict) or not server.get("name"):
        raise AcquireError(f"mcp:{name}: unexpected registry response")
    if str(server["name"]) != name:
        raise AcquireError(f"mcp:{name}: the registry answered with a different server ({str(server['name'])[:80]})")
    resolved = str(server.get("version") or version)
    body = (json.dumps(server, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    digest = hashlib.sha256(body).hexdigest()
    tree = ArtifactTree(source=ImmutableRef(kind=SourceKind.mcp_registry, locator=f"mcp:{name}@{resolved}", resolved=resolved,
                                            integrity=f"sha256-{digest}"), display_root=f"mcp:{name}@{resolved}")
    tree.add("server.json", body, ctx.limits)
    meta = (doc.get("_meta") or {}).get("io.modelcontextprotocol.registry/official") if isinstance(doc, dict) else None
    notes = [f"mcp:{name}: version {resolved}" + (f", registry status {meta.get('status')}" if isinstance(meta, dict) and meta.get("status") else "")
             + "; the registry does not scan what an entry points at, so each package it names is fetched and scanned here"]
    out = Acquired(target=target, tree=tree, notes=notes, hosts=["registry.modelcontextprotocol.io"])

    from . import acquire as acquire_any          # late import: the package module imports this one

    packages = [p for p in server.get("packages") or [] if isinstance(p, dict)]
    for i, pkg in enumerate(packages):
        label, sub, why = _package_target(pkg)
        prefix = f"packages/{_SAFE.sub('-', label).strip('-')[:80] or i}"
        if i >= MAX_PACKAGES:
            why, sub = f"more than {MAX_PACKAGES} packages; not fetched", None
        if sub is None:
            tree.limit_events.append(LimitEvent(kind="not_fetched", path=prefix, detail=why[:200]))
            continue
        try:
            if sub.kind == "url":
                got = _bundle(sub, pkg, ctx)
            else:
                got = acquire_any(sub, ctx)
        except (AcquireError, TargetError) as exc:
            tree.limit_events.append(LimitEvent(kind="not_fetched", path=prefix, detail=str(exc)[:200]))
            notes.append(f"{label}: not fetched ({str(exc)[:160]})")
            continue
        for path in sorted(got.tree.files):
            tree.add(f"{prefix}/{path}", got.tree.files[path].data, ctx.limits)
        for ev in got.tree.limit_events:
            tree.limit_events.append(LimitEvent(kind=ev.kind, path=f"{prefix}/{ev.path}", detail=ev.detail, bytes=ev.bytes))
        for key, value in got.facts.items():
            bucket = out.facts.setdefault(key, {})
            for k, v in value.items():
                if key == "images" and isinstance(v, dict) and isinstance(v.get("root"), str):
                    v = {**v, "root": f"{prefix}/{v['root']}"}
                bucket[k] = v
        out.notes += got.notes
        out.hosts += [h for h in got.hosts if h not in out.hosts]

    remotes = [r for r in server.get("remotes") or [] if isinstance(r, dict) and str(r.get("url", "")).startswith("https://")]
    if remotes and not ctx.offline:
        from ..net.remote import probe_server

        for r in remotes[:4]:
            probe = probe_server(http, str(server.get("title") or name), str(r["url"]), "server.json", metadata=False, auth=True)
            out.probes.append(probe)
            host = urllib.parse.urlsplit(str(r["url"])).hostname
            if host and host not in out.hosts:
                out.hosts.append(host)
        out.network.append("auth_checks")
        notes.append(f"mcp:{name}: {len(remotes[:4])} remote endpoint(s) probed read-only (no tool was listed or called)")
    return out


def _bundle(sub: Target, pkg: dict[str, Any], ctx: AcquireContext) -> Acquired:
    """An MCPB bundle named by a registry entry: downloaded, checked against the hash the entry records, unpacked."""
    resp = fetch(http_client(ctx, big=True), sub.url, None, sub.url)
    if resp.status != 200:
        raise AcquireError(f"the bundle download answered HTTP {resp.status}")
    digest = hashlib.sha256(resp.body).hexdigest()
    want = str(pkg.get("fileSha256") or pkg.get("file_sha256") or "").lower()
    tree = ArtifactTree()
    try:
        tree = from_archive(resp.body, None, ctx.limits)
    except ArchiveError as exc:
        raise AcquireError(f"the bundle could not be unpacked ({exc})") from exc
    notes = [f"{sub.url}: bundle sha256 {digest}"]
    facts: dict[str, dict] = {"artifact_sha256": {sub.url: digest}}
    if want and want != digest:
        tree.limit_events.append(LimitEvent(kind="hash_mismatch", path="(bundle)", detail=f"entry records {want[:16]}…, download is {digest[:16]}…"))
        notes.append(f"{sub.url}: the download does NOT match the hash in the registry entry")
    elif not want:
        notes.append(f"{sub.url}: the registry entry records no hash for this bundle")
    return Acquired(target=sub, tree=tree, notes=notes, hosts=[urllib.parse.urlsplit(sub.url).hostname or ""], facts=facts)
