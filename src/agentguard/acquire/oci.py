"""Container images (PLAN §5.2, engine H): manifest, configuration and layers
are read through the registry API by digest. No Docker daemon is involved and
nothing in the image runs.

What the host records for the image rules (``ScanOptions.facts["images"][ref]``):
the user the image runs as, its entry point and command, labels, build history,
whether a signature, build provenance and an SBOM are published with it, and
(with ``--osv``) known vulnerabilities of the Python and npm packages inside.

A published signature is reported as present; verifying it against an expected
signer identity is not done here.
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
from .targets import Target

ROOT = "rootfs"
LAUNCH_FILE = "image.mcp.json"
_ACCEPT = ", ".join((
    "application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json",
))
_INDEX_TYPES = ("application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json")
_SIG_TYPES = ("application/vnd.dev.cosign.artifact.sig.v1+json", "application/vnd.dev.sigstore.bundle", "application/vnd.cncf.notary.signature")
_CHALLENGE = re.compile(r'(\w+)="([^"]*)"')
_NORMAL_IN_A_ROOTFS = ("symlink", "hardlink", "special_file", "windows_hazard")
MAX_OSV_PACKAGES = 400


def split_image(image: str) -> tuple[str, str]:
    """(registry host, repository) for an image name, with Docker Hub's defaults."""
    first, sep, rest = image.partition("/")
    if sep and ("." in first or ":" in first or first == "localhost"):
        registry, repo = first, rest
    else:
        registry, repo = "registry-1.docker.io", image if "/" in image else f"library/{image}"
    if registry in ("docker.io", "index.docker.io"):
        registry = "registry-1.docker.io"
        repo = repo if "/" in repo else f"library/{repo}"
    return registry, repo


class _Registry:
    def __init__(self, ctx: AcquireContext, registry: str, repo: str) -> None:
        self.ctx, self.registry, self.repo = ctx, registry, repo
        self.http = http_client(ctx)
        self.big = http_client(ctx, big=True)
        self.token: str | None = None
        self.hosts = [registry]

    def _get(self, http: Any, path: str, accept: str, what: str) -> Any:
        url = f"https://{self.registry}/v2/{self.repo}/{path}"
        headers = {"Accept": accept}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        resp = fetch(http, url, headers, what)
        if resp.status == 401 and self.token is None:
            challenge = resp.header("www-authenticate") or ""
            params = dict(_CHALLENGE.findall(challenge))
            realm = params.get("realm", "")
            if not challenge.lower().startswith("bearer") or not realm.startswith("https://"):
                raise AcquireError(f"{what}: the registry requires credentials this tool does not have")
            query = {"service": params.get("service", ""), "scope": params.get("scope") or f"repository:{self.repo}:pull"}
            tok = fetch(self.http, f"{realm}?{urllib.parse.urlencode({k: v for k, v in query.items() if v})}", None, "registry token")
            try:
                data = tok.json() if tok.status == 200 else {}
            except ValueError:
                data = {}
            self.token = str(data.get("token") or data.get("access_token") or "")
            if not self.token:
                raise AcquireError(f"{what}: the registry did not issue an anonymous pull token (a private image needs credentials)")
            host = urllib.parse.urlsplit(realm).hostname
            if host and host not in self.hosts:
                self.hosts.append(host)
            headers["Authorization"] = f"Bearer {self.token}"
            resp = fetch(http, url, headers, what)
        return resp

    def manifest(self, ref: str, what: str, accept: str = _ACCEPT) -> tuple[dict[str, Any], str, int]:
        resp = self._get(self.http, f"manifests/{ref}", accept, what)
        if resp.status != 200:
            return {}, "", resp.status
        digest = "sha256:" + hashlib.sha256(resp.body).hexdigest()
        if ref.startswith("sha256:") and ref != digest:
            raise AcquireError(f"{what}: the registry returned content that does not match {ref[:19]}…")
        try:
            doc = json.loads(resp.body)
        except ValueError as exc:
            raise AcquireError(f"{what}: the manifest is not JSON") from exc
        return (doc if isinstance(doc, dict) else {}), digest, 200

    def blob(self, digest: str, what: str, limit: int) -> bytes | None:
        resp = self._get(self.big, f"blobs/{digest}", "application/octet-stream", what)
        if resp.status != 200:
            raise AcquireError(f"{what}: the registry answered HTTP {resp.status}")
        if len(resp.body) > limit:
            return None
        if digest.startswith("sha256:") and hashlib.sha256(resp.body).hexdigest() != digest[7:]:
            raise AcquireError(f"{what}: the layer does not match its digest")
        return resp.body


def _apply_layer(root: dict[str, bytes], removed: dict[str, bytes], layer: ArtifactTree, index: int) -> None:
    """Overlay one layer: whiteout entries delete what earlier layers added. Deleted files are kept
    aside so secrets removed by a later layer are still scanned."""
    for path in sorted(layer.files):
        base = path.rsplit("/", 1)[-1]
        parent = path[: -len(base)]
        if base == ".wh..wh..opq":
            for p in [p for p in root if p.startswith(parent)]:
                removed[f"layer-{index - 1}-removed!/{p}"] = root.pop(p)
        elif base.startswith(".wh."):
            gone = parent + base[4:]
            for p in [p for p in root if p == gone or p.startswith(gone + "/")]:
                removed[f"layer-{index - 1}-removed!/{p}"] = root.pop(p)
    for path in sorted(layer.files):
        if not path.rsplit("/", 1)[-1].startswith(".wh."):
            root[path] = layer.files[path].data


def _packages(root: dict[str, bytes]) -> list[tuple[str, str, str]]:
    """(ecosystem, name, version) of the Python and npm packages installed in the image."""
    out: set[tuple[str, str, str]] = set()
    for path, data in root.items():
        if path.endswith(".dist-info/METADATA") or path.endswith(".egg-info/PKG-INFO"):
            head = data[:4096].decode("utf-8", "replace")
            name, ver = re.search(r"(?m)^Name:\s*(\S+)", head), re.search(r"(?m)^Version:\s*(\S+)", head)
            if name and ver:
                out.add(("PyPI", name.group(1), ver.group(1)))
        elif path.endswith("/package.json") and "/node_modules/" in "/" + path and path.count("/node_modules/") <= 2:
            try:
                doc = json.loads(data)
            except ValueError:
                continue
            if isinstance(doc, dict) and isinstance(doc.get("name"), str) and isinstance(doc.get("version"), str):
                out.add(("npm", doc["name"], doc["version"]))
    return sorted(out)


def _osv(http: Any, packages: list[tuple[str, str, str]]) -> list[dict[str, Any]]:
    from ..net.safe_http import BlockedRequest, FetchError

    packages = packages[:MAX_OSV_PACKAGES]
    if not packages:
        return []
    queries = [{"package": {"name": n, "ecosystem": e}, "version": v} for e, n, v in packages]
    try:
        res = http.post_json("https://api.osv.dev/v1/querybatch", {"queries": queries}).json()
    except (BlockedRequest, FetchError, ValueError, AttributeError):
        return []
    out: list[dict[str, Any]] = []
    for (_eco, name, ver), r in zip(packages, res.get("results", []), strict=False):
        for v in (r or {}).get("vulns", [])[:5]:
            vid = str(v.get("id", ""))
            entry: dict[str, Any] = {"id": vid, "package": f"{name}@{ver}", "severity": "unknown", "fixed": ""}
            if len(out) < 40:
                try:
                    detail = http.get(f"https://api.osv.dev/v1/vulns/{urllib.parse.quote(vid)}").json()
                    sev = (detail.get("database_specific") or {}).get("severity")
                    if isinstance(sev, str):
                        entry["severity"] = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium",
                                             "LOW": "low"}.get(sev.upper(), "unknown")
                    for aff in detail.get("affected") or []:
                        for rng in aff.get("ranges") or []:
                            for ev in rng.get("events") or []:
                                if ev.get("fixed"):
                                    entry["fixed"] = str(ev["fixed"])
                except (BlockedRequest, FetchError, ValueError, AttributeError):
                    pass
            out.append(entry)
    return out


def acquire_image(target: Target, ctx: AcquireContext) -> Acquired:
    registry, repo = split_image(target.image)
    reg = _Registry(ctx, registry, repo)
    shown = target.raw[len("oci://"):]
    ref = target.digest or target.tag or "latest"
    doc, digest, status = reg.manifest(ref, shown)
    if status != 200:
        raise AcquireError(f"{shown}: the registry answered HTTP {status} for the manifest" +
                           (" (not found, or a private image)" if status in (401, 403, 404) else ""))
    index_digest = digest
    provenance = sbom = False
    notes: list[str] = []
    if doc.get("mediaType") in _INDEX_TYPES or isinstance(doc.get("manifests"), list):
        entries = [m for m in doc.get("manifests") or [] if isinstance(m, dict) and m.get("digest")]
        attest = [m for m in entries if (m.get("annotations") or {}).get("vnd.docker.reference.type") == "attestation-manifest"]
        images = [m for m in entries if m not in attest]
        pick = next((m for m in images if (m.get("platform") or {}).get("os") == "linux"
                     and (m.get("platform") or {}).get("architecture") == "amd64"), images[0] if images else None)
        if pick is None:
            raise AcquireError(f"{shown}: the image index lists no image")
        for m in attest[:4]:
            adoc, _, st = reg.manifest(str(m["digest"]), "attestation")
            for layer in adoc.get("layers") or [] if st == 200 else []:
                kind = str((layer.get("annotations") or {}).get("in-toto.io/predicate-type", ""))
                provenance = provenance or "slsa.dev/provenance" in kind
                sbom = sbom or "spdx" in kind or "cyclonedx" in kind
        plat = pick.get("platform") or {}
        notes.append(f"{shown}: multi-platform image; read {plat.get('os', '?')}/{plat.get('architecture', '?')}")
        doc, digest, status = reg.manifest(str(pick["digest"]), shown)
        if status != 200:
            raise AcquireError(f"{shown}: the registry answered HTTP {status} for the platform manifest")
    config_desc, layers = doc.get("config") or {}, [x for x in doc.get("layers") or [] if isinstance(x, dict)]
    if not config_desc.get("digest") or not layers:
        raise AcquireError(f"{shown}: not a container image manifest")
    cfg_bytes = reg.blob(str(config_desc["digest"]), f"{shown} configuration", 8 * 1024 * 1024)
    try:
        config = json.loads(cfg_bytes or b"{}")
    except ValueError:
        config = {}
    run = config.get("config") or {}

    # A signature published with the image: a cosign tag, or an OCI referrer of a signature type.
    signed = False
    for d in dict.fromkeys((index_digest, digest)):
        _, _, st = reg.manifest(d.replace(":", "-") + ".sig", "signature")
        signed = signed or st == 200
        resp = reg._get(reg.http, f"referrers/{d}", "application/vnd.oci.image.index.v1+json", "referrers")
        if resp.status == 200:
            try:
                refs = json.loads(resp.body).get("manifests") or []
            except (ValueError, AttributeError):
                refs = []
            for r in refs:
                kind = str(r.get("artifactType", ""))
                signed = signed or any(kind.startswith(t) for t in _SIG_TYPES)
                provenance = provenance or "slsa" in kind or "in-toto" in kind
                sbom = sbom or "spdx" in kind or "cyclonedx" in kind

    tree = ArtifactTree()
    root: dict[str, bytes] = {}
    removed: dict[str, bytes] = {}
    budget = ctx.limits.max_total_bytes
    for i, layer in enumerate(layers):
        size = int(layer.get("size") or 0)
        media = str(layer.get("mediaType", ""))
        where = f"layer-{i}"
        if "zstd" in media:
            tree.limit_events.append(LimitEvent(kind="not_fetched", path=where, detail="zstd-compressed layer is not read", bytes=size))
            continue
        if size > budget:
            tree.limit_events.append(LimitEvent(kind="not_fetched", path=where, detail=f"layer of {size} bytes exceeds the scan limit", bytes=size))
            continue
        data = reg.blob(str(layer.get("digest", "")), f"{shown} {where}", budget)
        if data is None:
            tree.limit_events.append(LimitEvent(kind="not_fetched", path=where, detail="layer larger than its manifest says", bytes=size))
            continue
        budget -= len(data)
        try:
            unpacked = from_archive(data, None, ctx.limits)
        except ArchiveError as exc:
            tree.limit_events.append(LimitEvent(kind="archive_error", path=where, detail=str(exc)[:160], bytes=size))
            continue
        for ev in unpacked.limit_events:
            if ev.kind not in _NORMAL_IN_A_ROOTFS:
                tree.limit_events.append(LimitEvent(kind=ev.kind, path=f"{ROOT}/{ev.path}", detail=ev.detail, bytes=ev.bytes))
        _apply_layer(root, removed, unpacked, i)
    for path in sorted(root):
        tree.add(f"{ROOT}/{path}", root[path], ctx.limits)
    for path in sorted(removed):
        tree.add(path, removed[path], ctx.limits)

    pinned = f"{target.image}@{digest}"
    name = target.image.rsplit("/", 1)[-1]
    launch = {"mcpServers": {name: {"command": "docker", "args": ["run", "-i", "--rm", pinned]}}}
    tree.add(LAUNCH_FILE, (json.dumps(launch, indent=2) + "\n").encode("utf-8"), ctx.limits)
    fact: dict[str, Any] = {
        "digest": digest, "signed": signed, "provenance": provenance, "sbom": sbom,
        "user": str(run.get("User") or ""), "entrypoint": list(run.get("Entrypoint") or []), "cmd": list(run.get("Cmd") or []),
        "labels": {str(k): str(v) for k, v in (run.get("Labels") or {}).items()},
        "history": [str(h.get("created_by", "")) for h in config.get("history") or [] if isinstance(h, dict)],
        "root": ROOT, "vulnerabilities": [],
    }
    packages = _packages(root)
    if getattr(ctx, "osv", False):
        fact["vulnerabilities"] = _osv(reg.http, packages)
        reg.hosts.append("api.osv.dev")
    tree.source = ImmutableRef(kind=SourceKind.oci, locator=target.raw, resolved=digest, integrity=digest)
    tree.display_root = target.raw
    notes.insert(0, f"{shown}: resolved to {digest}; {len(layers)} layer(s), {len(root)} file(s), {len(removed)} file(s) removed by a "
                    f"later layer; {len(packages)} Python and npm package(s) found; "
                    f"{'a signature is published (not verified against an identity)' if signed else 'no signature is published'}")
    if not target.digest:
        notes.append(f"{shown}: the reference names a tag; the scan is of {digest}, which that tag pointed at when it was read")
    return Acquired(target=target, tree=tree, notes=notes, hosts=reg.hosts,
                    facts={"images": {pinned: fact, shown: fact, target.image: fact}})
