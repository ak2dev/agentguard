"""Container images (the IMG family, engine H).

Static part: Dockerfiles, compose files and the image references in MCP
configuration and registry entries. Facts part: what the host recorded about a
pulled image (``options.facts["images"][reference]``), so signature, layer,
package and history rules stay pure and testable offline:

    {"signed": bool, "provenance": bool, "sbom": bool, "user": "", "entrypoint": [...], "cmd": [...],
     "labels": {...}, "history": ["<created_by>", ...], "vulnerabilities": [{"id", "package", "severity", "fixed"}],
     "root": "<tree prefix the layers were unpacked under>"}

AG-IMG-001 (tag instead of digest in an MCP configuration) is emitted by the MCP
configuration analyzer.
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass
from typing import Any, ClassVar

import regex

from ..inventory_surfaces import span_of
from ..mcp_config import docker_image, exe_name
from ..models import Span
from ..models.enums import EvidenceKind, Severity
from ..parsers import parse_json
from ..secrets import is_placeholder
from ..textutil import TIMEOUT
from .base import Context
from .heuristics import damerau_levenshtein

_F = regex.IGNORECASE
_INSTR = regex.compile(r"(?im)^[ \t]*([A-Z]+)[ \t]+")
_PIPE_SHELL = regex.compile(r"\b(?:curl|wget|fetch)\b[^|;&\n]*\|\s*(?:sudo\s+)?(?:\w+=\S+\s+)*(?:ba|z|da|k)?sh\b|\b(?:ba|z)?sh\s+<\(\s*(?:curl|wget)\b"
                            r"|\b(?:ba|z)?sh\s+-c\s+[\"']?\$\(\s*(?:curl|wget)\b|\b(?:curl|wget)\b[^|;&\n]*\|\s*(?:python3?|node|perl|ruby)\b", _F)
_REMOTE_ADD = regex.compile(r"^(?:--\S+\s+)*https?://\S+", _F)
_SECRET_NAME = regex.compile(r"(?:^|_)(?:TOKEN|SECRET|PASSWORD|PASSWD|PWD|API_?KEY|PRIVATE_KEY|ACCESS_KEY|SECRET_KEY|CREDENTIALS?|AUTH)$", _F)
_SECRET_FILE = regex.compile(r"(?:^|/)(?:\.env(?:\.[\w-]+)?|id_(?:rsa|ed25519|ecdsa|dsa)|[\w.-]*\.pem|[\w.-]*\.key|\.npmrc|\.netrc|\.pypirc|credentials(?:\.json)?"
                             r"|\.git-credentials|secrets?(?:\.\w+)?|[\w.-]*token[\w.-]*|service[-_]account[\w.-]*\.json)$", _F)
_BROAD_CAPS = frozenset({"ALL", "SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN", "SYS_MODULE", "DAC_READ_SEARCH"})
_SERVER_LABEL = "io.modelcontextprotocol.server.name"
# Widely used MCP server images: a name one or two edits away from one of these is a lookalike.
KNOWN_IMAGES = (
    "ghcr.io/github/github-mcp-server", "mcp/github", "mcp/filesystem", "mcp/fetch", "mcp/postgres", "mcp/sqlite", "mcp/slack",
    "mcp/git", "mcp/memory", "mcp/puppeteer", "mcp/playwright", "mcp/time", "mcp/sequentialthinking", "mcp/brave-search",
    "mcp/notion", "mcp/stripe", "mcp/aws-documentation", "mcr.microsoft.com/playwright/mcp", "ghcr.io/modelcontextprotocol/servers",
    "docker.io/hashicorp/terraform-mcp-server", "ghcr.io/sooperset/mcp-atlassian", "mcp/grafana", "mcp/mongodb", "mcp/redis",
)
_SEV = {"critical": Severity.critical, "high": Severity.high, "medium": Severity.medium, "moderate": Severity.medium, "low": Severity.low}


@dataclass(frozen=True)
class ImageRef:
    ref: str
    path: str
    span: Span
    component_id: str
    source: str            # mcp-config | dockerfile | compose | server.json

    @property
    def parts(self) -> tuple[str, str, str, str]:
        return parse_ref(self.ref)


def parse_ref(ref: str) -> tuple[str, str, str, str]:
    """(registry, repository, tag, digest) of an image reference."""
    ref = ref.strip()
    for prefix in ("oci://", "docker://"):
        if ref.startswith(prefix):
            ref = ref[len(prefix):]
    digest = ""
    if "@" in ref:
        ref, digest = ref.split("@", 1)
    tag = ""
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        ref, tag = ref.rsplit(":", 1)
    first, _, rest = ref.partition("/")
    if rest and ("." in first or ":" in first or first == "localhost"):
        return first.lower(), rest.lower(), tag, digest
    repo = ref.lower()
    return "docker.io", repo if "/" in repo else f"library/{repo}", tag, digest


def instructions(text: str) -> list[tuple[int, str, str]]:
    """(line, KEYWORD, arguments) of each Dockerfile instruction, continuation lines joined."""
    out: list[tuple[int, str, str]] = []
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        raw = lines[i]
        m = _INSTR.match(raw)
        if not m or raw.lstrip().startswith("#"):
            i += 1
            continue
        start = i
        body = raw[m.end():]
        while body.rstrip().endswith("\\") and i + 1 < len(lines):
            i += 1
            nxt = lines[i]
            if nxt.lstrip().startswith("#"):
                continue
            body = body.rstrip()[:-1] + " " + nxt.strip()
        out.append((start + 1, m.group(1).upper(), body.strip()))
        i += 1
    return out


def _argv(value: str) -> list[str]:
    """ENTRYPOINT / CMD arguments as a token list (JSON form or shell form)."""
    value = value.strip()
    if value.startswith("["):
        parsed = parse_json(value)
        if isinstance(parsed.value, list):
            return [str(x) for x in parsed.value]
    return value.split()


def _search(rx: regex.Pattern[str], text: str) -> regex.Match[str] | None:
    try:
        return rx.search(text, timeout=TIMEOUT)
    except TimeoutError:
        return None


class ImageAnalyzer:
    id: ClassVar[str] = "image"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = tuple(f"AG-IMG-{i:03d}" for i in range(2, 11))

    def run(self, ctx: Context) -> None:
        self.ctx = ctx
        inv = ctx.inventory
        facts = ctx.options.facts.get("images")
        self.facts: dict[str, dict[str, Any]] = {str(k): v for k, v in facts.items() if isinstance(v, dict)} if isinstance(facts, dict) else {}
        self.dockerfiles: dict[str, list[tuple[int, str, str]]] = {}
        refs: list[ImageRef] = []
        for path in sorted(inv.surfaces):
            if inv.surfaces[path].id != "container.dockerfile":
                continue
            at = inv.texts.get(path)
            art = inv.artifacts.get(path)
            if at is None or art is None:
                continue
            ins = instructions(at.text)
            self.dockerfiles[path] = ins
            stages = {a.split()[-1].lower() for _, k, a in ins if k == "FROM" and regex.search(r"\sAS\s+\S+$", a, _F)}
            for line, kw, args in ins:
                if kw == "FROM":
                    image = next((t for t in args.split() if not t.startswith("--")), "")
                    if image and image.lower() not in stages and image.lower() != "scratch" and "$" not in image:
                        refs.append(ImageRef(image, path, Span(path=path, start_line=line), art.component_id, "dockerfile"))
            self._dockerfile(path, art.component_id, ins)
        for doc in inv.of_surface("container.compose"):
            art = inv.artifacts.get(doc.path)
            services = doc.data.get("services") if isinstance(doc.data.get("services"), dict) else {}
            for name, svc in services.items():
                if not isinstance(svc, dict):
                    continue
                cid = art.component_id if art else ""
                if isinstance(svc.get("image"), str) and "$" not in svc["image"]:
                    refs.append(ImageRef(svc["image"], doc.path, span_of(doc.text, str(name), svc["image"], path=doc.path), cid, "compose"))
                self._compose_service(doc, cid, str(name), svc)
        for comp in inv.components.values():
            spec = comp.server
            if spec is None or exe_name(spec.command) not in ("docker", "podman", "nerdctl"):
                continue
            image = docker_image(spec.args)
            span = spec.config_span or Span(path=spec.config_path)
            if image:
                refs.append(ImageRef(image, spec.config_path, span, comp.id, "mcp-config"))
            for i, a in enumerate(spec.args):
                if a == "--entrypoint" or a.startswith("--entrypoint="):
                    value = a.split("=", 1)[1] if "=" in a else (spec.args[i + 1] if i + 1 < len(spec.args) else "")
                    ctx.emit("AG-IMG-006", component_ids=comp.id, span=span, snippet=" ".join([spec.command or "", *spec.args])[:300],
                             match=f"entrypoint:{comp.name}:{value}", kind=EvidenceKind.config, detail="key: args",
                             message=f"Server '{comp.name}' starts its image with `--entrypoint {value}`: the configuration replaces "
                                     "the program the image was built and documented to run.")
        self.server_json = self._server_json(refs)
        for ref in refs:
            self._reference(ref)
        self._labels()
        self._layers()

    # -- Dockerfile ---------------------------------------------------------------------------------
    def _dockerfile(self, path: str, cid: str, ins: list[tuple[int, str, str]]) -> None:
        emit = self.ctx.emit
        user = ""
        user_line = 0
        last_from = 0
        copied: list[tuple[int, str]] = []          # (line, file) secret-looking files copied into a layer
        for line, kw, args in ins:
            span = Span(path=path, start_line=line)
            if kw == "FROM":
                user, user_line, last_from = "", 0, line
                copied = []
            elif kw == "USER":
                user, user_line = args.split()[0] if args.split() else "", line
            elif kw == "RUN":
                m = _search(_PIPE_SHELL, args)
                if m:
                    emit("AG-IMG-008", component_ids=cid, span=span, snippet=f"RUN {args}"[:300], match=f"{path}:pipe:{m.group(0)}",
                         kind=EvidenceKind.config,
                         message=f"The image build downloads a script and runs it (`{m.group(0)[:80]}`). What is baked into the "
                                 "image depends on what that URL serves at build time.")
                for copy_line, name in copied:
                    base = posixpath.basename(name)
                    if base and _search(regex.compile(rf"\brm\b[^\n;&|]*{regex.escape(base)}"), args):
                        emit("AG-IMG-009", component_ids=cid, span=Span(path=path, start_line=copy_line), snippet=f"COPY {name}"[:200],
                             match=f"{path}:removed:{name}", kind=EvidenceKind.config, related=[span],
                             message=f"`{name}` is copied into a layer on line {copy_line} and removed on line {line}. The file is "
                                     "still in the earlier layer, and anyone who pulls the image can read it.")
            elif kw in ("COPY", "ADD"):
                toks = [t for t in args.split() if not t.startswith("--")]
                if kw == "ADD" and _search(_REMOTE_ADD, args) and "--checksum=" not in args:
                    emit("AG-IMG-008", component_ids=cid, span=span, snippet=f"ADD {args}"[:300], match=f"{path}:add:{args[:80]}",
                         kind=EvidenceKind.config,
                         message=f"`ADD {toks[0][:80] if toks else ''}` fetches a remote file at build time with no checksum.")
                if "--from=" not in args:
                    for src in toks[:-1]:
                        if _search(_SECRET_FILE, src.strip("\"'[],")):
                            copied.append((line, src.strip("\"'[],")))
            elif kw in ("ARG", "ENV"):
                for tok in regex.findall(r"([A-Za-z_]\w*)(?:=(\"[^\"]*\"|'[^']*'|\S*))?", args) if kw == "ARG" else \
                        regex.findall(r"([A-Za-z_]\w*)[= ](\"[^\"]*\"|'[^']*'|\S+)", args):
                    name, value = tok[0], tok[1].strip("\"'")
                    if not _search(_SECRET_NAME, name):
                        continue
                    literal = bool(value) and "$" not in value and not is_placeholder(value)
                    if kw == "ENV" and not literal:
                        continue
                    emit("AG-IMG-008", component_ids=cid, span=span, snippet=f"{kw} {name}{'=…' if value else ''}",
                         match=f"{path}:{kw}:{name}", kind=EvidenceKind.config, severity=None if literal else Severity.medium,
                         message=f"`{kw} {name}` passes a secret through {'a build argument' if kw == 'ARG' else 'an environment variable'}"
                                 f"{' with a literal value' if literal else ''}. Build arguments and environment values are recorded "
                                 "in the image's history and metadata.")
                    break
        if last_from and user.lower() in ("", "root", "0", "0:0", "root:root"):
            line = user_line or last_from
            emit("AG-IMG-005", component_ids=cid, span=Span(path=path, start_line=line),
                 snippet=f"USER {user}" if user else "(no USER instruction in the final stage)", match=f"{path}:root",
                 kind=EvidenceKind.config,
                 message="The image's final stage " + (f"sets `USER {user}`" if user else "has no `USER` instruction")
                         + ", so the server runs as root inside the container.")

    def _compose_service(self, doc: Any, cid: str, name: str, svc: dict[str, Any]) -> None:
        emit = self.ctx.emit
        caps = [str(c).upper() for c in svc.get("cap_add")] if isinstance(svc.get("cap_add"), list) else []
        why = ""
        needle = ""
        if svc.get("privileged") is True:
            why, needle = "runs privileged", "privileged"
        elif set(caps) & _BROAD_CAPS:
            why, needle = f"adds capabilities ({', '.join(sorted(set(caps) & _BROAD_CAPS))})", "cap_add"
        elif str(svc.get("user", "")).lower() in ("root", "0", "0:0"):
            why, needle = "runs as root (`user: root`)", "user"
        if why:
            emit("AG-IMG-005", component_ids=[cid] if cid else [], span=span_of(doc.text, name, needle, path=doc.path),
                 snippet=f"{name}: {needle}", match=f"{doc.path}:{name}:{needle}", kind=EvidenceKind.config,
                 detail=f"key: services.{name}.{needle}", message=f"Compose service '{name}' {why}.")
        build = svc.get("build") if isinstance(svc.get("build"), dict) else {}
        args = build.get("args")
        pairs = list(args.items()) if isinstance(args, dict) else \
            [tuple(str(a).split("=", 1)) for a in args if "=" in str(a)] if isinstance(args, list) else []
        for key, value in pairs:
            if _search(_SECRET_NAME, str(key)) and isinstance(value, str) and value and "$" not in value and not is_placeholder(value):
                emit("AG-IMG-008", component_ids=[cid] if cid else [], span=span_of(doc.text, name, str(key), path=doc.path),
                     snippet=f"{key}: …", match=f"{doc.path}:{name}:arg:{key}", kind=EvidenceKind.config,
                     detail=f"key: services.{name}.build.args.{key}",
                     message=f"Compose service '{name}' passes a literal secret as the build argument `{key}`; build arguments stay "
                             "in the image's history.")
                break

    # -- references ----------------------------------------------------------------------------------
    def _reference(self, ref: ImageRef) -> None:
        emit = self.ctx.emit
        registry, repo, tag, digest = ref.parts
        full = f"{registry}/{repo}"
        allowed = self.ctx.options.effective_policy.allow.registries
        if allowed:
            ok = any(full == a.lower().rstrip("/") or full.startswith(a.lower().rstrip("/") + "/") or registry == a.lower().rstrip("/")
                     for a in allowed)
            if not ok:
                emit("AG-IMG-002", component_ids=[ref.component_id] if ref.component_id else [], span=ref.span, snippet=ref.ref,
                     match=f"{ref.path}:registry:{ref.ref}", kind=EvidenceKind.policy,
                     message=f"Image `{ref.ref}` comes from `{registry}`, which is not in the policy's allowed registries "
                             f"({', '.join(allowed[:4])}).")
        short = repo if registry == "docker.io" else full
        for known in KNOWN_IMAGES:
            k_reg, k_repo, _, _ = parse_ref(known)
            k_short = k_repo if k_reg == "docker.io" else f"{k_reg}/{k_repo}"
            if short == k_short or full == f"{k_reg}/{k_repo}":
                break
            if abs(len(short) - len(k_short)) <= 2 and 0 < damerau_levenshtein(short, k_short, cap=3) <= 2:
                emit("AG-IMG-010", component_ids=[ref.component_id] if ref.component_id else [], span=ref.span, snippet=ref.ref,
                     match=f"{ref.path}:lookalike:{ref.ref}", kind=EvidenceKind.metadata,
                     message=f"Image `{ref.ref}` is one or two characters away from the widely used `{known}`. A lookalike name is "
                             "how a different image gets pulled in place of the expected server.")
                break
        fact = self.facts.get(ref.ref) or self.facts.get(f"{full}:{tag}" if tag else full) or (self.facts.get(f"{full}@{digest}") if digest else None)
        if not fact:
            return
        cids = [ref.component_id] if ref.component_id else []
        missing = [label for key, label in (("signed", "a signature"), ("provenance", "build provenance"), ("sbom", "an SBOM"))
                   if fact.get(key) is False]
        if missing:
            emit("AG-IMG-003", component_ids=cids, span=ref.span, snippet=ref.ref, match=f"{ref.path}:unsigned:{ref.ref}",
                 kind=EvidenceKind.live,
                 message=f"Image `{ref.ref}` has no {', no '.join(missing)}. Nothing ties the image to a build of the source.")
        vulns = [v for v in fact.get("vulnerabilities") or [] if isinstance(v, dict) and v.get("id")]
        if vulns:
            top = max((_SEV.get(str(v.get("severity", "")).lower(), Severity.low) for v in vulns), key=lambda s: s.rank)
            shown = ", ".join(f"{v['id']} ({v.get('package', '?')})" for v in vulns[:4])
            fixable = sum(1 for v in vulns if v.get("fixed"))
            emit("AG-IMG-007", component_ids=cids, span=ref.span, snippet=ref.ref, match=f"{ref.path}:vulns:{ref.ref}", severity=top,
                 kind=EvidenceKind.intel,
                 message=f"Image `{ref.ref}` contains packages with {len(vulns)} known vulnerabilit{'y' if len(vulns) == 1 else 'ies'}: "
                         f"{shown}{'…' if len(vulns) > 4 else ''}. {fixable} of them have a fixed version.")
        user = fact.get("user")
        if isinstance(user, str) and user.lower() in ("", "root", "0", "0:0") and ref.source != "dockerfile":
            emit("AG-IMG-005", component_ids=cids, span=ref.span, snippet=ref.ref, match=f"{ref.path}:rootuser:{ref.ref}",
                 kind=EvidenceKind.live, message=f"Image `{ref.ref}` is configured to run as root.")
        for entry in fact.get("history") or []:
            text = entry if isinstance(entry, str) else str(entry.get("created_by", "")) if isinstance(entry, dict) else ""
            hit = next((mm for mm in regex.finditer(r"\b([A-Za-z_]\w*)=(\"[^\"]{8,}\"|'[^']{8,}'|[^\s\"']{8,})", text)
                        if _search(_SECRET_NAME, mm.group(1)) and "$" not in mm.group(2) and not is_placeholder(mm.group(2).strip("\"'"))), None)
            if hit is not None:
                emit("AG-IMG-009", component_ids=cids, span=ref.span, snippet=f"{hit.group(1)}=…", match=f"{ref.path}:history:{ref.ref}:{hit.group(1)}",
                     kind=EvidenceKind.live,
                     message=f"The build history of `{ref.ref}` records a value for `{hit.group(1)}`. Secrets passed at build time "
                             "stay readable in the image's history even when later layers remove them.")
                break
        entry_fact = [str(x) for x in (fact.get("entrypoint") or [])] + [str(x) for x in (fact.get("cmd") or [])]
        if entry_fact and ref.source != "dockerfile":
            for path, ins in sorted(self.dockerfiles.items()):
                ep = next((a for _, k, a in reversed(ins) if k == "ENTRYPOINT"), "")
                cmd = next((a for _, k, a in reversed(ins) if k == "CMD"), "")
                declared = _argv(ep) + _argv(cmd)
                if declared and declared != entry_fact:
                    line = next((ln for ln, k, _ in reversed(ins) if k in ("ENTRYPOINT", "CMD")), 1)
                    emit("AG-IMG-006", component_ids=cids, span=ref.span, snippet=" ".join(entry_fact)[:200],
                         match=f"{ref.path}:entry:{ref.ref}", kind=EvidenceKind.live, related=[Span(path=path, start_line=line)],
                         message=f"Image `{ref.ref}` starts `{' '.join(entry_fact)[:80]}`, but the Dockerfile in this source "
                                 f"(`{path}`) declares `{' '.join(declared)[:80]}`. The published image does not run what the "
                                 "source documents.")
                break

    # -- claimed server name --------------------------------------------------------------------------
    def _server_json(self, refs: list[ImageRef]) -> list[tuple[str, str, str]]:
        """(path, server name, text) of each registry entry; adds its OCI packages to ``refs``."""
        inv = self.ctx.inventory
        tree = inv.tree
        out: list[tuple[str, str, str]] = []
        for path in sorted(tree.files if tree is not None else []):
            if posixpath.basename(path).lower() != "server.json":
                continue
            text = tree.files[path].data.decode("utf-8", "replace")
            parsed = parse_json(text)
            data = parsed.value if isinstance(parsed.value, dict) else {}
            name = data.get("name")
            if not isinstance(name, str) or "/" not in name:
                continue
            out.append((path, name, text))
            art = inv.artifacts.get(path)
            cid = art.component_id if art else ""
            for pkg in data.get("packages") if isinstance(data.get("packages"), list) else []:
                if not isinstance(pkg, dict) or str(pkg.get("registryType") or pkg.get("registry_type") or "").lower() != "oci":
                    continue
                ident = pkg.get("identifier")
                if not isinstance(ident, str) or not ident:
                    continue
                version = pkg.get("version")
                ref = ident if (":" in ident.rsplit("/", 1)[-1] or "@" in ident or not isinstance(version, str)) else f"{ident}:{version}"
                span = span_of(text, ident, path=path)
                refs.append(ImageRef(ref, path, span, cid, "server.json"))
                owner = name.split("/", 1)[0].rsplit(".", 1)[-1].lower()
                _, repo, _, _ = parse_ref(ref)
                ns = repo.split("/", 1)[0]
                if name.lower().startswith("io.github.") and ns not in (owner, "library") and owner not in repo.split("/"):
                    self.ctx.emit("AG-IMG-010", component_ids=[cid] if cid else [], span=span, snippet=ident,
                                  match=f"{path}:owner:{ident}", kind=EvidenceKind.metadata,
                                  message=f"`server.json` names the server `{name}`, but its image `{ident}` is published under "
                                          f"`{ns}`, not `{owner}`. The registry entry and the image belong to different owners.")
        return out

    def _labels(self) -> None:
        if not self.server_json:
            return
        claimed = {name for _, name, _ in self.server_json}
        first_path, first_name, _ = self.server_json[0]
        for path, ins in sorted(self.dockerfiles.items()):
            for line, kw, args in ins:
                if kw != "LABEL":
                    continue
                m = regex.search(rf"{regex.escape(_SERVER_LABEL)}\s*=\s*[\"']?([^\"'\s]+)", args)
                if m and m.group(1) not in claimed:
                    art = self.ctx.inventory.artifacts.get(path)
                    self.ctx.emit("AG-IMG-010", component_ids=[art.component_id] if art else [], span=Span(path=path, start_line=line),
                                  snippet=f"LABEL {args}"[:200], match=f"{path}:label:{m.group(1)}", kind=EvidenceKind.metadata,
                                  related=[Span(path=first_path)],
                                  message=f"The image is labelled as the server `{m.group(1)}`, but `{first_path}` names the server "
                                          f"`{first_name}`. The ownership label does not match the registry entry.")
        for ref, fact in sorted(self.facts.items()):
            labels = fact.get("labels") if isinstance(fact.get("labels"), dict) else {}
            label = labels.get(_SERVER_LABEL)
            if isinstance(label, str) and label and label not in claimed:
                self.ctx.emit("AG-IMG-010", component_ids=[], span=Span(path=first_path), snippet=f"{_SERVER_LABEL}={label}",
                              match=f"facts:label:{ref}:{label}", kind=EvidenceKind.live,
                              message=f"Image `{ref}` carries the ownership label `{label}`, but `{first_path}` names the server "
                                      f"`{first_name}`.")

    # -- findings inside layers -------------------------------------------------------------------------
    def _layers(self) -> None:
        roots = sorted((str(f["root"]).strip("/"), ref) for ref, f in self.facts.items() if isinstance(f.get("root"), str) and f["root"].strip("/"))
        for root, ref in roots:
            inner = [r for r in self.ctx.raw if r.primary is not None and r.primary.path.startswith(root + "/")
                     and not r.rule_id.startswith(("AG-IMG-", "AG-HYG-"))]
            if not inner:
                continue
            def sev(r: Any) -> Severity:
                det = self.ctx.pack.detectors.get(r.rule_id)
                return r.severity or (det.severity if det else Severity.low)
            inner.sort(key=lambda r: (-sev(r).rank, r.rule_id, r.primary.path))
            top = inner[0]
            ids = sorted({r.rid for r in inner})
            self.ctx.emit("AG-IMG-004", component_ids=top.component_ids, span=top.primary, snippet=top.primary.path,
                          match=f"layers:{ref}", kind=EvidenceKind.live, severity=sev(top),
                          related=[r.primary for r in inner[1:6] if r.primary is not None],
                          message=f"{len(inner)} finding(s) are inside the layers of image `{ref}` ({', '.join(ids[:6])}"
                                  f"{'…' if len(ids) > 6 else ''}); the most severe is {top.rid} in `{top.primary.path}`.")


__all__ = ["ImageAnalyzer", "ImageRef", "KNOWN_IMAGES", "instructions", "parse_ref"]
