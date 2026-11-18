"""Remote connectors and descriptors (the CONN family beyond the authorization checks).

Static part: OpenAPI action descriptors, ``ai-plugin.json`` and A2A agent cards
in the tree, and the host names of remote MCP servers in configuration.
Recorded part: what a read-only probe of a live endpoint returned
(``options.remote_probes``) and facts the host collected about it
(``options.facts["endpoints"][url]``):

    {"tools_by_identity": {"anonymous": [names], "authenticated": [names]},
     "responses": ["text returned to a harmless probe", ...],
     "vulnerabilities": [{"id": "...", "severity": "...", "summary": "..."}]}

Nothing here opens a connection.
"""

from __future__ import annotations

import urllib.parse
from typing import Any, ClassVar

import regex

from ..inventory_surfaces import Doc, span_of
from ..lock import lock_key, tool_hash
from ..mcp_config import package_arg, split_package_spec
from ..models import Component, RemoteProbe, Span, ToolDef
from ..models.enums import EvidenceKind, Severity
from ..textutil import TIMEOUT
from .base import Context
from .heuristics import damerau_levenshtein
from .network_rules import _server_component

_F = regex.IGNORECASE
# Text that gives orders to the model reading it. Stricter than the general "agent-directed" heuristic: ordinary API
# documentation says "you must supply a key" all the time.
DIRECTIVE = regex.compile(
    r"\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+|the\s+|your\s+)?(?:previous|prior|above|earlier|system|other)\s+(?:instructions?|rules?|prompts?|messages?)"
    r"|\bdo\s+not\s+(?:tell|inform|mention|reveal|show|notify|alert)\b[^.\n]{0,30}\b(?:the\s+)?user\b"
    r"|\bwithout\s+(?:asking|telling|informing|notifying|mentioning\s+it\s+to)\s+(?:the\s+)?user\b"
    r"|\b(?:send|post|upload|forward|include|attach|append|pass|copy)\b[^.\n]{0,60}\b(?:conversation|chat\s+history|system\s+prompt|api[ _-]?keys?|"
    r"access\s+tokens?|credentials|secrets|ssh\s+keys?|\.ssh\b|\.env\b|environment\s+variables)\b"
    r"|\b(?:always|must|should)\s+(?:first\s+)?(?:call|invoke|use|run)\s+(?:this|the\s+[\w.-]+)\s+(?:tool|function|endpoint|action|skill)\s+"
    r"(?:before|instead|first|whenever|for\s+every|on\s+every)\b"
    r"|<\s*(?:important|system|instructions?|secret)\s*>|\[\s*system\s*\]|^\s*system\s*:|\byou\s+are\s+now\b|\bnew\s+instructions?\s*:"
    r"|\b(?:to|for)\s+the\s+(?:assistant|ai|agent|model|llm)\s*[:,]|\bnote\s+to\s+(?:the\s+)?(?:assistant|ai|agent|model|llm)\b"
    r"|\bbefore\s+(?:responding|answering|any\s+other\s+(?:tool|action))\b[^.\n]{0,60}\b(?:read|send|fetch|call|run|open)\b", _F | regex.MULTILINE)
_SECOND_LEVEL = frozenset({"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.jp", "co.nz", "co.in", "com.br", "com.cn",
                           "com.mx", "co.za", "com.sg", "com.tr", "co.kr"})
_GENERIC_VENDOR_WORDS = frozenset({"box", "square", "linear", "neon", "monday", "aws", "google", "microsoft", "notion", "render"})
_LOCAL = regex.compile(r"^(?:localhost|127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|\[?::1\]?$|0\.0\.0\.0)|\.(?:local|localhost|internal|lan|corp|home|test)$", _F)
_READ_ONLY_NAME = regex.compile(r"^(?:get|list|search|read|fetch|find|query|describe|show|view|lookup|check|count|browse|preview|summari[sz]e|explain)(?:_|$)")
_BROAD_SCOPE = regex.compile(r"^(?:\*|all|root|full[_-]?access|repo|admin(?:[:.].*)?|.*[:./](?:admin|\*|all|write|delete|manage|full)|(?:write|delete|manage|admin)[:._-].*|write|delete|manage)$", _F)
_DESTRUCTIVE = regex.compile(r"(?:^|_)(?:delete|remove|drop|destroy|wipe|purge|truncate|revoke|terminate|kill|erase|reset|overwrite|force_push)(?:_|$)")
_FINANCIAL = regex.compile(r"(?:^|_)(?:pay|payment|payments|refund|transfer|charge|payout|withdraw|purchase|buy|sell|trade|order|invoice|checkout|send_money|wire)(?:_|$)")
_ADMIN = regex.compile(r"(?:^|_)(?:admin|grant|permission|permissions|role|roles|impersonate|invite|member|members|token|tokens|api_key|secret|secrets|sudo|policy|billing|org|organization)(?:_|$)")
_DESTRUCTIVE_OP = regex.compile(r"\b(?:delete|remove|destroy|drop|purge|wipe|cancel|revoke|terminate|transfer|pay|refund|charge|send|publish|merge|deploy)\w*", _F)
_METHODS = ("get", "put", "post", "delete", "patch", "options", "head")
_SEV = {"critical": Severity.critical, "high": Severity.high, "medium": Severity.medium, "moderate": Severity.medium, "low": Severity.low}


def _search(rx: regex.Pattern[str], text: str) -> regex.Match[str] | None:
    try:
        return rx.search(text, timeout=TIMEOUT)
    except TimeoutError:
        return None


def host_of(url: str) -> str:
    try:
        return (urllib.parse.urlsplit(url if "://" in url else f"//{url}").hostname or "").lower()
    except ValueError:
        return ""


def registrable(host: str) -> str:
    """The registrable part of a host name (a short suffix list; enough to compare vendor domains)."""
    labels = host.strip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    tail2 = ".".join(labels[-2:])
    return ".".join(labels[-3:]) if tail2 in _SECOND_LEVEL else tail2


def snake(name: str) -> str:
    return regex.sub(r"[^a-z0-9]+", "_", regex.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).lower()).strip("_")


def version_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(x) for x in regex.findall(r"\d+", version.split("+", 1)[0].split("-", 1)[0])[:4])


def vendor_claim(name: str, url: str, vendors: dict[str, list[str]]) -> tuple[str, str, str] | None:
    """(vendor, kind, detail) when a server carries a vendor's name but is not on that vendor's domains.
    kind: lookalike | host | name."""
    host = host_of(url)
    if not host or _search(_LOCAL, host) or regex.fullmatch(r"[\d.]+", host):
        return None
    reg = registrable(host)
    for domains in vendors.values():
        if any(host == d or host.endswith("." + d) for d in domains):
            return None
    tokens = set(regex.split(r"[.\-_]", host))
    name_tokens = set(regex.split(r"[^a-z0-9]+", name.lower()))
    best: tuple[str, str, str] | None = None
    for vendor, domains in sorted(vendors.items()):
        for d in domains:
            limit = 1 if len(d) <= 9 else 2
            if abs(len(reg) - len(d)) <= limit and 0 < damerau_levenshtein(reg, d, cap=3) <= limit:
                return vendor, "lookalike", d
        if vendor in tokens and vendor not in _GENERIC_VENDOR_WORDS and len(vendor) >= 5:
            best = best or (vendor, "host", domains[0])
        elif vendor in name_tokens and (name.lower() in (vendor, f"{vendor}-mcp", f"{vendor}_mcp", f"mcp-{vendor}", f"{vendor}-server")):
            best = best or (vendor, "name", domains[0])
    return best


class ConnectorAnalyzer:
    id: ClassVar[str] = "connector"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = (
        "AG-CONN-005", "AG-CONN-006", "AG-CONN-007", "AG-CONN-008", "AG-CONN-009", "AG-CONN-010", "AG-CONN-011", "AG-CONN-012",
        "AG-CONN-013", "AG-CONN-014", "AG-CONN-017", "AG-CONN-002/open-write-tools", "AG-SUPPLY-001/bundled-advisory",
    )

    def run(self, ctx: Context) -> None:
        self.ctx = ctx
        inv = ctx.inventory
        data = ctx.pack.data
        vendors_raw = (data.get("vendor-domains") or {}).get("vendors") or {}
        self.vendors = {str(k).lower(): [str(d).lower() for d in v] for k, v in vendors_raw.items() if isinstance(v, list)}
        self.advisories = [a for a in (data.get("mcp-advisories") or {}).get("advisories") or [] if isinstance(a, dict)]
        facts = ctx.options.facts.get("endpoints")
        self.endpoints: dict[str, dict[str, Any]] = {str(k): v for k, v in facts.items() if isinstance(v, dict)} if isinstance(facts, dict) else {}
        for comp in sorted(inv.components.values(), key=lambda c: c.id):
            if comp.server is not None and comp.server.url:
                self._domain(comp)
            if comp.server is not None and comp.server.command:
                self._launcher(comp)
        probed: set[str] = set()
        for probe in sorted(ctx.options.remote_probes, key=lambda p: (p.server_name, p.url)):
            probed.add(probe.url)
            self._probe(probe)
        for url in sorted(set(self.endpoints) - probed):
            self._probe(RemoteProbe(server_name=host_of(url) or url, url=url))
        for doc in inv.of_surface("descriptor.openapi", "descriptor.ai_plugin"):
            if isinstance(doc.value, dict):
                self._openapi(doc)
        for doc in inv.of_surface("descriptor.a2a"):
            if isinstance(doc.value, dict):
                self._agent_card(doc)

    # -- AG-SUPPLY-001/bundled-advisory: a launcher pinned to a version the advisory snapshot lists -------------
    def _affected(self, name: str, version: str) -> list[tuple[str, str, str, str]]:
        """(id, severity, summary, first fixed version) of every bundled advisory that covers ``name`` at ``version``."""
        v = version_tuple(version)
        hits: list[tuple[str, str, str, str]] = []
        if not name or not v:
            return hits
        for adv in self.advisories:
            if name.lower() not in [str(n).lower() for n in adv.get("names") or []]:
                continue
            fixed = [(version_tuple(str(f)), str(f)) for f in adv.get("fixed") or []]
            line = [f for f in fixed if f[0] and (f[0][0] >= 2000) == (v[0] >= 2000)]
            if line and v < min(line)[0]:
                hits.append((str(adv.get("id")), str(adv.get("severity") or "high"), str(adv.get("summary") or ""), min(line)[1]))
        return hits

    def _launcher(self, comp: Component) -> None:
        spec = comp.server
        assert spec is not None
        _runner, package = package_arg(spec.command, spec.args)
        if not package:
            return
        name, version = split_package_spec(package)
        hits = self._affected(name, version or "")
        if not hits:
            return
        span = spec.config_span or Span(path=spec.config_path)
        at = self.ctx.inventory.texts.get(spec.config_path)
        if at is not None:
            # Point at the argument that names the package, inside this server's entry when it can be told apart.
            start = at.index.line_start(span.start_line) if span.start_line and span.start_line >= 1 else 0
            pos = at.text.find(package, start)
            if pos >= 0:
                span = at.span(pos, pos + len(package))
        top = max((_SEV.get(s.lower(), Severity.high) for _, s, _, _ in hits), key=lambda s: s.rank)
        self.ctx.emit("AG-SUPPLY-001/bundled-advisory", component_ids=comp.id, span=span, snippet=package, kind=EvidenceKind.intel,
                      match=f"{name}@{version}:{[h[0] for h in hits]}", severity=top,
                      message=f"'{comp.name}' starts {name} {version}, which is affected by {', '.join(h[0] for h in hits[:4])}: "
                              f"{hits[0][2][:160]} Fixed in {hits[0][3]}.")

    # -- helpers --------------------------------------------------------------------------------------
    def _where(self, probe: RemoteProbe) -> tuple[list[str], Span]:
        comp = _server_component(self.ctx, probe)
        if comp is None:
            comp = next((c for c in self.ctx.inventory.components.values() if c.server and c.server.url == probe.url), None)
        span = comp.server.config_span if comp and comp.server and comp.server.config_span else Span(path=probe.config_path or probe.url)
        return ([comp.id] if comp else []), span

    def _cid(self, path: str) -> list[str]:
        art = self.ctx.inventory.artifacts.get(path)
        return [art.component_id] if art else []

    # -- AG-CONN-006 -----------------------------------------------------------------------------------
    def _domain(self, comp: Component) -> None:
        spec = comp.server
        assert spec is not None and spec.url
        claim = vendor_claim(comp.name, spec.url, self.vendors)
        if claim is None:
            return
        vendor, kind, domain = claim
        host = host_of(spec.url)
        if kind == "lookalike":
            msg = f"Server '{comp.name}' is served from `{host}`, which is one or two characters away from `{domain}`."
        elif kind == "host":
            msg = f"Server '{comp.name}' is served from `{host}`: the host carries the name '{vendor}' but is not on {vendor}'s own " \
                  f"domain (`{domain}`)."
        else:
            msg = f"Server '{comp.name}' is named after {vendor} but is served from `{host}`, not from {vendor}'s own domain (`{domain}`)."
        self.ctx.emit("AG-CONN-006", component_ids=comp.id, span=spec.config_span or Span(path=spec.config_path), snippet=spec.url[:200],
                      match=f"{comp.name}:{host}:{vendor}", kind=EvidenceKind.metadata, detail="key: url",
                      severity=Severity.medium if kind == "name" else None,
                      message=msg + " Tokens and data sent there go to whoever runs that host.")

    # -- recorded probes ----------------------------------------------------------------------------------
    def _probe(self, probe: RemoteProbe) -> None:
        emit = self.ctx.emit
        cids, span = self._where(probe)
        name = probe.server_name
        fact = self.endpoints.get(probe.url, {})
        tools = [t for t in probe.tools if isinstance(t, dict) and isinstance(t.get("name"), str)]
        # AG-CONN-005: scopes against the tool surface
        scopes: list[str] = []
        if probe.prm and isinstance(probe.prm.get("scopes_supported"), list):
            scopes = [str(s) for s in probe.prm["scopes_supported"]]
        elif probe.www_authenticate:
            m = regex.search(r'scope="([^"]+)"', probe.www_authenticate)
            scopes = m.group(1).split() if m else []
        broad = [s for s in scopes if _search(_BROAD_SCOPE, s)]
        if tools and broad and all(self._read_only(t) for t in tools):
            emit("AG-CONN-005", component_ids=cids, span=span, snippet=" ".join(scopes)[:200], match=f"{probe.url}:scopes:{broad}",
                 kind=EvidenceKind.live,
                 message=f"'{name}' asks for the scope(s) {', '.join(broad[:4])}, but every one of its {len(tools)} tools only reads. "
                         "The token you grant can do more than the server's tools need.")
        # AG-CONN-007: what the tool surface can do
        groups: dict[str, list[str]] = {"destructive": [], "financial": [], "administrative": []}
        for t in tools:
            n = snake(t["name"])
            ann = t.get("annotations") if isinstance(t.get("annotations"), dict) else {}
            if ann.get("destructiveHint") is True or _search(_DESTRUCTIVE, n):
                groups["destructive"].append(t["name"])
            elif _search(_FINANCIAL, n) and not _search(_READ_ONLY_NAME, n):
                groups["financial"].append(t["name"])
            elif _search(_ADMIN, n) and not _search(_READ_ONLY_NAME, n):
                groups["administrative"].append(t["name"])
        if any(groups.values()):
            parts = [f"{k}: {', '.join(v[:4])}" for k, v in groups.items() if v]
            emit("AG-CONN-007", component_ids=cids, span=span, snippet="; ".join(parts)[:300], match=f"{probe.url}:surface:{parts}",
                 kind=EvidenceKind.live,
                 message=f"'{name}' offers tools that change or spend things ({'; '.join(parts)}). An agent connected to it can be "
                         "steered into calling them.")
            # AG-CONN-002/open-write-tools: the same tools, and the server asked for no credentials.
            if probe.unauthenticated_list:
                emit("AG-CONN-002/open-write-tools", component_ids=cids, span=span, snippet="; ".join(parts)[:300],
                     match=f"{probe.url}:open-write:{parts}", kind=EvidenceKind.live,
                     message=f"'{name}' listed its tools without asking for any credentials, and they include tools that change or "
                             f"spend things ({'; '.join(parts)}). Anyone who can reach the address can call them.")
        # AG-CONN-008: definitions against the baseline
        lock = self.ctx.options.lock
        if lock is not None and tools:
            comp = _server_component(self.ctx, probe)
            key = lock_key(comp) if comp is not None else ""
            entry = next((e for e in lock.artifacts if e.tools is not None and (e.name == name or (key and e.id == key))), None)
            if entry is not None and entry.tools is not None:
                now = {t["name"]: tool_hash(self._tooldef(t).canonical(), lock.tool_hash_version) for t in tools}
                changed = sorted(n for n in set(now) & set(entry.tools) if now[n] != entry.tools[n])
                added, removed = sorted(set(now) - set(entry.tools)), sorted(set(entry.tools) - set(now))
                if changed or added or removed:
                    parts = [f"changed: {', '.join(changed[:5])}" if changed else "", f"added: {', '.join(added[:5])}" if added else "",
                             f"removed: {', '.join(removed[:5])}" if removed else ""]
                    emit("AG-CONN-008", component_ids=cids, span=span, snippet="; ".join(p for p in parts if p)[:300],
                         match=f"{probe.url}:baseline:{changed}:{added}:{removed}", kind=EvidenceKind.lock_diff,
                         message=f"The tools '{name}' serves now differ from the approved baseline ({'; '.join(p for p in parts if p)}). "
                                 "What was reviewed is not what the agent would be given.")
        # AG-CONN-009: tool list by identity
        by_id = fact.get("tools_by_identity")
        if isinstance(by_id, dict) and len(by_id) >= 2:
            sets = {str(k): (v if isinstance(v, dict) else {str(x): "" for x in v} if isinstance(v, list) else {}) for k, v in by_id.items()}
            ids = sorted(sets)
            base = sets[ids[0]]
            for other in ids[1:]:
                cur = sets[other]
                only_a, only_b = sorted(set(base) - set(cur)), sorted(set(cur) - set(base))
                differ = sorted(n for n in set(base) & set(cur) if base[n] != cur[n])
                if only_a or only_b or differ:
                    detail = "; ".join(p for p in (f"only for {ids[0]}: {', '.join(only_a[:4])}" if only_a else "",
                                                   f"only for {other}: {', '.join(only_b[:4])}" if only_b else "",
                                                   f"defined differently: {', '.join(differ[:4])}" if differ else "") if p)
                    emit("AG-CONN-009", component_ids=cids, span=span, snippet=detail[:300], match=f"{probe.url}:identity:{detail}",
                         kind=EvidenceKind.live,
                         message=f"'{name}' lists different tools depending on who asks ({detail}). A review made with one identity "
                                 "does not cover what another client is served.")
                    break
        # AG-CONN-010: reported version against published advisories
        info = probe.server_info or {}
        reported, version = str(info.get("name") or ""), str(info.get("version") or "")
        hits: list[tuple[str, str, str]] = []
        if reported and version_tuple(version):
            v = version_tuple(version)
            for adv in self.advisories:
                names = [str(n).lower() for n in adv.get("names") or []]
                if reported.lower() not in names:
                    continue
                fixed = [version_tuple(str(f)) for f in adv.get("fixed") or []]
                line = [f for f in fixed if f and (f[0] >= 2000) == (v[0] >= 2000)]
                if line and v < min(line):
                    hits.append((str(adv.get("id")), str(adv.get("severity") or "high"), str(adv.get("summary") or "")))
        for vuln in fact.get("vulnerabilities") or []:
            if isinstance(vuln, dict) and vuln.get("id"):
                hits.append((str(vuln["id"]), str(vuln.get("severity") or "high"), str(vuln.get("summary") or "")))
        if hits:
            top = max((_SEV.get(s.lower(), Severity.high) for _, s, _ in hits), key=lambda s: s.rank)
            emit("AG-CONN-010", component_ids=cids, span=span, snippet=f"{reported} {version}".strip() or probe.url,
                 match=f"{probe.url}:vuln:{[h[0] for h in hits]}", kind=EvidenceKind.intel, severity=top,
                 message=f"'{name}' reports {reported or 'a server'} {version}, which is affected by "
                         f"{', '.join(h[0] for h in hits[:4])}: {hits[0][2][:160]}")
        # AG-CONN-017: directives in what the server sends back
        texts: list[tuple[str, str]] = [("error text", probe.error or ""), ("WWW-Authenticate", probe.www_authenticate or "")]
        texts += [(f"serverInfo.{k}", v) for k, v in info.items() if isinstance(v, str)]
        texts += [(f"resource metadata `{k}`", v) for k, v in (probe.prm or {}).items() if isinstance(v, str)]
        texts += [("probe response", r) for r in fact.get("responses") or [] if isinstance(r, str)]
        for label, text in texts:
            m = _search(DIRECTIVE, text)
            if m:
                emit("AG-CONN-017", component_ids=cids, span=span, snippet=text[max(0, m.start() - 60): m.end() + 80],
                     match=f"{probe.url}:directive:{m.group(0).lower()}", kind=EvidenceKind.live, detail=label,
                     message=f"'{name}' returned text that gives instructions to the model in its {label} "
                             f"(\"{m.group(0)[:80]}\"). A harmless request should come back with data, not orders.")
                break

    @staticmethod
    def _read_only(tool: dict[str, Any]) -> bool:
        ann = tool.get("annotations") if isinstance(tool.get("annotations"), dict) else {}
        if ann.get("readOnlyHint") is True and ann.get("destructiveHint") is not True:
            return True
        return bool(_search(_READ_ONLY_NAME, snake(tool["name"])))

    @staticmethod
    def _tooldef(t: dict[str, Any]) -> ToolDef:
        return ToolDef(name=t["name"], title=t.get("title") if isinstance(t.get("title"), str) else None,
                       description=t.get("description") if isinstance(t.get("description"), str) else None,
                       input_schema=t.get("inputSchema") if isinstance(t.get("inputSchema"), dict) else {},
                       output_schema=t.get("outputSchema") if isinstance(t.get("outputSchema"), dict) else None,
                       annotations=t.get("annotations") if isinstance(t.get("annotations"), dict) else {}, origin="live_list")

    # -- OpenAPI and ai-plugin.json ------------------------------------------------------------------------
    def _openapi(self, doc: Doc) -> None:
        emit = self.ctx.emit
        d = doc.data
        cids = self._cid(doc.path)
        self._descriptions(doc, "AG-CONN-012", "OpenAPI")
        if doc.surface.id == "descriptor.ai_plugin":
            api = d.get("api") if isinstance(d.get("api"), dict) else {}
            auth = d.get("auth") if isinstance(d.get("auth"), dict) else {}
            url = str(api.get("url") or "")
            if url.lower().startswith("http://") and not _search(_LOCAL, host_of(url)):
                emit("AG-CONN-011", component_ids=cids, span=span_of(doc.text, url, path=doc.path), snippet=url[:200],
                     match=f"{doc.path}:http:{url}", kind=EvidenceKind.config, detail="key: api.url",
                     message=f"The plugin's API description is fetched over plain HTTP (`{url[:100]}`); anyone on the path can change "
                             "what the agent is told the API does.")
            if str(auth.get("type", "")).lower() == "none" and url:
                emit("AG-CONN-011", component_ids=cids, span=span_of(doc.text, '"auth"', path=doc.path), snippet='auth: {"type": "none"}',
                     match=f"{doc.path}:noauth", kind=EvidenceKind.config, severity=Severity.medium, detail="key: auth.type",
                     message="The plugin declares no authentication (`auth.type: none`): every call the agent makes is anonymous.")
            return
        servers = d.get("servers") if isinstance(d.get("servers"), list) else []
        for s in servers:
            url = str(s.get("url") or "") if isinstance(s, dict) else ""
            if url.lower().startswith("http://") and not _search(_LOCAL, host_of(url)):
                emit("AG-CONN-011", component_ids=cids, span=span_of(doc.text, url, path=doc.path), snippet=url[:200],
                     match=f"{doc.path}:http:{url}", kind=EvidenceKind.config, detail="key: servers.url",
                     message=f"The action's server is `{url[:100]}`: requests, including any credentials, travel over plain HTTP.")
                break
        schemes_v2 = [str(x).lower() for x in d.get("schemes")] if isinstance(d.get("schemes"), list) else []
        if schemes_v2 and "https" not in schemes_v2 and "http" in schemes_v2 and not _search(_LOCAL, str(d.get("host") or "")):
            emit("AG-CONN-011", component_ids=cids, span=span_of(doc.text, "schemes", path=doc.path), snippet="schemes: [http]",
                 match=f"{doc.path}:http:schemes", kind=EvidenceKind.config, detail="key: schemes",
                 message="The action is offered over plain HTTP only (`schemes: [http]`).")
        comps = d.get("components") if isinstance(d.get("components"), dict) else {}
        sec = comps.get("securitySchemes") if isinstance(comps.get("securitySchemes"), dict) else \
            d.get("securityDefinitions") if isinstance(d.get("securityDefinitions"), dict) else {}
        paths = d.get("paths") if isinstance(d.get("paths"), dict) else {}
        ops: list[tuple[str, str, dict[str, Any]]] = []
        for p, item in paths.items():
            if isinstance(item, dict):
                ops += [(str(p), m, item[m]) for m in _METHODS if isinstance(item.get(m), dict)]
        for sname, scheme in sec.items():
            if isinstance(scheme, dict) and str(scheme.get("type", "")).lower() == "apikey" and str(scheme.get("in", "")).lower() == "query":
                emit("AG-CONN-011", component_ids=cids, span=span_of(doc.text, str(sname), path=doc.path),
                     snippet=f"{sname}: apiKey in query", match=f"{doc.path}:query-key:{sname}", kind=EvidenceKind.config,
                     detail=f"key: components.securitySchemes.{sname}.in",
                     message=f"Security scheme '{sname}' sends the API key in the query string, where it is written to logs, "
                             "history and referrer headers.")
                break
        if not sec and not d.get("security") and ops and not any(o.get("security") for _, _, o in ops):
            writes = [f"{m.upper()} {p}" for p, m, _ in ops if m not in ("get", "head", "options")]
            emit("AG-CONN-011", component_ids=cids, span=span_of(doc.text, "paths", path=doc.path), snippet=", ".join(writes[:4]) or "paths",
                 match=f"{doc.path}:nosecurity", kind=EvidenceKind.config, severity=None if writes else Severity.medium,
                 message="The action declares no security scheme" + (f", and it has operations that change data ({', '.join(writes[:3])})"
                                                                     if writes else "") + ". Calls made by the agent are anonymous.")
        # AG-CONN-013
        n = 0
        for p, m, op in ops:
            text = " ".join(str(op.get(k) or "") for k in ("operationId", "summary"))
            destructive = m == "delete" or (m in ("post", "put", "patch") and _search(_DESTRUCTIVE_OP, snake(text).replace("_", " ")))
            if not destructive or op.get("x-openai-isConsequential") is True:
                continue
            needle = str(op.get("operationId") or p)
            emit("AG-CONN-013", component_ids=cids, span=span_of(doc.text, p, needle, path=doc.path) if needle != p
                 else span_of(doc.text, p, path=doc.path), snippet=f"{m.upper()} {p}", match=f"{doc.path}:conseq:{m}:{p}",
                 kind=EvidenceKind.config, detail=f"key: paths.{p}.{m}",
                 message=f"`{m.upper()} {p}`{' (' + str(op.get('operationId')) + ')' if op.get('operationId') else ''} changes or "
                         "removes data but is not marked `x-openai-isConsequential: true`, so an agent may call it without asking.")
            n += 1
            if n >= 5:
                break

    def _descriptions(self, doc: Doc, rule: str, what: str) -> None:
        values: list[tuple[tuple[str, ...], str, Span]] = self.ctx.data.get("config_values", {}).get(doc.path, [])  # type: ignore[union-attr]
        for keypath, text, span in values:
            key = next((k.lower() for k in reversed(keypath) if not k.isdigit()), "")
            if key not in ("description", "summary", "description_for_model", "description_for_human", "title", "name", "examples",
                           "x-description", "instructions"):
                continue
            m = _search(DIRECTIVE, text)
            if m:
                self.ctx.emit(rule, component_ids=self._cid(doc.path), span=span, snippet=text[max(0, m.start() - 60): m.end() + 80],
                              match=f"{doc.path}:{'.'.join(keypath)}:{m.group(0).lower()}", kind=EvidenceKind.config,
                              detail=f"key: {'.'.join(keypath)}",
                              message=f"The {what} field `{'.'.join(keypath)[:80]}` gives the model an instruction "
                                      f"(\"{m.group(0)[:80]}\"). Agents read these descriptions when they decide how to call the "
                                      "action.")
                return

    # -- A2A agent cards -------------------------------------------------------------------------------------
    def _agent_card(self, doc: Doc) -> None:
        emit = self.ctx.emit
        d = doc.data
        cids = self._cid(doc.path)
        url = str(d.get("url") or "")
        if url.lower().startswith("http://") and not _search(_LOCAL, host_of(url)):
            emit("AG-CONN-014", component_ids=cids, span=span_of(doc.text, url, path=doc.path), snippet=url[:200], match=f"{doc.path}:http",
                 kind=EvidenceKind.config, detail="key: url",
                 message=f"The agent card's endpoint is `{url[:100]}`: tasks and results travel over plain HTTP.")
        self._descriptions(doc, "AG-CONN-014", "agent card")
        if not d.get("signatures"):
            emit("AG-CONN-014", component_ids=cids, span=span_of(doc.text, '"name"', path=doc.path), snippet=str(d.get("name") or doc.path)[:120],
                 match=f"{doc.path}:unsigned", kind=EvidenceKind.config, severity=Severity.low,
                 message="The agent card carries no signature, so nothing shows that the named provider published it.")


__all__ = ["ConnectorAnalyzer", "DIRECTIVE", "host_of", "registrable", "vendor_claim", "version_tuple"]
