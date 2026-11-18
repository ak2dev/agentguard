"""Live MCP servers (PLAN §5.4 engine N; spec/sandbox.md §6.3 and §6.4).

Remote (``mcp+https://…``): read-only protocol calls only. ``server/discover``
with a fallback to the older ``initialize`` handshake, then ``tools/list``,
``prompts/list`` and ``resources/list``; the unauthenticated response and its
challenge; protected-resource and authorization-server metadata. The tool list
is read a second time as a different client, because a server can serve one
set of definitions to a scanner and another to an agent. No tool is called.

Local (``mcp+stdio:<command>``): the command is never started on the host. It
is scanned as a one-entry client configuration; when a sandbox runtime is
available the server is started inside it and what it serves is recorded.

Either way the server is represented in the tree by a one-entry client
configuration, so the configuration, definition, authorization and flow rules
all see it, and every definition is hashed the way ``agentguard.lock`` hashes
it.
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..core.lock import tool_hash
from ..core.models import ImmutableRef, LimitEvent, RemoteProbe, Report, SourceRef, ToolDef
from ..core.models.component import canonical_json
from ..core.models.enums import SourceKind
from ..core.textutil import visible_escape
from ..core.tree import ArtifactTree
from . import AcquireContext, AcquireError, Acquired
from .targets import Target, TargetError, parse_target

CONFIG_PATH = "live-mcp/.mcp.json"
# The identity the listing is repeated with. A server that hides tools from a scanner keys on the client's name,
# so the second listing names an ordinary coding agent.
AGENT_IDENTITY = {"client_name": "claude-code", "client_version": "2.1.0", "user_agent": "claude-code/2.1.0 (cli)"}
_SAFE = re.compile(r"[^A-Za-z0-9._-]+")
_RUNNERS = {"npx", "bunx", "pnpx", "uvx", "pipx", "uv", "node", "python", "python3", "py", "deno", "bun", "docker", "podman"}


def server_label(url: str) -> str:
    return _SAFE.sub("-", urllib.parse.urlsplit(url).hostname or "").strip("-") or "remote"


def stdio_label(argv: list[str]) -> str:
    """A name for a server given only its launch command: the package or script it starts."""
    rest = [a for a in argv[1:] if a and not a.startswith("-") and a not in ("run", "exec", "dlx", "x", "tool", "-m")]
    base = Path(argv[0].replace("\\", "/")).name.lower()
    base = base[:-4] if base.endswith((".exe", ".cmd", ".bat")) else base
    pick = rest[0] if base in _RUNNERS and rest else argv[0]
    pick = pick.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    pick = pick.split("@", 1)[0] if not pick.startswith("@") and "@" in pick else pick
    for ext in (".py", ".js", ".mjs", ".cjs", ".ts"):
        pick = pick[: -len(ext)] if pick.endswith(ext) else pick
    return _SAFE.sub("-", pick).strip("-") or "stdio-server"


def tool_def(t: dict[str, Any]) -> ToolDef:
    return ToolDef(name=str(t.get("name")), title=t.get("title") if isinstance(t.get("title"), str) else None,
                   description=t.get("description") if isinstance(t.get("description"), str) else None,
                   input_schema=t.get("inputSchema") if isinstance(t.get("inputSchema"), dict) else {},
                   output_schema=t.get("outputSchema") if isinstance(t.get("outputSchema"), dict) else None,
                   annotations=t.get("annotations") if isinstance(t.get("annotations"), dict) else {}, origin="live_list")


def _sha(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def definition_hashes(tools: list[dict[str, Any]], prompts: list[dict[str, Any]], resources: list[dict[str, Any]],
                      instructions: str | None) -> dict[str, Any]:
    """A hash per served definition: tools as the lockfile hashes them, prompts and resources over their canonical JSON."""
    return {
        "tools": {str(t["name"]): tool_hash(tool_def(t).canonical()) for t in tools if isinstance(t.get("name"), str)},
        "prompts": {str(p["name"]): _sha(p) for p in prompts if isinstance(p.get("name"), str)},
        "resources": {str(r.get("uri") or r.get("name")): _sha(r) for r in resources if r.get("uri") or r.get("name")},
        "server_instructions_sha256": hashlib.sha256(instructions.encode("utf-8")).hexdigest() if instructions else None,
    }


def served_fingerprint(hashes: dict[str, Any], server_info: dict[str, Any] | None) -> str:
    """Identity of what a server served: unchanged definitions give the same value, any change a new one."""
    return "sha256:" + _sha({"definitions": hashes, "server": server_info or {}})


def _tree(target: Target, config: dict[str, Any], resolved: str, limits: Any, detail: str) -> ArtifactTree:
    source: SourceRef | ImmutableRef = ImmutableRef(kind=SourceKind.remote_mcp, locator=target.raw[:300], resolved=resolved)
    tree = ArtifactTree(source=source, display_root=target.raw)
    tree.add(CONFIG_PATH, (json.dumps(config, indent=2, sort_keys=True) + "\n").encode("utf-8"), limits)
    tree.limit_events.append(LimitEvent(kind="remote", path=CONFIG_PATH, detail=detail))
    return tree


# ------------------------------------------------------------------ remote --
def acquire_remote(target: Target, ctx: AcquireContext) -> Acquired:
    from ..net.remote import list_as, probe_server
    from ..net.safe_http import SafeHttpClient

    url = target.url
    scheme = urllib.parse.urlsplit(url).scheme.lower()
    if scheme not in ("https", "http"):
        raise AcquireError(f"{url}: a live MCP endpoint is https:// (plain http:// only on this machine)")
    http: Any = ctx.http or SafeHttpClient(timeout=15, deadline_s=60, max_bytes=8 * 1024 * 1024, allow_http_loopback=True)
    name = server_label(url)
    probe = probe_server(http, name, url, CONFIG_PATH, metadata=not ctx.probe_only, auth=True, token=ctx.mcp_token)
    if not probe.reachable and (probe.error or "").startswith("blocked:"):
        raise AcquireError(f"{url}: refused ({(probe.error or '')[9:]})")
    hashes = definition_hashes(probe.tools, probe.prompts, probe.resources, probe.instructions)
    fact: dict[str, Any] = {}
    notes: list[str] = []
    if not probe.reachable:
        notes.append(f"{url}: not reachable ({probe.error or 'no answer'}); only the endpoint's address and transport were evaluated")
    elif ctx.probe_only:
        notes.append(f"{url}: posture probe only (HTTP {probe.status_unauth}, TLS {probe.tls_version or 'unknown'}); "
                     "no tool, prompt or resource was listed or called")
    else:
        who = "with the token in $AGENTGUARD_MCP_TOKEN" if ctx.mcp_token else "unauthenticated"
        if probe.protocol_version is None:
            notes.append(f"{url}: the server did not list its definitions to an {who} client (HTTP {probe.status_unauth}); "
                         "only its transport and authorization posture were evaluated")
        else:
            notes.append(f"{url}: protocol {probe.protocol_version}, listed {who}: {len(probe.tools)} tool(s), "
                         f"{len(probe.prompts)} prompt(s), {len(probe.resources)} resource(s); read-only, no tool was called")
            if ctx.mcp_identities:
                by_identity: dict[str, dict[str, str]] = {"agentguard": hashes["tools"]}
                again = list_as(http, url, token=ctx.mcp_token, **AGENT_IDENTITY)
                if again is not None:
                    by_identity[AGENT_IDENTITY["client_name"]] = definition_hashes(again, [], [], None)["tools"]
                if ctx.mcp_token:
                    anonymous = list_as(http, url, client_name="agentguard", client_version="0.1")
                    if anonymous is not None:
                        by_identity["anonymous"] = definition_hashes(anonymous, [], [], None)["tools"]
                if len(by_identity) >= 2:
                    fact["tools_by_identity"] = by_identity
                    same = all(v == hashes["tools"] for v in by_identity.values())
                    notes.append(f"{url}: listed again as {', '.join(k for k in by_identity if k != 'agentguard')}: "
                                 + ("the same definitions were served" if same else "the definitions DIFFER by client"))
                else:
                    notes.append(f"{url}: the second listing (as a different client) got no answer, so cloaking was not checked")
    resolved = served_fingerprint(hashes, probe.server_info)
    config = {"mcpServers": {name: {"type": "http", "url": url}}}
    tree = _tree(target, config, resolved, ctx.limits,
                 f"what {url} returned to a read-only client (no tool was called); a remote server can return different "
                 "definitions at any time")
    hosts = list(getattr(http, "hosts_contacted", []) or [])
    host = urllib.parse.urlsplit(url).hostname
    if host and host not in hosts:
        hosts.append(host)
    features = ["auth_checks"] if ctx.probe_only else ["live_metadata", "auth_checks"]
    return Acquired(target=target, tree=tree, probes=[probe], hosts=hosts, notes=notes, network=features,
                    facts={"endpoints": {url: fact}} if fact else {})


# ------------------------------------------------------------------- stdio --
def acquire_stdio_config(target: Target, ctx: AcquireContext) -> Acquired:
    argv = list(target.command)
    name = stdio_label(argv)
    config = {"mcpServers": {name: {"command": argv[0], "args": argv[1:]}}}
    facts: dict[str, dict] = {}
    notes: list[str] = []
    resolved = "sha256:" + _sha(argv)
    if ctx.sandbox is None:
        notes.append(f"mcp+stdio: `{' '.join(argv)[:120]}` was scanned as configuration only. A local server is started only "
                     "inside the sandbox (`--dynamic on`, or `agentguard mcp inspect`), never on this machine")
    else:
        from ..sandbox import SandboxUnavailable

        try:
            listing = ctx.sandbox.enumerate_server(argv, cwd=ctx.cwd)       # type: ignore[attr-defined]
        except SandboxUnavailable as exc:
            raise AcquireError(f"mcp+stdio: the sandbox is not available, so the server was not started: {exc}") from exc
        served = served_record(listing)
        if listing.get("error") and not served["tools"]:
            notes.append(f"mcp+stdio: the server did not answer inside the sandbox ({str(listing['error'])[:160]}); "
                         "its command was scanned as configuration only")
        else:
            facts["served"] = {name: served}
            facts["served_tools"] = {name: [str(t["name"]) for t in served["tools"]]}
            if listing.get("tool_results"):
                facts["tool_results"] = {name: [r for r in listing["tool_results"] if isinstance(r, dict)]}
            hashes = definition_hashes(served["tools"], served["prompts"], served["resources"], served["instructions"])
            resolved = served_fingerprint(hashes, served["server_info"])
            notes.append(f"mcp+stdio: started inside the sandbox ({listing.get('level') or 'baseline'} level); it served "
                         f"{len(served['tools'])} tool(s), {len(served['prompts'])} prompt(s), {len(served['resources'])} resource(s)")
    tree = _tree(target, config, resolved, ctx.limits,
                 "a local server given by its launch command; the command was not started on this machine")
    return Acquired(target=target, tree=tree, notes=notes, facts=facts)


def served_record(listing: dict[str, Any]) -> dict[str, Any]:
    """The part of a sandbox enumeration the definition rules read, with everything of an unexpected type dropped."""
    def dicts(key: str) -> list[dict[str, Any]]:
        return [x for x in listing.get(key) or [] if isinstance(x, dict)][:500]

    info = listing.get("server_info")
    return {
        "tools": [t for t in dicts("tools") if isinstance(t.get("name"), str)],
        "prompts": dicts("prompts"), "resources": dicts("resources"),
        "instructions": listing["instructions"] if isinstance(listing.get("instructions"), str) else None,
        "server_info": info if isinstance(info, dict) else None,
        "protocol_version": str(listing.get("protocol_version") or "") or None,
    }


# ----------------------------------------------------------------- inspect --
@dataclass
class Inspection:
    endpoint: str
    transport: str                              # http | stdio
    name: str = ""
    reachable: bool = True
    error: str = ""
    protocol_version: str | None = None
    server_info: dict[str, Any] | None = None
    status_unauth: int | None = None
    tools: list[dict[str, Any]] = field(default_factory=list)
    prompts: list[dict[str, Any]] = field(default_factory=list)
    resources: list[dict[str, Any]] = field(default_factory=list)
    instructions: str | None = None
    hashes: dict[str, Any] = field(default_factory=dict)
    fingerprint: str = ""
    identities: dict[str, dict[str, str]] | None = None
    notes: list[str] = field(default_factory=list)
    report: Report | None = None

    def identities_differ(self) -> bool | None:
        if not self.identities or len(self.identities) < 2:
            return None
        values = list(self.identities.values())
        return any(v != values[0] for v in values[1:])

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "endpoint": self.endpoint, "transport": self.transport, "name": self.name, "reachable": self.reachable,
            "error": self.error or None, "protocol_version": self.protocol_version, "server_info": self.server_info,
            "status_unauthenticated": self.status_unauth, "fingerprint": self.fingerprint,
            "tools": [{"name": t.get("name"), "sha256": self.hashes.get("tools", {}).get(str(t.get("name"))), "definition": t}
                      for t in self.tools],
            "prompts": [{"name": p.get("name"), "sha256": self.hashes.get("prompts", {}).get(str(p.get("name"))), "definition": p}
                        for p in self.prompts],
            "resources": [{"uri": r.get("uri"), "sha256": self.hashes.get("resources", {}).get(str(r.get("uri") or r.get("name"))),
                           "definition": r} for r in self.resources],
            "server_instructions": self.instructions,
            "server_instructions_sha256": self.hashes.get("server_instructions_sha256"),
            "identities": self.identities, "identities_differ": self.identities_differ(),
            "tools_called": 0, "notes": self.notes,
        }
        if self.report is not None:
            r = self.report
            out["scan"] = {"verdict": r.verdict.value, "score": r.score, "risk_tier": r.risk_tier.value,
                           "findings": [{"id": f.key, "severity": f.severity.value, "title": f.title, "risk": f.message,
                                         "location": f"{f.location.file}:{f.location.start.line}"} for f in r.findings]}
        return out

    def print(self, console: Any) -> None:
        from rich.markup import escape
        from rich.table import Table

        def clean(text: Any, width: int = 110) -> str:
            flat = " ".join(str(text or "").split())
            return escape(visible_escape(flat[:width] + ("…" if len(flat) > width else "")))

        info = self.server_info or {}
        head = f"[bold]{clean(self.endpoint, 160)}[/bold] ({self.transport})"
        if info.get("name"):
            head += f" · {clean(info.get('name'), 60)} {clean(info.get('version'), 30)}"
        if self.protocol_version:
            head += f" · protocol {clean(self.protocol_version, 20)}"
        console.print(head)
        if not self.reachable or self.error:
            console.print(f"[yellow]{clean(self.error or 'the server did not answer', 300)}[/yellow]")
        t = Table(title=f"Tools ({len(self.tools)}), listed without calling any", title_justify="left")
        for col in ("Name", "Hints", "Description", "sha256"):
            t.add_column(col, overflow="fold")
        for tool in self.tools:
            ann = tool.get("annotations") if isinstance(tool.get("annotations"), dict) else {}
            hints = ", ".join(k[:-4] for k in ("readOnlyHint", "destructiveHint", "openWorldHint", "idempotentHint") if ann.get(k) is True)
            t.add_row(clean(tool.get("name"), 60), hints, clean(tool.get("description")),
                      str(self.hashes.get("tools", {}).get(str(tool.get("name")), ""))[:16])
        console.print(t)
        for title, items, key in (("Prompts", self.prompts, "name"), ("Resources", self.resources, "uri")):
            if items:
                p = Table(title=f"{title} ({len(items)})", title_justify="left")
                for col in ("Name" if key == "name" else "URI", "Description", "sha256"):
                    p.add_column(col, overflow="fold")
                for item in items:
                    ident = str(item.get(key) or item.get("name") or "")
                    p.add_row(clean(ident, 80), clean(item.get("description")),
                              str(self.hashes.get(title.lower(), {}).get(ident, ""))[:16])
                console.print(p)
        if self.instructions:
            console.print(f"Server instructions ({len(self.instructions)} characters, sha256 "
                          f"{str(self.hashes.get('server_instructions_sha256'))[:16]}): {clean(self.instructions, 240)}")
        differ = self.identities_differ()
        if differ is True:
            console.print("[bold red]The server lists different tools to different clients.[/bold red] "
                          f"Identities compared: {escape(', '.join(self.identities or {}))}")
        elif differ is False:
            console.print(f"[green]Same definitions served to {escape(' and '.join(self.identities or {}))}.[/green]")
        if self.fingerprint:
            console.print(f"Fingerprint of what was served: {self.fingerprint}")
        for note in self.notes:
            console.print(f"[dim]{clean(note, 400)}[/dim]")
        if self.report is not None:
            r = self.report
            console.print(f"[bold]Definition rules:[/bold] verdict {r.verdict.value}, score {r.score}, {len(r.findings)} finding(s)")
            for f in r.findings[:40]:
                console.print(f"  {escape('[' + f.severity.value + ']')} [bold]{f.key}[/bold] {clean(f.message, 220)}")
            if len(r.findings) > 40:
                console.print(f"  … {len(r.findings) - 40} more (see `agentguard report`)")


def inspect_endpoint(endpoint: str, *, two_identities: bool = True, scan: bool = True, cwd: Path | None = None,
                     http: Any = None, sandbox: Any = None, env: dict[str, str] | None = None) -> Inspection:
    """List what a server serves without calling anything, hash each definition, and (``scan``) run the
    definition rules on it. A remote endpoint gets read-only protocol calls; a ``mcp+stdio:`` command is
    started only inside the sandbox."""
    from ..core.models import NetworkOptions
    from ..runner import MCP_TOKEN_VAR, ScanRequest, UsageError, _env, run_scan

    raw = endpoint.strip()
    if raw.lower().startswith(("https://", "http://")):
        raw = "mcp+" + raw
    try:
        target = parse_target(raw)
    except TargetError as exc:
        raise UsageError(str(exc)) from exc
    if target.kind not in ("mcp_remote", "mcp_stdio"):
        raise UsageError("mcp inspect takes mcp+https://… (or https://…) for a remote server, or mcp+stdio:<command> for a local one")
    cwd = cwd or Path.cwd()
    if target.kind == "mcp_stdio" and sandbox is None:
        from ..sandbox import SandboxUnavailable
        from ..sandbox.runtime import default_runtime

        try:
            sandbox = default_runtime()
        except SandboxUnavailable as exc:
            raise UsageError(f"a local server is started only inside the sandbox, and the sandbox is not available: {exc}") from exc

    req = ScanRequest(targets=[raw], profile="quick", llm="off", context="none", cwd=cwd, http=http, sandbox=sandbox, env=env,
                      network=NetworkOptions(), mcp_identities=two_identities)
    part: Acquired
    report: Report | None = None
    if scan:
        outcome = run_scan(req)
        part, report = outcome.acquired[0], outcome.report
    else:
        from . import acquire

        actx = AcquireContext(cwd=cwd, http=http, sandbox=sandbox, mcp_identities=two_identities,
                              mcp_token=_env(req).get(MCP_TOKEN_VAR) or None)
        try:
            part = acquire(target, actx)
        except AcquireError as exc:
            raise UsageError(str(exc)) from exc

    out = Inspection(endpoint=raw, transport="http" if target.kind == "mcp_remote" else "stdio", notes=list(part.notes), report=report)
    if target.kind == "mcp_remote":
        probe = part.probes[0] if part.probes else RemoteProbe(server_name=server_label(target.url), url=target.url)
        out.name, out.reachable, out.error = probe.server_name, probe.reachable, probe.error or ""
        out.protocol_version, out.server_info, out.status_unauth = probe.protocol_version, probe.server_info, probe.status_unauth
        out.tools, out.prompts, out.resources, out.instructions = probe.tools, probe.prompts, probe.resources, probe.instructions
        by_identity = ((part.facts.get("endpoints") or {}).get(target.url) or {}).get("tools_by_identity")
        out.identities = by_identity if two_identities and isinstance(by_identity, dict) else None
    else:
        out.name = stdio_label(list(target.command))
        served = (part.facts.get("served") or {}).get(out.name)
        if served is None:
            out.reachable, out.error = False, "the server did not answer inside the sandbox"
        else:
            out.tools, out.prompts, out.resources = served["tools"], served["prompts"], served["resources"]
            out.instructions, out.server_info, out.protocol_version = served["instructions"], served["server_info"], served["protocol_version"]
    out.hashes = definition_hashes(out.tools, out.prompts, out.resources, out.instructions)
    out.fingerprint = served_fingerprint(out.hashes, out.server_info) if (out.tools or out.prompts or out.resources) else ""
    return out


__all__ = ["AGENT_IDENTITY", "CONFIG_PATH", "Inspection", "acquire_remote", "acquire_stdio_config", "definition_hashes",
           "inspect_endpoint", "served_fingerprint", "served_record", "server_label", "stdio_label", "tool_def"]
