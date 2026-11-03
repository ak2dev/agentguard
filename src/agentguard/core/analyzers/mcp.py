"""MCP analyzers: unit building (tool metadata → scannable text), client
configuration (AG-MCP-CFG-*), and tool/prompt/resource metadata (AG-MCP-META-*)."""

from __future__ import annotations

import ipaddress
import shlex
import urllib.parse
from dataclasses import dataclass
from typing import Any, ClassVar

import regex

from ..artifacts import TextUnit
from ..extract.tools import extract_tools
from ..mcp_config import ClientConfig, ServerEntry, docker_image, exe_name, package_arg, split_package_spec
from ..models import Component, Span, ToolDef
from ..models.enums import ArtifactRole, CapLabel, ComponentKind, Confidence, EvidenceKind, Severity, Transport
from ..normalize.unicode import normalize
from ..secrets import find_secrets, is_placeholder, shannon_entropy
from ..textutil import TIMEOUT
from .base import Context
from .heuristics import damerau_levenshtein, finditer, search

SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "cmd", "powershell", "pwsh"}
INTERPRETERS = {"python", "python3", "node", "deno", "bun", "perl", "ruby", "php", "osascript"}
_INLINE_FLAGS = {"-c", "-e", "--eval", "-p", "--print", "-r", "eval", "-Command", "-command", "-EncodedCommand", "-enc", "-ec"}
_SHELL_META = regex.compile(r"[;&|`<>]|\$\(|\$\{|\bcurl\b|\bwget\b")
_SECRET_NAME = regex.compile(r"(?i)(key|token|secret|passw(or)?d|pwd|credential|auth|bearer|cookie|session)")
# Values that reference the environment / client inputs instead of holding a literal.
_ENV_REF = regex.compile(r"\$\{[^}]+\}|\$[A-Z_][A-Z0-9_]*\b|%[A-Z_][A-Z0-9_]*%|\$env:[A-Za-z_]\w*|\{\{[^}]+\}\}")
_METADATA_HOSTS = {"169.254.169.254", "fd00:ec2::254", "metadata.google.internal", "metadata", "100.100.100.200", "169.254.170.2"}
_SENSITIVE_MOUNT = regex.compile(
    r"^(?:/|~|\$HOME|\$\{HOME\}|%USERPROFILE%|/root|/home/[^/:]+|/Users/[^/:]+|[A-Za-z]:\\Users\\[^\\:]+)/?$"
    r"|(?:^|/)\.(?:ssh|aws|kube|gnupg|docker|config/gcloud|azure)(?:/|$)"
)


def _loopback(host: str) -> bool:
    h = host.strip("[]").lower()
    if h in ("localhost",) or h.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def _ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Units builder: turns tool metadata into TextUnits for rules and detectors.
# ---------------------------------------------------------------------------
@dataclass
class ToolHandler:
    component_id: str
    path: str
    tool: str
    start: int
    end: int
    params: list[str]


def _unit(comp: Component, path: str, span: Span | None, role: str, scope: str, text: str, label: str) -> TextUnit:
    return TextUnit(path=path, component_id=comp.id, role=role, scope=scope, text=text, norm=normalize(text),
                    base=None, anchor_span=span, label=label)


def tool_units(comp: Component, tool: ToolDef) -> list[TextUnit]:
    path = tool.span.path if tool.span else comp.root
    span = tool.span
    units: list[TextUnit] = []
    if tool.description:
        units.append(_unit(comp, path, span, "tool", "tool_text", tool.description, f"tool:{tool.name}.description"))
    if tool.title:
        units.append(_unit(comp, path, span, "tool_title", "tool_text", tool.title, f"tool:{tool.name}.title"))
    props = (tool.input_schema or {}).get("properties") or {}
    if isinstance(props, dict):
        for pname, pschema in props.items():
            if not isinstance(pschema, dict):
                continue
            if isinstance(pschema.get("description"), str):
                units.append(_unit(comp, path, span, "tool_param", "tool_text", pschema["description"],
                                   f"tool:{tool.name}.param:{pname}.description"))
            if isinstance(pschema.get("title"), str):
                units.append(_unit(comp, path, span, "tool_title", "tool_text", pschema["title"], f"tool:{tool.name}.param:{pname}.title"))
            for key in ("enum", "examples"):
                vals = pschema.get(key)
                if isinstance(vals, list):
                    text = "\n".join(str(v) for v in vals if isinstance(v, (str, int, float)))
                    if text.strip():
                        units.append(_unit(comp, path, span, "tool_enum", "tool_text", text, f"tool:{tool.name}.param:{pname}.{key}"))
            if isinstance(pschema.get("default"), str) and pschema["default"].strip():
                units.append(_unit(comp, path, span, "tool_default", "tool_text", pschema["default"], f"tool:{tool.name}.param:{pname}.default"))
    for k, v in (tool.annotations or {}).items():
        if isinstance(v, str) and v.strip():
            units.append(_unit(comp, path, span, "tool_annotation", "tool_text", v, f"tool:{tool.name}.annotations.{k}"))
    # The output schema guides "clients and LLMs" (MCP 2026-07-28, Tools), so its text reaches the model too.
    for where, text in _schema_texts(tool.output_schema):
        units.append(_unit(comp, path, span, "tool_output", "tool_text", text, f"tool:{tool.name}.outputSchema.{where}"))
    return units


_SCHEMA_TEXT_KEYS = ("description", "title")
_DATA_KEYS = ("enum", "const", "default", "examples")  # values are instance data, not subschemas
# Keywords whose value maps arbitrary names to subschemas: a property called "default" is a schema.
_MAP_KEYWORDS = frozenset({"properties", "patternProperties", "$defs", "definitions", "dependentSchemas"})


def _schema_children(node: Any, is_map: bool = False) -> list[tuple[str, Any, bool]]:
    """(key, child, child_is_map) for the subschemas under a schema object, a keyword map or a list."""
    if isinstance(node, list):
        return [(f"[{i}]", v, False) for i, v in enumerate(node) if isinstance(v, (dict, list))]
    if not isinstance(node, dict):
        return []
    if is_map:
        return [(str(k), v, False) for k, v in node.items() if isinstance(v, (dict, list))]
    return [(str(k), v, k in _MAP_KEYWORDS) for k, v in node.items() if k not in _DATA_KEYS and isinstance(v, (dict, list))]


def _schema_texts(schema: Any, limit: int = 500) -> list[tuple[str, str]]:
    """(path, text) for every description, title and string enum/example/default/const in a schema."""
    out: list[tuple[str, str]] = []
    stack: list[tuple[Any, str, bool]] = [(schema, "", False)]
    while stack and len(out) < limit:
        node, where, is_map = stack.pop()
        if isinstance(node, dict) and not is_map:
            for k in _SCHEMA_TEXT_KEYS:
                if isinstance(node.get(k), str) and node[k].strip():
                    out.append((f"{where}.{k}" if where else k, node[k]))
            for k in _DATA_KEYS:
                vals = node.get(k) if isinstance(node.get(k), list) else [node.get(k)]
                text = "\n".join(x for x in vals if isinstance(x, str))
                if text.strip():
                    out.append((f"{where}.{k}" if where else k, text))
        stack.extend((v, f"{where}{k}" if k.startswith("[") else (f"{where}.{k}" if where else k), m)
                     for k, v, m in reversed(_schema_children(node, is_map)))
    return out


class McpUnitsBuilder:
    id: ClassVar[str] = "mcp.units"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = ()

    def run(self, ctx: Context) -> None:
        inv = ctx.inventory
        extra: list[TextUnit] = ctx.data.setdefault("extra_units", [])  # type: ignore[assignment]
        handlers: list[ToolHandler] = ctx.data.setdefault("tool_handlers", [])  # type: ignore[assignment]
        # Tool registrations extracted from server source code.
        for at in ctx.texts("source_code"):
            comp = inv.components.get(at.artifact.component_id)
            if comp is None or comp.kind != ComponentKind.mcp_server:
                continue
            known = {t.name for t in comp.tools}
            for ex in extract_tools(at.path, at.text, at.artifact.language):
                handlers.append(ToolHandler(comp.id, at.path, ex.tool.name, ex.handler_start, ex.handler_end, ex.params))
                if ex.tool.name not in known:
                    comp.tools.append(ex.tool)
                    known.add(ex.tool.name)
        # Opt-in live metadata (read-only */list results recorded before the scan).
        if ctx.options.network.live_metadata:
            for probe in ctx.options.remote_probes:
                sid = next((cid for (path, _p, name), cid in inv.server_components.items()
                            if name == probe.server_name and (not probe.config_path or path == probe.config_path)), None)
                comp = inv.components.get(sid or "")
                if comp is None:
                    continue
                span = comp.server.config_span if comp.server else None
                known = {t.name for t in comp.tools}
                for t in probe.tools:
                    if isinstance(t.get("name"), str) and t["name"] not in known:
                        comp.tools.append(ToolDef(
                            name=t["name"], title=t.get("title") if isinstance(t.get("title"), str) else None,
                            description=t.get("description") if isinstance(t.get("description"), str) else None,
                            input_schema=t.get("inputSchema") if isinstance(t.get("inputSchema"), dict) else {},
                            annotations=t.get("annotations") if isinstance(t.get("annotations"), dict) else {},
                            origin="live_list", span=span))
                if probe.instructions and not comp.instructions:
                    comp.instructions = probe.instructions
                if probe.server_info and isinstance(probe.server_info.get("version"), str):
                    comp.version = probe.server_info["version"]
        for comp in sorted(inv.components.values(), key=lambda c: c.id):
            for tool in comp.tools:
                extra.extend(tool_units(comp, tool))
            path = comp.root
            if comp.instructions:
                extra.append(_unit(comp, path, Span(path=path), "server_instructions", "server_instructions",
                                   comp.instructions, "server.instructions"))
            for pr in comp.prompts:
                text = "\n".join(filter(None, [pr.description or "", *pr.messages]))
                if text.strip():
                    extra.append(_unit(comp, pr.span.path if pr.span else path, pr.span, "prompt", "tool_text", text, f"prompt:{pr.name}"))
            for rs in comp.resources:
                text = "\n".join(filter(None, [rs.name or "", rs.title or "", rs.description or ""]))
                if text.strip():
                    extra.append(_unit(comp, rs.span.path if rs.span else path, rs.span, "resource", "tool_text", text, f"resource:{rs.uri}"))
        # Client-config commands become "command" units (e.g. for AG-MCP-CFG-006).
        for cfg in inv.configs:
            for entry in cfg.servers:
                sid = inv.server_components.get((cfg.path, entry.project or "", entry.name))
                comp = inv.components.get(sid or "")
                if comp is None or not entry.spec.command:
                    continue
                cmdline = " ".join([entry.spec.command, *entry.spec.args])
                extra.append(_unit(comp, cfg.path, Span(path=cfg.path, start_line=entry.line), "client_config",
                                   "command", cmdline, f"server:{entry.name}.command"))


# ---------------------------------------------------------------------------
# Client configuration
# ---------------------------------------------------------------------------
class McpConfigAnalyzer:
    id: ClassVar[str] = "mcp.config"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = (
        "AG-MCP-CFG-001", "AG-MCP-CFG-002", "AG-MCP-CFG-003", "AG-MCP-CFG-004", "AG-MCP-CFG-007",
        "AG-MCP-CFG-008", "AG-MCP-CFG-009", "AG-MCP-CFG-010", "AG-MCP-CFG-011", "AG-MCP-CFG-012",
        "AG-MCP-CFG-013", "AG-MCP-CFG-014", "AG-MCP-CFG-015", "AG-MCP-CFG-016", "AG-MCP-CFG-017",
        "AG-MCP-CFG-018", "AG-MCP-CFG-019", "AG-MCP-CFG-020", "AG-MCP-CFG-021", "AG-MCP-CFG-022",
        "AG-MCP-CFG-023", "AG-SYS-001",
    )

    def run(self, ctx: Context) -> None:
        inv = ctx.inventory
        for cfg in inv.configs:
            if cfg.error:
                cc = next((c for c in inv.components.values() if c.kind == ComponentKind.mcp_client_config and c.root == cfg.path), None)
                ctx.emit("AG-SYS-001", component_ids=[cc.id] if cc else [], span=Span(path=cfg.path), snippet=cfg.path,
                         match=f"unparseable:{cfg.path}", kind=EvidenceKind.loader, detail=cfg.error,
                         message=f"MCP client config could not be parsed ({cfg.error}); it was not analyzed.")
            self._settings(ctx, cfg)
            for entry in cfg.servers:
                sid = inv.server_components.get((cfg.path, entry.project or "", entry.name))
                if sid is None:
                    continue
                self._server(ctx, cfg, entry, sid)
        self._cross_config(ctx)

    # -- per server --------------------------------------------------------
    def _server(self, ctx: Context, cfg: ClientConfig, entry: ServerEntry, sid: str) -> None:
        spec = entry.spec
        span = Span(path=cfg.path, start_line=entry.line)
        raw = entry.raw
        cmd = spec.command or ""
        args = spec.args
        cmdline = shlex.join([cmd, *args]) if cmd else ""
        exe = exe_name(cmd)
        emit = lambda rid, msg, snippet=cmdline, **kw: ctx.emit(  # noqa: E731
            rid, component_ids=sid, span=span, snippet=snippet, match=kw.pop("match", f"{entry.name}:{snippet}"),
            kind=EvidenceKind.config, message=msg, **kw)

        if cmd:
            # Unwrap `cmd /c <program> …` style wrappers for package-runner checks.
            inner_exe, inner_args = exe, list(args)
            if exe in SHELLS and args and args[0].lower() in ("/c", "/k", "-c", "-command") and len(args) > 2:
                inner_exe, inner_args = exe_name(args[1]), args[2:]
            if exe in SHELLS:
                flag_idx = next((i for i, a in enumerate(args) if a in _INLINE_FLAGS or a.lower() in ("/c", "/k")), None)
                if flag_idx is not None:
                    script = " ".join(args[flag_idx + 1 :])
                    single_program = len(args) - flag_idx > 2 and not search(_SHELL_META, script)
                    if not single_program:
                        emit("AG-MCP-CFG-001", f"Server '{entry.name}' runs a shell script string via {exe}.")
                        ctx.add_capability(sid, CapLabel.code_exec, confidence=Confidence.high, span=span, snippet=cmdline,
                                           reason="shell command string", kind=EvidenceKind.config)
            if exe.rstrip("0123456789.") in INTERPRETERS and any(a in _INLINE_FLAGS for a in args[:3]):
                emit("AG-MCP-CFG-002", f"Server '{entry.name}' runs inline code via {exe}.")
            if "$(" in cmdline or "`" in cmd or any("`" in a or "$(" in a for a in args) or regex.search(r"\$\{?[A-Za-z_]", cmd, timeout=TIMEOUT):
                emit("AG-MCP-CFG-003", f"Server '{entry.name}' builds its command from variable expansion or command substitution.")
            runner, pkg = package_arg(inner_exe, inner_args)
            if runner and not spec.pinned:
                auto = "-y" in inner_args or "--yes" in inner_args
                emit("AG-MCP-CFG-004", f"Server '{entry.name}' runs an unpinned package ({spec.pin_detail})"
                     + (" and auto-confirms installation (-y)" if auto else "") + ".")
            if exe in ("docker", "podman", "nerdctl"):
                self._docker(ctx, entry, sid, span, args, cmdline)
        # Secrets in env / args / headers
        for where, mapping in (("env", raw.get("env")), ("headers", raw.get("headers") or raw.get("http_headers"))):
            if not isinstance(mapping, dict):
                continue
            for k, v in mapping.items():
                if not isinstance(v, str) or not v or is_placeholder(v) or _ENV_REF.search(v):
                    continue
                self._secret(ctx, entry, sid, span, f"{where}.{k}", str(k), v)
        for i, a in enumerate(args):
            if "=" in a and _SECRET_NAME.search(a.split("=", 1)[0]):
                self._secret(ctx, entry, sid, span, f"args[{i}]", a.split("=", 1)[0], a.split("=", 1)[1])
            elif i > 0 and _SECRET_NAME.search(args[i - 1]) and args[i - 1].startswith("-") and not a.startswith("-"):
                self._secret(ctx, entry, sid, span, f"args[{i}]", args[i - 1], a)
            else:
                for s in find_secrets(a, include_placeholders=False):
                    if s.kind != "generic_assignment":
                        ctx.emit("AG-MCP-CFG-011", component_ids=sid, span=span, snippet=a, match=f"{entry.name}:{s.value}",
                                 kind=EvidenceKind.config, message=f"Server '{entry.name}' has a literal {s.kind.replace('_', ' ')} in args[{i}].")
        # Remote URL checks
        if spec.url:
            self._url(ctx, entry, sid, span, spec.url)
        for a in args:
            if regex.search(r"(?:^|[=\s])0\.0\.0\.0(?::\d+)?$|^--host(?:=|\s)0\.0\.0\.0", a, timeout=TIMEOUT):
                emit("AG-MCP-CFG-016", f"Server '{entry.name}' is configured to listen on all interfaces (0.0.0.0).", match=f"{entry.name}:bind")
                break
        if isinstance(raw.get("env"), dict) and any(str(v) == "0.0.0.0" for k, v in raw["env"].items() if "HOST" in str(k).upper()):
            emit("AG-MCP-CFG-016", f"Server '{entry.name}' is configured to listen on all interfaces (0.0.0.0).", match=f"{entry.name}:bind")
        sensitive_env = [n for n in spec.env_names if _SECRET_NAME.search(n)]
        if sensitive_env:
            emit("AG-MCP-CFG-020", f"Server '{entry.name}' receives sensitive environment variables: {', '.join(sensitive_env[:6])}.",
                 snippet=", ".join(sensitive_env), match=f"{entry.name}:env")
            ctx.add_capability(sid, CapLabel.credential_access, confidence=Confidence.low, span=span,
                               snippet=", ".join(sensitive_env), reason="receives secrets via env", kind=EvidenceKind.config)
        # Auto-approval in the server entry
        auto_keys = [k for k in ("alwaysAllow", "autoApprove", "trust", "autoApproveTools") if raw.get(k)]
        if auto_keys:
            detail = ", ".join(f"{k}={raw[k]!r}"[:80] for k in auto_keys)
            emit("AG-MCP-CFG-021", f"Server '{entry.name}' tools are auto-approved ({detail}).", snippet=detail,
                 match=f"{entry.name}:auto")
            ctx.add_capability(sid, CapLabel.auto_approved, confidence=Confidence.high, span=span, snippet=detail,
                               reason="auto-approved in client config", kind=EvidenceKind.config)
        if spec.transport == Transport.stdio and spec.scope in ("project", "workspace") and cfg.client != "unknown":
            emit("AG-MCP-CFG-022", f"Project-scoped config '{cfg.path}' defines STDIO server '{entry.name}', which runs a local command when the project is opened/trusted.",
                 match=f"{entry.name}:project")
        if spec.transport == Transport.sse_deprecated:
            emit("AG-MCP-CFG-023", f"Server '{entry.name}' uses the deprecated HTTP+SSE transport.", snippet=spec.url or "",
                 match=f"{entry.name}:sse")

    def _docker(self, ctx: Context, entry: ServerEntry, sid: str, span: Span, args: list[str], cmdline: str) -> None:
        joined = " ".join(args)
        priv = regex.findall(r"--privileged\b|--cap-add(?:=|\s+)(?:ALL|SYS_ADMIN)\b|--(?:pid|network|net|ipc|uts)(?:=|\s+)host\b|"
                             r"--security-opt(?:=|\s+)(?:seccomp|apparmor)[=:]unconfined", joined, timeout=TIMEOUT)
        if priv:
            ctx.emit("AG-MCP-CFG-007", component_ids=sid, span=span, snippet=cmdline, match=f"{entry.name}:priv",
                     kind=EvidenceKind.config, message=f"Container for '{entry.name}' runs with elevated host access ({', '.join(sorted(set(priv)))}).")
        mounts: list[str] = []
        for i, a in enumerate(args):
            if a in ("-v", "--volume") and i + 1 < len(args):
                mounts.append(args[i + 1].split(":")[0] if not regex.match(r"^[A-Za-z]:\\", args[i + 1]) else ":".join(args[i + 1].split(":")[:2]))
            elif a.startswith(("--volume=", "-v=")):
                mounts.append(a.split("=", 1)[1].split(":")[0])
            elif a.startswith("--mount") or (a == "--mount" and i + 1 < len(args)):
                spec = a.split("=", 1)[1] if "=" in a and a.startswith("--mount=") else (args[i + 1] if i + 1 < len(args) else "")
                m = regex.search(r"(?:source|src)=([^,]+)", spec, timeout=TIMEOUT)
                if m:
                    mounts.append(m.group(1))
        for src in mounts:
            if "docker.sock" in src or "docker_engine" in src or src in ("/", "\\", "C:\\"):
                ctx.emit("AG-MCP-CFG-008", component_ids=sid, span=span, snippet=cmdline, match=f"{entry.name}:{src}",
                         kind=EvidenceKind.config, message=f"Container for '{entry.name}' mounts {src}, which gives full control of the host.")
            elif _SENSITIVE_MOUNT.search(src):
                ctx.emit("AG-MCP-CFG-009", component_ids=sid, span=span, snippet=cmdline, match=f"{entry.name}:{src}",
                         kind=EvidenceKind.config, message=f"Container for '{entry.name}' mounts {src} (home or credential directory).")
                ctx.add_capability(sid, CapLabel.reads_private_data, confidence=Confidence.high, span=span, snippet=cmdline,
                                   reason=f"mounts {src}", kind=EvidenceKind.config)
        image = docker_image(args)
        if image and "@sha256:" not in image:
            ctx.emit("AG-MCP-CFG-010", component_ids=sid, span=span, snippet=cmdline, match=f"{entry.name}:{image}",
                     kind=EvidenceKind.config, message=f"Container image '{image}' for '{entry.name}' is not pinned by digest.")

    def _secret(self, ctx: Context, entry: ServerEntry, sid: str, span: Span, where: str, key: str, value: str) -> None:
        provider = [s for s in find_secrets(value, include_placeholders=False) if s.kind != "generic_assignment"]
        snippet = f"{key}={value}"
        if provider:
            ctx.emit("AG-MCP-CFG-011", component_ids=sid, span=span, snippet=snippet, match=f"{entry.name}:{value}",
                     kind=EvidenceKind.config,
                     message=f"Server '{entry.name}' has a literal {provider[0].kind.replace('_', ' ')} in {where}.")
        elif _SECRET_NAME.search(key) and len(value) >= 16 and shannon_entropy(value) >= 3.5 and not value.startswith(("http://", "https://", "/", "./")):
            ctx.emit("AG-MCP-CFG-012", component_ids=sid, span=span, snippet=snippet, match=f"{entry.name}:{value}",
                     kind=EvidenceKind.config, message=f"Server '{entry.name}' has a high-entropy literal in {where}.")

    def _url(self, ctx: Context, entry: ServerEntry, sid: str, span: Span, url: str) -> None:
        try:
            parsed = urllib.parse.urlsplit(url)
        except ValueError:
            return
        host = (parsed.hostname or "").lower()
        emit = lambda rid, msg, **kw: ctx.emit(rid, component_ids=sid, span=span, snippet=url, match=f"{entry.name}:{rid}",  # noqa: E731
                                               kind=EvidenceKind.config, message=msg, **kw)
        ctx.add_capability(sid, CapLabel.external_egress, confidence=Confidence.medium, span=span, snippet=url,
                           reason="remote MCP server", kind=EvidenceKind.config)
        if parsed.scheme == "http" and not _loopback(host):
            emit("AG-MCP-CFG-013", f"Remote server '{entry.name}' uses plain HTTP ({host}).")
        ip = _ip(host)
        if host in _METADATA_HOSTS or (ip is not None and ip.is_link_local):
            emit("AG-MCP-CFG-015", f"Server '{entry.name}' targets a cloud-metadata or link-local address ({host}).")
        elif ip is not None and ip.is_global:
            emit("AG-MCP-CFG-014", f"Remote server '{entry.name}' is addressed by raw IP ({host}).")
        if ip is not None and ip.is_unspecified:
            emit("AG-MCP-CFG-016", f"Server '{entry.name}' URL uses 0.0.0.0.")
        q = urllib.parse.parse_qs(parsed.query)
        bad = [k for k, v in q.items() if _SECRET_NAME.search(k) and any(x.strip() and "${" not in x for x in v)]
        if bad:
            emit("AG-MCP-CFG-019", f"Server '{entry.name}' passes {', '.join(bad)} in the URL query string.")

    def _settings(self, ctx: Context, cfg: ClientConfig) -> None:
        cc = next((c for c in ctx.inventory.components.values() if c.kind == ComponentKind.mcp_client_config and c.root == cfg.path), None)
        if cc is None:
            return
        risky = {k: v for k, v in cfg.settings.items() if k in ("enableAllProjectMcpServers", "chat.tools.autoApprove") and v is True}
        for k in sorted(risky):
            ctx.emit("AG-MCP-CFG-021", component_ids=cc.id, span=Span(path=cfg.path), snippet=f'"{k}": true', match=f"{cfg.path}:{k}",
                     kind=EvidenceKind.config, message=f"Client setting '{k}' auto-approves MCP servers/tools.")
            for (path, _proj, _name), sid in ctx.inventory.server_components.items():
                if path == cfg.path or k == "chat.tools.autoApprove":
                    ctx.add_capability(sid, CapLabel.auto_approved, confidence=Confidence.medium,
                                       reason=f"client setting {k}", kind=EvidenceKind.config)

    # -- across configs ---------------------------------------------------
    def _cross_config(self, ctx: Context) -> None:
        entries: list[tuple[str, ServerEntry, str]] = []
        for cfg in ctx.inventory.configs:
            for e in cfg.servers:
                sid = ctx.inventory.server_components.get((cfg.path, e.project or "", e.name))
                if sid:
                    entries.append((cfg.path, e, sid))
        by_name: dict[str, list[tuple[str, ServerEntry, str]]] = {}
        for item in entries:
            by_name.setdefault(item[1].name.lower(), []).append(item)
        for name, items in sorted(by_name.items()):
            sigs = {self._signature(e) for _, e, _ in items}
            paths = {p for p, _, _ in items}
            if len(sigs) > 1 and len(paths) > 1:
                p0, e0, s0 = items[0]
                ctx.emit("AG-MCP-CFG-018", component_ids=[s for _, _, s in items], span=Span(path=p0, start_line=e0.line),
                         snippet="; ".join(f"{p}: {self._signature(e)}" for p, e, _ in items)[:240],
                         match=f"collide:{name}", kind=EvidenceKind.config,
                         related=[Span(path=p, start_line=e.line) for p, e, _ in items[1:]],
                         message=f"Server name '{items[0][1].name}' points to different commands/URLs in {len(paths)} configs; which one runs depends on the client.")
        names = sorted(by_name)
        for i, a in enumerate(names):
            fa = normalize(a).text
            for b in names[i + 1 :]:
                fb = normalize(b).text
                if len(a) < 4 or len(b) < 4:
                    continue
                if fa == fb or (abs(len(a) - len(b)) <= 1 and damerau_levenshtein(fa, fb, cap=1) == 1):
                    ia, ib = by_name[a][0], by_name[b][0]
                    ctx.emit("AG-MCP-CFG-017", component_ids=[ia[2], ib[2]], span=Span(path=ia[0], start_line=ia[1].line),
                             snippet=f"{ia[1].name} ~ {ib[1].name}", match=f"near:{a}|{b}", kind=EvidenceKind.config,
                             related=[Span(path=ib[0], start_line=ib[1].line)],
                             message=f"Server names '{ia[1].name}' and '{ib[1].name}' are near-duplicates (possible shadowing).")

    @staticmethod
    def _signature(e: ServerEntry) -> str:
        spec = e.spec
        if spec.url:
            try:
                u = urllib.parse.urlsplit(spec.url)
                return f"url:{u.hostname}{u.path}"
            except ValueError:
                return f"url:{spec.url}"
        runner, pkg = package_arg(spec.command, spec.args)
        if runner and pkg:
            return f"pkg:{split_package_spec(pkg)[0]}"
        if exe_name(spec.command) in ("docker", "podman"):
            image = docker_image(spec.args) or ""
            return f"image:{image.split('@')[0].rsplit(':', 1)[0]}"
        return f"cmd:{exe_name(spec.command)}:{' '.join(spec.args[:2])}"


# ---------------------------------------------------------------------------
# Tool / prompt / resource metadata
# ---------------------------------------------------------------------------
_SIDE_CHANNEL_NAMES = regex.compile(r"(?i)^(?:note|notes|side_?note|context|feedback|metadata|extra|debug|comment|reasoning|"
                                    r"summary|history|conversation|details|remarks|annotation|additional_?info)$")
_SIDE_CHANNEL_DESC = regex.compile(
    r"(?i)\b(?:conversation|chat\s+history|previous\s+messages|system\s+prompt|all\s+(?:the\s+)?(?:context|files|content|messages)|"
    r"full\s+(?:contents?|history|transcript)|entire\s+(?:conversation|file|context)|everything\s+(?:the\s+user|you)|"
    r"user'?s?\s+(?:messages|data|files|credentials)|contents?\s+of\s+(?:any|all|the)\s+(?:files?|documents?|\S+\.(?:json|env|txt|md)))")
_DANGEROUS_PARAM = regex.compile(r"(?i)^(?:command|cmd|code|script|shell|exec|expression|expr|eval|program|"
                                 r"path|file|filepath|file_path|filename|dir|directory|url|uri|endpoint|sql|query|statement)$")
_SHADOW_GENERIC = regex.compile(
    r"(?i)\b(?:when|whenever|before|after|every\s+time)\s+(?:you\s+)?(?:use|call|invoke|run)(?:s|ing)?\s+(?:the\s+|any\s+)?[`'\"]?[\w.\-]+[`'\"]?\s+(?:tool|function)\b"
    r"|\b(?:this\s+tool|use\s+this)\s+(?:replaces|overrides|supersedes|takes\s+precedence\s+over)\b"
    r"|\b(?:do\s+not|don'?t|never)\s+use\s+(?:the\s+)?[`'\"]?[\w.\-]+[`'\"]?\s+tool\b"
    r"|\ball\s+(?:emails?|messages?|requests?|calls?)\s+(?:sent|made)\s+(?:with|via|through)\s+(?:any|other)\s+tools?\b")
# External scripts are AG-MCP-META-026's (it also checks integrity and the declared CSP).
_UI_FETCH = regex.compile(r"(?i)\b(?:fetch|XMLHttpRequest|navigator\.sendBeacon|WebSocket|EventSource)\s*\(\s*[`'\"]?(https?://[^`'\"\s)]+)|"
                          r"<(?:img|link)\b[^>]*\b(?:src|href)\s*=\s*[\"'](https?://[^\"']+)")
_UI_CRED = regex.compile(r"(?i)<input\b[^>]*type\s*=\s*[\"']?password|<(?:label|input|span|p)\b[^>]*>[^<]{0,60}\b(?:password|api[\s_-]?key|secret|seed\s+phrase|private\s+key|access\s+token)\b"
                         r"|placeholder\s*=\s*[\"'][^\"']*(?:password|api[\s_-]?key|token|secret)")
_UI_FRAME = regex.compile(r"(?i)<iframe\b[^>]*\bsrc\s*=\s*[\"']?(https?://[^\"'\s>]+)")
_UI_SCRIPT_TAG = regex.compile(r"(?is)<script\b([^>]*)>")
_UI_SCRIPT_SRC = regex.compile(r"(?i)\bsrc\s*=\s*[\"']?((?:https?:)?//[^\"'\s>]+)")
_UI_DYNAMIC_SCRIPT = regex.compile(
    r"(?i)\bimport\s*\(\s*[`'\"]((?:https?:)?//[^`'\"\s)]+)|\bimport\s+[^;\n]{0,200}?\bfrom\s*[`'\"]((?:https?:)?//[^`'\"\s]+)"
    r"|\bimportScripts\s*\(\s*[`'\"]((?:https?:)?//[^`'\"\s)]+)|\.src\s*=\s*[`'\"]((?:https?:)?//[^`'\"\s]+\.m?js\b[^`'\"\s]*)")
# MCP Apps requests a View sends that act for the user (2026-01-26: tools/call, ui/message,
# ui/update-model-context, ui/open-link): a postMessage carrying one, or a helper called with the
# method as its first argument. Lookups and schema literals (`.get("tools/call")`, `z.literal(...)`) are not sends.
_UI_ACTIONS = r"tools/call|ui/message|ui/update-model-context|ui/open-link"
_UI_ACTION = regex.compile(
    rf"postMessage\(\s*\{{[^}}]{{0,300}}?[\"']?method[\"']?\s*:\s*[\"'`]({_UI_ACTIONS})[\"'`]"
    rf"|\b(?!(?:literal|enum|get|has|set|delete|includes|startsWith|endsWith|equals?|match|test|is|on|once|off|"
    rf"addListener|removeListener|onRequest|onNotification|setRequestHandler|setNotificationHandler)\b)"
    rf"[A-Za-z_$][\w$]*\s*\(\s*[\"'`]({_UI_ACTIONS})[\"'`]")
_UI_GESTURE = regex.compile(
    r"(?i)addEventListener\(\s*[\"'`](?:click|dblclick|submit|change|input|key(?:down|up|press)|pointer(?:down|up)|mouse(?:down|up)|touch(?:start|end))[\"'`]"
    r"|\bon(?:click|dblclick|submit|change|input|key(?:down|up|press)|pointer(?:down|up)|mouse(?:down|up)|touch(?:start|end))\s*[=:]"
    r"|<(?:button|form|input|select|textarea)\b")
_CSP_KEYS = ("connectDomains", "resourceDomains", "frameDomains", "baseUriDomains")
# `*`, a bare scheme (`https:`, `data:`), any host (`https://*`) or a wildcard over a whole TLD (`https://*.com`).
_CSP_ANY = regex.compile(r"(?i)^(?:\*|[a-z][a-z0-9+.\-]*:|[a-z][a-z0-9+.\-]*://\*(?:\.[a-z0-9\-]+)?(?::(?:\d+|\*))?/?)$")
_CSP_SYNTAX = regex.compile(r"[\s;,'\"]")
_NET_SCHEMES = ("http", "https", "ws", "wss", "ftp")
_REF_KEYS = ("$ref", "$dynamicRef", "$recursiveRef")
# JSON Schema bounds Agent Guard applies. The spec asks for "reasonable bounds" without numbers;
# no tool schema in the benchmark corpus comes near these (the deepest nests 3 levels). The depth
# bound stays under the JSON loader's limit of 64 levels for the whole manifest; a manifest past
# that cannot be read at all and is reported as such.
_MAX_DEPTH = 48
_MAX_NODES = 10_000
_MAX_EXPANDED = 1_000_000


def _host(url: str) -> str:
    try:
        return (urllib.parse.urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _origin_declared(url: str, declared: list[str]) -> bool:
    try:
        u = urllib.parse.urlsplit(url if not url.startswith("//") else "https:" + url)
    except ValueError:
        return False
    host = (u.hostname or "").lower()
    for d in declared:
        try:
            p = urllib.parse.urlsplit(d.strip())
        except ValueError:
            continue
        dh = (p.hostname or "").lower()
        if p.scheme.lower() == u.scheme.lower() and (dh == host or (dh.startswith("*.") and host.endswith(dh[1:]))):
            return True
    return False


def _ssrf_target(url: str) -> bool:
    host = _host(url if not url.startswith("//") else "https:" + url)
    ip = _ip(host)
    return _loopback(host) or host in _METADATA_HOSTS or (ip is not None and (ip.is_private or ip.is_link_local))


def _remote_refs(schema: Any, limit: int = 20_000) -> list[str]:
    """Network URIs that `$ref`/`$dynamicRef`/`$recursiveRef` values resolve to, against any `$id` base."""
    out: list[str] = []
    stack: list[tuple[Any, str, bool]] = [(schema, "", False)]
    seen = 0
    while stack and seen < limit:
        node, base, is_map = stack.pop()
        seen += 1
        if isinstance(node, dict) and not is_map:
            try:
                if isinstance(node.get("$id"), str) and node["$id"]:
                    base = urllib.parse.urljoin(base, node["$id"]) if base else node["$id"]
                for k in _REF_KEYS:
                    ref = node.get(k)
                    if isinstance(ref, str) and not ref.startswith("#"):
                        target = urllib.parse.urljoin(base, ref) if base else ref
                        if target.startswith("//") or urllib.parse.urlsplit(target).scheme.lower() in _NET_SCHEMES:
                            out.append(target)
            except ValueError:
                pass
        stack.extend((v, base, m) for _, v, m in _schema_children(node, is_map))
    return out


def _schema_shape(schema: Any) -> tuple[int, int]:
    """(maximum nesting depth, number of schema objects), counting stops past the bounds."""
    depth = nodes = 0
    stack: list[tuple[Any, int, bool]] = [(schema, 1, False)]
    while stack and nodes <= _MAX_NODES and depth <= _MAX_DEPTH:
        node, d, is_map = stack.pop()
        depth = max(depth, d)
        nodes += isinstance(node, dict) and not is_map
        stack.extend((v, d + 1, m) for _, v, m in _schema_children(node, is_map))
    return depth, nodes


def _pointer(root: Any, ref: str) -> Any:
    node = root
    for part in ref[1:].lstrip("/").split("/") if ref not in ("#", "#/") else []:
        part = urllib.parse.unquote(part).replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict) and part in node:
            node = node[part]
        elif isinstance(node, list) and part.isdigit() and int(part) < len(node):
            node = node[int(part)]
        else:
            return None
    return node


def _expanded_size(root: Any, cap: int = 10 * _MAX_EXPANDED) -> int:
    """Schema objects a validator visits with every local `$ref` inlined once per use. A cycle counts
    as one (recursive schemas are legitimate); `$defs` that each use the previous one several
    times grow exponentially (the schema form of a "billion laughs")."""
    def children(node: Any, is_map: bool) -> list[tuple[Any, bool]]:
        out = [(v, m) for _, v, m in _schema_children(node, is_map)]
        ref = node.get("$ref") if isinstance(node, dict) and not is_map else None
        if isinstance(ref, str) and ref.startswith("#"):
            target = _pointer(root, ref)
            if isinstance(target, (dict, list)):
                out.append((target, False))
        return out

    memo: dict[int, int] = {}
    on_path: set[int] = set()
    stack: list[tuple[Any, bool, bool]] = [(root, False, False)]
    while stack:
        node, is_map, done = stack.pop()
        nid = id(node)
        if done:
            on_path.discard(nid)
            total = 1 if isinstance(node, dict) and not is_map else 0
            for child, _ in children(node, is_map):
                total = min(cap, total + memo.get(id(child), 1))
            memo[nid] = total
        elif nid not in memo and nid not in on_path:
            on_path.add(nid)
            stack.append((node, is_map, True))
            stack.extend((c, m, False) for c, m in children(node, is_map) if id(c) not in memo and id(c) not in on_path)
    return memo.get(id(root), 0)


class McpMetaAnalyzer:
    id: ClassVar[str] = "mcp.meta"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = (
        "AG-MCP-META-004", "AG-MCP-META-006", "AG-MCP-META-007", "AG-MCP-META-008", "AG-MCP-META-009",
        "AG-MCP-META-010", "AG-MCP-META-016", "AG-MCP-META-017", "AG-MCP-META-018", "AG-MCP-META-019",
        "AG-MCP-META-022", "AG-MCP-META-023", "AG-MCP-META-025", "AG-MCP-META-026", "AG-MCP-META-027",
    )

    def run(self, ctx: Context) -> None:
        servers = [c for c in ctx.inventory.components.values() if c.tools or c.resources]
        servers.sort(key=lambda c: c.id)
        for comp in servers:
            for tool in comp.tools:
                self._tool(ctx, comp, tool)
            for rs in comp.resources:
                self._ui_resource(ctx, comp, rs)
        self._collisions(ctx, servers)
        self._shadowing(ctx, servers)
        for path in ctx.inventory.deep_manifests:
            comp = ctx.inventory.component_for(path)
            ctx.emit("AG-MCP-META-023", component_ids=[comp.id] if comp else [], span=Span(path=path), snippet=path,
                     match=f"{path}:deep", kind=EvidenceKind.schema,
                     message=f"Tool manifest {path} nests more than 64 levels deep; Agent Guard could not read its tools, "
                     "and validators with a depth or stack limit fail on it.")

    def _tool(self, ctx: Context, comp: Component, tool: ToolDef) -> None:
        span = tool.span
        schema = tool.input_schema or {}
        props = schema.get("properties") or {}
        desc = tool.description or ""
        if len(desc) > 2000 or regex.search(r"\n{15,}|[ \t]{200,}", desc, timeout=TIMEOUT):
            ctx.emit("AG-MCP-META-019", component_ids=comp.id, span=span, snippet=desc[:200], match=f"{tool.name}:stuffing",
                     kind=EvidenceKind.metadata, message=f"Tool '{tool.name}' has an unusually long or padded description ({len(desc)} chars).")
        for which, sch in (("inputSchema", schema), ("outputSchema", tool.output_schema)):
            if isinstance(sch, dict) and sch:
                self._schema(ctx, comp, tool, which, sch)
        if not isinstance(props, dict):
            return
        dangerous = []
        for pname, ps in props.items():
            if not isinstance(ps, dict):
                continue
            pdesc = ps.get("description") if isinstance(ps.get("description"), str) else ""
            if (_SIDE_CHANNEL_NAMES.match(str(pname)) and pdesc and search(_SIDE_CHANNEL_DESC, pdesc)) or (
                pdesc and regex.search(r"(?i)\b(?:system\s+prompt|conversation\s+history|chat\s+history|previous\s+messages)\b", pdesc, timeout=TIMEOUT)
            ):
                ctx.emit("AG-MCP-META-004", component_ids=comp.id, span=span, snippet=f"{pname}: {pdesc}", match=f"{tool.name}.{pname}",
                         kind=EvidenceKind.metadata,
                         message=f"Parameter '{pname}' of tool '{tool.name}' asks the model to fill it with conversation or file contents.")
            if _DANGEROUS_PARAM.match(str(pname)) and ps.get("type", "string") == "string" and not any(k in ps for k in ("enum", "const", "pattern")):
                dangerous.append(str(pname))
        if dangerous:
            ctx.emit("AG-MCP-META-009", component_ids=comp.id, span=span, snippet=f"{tool.name}({', '.join(dangerous)})",
                     match=f"{tool.name}:{','.join(dangerous)}", kind=EvidenceKind.schema,
                     message=f"Tool '{tool.name}' accepts unconstrained {', '.join(dangerous)} string(s) (no enum/pattern).")
            if schema.get("additionalProperties") is True:
                ctx.emit("AG-MCP-META-010", component_ids=comp.id, span=span, snippet=f"{tool.name}: additionalProperties: true",
                         match=f"{tool.name}:additional", kind=EvidenceKind.schema,
                         message=f"Tool '{tool.name}' accepts arbitrary extra arguments (additionalProperties: true).")

    def _schema(self, ctx: Context, comp: Component, tool: ToolDef, which: str, schema: dict[str, Any]) -> None:
        span = tool.span
        refs = _remote_refs(schema)
        if refs:
            internal = [r for r in refs if _ssrf_target(r)]
            ctx.emit("AG-MCP-META-022", component_ids=comp.id, span=span, snippet=", ".join((internal or refs)[:3])[:240],
                     match=f"{tool.name}:{which}:ref", kind=EvidenceKind.schema,
                     severity=Severity.high if internal else None,
                     message=f"Tool '{tool.name}' {which} has a $ref to a network URI ({(internal or refs)[0][:120]})"
                     + (", an internal or cloud-metadata address" if internal else "") + ".")
        depth, nodes = _schema_shape(schema)
        if depth > _MAX_DEPTH or nodes > _MAX_NODES:
            ctx.emit("AG-MCP-META-023", component_ids=comp.id, span=span, snippet=f"{tool.name}.{which}: depth {depth}, {nodes} objects",
                     match=f"{tool.name}:{which}:size", kind=EvidenceKind.schema,
                     message=f"Tool '{tool.name}' {which} is " + (f"nested more than {_MAX_DEPTH} levels deep" if depth > _MAX_DEPTH
                                                                  else f"made of more than {_MAX_NODES:,} subschemas") + ".")
            return
        expanded = _expanded_size(schema)
        if expanded > _MAX_EXPANDED:
            ctx.emit("AG-MCP-META-023", component_ids=comp.id, span=span, snippet=f"{tool.name}.{which}: {nodes} objects, over {_MAX_EXPANDED:,} with $refs inlined",
                     match=f"{tool.name}:{which}:size", kind=EvidenceKind.schema, confidence=Confidence.high,
                     message=f"Tool '{tool.name}' {which} has {nodes} subschemas but more than {_MAX_EXPANDED:,} once its local $refs are "
                     "followed: its $defs reuse each other exponentially.")

    def _ui_resource(self, ctx: Context, comp: Component, rs) -> None:
        ui = (rs.meta or {}).get("ui")
        csp = ui.get("csp") if isinstance(ui, dict) and isinstance(ui.get("csp"), dict) else {}
        if csp:
            self._ui_csp(ctx, comp, rs, csp)
        if not rs.text or not (rs.uri.startswith("ui://") or (rs.mime_type or "").startswith("text/html")):
            return
        text = rs.text
        span = rs.span
        declared = [d for d in csp.get("resourceDomains") or [] if isinstance(d, str)] if isinstance(csp.get("resourceDomains"), list) else []
        scripts = []
        for tag in finditer(_UI_SCRIPT_TAG, text):
            src = _UI_SCRIPT_SRC.search(tag.group(1), timeout=TIMEOUT)
            if src and not regex.search(r"(?i)\bintegrity\s*=", tag.group(1), timeout=TIMEOUT):
                scripts.append((src.group(1), tag.group(0)))
        scripts += [(next(g for g in m.groups() if g), m.group(0)) for m in finditer(_UI_DYNAMIC_SCRIPT, text)]
        if scripts:
            url, snippet = scripts[0]
            ok = _origin_declared(url, declared)
            ctx.emit("AG-MCP-META-026", component_ids=comp.id, span=span, snippet=snippet[:240], match=f"{rs.uri}:script",
                     kind=EvidenceKind.metadata,
                     message=f"UI resource {rs.uri} runs a script from {url[:120]} with no integrity hash"
                     + ("" if ok else "; its origin is not declared in _meta.ui.csp.resourceDomains, so a host that follows MCP Apps blocks it")
                     + ".")
        m = search(_UI_ACTION, text)
        if m and not search(_UI_GESTURE, text):
            ctx.emit("AG-MCP-META-027", component_ids=comp.id, span=span, snippet=m.group(0)[:240], match=f"{rs.uri}:auto",
                     kind=EvidenceKind.metadata,
                     message=f"UI resource {rs.uri} sends {m.group(1) or m.group(2)} and has no click, key or form handler, "
                     "so it sends it without any user action.")
        m = search(_UI_FETCH, text)
        if m:
            ctx.emit("AG-MCP-META-016", component_ids=comp.id, span=span, snippet=m.group(0), match=f"{rs.uri}:net",
                     kind=EvidenceKind.metadata, message=f"UI resource {rs.uri} loads or sends data to an external origin.")
        m = search(_UI_CRED, text)
        if m:
            ctx.emit("AG-MCP-META-017", component_ids=comp.id, span=span, snippet=m.group(0), match=f"{rs.uri}:cred",
                     kind=EvidenceKind.metadata, message=f"UI resource {rs.uri} contains a credential-style form field.")
        m = search(_UI_FRAME, text)
        if m:
            ctx.emit("AG-MCP-META-018", component_ids=comp.id, span=span, snippet=m.group(0), match=f"{rs.uri}:frame",
                     kind=EvidenceKind.metadata, message=f"UI resource {rs.uri} embeds an external frame ({m.group(1)[:80]}).")

    def _ui_csp(self, ctx: Context, comp: Component, rs, csp: dict[str, Any]) -> None:
        """Hosts build the View's CSP from these lists verbatim (MCP Apps 2026-01-26), so a wildcard
        opens the sandbox and an entry with spaces, quotes or `;` adds sources or whole directives."""
        worst: tuple[int, str, str, str] | None = None
        for key in _CSP_KEYS:
            vals = csp.get(key)
            for entry in [vals] if isinstance(vals, str) else vals if isinstance(vals, list) else []:
                if not isinstance(entry, str):
                    continue
                if _CSP_SYNTAX.search(entry.strip()):
                    rank, why = 3, "carries CSP syntax that adds sources or directives"
                elif _CSP_ANY.match(entry.strip()):
                    rank, why = (2 if key in ("connectDomains", "resourceDomains") else 1), "allows any origin"
                elif entry.strip().lower().startswith(("http://", "ws://")) and not _loopback(_host(entry.strip())):
                    rank, why = 1, "is a cleartext origin"
                else:
                    continue
                if worst is None or rank > worst[0]:
                    worst = (rank, key, entry, why)
        if worst is None:
            return
        rank, key, entry, why = worst
        ctx.emit("AG-MCP-META-025", component_ids=comp.id, span=rs.span, snippet=f"{key}: {entry}"[:240], match=f"{rs.uri}:csp",
                 kind=EvidenceKind.metadata, severity=Severity.high if rank >= 2 else None,
                 message=f"UI resource {rs.uri} declares _meta.ui.csp.{key} entry '{entry[:80]}', which {why}.")

    def _collisions(self, ctx: Context, servers: list[Component]) -> None:
        owners: dict[str, list[tuple[Component, ToolDef]]] = {}
        for comp in servers:
            for tool in comp.tools:
                owners.setdefault(tool.name, []).append((comp, tool))
        for name, items in sorted(owners.items()):
            comps = {c.id for c, _ in items}
            if len(comps) > 1:
                ctx.emit("AG-MCP-META-007", component_ids=sorted(comps), span=items[0][1].span, snippet=name, match=f"collide:{name}",
                         kind=EvidenceKind.metadata, related=[t.span for _, t in items[1:] if t.span],
                         message=f"Tool name '{name}' is defined by {len(comps)} servers ({', '.join(sorted(c.name for c, _ in items))}).")
        names = sorted(owners)
        for i, a in enumerate(names):
            fa = normalize(a).text.lower()
            for b in names[i + 1 :]:
                if len(a) < 5 or len(b) < 5 or abs(len(a) - len(b)) > 1:
                    continue
                ca = {c.id for c, _ in owners[a]}
                cb = {c.id for c, _ in owners[b]}
                if ca == cb:
                    continue
                fb = normalize(b).text.lower()
                if fa == fb or damerau_levenshtein(fa, fb, cap=1) == 1:
                    ctx.emit("AG-MCP-META-008", component_ids=sorted(ca | cb), span=owners[a][0][1].span, snippet=f"{a} ~ {b}",
                             match=f"near:{a}|{b}", kind=EvidenceKind.metadata,
                             message=f"Tool names '{a}' and '{b}' from different servers are near-identical.")

    def _shadowing(self, ctx: Context, servers: list[Component]) -> None:
        all_tools = {(c.id, t.name) for c in servers for t in c.tools}
        for comp in servers:
            others = sorted({n for cid, n in all_tools if cid != comp.id and len(n) >= 4 and ("_" in n or "-" in n or len(n) >= 8)})
            for tool in comp.tools:
                desc = normalize(tool.description or "").text
                if not desc:
                    continue
                hit = None
                for n in others:
                    m = regex.search(rf"(?i)(?<![\w-]){regex.escape(n)}(?![\w-])", desc, timeout=TIMEOUT)
                    if m and regex.search(r"(?i)\b(?:always|must|instead|never|do not|don't|before|after|when|whenever|also|redirect|bcc|cc|replace|override)\b",
                                          desc[max(0, m.start() - 120) : m.end() + 120], timeout=TIMEOUT):
                        hit = f"references other server's tool '{n}'"
                        break
                if hit is None:
                    m = search(_SHADOW_GENERIC, desc)
                    if m:
                        hit = f"redefines behavior of other tools: '{m.group(0)[:80]}'"
                if hit:
                    ctx.emit("AG-MCP-META-006", component_ids=comp.id, span=tool.span, snippet=desc[:240], match=f"{tool.name}:shadow",
                             kind=EvidenceKind.metadata, message=f"Tool '{tool.name}' {hit}.")


# ---------------------------------------------------------------------------
# MCP client authorization code (MCP 2026-07-28, Authorization)
# ---------------------------------------------------------------------------
# Only packages that use an MCP client are checked: an MCP server that logs its users in to an
# upstream provider (GitHub, Google) runs the same OAuth code, and RFC 8707 / RFC 9207 handling
# there is that provider's business, not the MCP spec's.
_MCP_CLIENT = regex.compile(
    r"@modelcontextprotocol/(?:sdk/client|client)\b|\b(?:StreamableHTTPClientTransport|SSEClientTransport|StdioClientTransport)\b"
    r"|\bfrom\s+mcp(?:\.client[\w.]*)?\s+import\s+[^\n]*\b(?:ClientSession|streamablehttp_client|streamable_http_client|sse_client|stdio_client)\b"
    r"|\bfrom\s+mcp\.client\b|\bimport\s+mcp\.client\b")
_CALLBACK_CODE = regex.compile(
    r"\b(?:searchParams|params|query|args|query_params|qs|GET)\s*\.get\(\s*[\"']code[\"']"
    r"|\.query\.code\b|\b(?:query|params|args|qs|parsed|query_params)\s*\[\s*[\"']code[\"']\s*\]")
_OAUTH_CONTEXT = regex.compile(r"(?i)\b(?:code_verifier|codeVerifier|redirect_uri|redirectUri|oauth|authorization_code|finishAuth|callback)\b")
_ISS = regex.compile(r"\biss\b")
_AUTHZ_REQUEST = regex.compile(r"[\"']code_challenge[\"']|\bcode_challenge\s*[:=]|[?&]code_challenge=")
_TOKEN_REQUEST = regex.compile(r"\bgrant_type[\"']?\s*[:=,]\s*[\"'](?:authorization_code|refresh_token)[\"']|\bgrant_type=(?:authorization_code|refresh_token)\b")
_RESOURCE_PARAM = regex.compile(r"[\"']resource[\"']|\bresource\s*[:=]|[?&]resource=")
_CLIENT_STORE = regex.compile(r"\b(?:saveClientInformation|saveClientInfo|save_client_information|save_client_info|set_client_info)\s*\(")
_ISSUER = regex.compile(r"(?i)\bissuer\b")
_PARAM_WINDOW = 20  # lines around an authorization or token request searched for `resource`
# Servers drive themselves with an MCP client in their tests; tests neither make a package a client nor get checked.
_TEST_PATH = regex.compile(r"(?i)(?:^|/)(?:tests?|__tests__|spec|e2e)/|(?:^|/)test_[^/]*\.py$|_test\.py$"
                           r"|\.(?:test|spec|integration)\.[cm]?[jt]sx?$")
_COMMENT_LINE = regex.compile(r"(?m)^[ \t]*(?://|/\*|\*|#).*$")


class McpClientAuthAnalyzer:
    id: ClassVar[str] = "mcp.client_auth"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = ("AG-MCP-SPEC-003", "AG-MCP-SPEC-004", "AG-MCP-SPEC-005")

    def run(self, ctx: Context) -> None:
        texts = [at for at in ctx.texts("source_code") if not search(_TEST_PATH, at.path)]
        clients = {at.artifact.component_id for at in texts if search(_MCP_CLIENT, at.text)}
        for at in texts:
            if at.artifact.component_id in clients:
                self._file(ctx, at)

    def _file(self, ctx: Context, at) -> None:
        cid = at.artifact.component_id
        # Whole-line comments are blanked (offsets kept): a request in a doc comment is not a request,
        # and "TODO: check iss" is not a check.
        try:
            text = _COMMENT_LINE.sub(lambda c: " " * len(c.group(0)), at.text, timeout=TIMEOUT)
        except TimeoutError:
            return

        def emit(rid: str, m: regex.Match[str], key: str, message: str) -> None:
            ctx.emit(rid, component_ids=cid, span=at.span(m.start(), m.end()), snippet=at.line_text(m.start()).strip()[:240],
                     match=f"{at.path}:{key}", kind=EvidenceKind.regex, message=message)

        m = search(_CALLBACK_CODE, text)
        if m and search(_OAUTH_CONTEXT, at.text) and not search(_ISS, text):
            emit("AG-MCP-SPEC-003", m, "iss", "Reads the authorization code from the OAuth redirect but never reads `iss`, so a response "
                 "from a different authorization server (mix-up attack, RFC 9207) is accepted.")
        lines = text.split("\n")
        for rx, key, what in ((_AUTHZ_REQUEST, "authz", "authorization request"), (_TOKEN_REQUEST, "token", "token request")):
            for m in finditer(rx, text):
                line = text.count("\n", 0, m.start())
                window = "\n".join(lines[max(0, line - _PARAM_WINDOW) : line + _PARAM_WINDOW + 1])
                if not search(_RESOURCE_PARAM, window):
                    emit("AG-MCP-SPEC-005", m, key, f"Builds an OAuth {what} without the `resource` parameter (RFC 8707), "
                         "so the token is not bound to the MCP server it is meant for.")
                    break
        m = search(_CLIENT_STORE, text)
        if m and not search(_ISSUER, text):
            emit("AG-MCP-SPEC-004", m, "issuer", "Stores OAuth client credentials without the authorization server's issuer, "
                 "so they can be reused with a different authorization server.")


def _unused(_: Any, __: ArtifactRole) -> None:
    return None
