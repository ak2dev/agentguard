"""Agent-facing mode (spec/interfaces.md §11): `agentguard serve --mcp` and `agentguard serve --http`.

A scanner that hands hostile text back to the agent that called it is an injection path. Everything
returned here is agent-safe: rule ids, the rule's own fixed wording, file and line, verdict and fix
summary. Evidence snippets and decoded payloads are never returned, and every string that came from the
target (names, paths) is length-limited and stripped of control and invisible characters. The full
report is written to disk for the human, and the response gives its path.

MCP: JSON-RPC 2.0 over stdio, one message per line; `initialize` (2025 revisions) and `server/discover`
(2026-07-28) are both answered. Tools: agentguard_scan, agentguard_check_install, agentguard_explain,
agentguard_inventory.

HTTP: the same four operations on loopback. Requests need the bearer token printed at start-up, a
loopback Host header and no Origin header, so a web page cannot drive the scanner through the browser.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sys
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, BinaryIO, TextIO

from .core.engine import ENGINE_VERSION
from .core.report.agent_safe import clean, scrub_report
from .core.report.render import render_json
from .core.rules.pack import RulePack

PROTOCOL_VERSIONS = ("2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26")
MAX_FINDINGS = 100
MAX_REQUEST = 1024 * 1024
TOKEN_VAR = "AGENTGUARD_SERVE_TOKEN"
_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "[::1]", "::1")


class ServeError(ValueError):
    """A request this server will not carry out. The message is fixed wording, safe to return to an agent."""


@dataclass
class ServeConfig:
    policy: str | None = None
    profile: str = "quick"
    reports_dir: Path | None = None
    cwd: Path = field(default_factory=Path.cwd)
    # Hooks for tests and embedders.
    http: Any = None
    sandbox: Any = None
    env: dict[str, str] | None = None


TOOLS: list[dict[str, Any]] = [
    {"name": "agentguard_scan",
     "title": "Scan an agent component",
     "description": "Scan a skill, plugin, instruction file, MCP server or repository before it is used. Returns a verdict (ALLOW, "
                    "REVIEW or BLOCK) and, per finding, the rule id, the rule's fixed wording, file and line, and the fix summary. "
                    "Text from the scanned target is never returned; the full report is written to disk for the user.",
     "inputSchema": {"type": "object", "required": ["target"], "additionalProperties": False, "properties": {
         "target": {"type": "string", "description": "A local path, a GitHub URL, pkg:npm/name@version, pkg:pypi/name@version, "
                                                     "oci://image, mcp:namespace/server, or mcp+https://endpoint."},
         "profile": {"type": "string", "enum": ["quick", "standard"], "description": "quick: deterministic static analysis (default)."}}},
     "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}},
    {"name": "agentguard_check_install",
     "title": "Check before installing",
     "description": "Scan a source the way `agentguard install --plan` does and say whether it may be installed. Nothing is written. "
                    "Returns the verdict, whether it is installable, and the files and settings an install would change.",
     "inputSchema": {"type": "object", "required": ["source"], "additionalProperties": False, "properties": {
         "source": {"type": "string", "description": "What would be installed: any scan target."},
         "agent": {"type": "string", "enum": ["claude-code", "codex", "cursor", "gemini", "copilot", "openclaw"]},
         "scope": {"type": "string", "enum": ["project", "user"]}}},
     "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}},
    {"name": "agentguard_explain",
     "title": "Explain a rule",
     "description": "Explain a rule by id (for example AG-INJ-001): what it detects, why it matters and how to fix it.",
     "inputSchema": {"type": "object", "required": ["id"], "additionalProperties": False, "properties": {
         "id": {"type": "string", "description": "A rule id, an id/variant, or an older alias."}}},
     "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}},
    {"name": "agentguard_inventory",
     "title": "List installed agent components",
     "description": "List the agent components found in this project and on this machine, with type, risk tier, verdict and capabilities.",
     "inputSchema": {"type": "object", "additionalProperties": False, "properties": {
         "include_user": {"type": "boolean", "description": "Also look in the home directory (default true)."}}},
     "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}},
]


class Service:
    """The four operations, shared by the MCP and HTTP front ends."""

    def __init__(self, cfg: ServeConfig) -> None:
        self.cfg = cfg
        self.pack = RulePack.default()
        self.lock = threading.Lock()         # one scan at a time: a scan installs process-wide guards

    # -- helpers --------------------------------------------------------------------------------------
    def _reports_dir(self) -> Path:
        if self.cfg.reports_dir is not None:
            return self.cfg.reports_dir
        from .io.intel_store import data_home

        return data_home() / "reports"

    def _save(self, report: Any, target: str) -> str:
        """The full report, for the human. Named after the target's hash so the name carries no text from it."""
        try:
            d = self._reports_dir()
            d.mkdir(parents=True, exist_ok=True)
            path = d / f"report-{hashlib.sha256(target.encode('utf-8', 'replace')).hexdigest()[:16]}.json"
            path.write_text(render_json(report), encoding="utf-8", newline="\n")
            return str(path)
        except OSError:
            return ""

    def _request(self, target: str, profile: str | None) -> Any:
        from .runner import ScanRequest

        if not isinstance(target, str) or not target.strip() or len(target) > 2048:
            raise ServeError("`target` must be a non-empty string of at most 2048 characters")
        profile = profile or self.cfg.profile
        if profile not in ("quick", "standard"):
            raise ServeError("`profile` must be quick or standard; dynamic analysis is started by the user, not by an agent")
        if target.strip().lower().startswith("mcp+stdio:"):
            raise ServeError("a local server command is not started on request of an agent; the user can run `agentguard mcp inspect`")
        return ScanRequest(targets=[target.strip()], profile=profile, llm="auto" if profile == "standard" else "off",
                           context="installed", policy=self.cfg.policy, agent_safe=True, cwd=self.cfg.cwd, http=self.cfg.http,
                           sandbox=self.cfg.sandbox, env=self.cfg.env)

    def _summary(self, report: Any, saved: str) -> dict[str, Any]:
        safe = scrub_report(report)
        findings = []
        for f in safe.findings[:MAX_FINDINGS]:
            det = self.pack.detectors.get(f.key)
            findings.append({
                "id": f.key, "title": det.title if det is not None else clean(f.title, 160), "severity": f.severity.value,
                "confidence": f.confidence.value, "category": f.category.value, "lane": f.lane.value,
                "file": f.location.file if f.location else "", "line": f.location.start.line if f.location else 0,
                "what_it_means": (det.description if det is not None else "")[:600],
                "fix": {"kind": f.fix.kind.value, "summary": (det.remediation if det is not None else "")[:600]},
                "fingerprint": f.fingerprint,
            })
        cov = safe.coverage
        return {
            "verdict": safe.verdict.value, "score": safe.score, "risk_tier": safe.risk_tier.value,
            "coverage": {"files_total": cov.files_total, "files_analysed": cov.files_analysed, "analyzability": cov.analyzability},
            "incomplete": bool(safe.incomplete),
            "findings_total": len(safe.findings), "findings": findings,
            "artifacts": [{"id": a.id, "type": a.type, "ecosystem": a.ecosystem, "risk_tier": a.risk_tier.value, "verdict": a.verdict.value,
                           "capabilities": list(a.capabilities)[:20]} for a in safe.artifacts[:50]],
            "full_report": saved,
            "note": "Findings carry the rule's fixed wording only. Text from the scanned target is withheld on purpose; "
                    "the user can open the full report at the path above.",
        }

    # -- operations -----------------------------------------------------------------------------------
    def scan(self, target: str, profile: str | None = None) -> dict[str, Any]:
        from .runner import UsageError, run_scan

        req = self._request(target, profile)
        with self.lock:
            try:
                outcome = run_scan(req)
            except UsageError:
                # The message may quote the target; an agent gets fixed wording.
                raise ServeError("the target could not be read or fetched (wrong form, not found, or refused); nothing was scanned") from None
        return self._summary(outcome.report, self._save(outcome.report, req.targets[0]))

    def check_install(self, source: str, agent: str | None = None, scope: str | None = None) -> dict[str, Any]:
        from .install import AGENTS, plan_install
        from .runner import UsageError

        agent, scope = agent or "claude-code", scope or "project"
        if agent not in AGENTS:
            raise ServeError(f"`agent` must be one of {', '.join(sorted(AGENTS))}")
        if scope not in ("project", "user"):
            raise ServeError("`scope` must be project or user")
        req = self._request(source, None)
        with self.lock:
            try:
                plan = plan_install(req, agent=agent, scope=scope)
            except UsageError:
                raise ServeError("the source could not be read, fetched or laid out for that agent; nothing was scanned or written") from None
        report = plan.outcome.report
        out = self._summary(report, self._save(report, req.targets[0]))
        data = plan.to_dict()
        verdict = report.verdict.value
        out.update({
            "installable": verdict == "ALLOW" and bool(data.get("installable")), "needs_user_approval": verdict == "REVIEW",
            "agent": agent, "scope": scope,
            "would_write": [clean(str(w.get("path", "")), 240) for w in data.get("writes", [])][:200],
            "would_change": [{"kind": clean(str(c.get("kind", "")), 40), "target": clean(str(c.get("target", "")), 240)}
                             for c in data.get("changes", [])][:100],
            "decision": {"ALLOW": "May be installed.",
                         "REVIEW": "Do not install on your own. Ask the user to review the report; they can install with `agentguard install --accept`.",
                         "BLOCK": "Do not install. Tell the user the scan blocked it and point them to the report."}[verdict],
        })
        return out

    def explain(self, ident: str) -> dict[str, Any]:
        if not isinstance(ident, str) or not ident.strip() or len(ident) > 120:
            raise ServeError("`id` must be a rule id such as AG-INJ-001")
        key = self.pack.resolve_key(ident.strip().upper()) or self.pack.resolve_key(ident.strip())
        rule = None
        try:
            rule = self.pack.rule((key or ident.strip().upper()).partition("/")[0])
        except (KeyError, ValueError):
            rule = None
        if rule is None:
            raise ServeError("no rule with that id; `agentguard rules list` shows every rule")
        det = self.pack.detectors.get(key or "") or next((d for d in self.pack.detectors.values() if d.rule_id == rule.id), None)
        return {
            "id": rule.id, "title": rule.title, "family": rule.family, "category": rule.category.value, "severity": rule.severity.value,
            "confidence": rule.confidence.value, "lane": rule.lane.value, "fix_kind": rule.fix.value, "status": rule.status.value,
            "description": det.description if det is not None else "", "why": det.why if det is not None else "",
            "remediation": det.remediation if det is not None else "",
            "detectors": sorted(d.key for d in self.pack.detectors.values() if d.rule_id == rule.id),
        }

    def inventory(self, include_user: bool = True) -> dict[str, Any]:
        from .acquire.machine import user_home
        from .core.engine import scan as core_scan
        from .core.models import ScanOptions
        from .io.discovery import discover

        with self.lock:
            disc = discover(self.cfg.cwd, include_user=bool(include_user), home=user_home())
            report = scrub_report(core_scan(disc.tree, ScanOptions(agent_safe=True)))
        return {
            "components": [{"id": a.id, "type": a.type, "ecosystem": a.ecosystem, "risk_tier": a.risk_tier.value, "verdict": a.verdict.value,
                            "findings": a.findings, "capabilities": list(a.capabilities)[:20], "location": a.root}
                           for a in report.artifacts[:300]],
            "verdict": report.verdict.value,
            "locations_checked": sum(1 for r in disc.records), "locations_found": sum(1 for r in disc.records if r.exists),
        }

    def call(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        if name == "agentguard_scan":
            return self.scan(args.get("target"), args.get("profile"))           # type: ignore[arg-type]
        if name == "agentguard_check_install":
            return self.check_install(args.get("source"), args.get("agent"), args.get("scope"))   # type: ignore[arg-type]
        if name == "agentguard_explain":
            return self.explain(args.get("id"))                                 # type: ignore[arg-type]
        if name == "agentguard_inventory":
            return self.inventory(args.get("include_user", True) is not False)
        raise ServeError("unknown tool")

    def info(self) -> dict[str, Any]:
        return {"name": "agentguard", "title": "Agent Guard", "version": ENGINE_VERSION, "rule_pack": self.pack.version}


# --------------------------------------------------------------------- MCP --
INSTRUCTIONS = ("Agent Guard scans agent extensions (skills, plugins, instruction files, MCP servers) before they are used. Call "
                "agentguard_check_install before installing anything, and act on `decision`. Results never contain text from the "
                "scanned target.")


def handle_rpc(service: Service, msg: Any) -> dict[str, Any] | None:
    """One JSON-RPC message in, one reply out (None for a notification)."""
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or not isinstance(msg.get("method"), str):
        return {"jsonrpc": "2.0", "id": msg.get("id") if isinstance(msg, dict) else None,
                "error": {"code": -32600, "message": "invalid request"}}
    method, params, mid = msg["method"], msg.get("params") if isinstance(msg.get("params"), dict) else {}, msg.get("id")
    if "id" not in msg:
        return None                                    # notifications/initialized, notifications/cancelled, …

    def ok(result: dict[str, Any]) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    def err(code: int, message: str) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}

    if method == "initialize":
        asked = params.get("protocolVersion")
        version = asked if asked in PROTOCOL_VERSIONS[1:] else PROTOCOL_VERSIONS[1]
        return ok({"protocolVersion": version, "capabilities": {"tools": {"listChanged": False}}, "serverInfo": service.info(),
                   "instructions": INSTRUCTIONS})
    if method == "server/discover":
        return ok({"supportedVersions": list(PROTOCOL_VERSIONS), "capabilities": {"tools": {"listChanged": False}},
                   "serverInfo": service.info(), "instructions": INSTRUCTIONS})
    if method == "ping":
        return ok({})
    if method == "tools/list":
        return ok({"tools": TOOLS})
    if method in ("prompts/list", "resources/list", "resources/templates/list"):
        return ok({method.split("/")[0] if method != "resources/templates/list" else "resourceTemplates": []})
    if method == "tools/call":
        name, args = params.get("name"), params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
        if not isinstance(name, str) or name not in {t["name"] for t in TOOLS}:
            return err(-32602, "unknown tool")
        try:
            result = service.call(name, args)
        except ServeError as exc:
            return ok({"content": [{"type": "text", "text": str(exc)}], "isError": True})
        except Exception as exc:                        # noqa: BLE001 — never a traceback (it can quote the target)
            return ok({"content": [{"type": "text", "text": f"the scan failed inside Agent Guard ({type(exc).__name__}); nothing is known about the target"}],
                       "isError": True})
        return ok({"content": [{"type": "text", "text": json.dumps(result, indent=2, ensure_ascii=True)}], "structuredContent": result,
                   "isError": False})
    return err(-32601, "method not found")


def serve_mcp(cfg: ServeConfig, stdin: BinaryIO | None = None, stdout: TextIO | None = None) -> None:
    """Speak MCP over stdio until the input closes. Nothing but protocol messages is ever written to stdout."""
    service = Service(cfg)
    src = stdin if stdin is not None else sys.stdin.buffer
    out = stdout if stdout is not None else sys.stdout
    for raw in src:
        line = raw.strip()
        if not line:
            continue
        if len(line) > MAX_REQUEST:
            reply: Any = {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "request too large"}}
        else:
            try:
                msg = json.loads(line)
            except ValueError:
                reply = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
            else:
                if isinstance(msg, list):
                    replies = [r for r in (handle_rpc(service, m) for m in msg[:50]) if r is not None]
                    reply = replies or None
                else:
                    reply = handle_rpc(service, msg)
        if reply is not None:
            out.write(json.dumps(reply, ensure_ascii=True, separators=(",", ":")) + "\n")
            out.flush()


# -------------------------------------------------------------------- HTTP --
def make_http_server(cfg: ServeConfig, host: str = "127.0.0.1", port: int = 8765, token: str | None = None) -> tuple[ThreadingHTTPServer, str]:
    service = Service(cfg)
    env = dict(os.environ) if cfg.env is None else cfg.env
    token = token or env.get(TOKEN_VAR) or secrets.token_urlsafe(24)
    allowed_hosts = {f"{h}:{port}" for h in _LOOPBACK_HOSTS} | set(_LOOPBACK_HOSTS)
    if host not in ("127.0.0.1", "localhost", "::1"):
        allowed_hosts |= {host, f"{host}:{port}"}

    class Handler(BaseHTTPRequestHandler):
        server_version = "agentguard"
        sys_version = ""

        def log_message(self, fmt: str, *args: Any) -> None:      # quiet: request lines can carry target text
            return

        def _send(self, status: int, body: dict[str, Any]) -> None:
            data = json.dumps(body, ensure_ascii=True).encode("ascii")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(data)

        def _allowed(self) -> bool:
            if self.headers.get("Origin") is not None or (self.headers.get("Sec-Fetch-Site") or "none") not in ("none",):
                self._send(403, {"error": "requests from a browser are refused"})
                return False
            if (self.headers.get("Host") or "").lower() not in allowed_hosts:
                self._send(403, {"error": "unexpected Host header"})
                return False
            given = (self.headers.get("Authorization") or "")
            if not given.startswith("Bearer ") or not hmac.compare_digest(given[7:].encode(), token.encode()):
                self._send(401, {"error": "missing or wrong bearer token (printed when the server started)"})
                return False
            return True

        def _run(self, fn: Any) -> None:
            try:
                self._send(200, fn())
            except ServeError as exc:
                self._send(400, {"error": str(exc)})
            except Exception as exc:                     # noqa: BLE001
                self._send(500, {"error": f"the request failed inside Agent Guard ({type(exc).__name__})"})

        def do_GET(self) -> None:                        # noqa: N802
            if self.path == "/health":
                self._send(200, {"status": "ok", **service.info()})
                return
            if not self._allowed():
                return
            path, _, query = self.path.partition("?")
            if path.startswith("/explain/"):
                self._run(lambda: service.explain(path[len("/explain/"):]))
            elif path == "/inventory":
                self._run(lambda: service.inventory("include_user=false" not in query))
            elif path == "/tools":
                self._send(200, {"tools": TOOLS})
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self) -> None:                       # noqa: N802
            if not self._allowed():
                return
            if "application/json" not in (self.headers.get("Content-Type") or "").lower():
                self._send(415, {"error": "send application/json"})
                return
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = -1
            if not 0 <= length <= MAX_REQUEST:
                self._send(413, {"error": "request too large"})
                return
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                self._send(400, {"error": "the body is not JSON"})
                return
            if not isinstance(body, dict):
                self._send(400, {"error": "the body must be a JSON object"})
                return
            if self.path == "/scan":
                self._run(lambda: service.scan(body.get("target"), body.get("profile")))
            elif self.path == "/check-install":
                self._run(lambda: service.check_install(body.get("source"), body.get("agent"), body.get("scope")))
            elif self.path == "/mcp":
                reply = handle_rpc(service, body)
                self._send(200, reply) if reply is not None else self._send(202, {})
            else:
                self._send(404, {"error": "not found"})

    return ThreadingHTTPServer((host, port), Handler), token


def serve_http(cfg: ServeConfig, host: str = "127.0.0.1", port: int = 8765) -> None:
    server, token = make_http_server(cfg, host, port)
    where = f"http://{host}:{server.server_address[1]}"
    err = sys.stderr
    err.write(f"Agent Guard HTTP API on {where} (agent-safe output)\n")
    if host not in ("127.0.0.1", "localhost", "::1"):
        err.write("WARNING: not bound to loopback; anyone who can reach this address and knows the token can run scans.\n")
    err.write(f"Bearer token: {token}\n")
    err.write("  GET  /health                 no token needed\n  POST /scan                   {\"target\": \"…\", \"profile\": \"quick\"}\n"
              "  POST /check-install          {\"source\": \"…\", \"agent\": \"claude-code\", \"scope\": \"project\"}\n"
              "  GET  /explain/<rule id>\n  GET  /inventory\n  POST /mcp                    one JSON-RPC message (the same tools as --mcp)\n")
    err.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


__all__ = ["INSTRUCTIONS", "ServeConfig", "ServeError", "Service", "TOOLS", "handle_rpc", "make_http_server", "serve_http", "serve_mcp"]
