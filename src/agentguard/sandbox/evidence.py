"""The detection policy of the dynamic tier (spec/sandbox.md §7): what the container reported, turned into
evidence for catalogue rules and tied back to the file and line that caused it.

Everything the container sends is untrusted data. It is read by fixed code, type-checked field by field
and length-limited; nothing from it is executed or interpreted beyond that.

A clean run proves nothing: evidence here is added to static findings and never clears one.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from ..core.models import DynamicEvidence
from .honey import Honey
from .plan import TARGET_DIR, Plan

_INSTRUCTION_FILE = re.compile(r"(?i)(?:^|/)(?:CLAUDE(?:\.local)?\.md|AGENTS(?:\.override)?\.md|GEMINI\.md|SOUL\.md|MEMORY\.md|USER\.md|"
                               r"\.cursorrules|\.windsurfrules|copilot-instructions\.md)$|/\.cursor/rules/|/\.claude/(?:rules|projects/[^/]+/memory)/|"
                               r"/\.github/instructions/|/\.codex/AGENTS\.md$")
_AGENT_CONFIG = re.compile(r"(?i)(?:^|/)(?:\.claude\.json|\.mcp\.json|mcp\.json|mcp_config\.json|claude_desktop_config\.json)$|"
                           r"/\.claude/settings(?:\.local)?\.json$|/\.claude/hooks/|/\.codex/(?:config\.toml|hooks\.json)$|"
                           r"/\.cursor/(?:mcp|hooks|cli)\.json$|/\.gemini/settings\.json$|/\.vscode/(?:mcp|settings)\.json$|/\.github/hooks/")
_INSTALLED = re.compile(r"(?i)/\.(?:claude|codex|cursor|gemini|agents|openclaw)/(?:skills|plugins|extensions|commands|agents)/")
_SHELL_PROFILE = re.compile(r"/\.(?:bashrc|bash_profile|bash_login|profile|zshrc|zprofile|zshenv|zlogin|config/fish/config\.fish)$|^/etc/profile")
_SCHEDULED = re.compile(r"(?i)/\.config/(?:systemd/user|autostart)/|^/etc/(?:cron|systemd)|^/var/spool/cron|/Library/LaunchAgents/")
_SSH_ACCESS = re.compile(r"/\.ssh/authorized_keys$|^/etc/ssh/sshd_config")
_QUIET = re.compile(r"/(?:__pycache__|\.cache|\.npm|\.local/share/(?:pip|uv|virtualenv)|\.config/pip|node_modules|\.pytest_cache)/|\.pyc$")
_NOTE = re.compile(r"(?i)(?:^|/)(?:[^/]*(?:decrypt|ransom|recover[_-]?(?:your)?[_-]?files|how[_-]?to[_-]?(?:restore|unlock)|readme[_-]?(?:locked|encrypted))[^/]*)$")
_MINERS = re.compile(r"(?i)^(?:xmrig|minerd|cpuminer|cgminer|ethminer|t-rex|nbminer|lolminer|phoenixminer|xmr-stak)")
_SHELLS = ("sh", "bash", "dash", "zsh", "ash")
MAX_EVIDENCE = 200


@dataclass
class Outcome:
    evidence: list[DynamicEvidence] = field(default_factory=list)
    not_reached: dict[str, str] = field(default_factory=dict)
    facts: dict[str, dict[str, Any]] = field(default_factory=dict)
    lifted: dict[str, bytes] = field(default_factory=dict)        # files the run wrote into the target (closure lift)
    lines: list[str] = field(default_factory=list)                # notes for the user
    level: str = "baseline"
    seconds: float = 0.0
    entries_run: int = 0


def _s(value: Any, limit: int = 400) -> str:
    return value[:limit] if isinstance(value, str) else ""


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _show(entry: dict[str, Any]) -> str:
    text = entry.get("shell") or " ".join(str(a) for a in entry.get("argv", []))
    return " ".join(str(text).replace(TARGET_DIR + "/", "").split())[:140]


def _record_text(rec: dict[str, Any]) -> str:
    body = _dict(rec.get("body") or rec.get("data"))
    return "\n".join([_s(rec.get("name")), _s(rec.get("host")), _s(rec.get("path"), 2000), json.dumps(_dict(rec.get("headers")))[:4000],
                      _s(body.get("text"), 70000), _s(body.get("b64"), 90000)])


def _where(rec: dict[str, Any]) -> str:
    kind = rec.get("t")
    if kind == "dns":
        return f"a DNS query for {_s(rec.get('name'), 120)}"
    if kind == "http":
        return f"{_s(rec.get('method'), 10)} {'https' if rec.get('tls') else 'http'}://{_s(rec.get('host'), 120)}{_s(rec.get('path'), 80)}"
    return f"a TCP connection to port {rec.get('port')}"


def analyze(plan: Plan, result: dict[str, Any], honey: Honey) -> Outcome:
    out = Outcome(not_reached=dict(plan.not_reached))
    if not isinstance(result, dict) or result.get("error"):
        for path, _line in plan.sources.values():
            out.not_reached.setdefault(path, f"the sandbox run failed ({_s(_dict(result).get('error'), 160) or 'no result'})")
        out.lines.append("dynamic: the run inside the sandbox failed; nothing was observed")
        return out
    traced = bool(result.get("strace"))
    net_ok = _dict(result.get("network_setup"))
    out.level = "baseline" if traced else "baseline (untraced)"
    out.seconds = round(float(result.get("finished") or 0) - float(result.get("started") or 0), 1) if result.get("finished") else 0.0
    by_id = {e["id"]: e for e in plan.job.get("entries", [])}
    network = [r for r in _list(result.get("network")) if isinstance(r, dict)]
    lifted_src = {str(x.get("id")): (str(x.get("path")), str(x.get("from"))) for x in _list(result.get("lifted")) if isinstance(x, dict)}
    seen: set[tuple[str, str, str]] = set()
    base_view: dict[str, set[str]] = {}
    served: dict[str, Any] = {}

    def emit(rule: str, path: str, line: int, detail: str, trace: list[str], confirmed: bool = True) -> None:
        key = (rule, path, detail[:120])
        if key in seen or len(out.evidence) >= MAX_EVIDENCE:
            return
        seen.add(key)
        out.evidence.append(DynamicEvidence(rule=rule, path=path, line=max(1, line), detail=detail[:480],
                                            trace=[t[:300] for t in trace[:8]], confirmed=confirmed))

    for rec in _list(result.get("entries")):
        if not isinstance(rec, dict):
            continue
        eid = _s(rec.get("id"), 20)
        entry = by_id.get(eid)
        if entry is None and eid in lifted_src:
            path = lifted_src[eid][0]
            entry = {"id": eid, "kind": "script", "argv": [path], "source": {"path": path, "line": 1}}
        if entry is None:
            continue
        path, line = entry["source"]["path"], int(entry["source"].get("line", 1))
        cmd = _show(entry)
        variant = _s(rec.get("variant"), 20) or "base"
        status = rec.get("status")
        if status != "ok":
            if variant == "base":
                out.not_reached.setdefault(path, _s(rec.get("reason"), 200) or f"`{cmd}` did not run to completion ({status})")
            if status != "timeout":
                continue
        out.entries_run += 1
        events = _dict(rec.get("events"))
        files = _dict(rec.get("files"))
        start, end = float(rec.get("start") or 0), float(rec.get("end") or 1e18)
        window = [r for r in network if start - 0.5 <= float(r.get("ts") or 0) <= end + 1.0]
        execs = [[_s(a, 200) for a in _list(argv)] for argv in _list(events.get("exec"))]
        during = f"While `{cmd}` ran" + ("" if variant == "base" else f" (in the '{variant}' environment)")
        behaviour: set[str] = set()

        # A canary reaching any network sink.
        for r in window:
            for _canary, label, how in honey.leaked(_record_text(r)):
                emit("AG-EXF-001", path, line, f"{during}, the decoy {label} left the machine in {_where(r)}"
                     + ("" if how == "as it is" else f", encoded as {how}") + ".", [json.dumps({k: r[k] for k in ("t", "host", "method", "path", "name", "port") if k in r})])
                behaviour.add("exfil")

        # Decoy credential files read by a program that has no business with them.
        for item in _list(events.get("open")):
            if not (isinstance(item, list) and len(item) >= 3):
                continue
            opened, mode, comm = _s(item[0], 300), _s(item[1], 2), _s(item[2], 40)
            rule = honey.reads.get(opened)
            if rule and mode == "r" and comm not in honey.owners.get(opened, ()):
                emit(rule, path, line, f"{during}, `{comm or 'a process'}` read {opened.replace(honey.home, '~')}, which the task did not need.",
                     [f"open {opened} by {comm}"])
                behaviour.add(f"read:{opened}")
        if any(len(a) >= 1 and a[0].rsplit("/", 1)[-1] in ("secret-tool", "security", "keyctl") for a in execs):
            emit("AG-CRED-005", path, line, f"{during}, it queried the operating system's credential store.", [" ".join(a) for a in execs][:4])

        # Writes outside the target's own directory, by where they landed.
        changed = [(x, "created") for x in _list(files.get("created"))] + [(x, "modified") for x in _list(files.get("modified"))]
        for item, what in changed:
            wrote = _s(_dict(item).get("path"), 300)
            if wrote.startswith(TARGET_DIR + "/"):
                # Closure lift: whatever the run wrote into the target's own directory is scanned like the rest of it,
                # wherever it was put (a packed skill rebuilds itself in a directory scanners tend to skip).
                rel = wrote[len(TARGET_DIR) + 1:]
                text = _dict(item).get("text")
                if what == "created" and isinstance(text, str) and not rel.endswith(".pyc") and "__pycache__/" not in rel \
                        and rel not in out.lifted and len(out.lifted) < 40:
                    out.lifted[rel] = text.encode("utf-8")
                continue
            if not wrote or _QUIET.search(wrote) or wrote.startswith("/tmp/") or wrote.startswith("/var/tmp/"):
                continue
            shown = wrote.replace(honey.home, "~")
            for rx, rule, text in (
                (_SSH_ACCESS, "AG-PERSIST-006", f"it {what} {shown}, which decides who may log in to this machine"),
                (_AGENT_CONFIG, "AG-PERSIST-002", f"it {what} {shown}, an agent settings, hook or MCP configuration file"),
                (_INSTRUCTION_FILE, "AG-PERSIST-001", f"it {what} {shown}, a file every later agent session loads"),
                (_INSTALLED, "AG-PERSIST-003", f"it {what} {shown}, installing another agent component without being asked"),
                (_SHELL_PROFILE, "AG-PERSIST-004", f"it {what} {shown}, which runs at every new shell"),
                (_SCHEDULED, "AG-PERSIST-005", f"it {what} {shown}, which runs on a schedule or at login"),
            ):
                if rx.search(wrote):
                    emit(rule, path, line, f"{during}, {text}.", [f"{what} {wrote}"])
                    behaviour.add(f"write:{rule}")
                    break
        if any(a and a[0].rsplit("/", 1)[-1] == "crontab" and "-l" not in a for a in execs):
            emit("AG-PERSIST-005", path, line, f"{during}, it changed the user's crontab.", [" ".join(a) for a in execs if a and "crontab" in a[0]][:3])

        # Downloaded content that was then run or obeyed.
        ran = [k for k in _list(rec.get("marker_ran")) if isinstance(k, str)]
        fetched = [r for r in window if r.get("t") == "http" and _s(r.get("method")) == "GET"]
        if any(k in ("sh", "py", "js") for k in ran):
            saved = any(plan.job.get("marker", "\0") in _s(_dict(x).get("text"), 4000) for x, _ in changed)
            src = _where(fetched[-1]) if fetched else "a URL"
            emit("AG-EXEC-003" if saved else "AG-EXEC-001", path, line,
                 f"{during}, it downloaded a script ({src}) and ran it. The sandbox served a harmless script; a real server chooses what runs.",
                 [_where(r) for r in fetched][-4:])
            behaviour.add("download-exec")
        elif fetched:
            for r in fetched:
                host = _s(r.get("host"), 200).split(":")[0].lower()
                if _s(r.get("served")) in ("text/x-shellscript", "text/x-python", "application/javascript", "text/markdown"):
                    emit("AG-SUPPLY-009", path, line, f"{during}, it fetched code or instructions at run time ({_where(r)})"
                         + ("" if host in plan.hosts_named else ", from a host the documentation never names") + ".", [_where(r)], confirmed=False)
                    behaviour.add(f"fetch:{host}")
        for r in window:
            host = _s(r.get("host") or r.get("name"), 200).split(":")[0].lower().rstrip(".")
            if r.get("t") == "http" and _s(r.get("method")) in ("POST", "PUT", "PATCH") and host and host not in plan.hosts_named:
                emit("AG-EXF-015", path, line, f"{during}, it sent data to {host}, a host the documentation never names ({_where(r)}).",
                     [_where(r)], confirmed=False)
                behaviour.add(f"post:{host}")
            if r.get("t") == "tcp" and re.search(r"mining\.(?:subscribe|authorize)|\"method\":\s*\"login\"", _record_text(r)):
                emit("AG-IMPACT-003", path, line, f"{during}, it spoke a mining-pool protocol on port {r.get('port')}.", [_where(r)])

        # Processes that have nothing to do with the task.
        if any(a and _MINERS.match(a[0].rsplit("/", 1)[-1]) for a in execs):
            emit("AG-IMPACT-003", path, line, f"{during}, it started a cryptocurrency miner.", [" ".join(a) for a in execs if a][:4])
        connects = [c for c in _list(events.get("connect")) if isinstance(c, list) and len(c) >= 3]
        shell_out = [c for c in connects if _s(c[2], 20) in _SHELLS + ("nc", "ncat", "socat") and int(c[1] or 0) not in (53, 80, 443)]
        if int(events.get("listen") or 0) > 0 and entry.get("kind") != "mcp":
            emit("AG-EXEC-004", path, line, f"{during}, it opened a listening socket, as a bind shell or backdoor does.", ["listen()"], confirmed=False)
            behaviour.add("listen")
        elif shell_out:
            emit("AG-EXEC-004", path, line, f"{during}, a shell connected out to {shell_out[0][0]}:{shell_out[0][1]}, as a reverse shell does.",
                 [f"connect {c[0]}:{c[1]} by {c[2]}" for c in shell_out[:3]], confirmed=False)
            behaviour.add("reverse-shell")

        # Mass delete or rewrite of the decoy documents.
        deleted = [p for p in _list(files.get("deleted")) if isinstance(p, str) and p in honey.decoys]
        rewritten = [_s(_dict(x).get("path")) for x in _list(files.get("modified")) if _s(_dict(x).get("path")) in honey.decoys]
        renamed = [r for r in _list(events.get("rename")) if isinstance(r, list) and len(r) == 2 and _s(r[0]) in honey.decoys]
        note = next((_s(_dict(x).get("path")) for x in _list(files.get("created")) if _NOTE.search(_s(_dict(x).get("path")))), "")
        if len(rewritten) + len(renamed) >= 4 and (note or len(renamed) >= 4):
            emit("AG-IMPACT-002", path, line, f"{during}, it rewrote or renamed {len(rewritten) + len(renamed)} of the user's documents"
                 + (f" and left {note.replace(honey.home, '~')}" if note else "") + ".", (rewritten + [str(r) for r in renamed])[:6])
            behaviour.add("encrypt")
        elif len(deleted) >= 4:
            emit("AG-IMPACT-001", path, line, f"{during}, it deleted {len(deleted)} of the user's documents.", deleted[:6])
            behaviour.add("wipe")

        # Checks for a debugger, a tracer, a container or a virtual machine.
        probes = [_s(p, 80) for p in _list(events.get("probes"))]
        if events.get("ptrace") is True:
            emit("AG-EVADE-020", path, line, f"{during}, it asked whether it was being traced.", ["ptrace(PTRACE_TRACEME)"], confirmed=False)
        if any(p.startswith(("/.dockerenv", "/sys/class/dmi", "/sys/hypervisor", "/run/.containerenv")) for p in probes) and \
                not any(a and a[0].rsplit("/", 1)[-1] in ("systemd-detect-virt", "docker", "npm", "node") for a in execs[:1]):
            emit("AG-EVADE-009", path, line, f"{during}, it checked whether it was inside a container or virtual machine "
                 f"({', '.join(probes[:3])}).", probes[:4], confirmed=False)

        # Behaviour that appears only in one environment.
        if variant == "base":
            base_view[eid] = behaviour
        elif eid in base_view and (behaviour - base_view[eid]):
            extra = sorted(behaviour - base_view[eid])
            rule = "AG-EVADE-010" if variant == "later" else "AG-EVADE-009"
            emit(rule, path, line, f"`{cmd}` behaved differently in the '{variant}' environment "
                 f"({'the clock moved forward 200 days' if variant == 'later' else 'made to look like a CI runner'}): "
                 f"only there did it {', '.join(extra)[:160]}.", extra)

        # A local MCP server: what it served, what its tools returned, and what the fuzzer proved.
        mcp = _dict(rec.get("mcp"))
        name = plan.servers.get(eid)
        if mcp and name:
            if mcp.get("error") and not mcp.get("tools"):
                out.not_reached.setdefault(path, f"the server `{name}` did not answer inside the sandbox ({_s(mcp.get('error'), 160)})")
            else:
                served[name] = mcp
            for hit in _list(mcp.get("confirmed")):
                hit = _dict(hit)
                rule = {"cmdi": "AG-VULN-001", "traversal": "AG-VULN-002", "ssrf": "AG-VULN-003", "sqli": "AG-VULN-004"}.get(_s(hit.get("kind"), 12))
                if rule:
                    emit(rule, path, line, f"Calling the tool `{_s(hit.get('tool'), 60)}` of `{name}` with a crafted `{_s(hit.get('param'), 40)}` "
                         f"argument inside the sandbox: {_s(hit.get('proof'), 160)}.", [f"payload: {_s(hit.get('payload'), 120)}"])

    for name, mcp in sorted(served.items()):
        tools = [t for t in _list(mcp.get("tools")) if isinstance(t, dict) and isinstance(t.get("name"), str)]
        out.facts.setdefault("served", {})[name] = {
            "tools": tools, "prompts": [p for p in _list(mcp.get("prompts")) if isinstance(p, dict)],
            "resources": [r for r in _list(mcp.get("resources")) if isinstance(r, dict)],
            "instructions": mcp.get("instructions") if isinstance(mcp.get("instructions"), str) else None,
            "server_info": mcp.get("server_info") if isinstance(mcp.get("server_info"), dict) else None,
            "protocol_version": _s(mcp.get("protocol_version"), 20) or None}
        out.facts.setdefault("served_tools", {})[name] = [t["name"] for t in tools]
        results = [{"tool": _s(_dict(r).get("tool"), 80), "text": _s(_dict(r).get("text"), 4000), "error": bool(_dict(r).get("error"))}
                   for r in _list(mcp.get("tool_results")) if isinstance(r, dict)]
        if results:
            out.facts.setdefault("tool_results", {})[name] = results
        out.lines.append(f"dynamic: `{name}` was started in the sandbox and served {len(tools)} tool(s); {len(results)} were called with "
                         f"harmless arguments, {len(_list(mcp.get('confirmed')))} injection flaw(s) were confirmed by fuzzing")

    if not traced:
        out.lines.append("dynamic: system-call tracing was not available in the container; file changes and network traffic were still observed")
    if not net_ok.get("anyip"):
        out.lines.append("dynamic: connections to literal IP addresses were refused rather than captured (names were still sinkholed)")
    if out.lifted:
        out.lines.append(f"dynamic: the run wrote {len(out.lifted)} new file(s) into the target's own directory; they were added to the scan "
                         f"({', '.join(sorted(out.lifted)[:4])})")
    return out


__all__ = ["Outcome", "analyze"]
