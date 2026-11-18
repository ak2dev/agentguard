"""agentguard.lock: what was approved (spec/interfaces.md §6).

Per artifact: file hashes, the launch command of a server, a hash per tool
definition (the canonical JSON of the whole definition: name, title,
description, input and output schema, annotations), its capabilities, risk
tier, verdict and the findings that were accepted. A later scan compares
against it; any difference re-opens review (rug pulls, update drift).
"""

from __future__ import annotations

import difflib
import json

from .models import Artifact, Component, LockEntry, Lockfile, Report, canonical_json
from .models.config import LockLaunch
from .models.enums import CapLabel, ComponentKind
from .textutil import sha256_hex, visible_escape

LOCKED_KINDS = (ComponentKind.skill, ComponentKind.mcp_server, ComponentKind.package, ComponentKind.instruction_file,
                ComponentKind.subagent, ComponentKind.command, ComponentKind.plugin, ComponentKind.marketplace,
                ComponentKind.settings, ComponentKind.hook, ComponentKind.bundle, ComponentKind.connector,
                ComponentKind.ci_workflow, ComponentKind.workspace, ComponentKind.container)
FLOW_LABELS = {CapLabel.reads_private_data, CapLabel.ingests_untrusted_content, CapLabel.external_egress,
               CapLabel.destructive, CapLabel.code_exec, CapLabel.persistence}
_FLOW_NAMES = {lab.spec_name for lab in FLOW_LABELS}

LOCK_VERSION = 2
TOOL_HASH_VERSION = 2
LEGACY_TOOL_KEYS = ("output_schema",)  # canonical keys a version-1 tool hash does not cover


def lock_key(c: Component) -> str:
    return f"{c.kind.value}:{c.name}@{c.root}"


def flow_capabilities(names: list[str]) -> set[str]:
    """The capabilities whose appearance after approval is itself a finding."""
    return set(names) & _FLOW_NAMES


def launch_of(c: Component) -> LockLaunch | None:
    s = c.server
    if s is None or not (s.command or s.url):
        return None
    digest = sha256_hex(canonical_json({"command": s.command, "args": s.args, "url": s.url, "env": sorted(s.env_names)}))
    return LockLaunch(command=s.command, args=list(s.args), url=s.url, sha256=digest)


def build_lock(report: Report, *, approved_by: str = "", approved_at: str = "", review_by: str = "",
               accept_findings: bool = False) -> Lockfile:
    """Record what a scan saw. The findings of that scan are recorded as
    *accepted* (a later scan against this lock does not report them again) only
    when the person approving says so; creating a baseline never accepts by itself."""
    summaries = {a.component_id: a for a in report.artifacts}
    accepted: dict[str, list[str]] = {}
    for f in report.findings:
        for cid in f.component_ids:
            accepted.setdefault(cid, []).append(f.fingerprint)
    entries = build_entries(report.inventory, report.files)
    by_key = {lock_key(c): c for c in report.inventory}
    for e in entries:
        comp = by_key.get(e.key)
        summary = summaries.get(comp.id) if comp else None
        if summary is not None:
            e.id, e.ecosystem = summary.id, summary.ecosystem
            e.risk_tier, e.verdict = summary.risk_tier.value, summary.verdict.value
        e.source = report.target.source if report.target.kind != "local" else ""
        e.commit = report.target.commit
        e.accepted_findings = sorted(accepted.get(comp.id, [])) if comp and accept_findings else []
        e.approved_by, e.approved_at, e.review_by = approved_by, approved_at, review_by
    return Lockfile(
        lock_version=LOCK_VERSION, tool_hash_version=TOOL_HASH_VERSION,
        generated_by={"engine": report.tool.version, "rule_pack": report.tool.rule_pack, "intel": report.tool.intel},
        artifacts=entries,
    )


def covered(definition: dict, version: int = TOOL_HASH_VERSION) -> dict:
    """The part of a canonical tool definition that a lock of tool_hash_version `version` pins."""
    if version >= 2:
        return definition
    return {k: v for k, v in definition.items() if k not in LEGACY_TOOL_KEYS}


def tool_hash(definition: dict, version: int = TOOL_HASH_VERSION) -> str:
    """Hash of a canonical tool definition as a lock of tool_hash_version `version` computed it."""
    return sha256_hex(canonical_json(covered(definition, version)))


def build_entries(components: list[Component], artifacts: list[Artifact]) -> list[LockEntry]:
    arts_by_comp: dict[str, list] = {}
    for a in artifacts:
        arts_by_comp.setdefault(a.component_id, []).append(a)
    entries: list[LockEntry] = []
    for c in sorted(components, key=lambda c: c.id):
        if c.kind not in LOCKED_KINDS:
            continue
        files = None
        if c.kind != ComponentKind.mcp_server or c.metadata.get("source_package"):
            files = {}
            for a in sorted(arts_by_comp.get(c.id, []), key=lambda a: a.path):
                rel = a.path[len(c.root) + 1:] if c.root and a.path.startswith(c.root + "/") else a.path
                files[rel] = a.sha256
        tools = {t.name: t.normalized_hash() for t in c.tools} or None
        definitions = {t.name: t.canonical() for t in c.tools} or None
        entries.append(LockEntry(
            id=f"{c.kind.value}:{c.name}", type=c.kind.spec_type, name=c.name, root=c.root, version=c.version,
            tree_sha256=c.content_hash, files=files or None, tools=tools, tool_definitions=definitions,
            capabilities=sorted({cap.label.spec_name for cap in c.capabilities if cap.label in FLOW_LABELS and cap.observed}),
            launch=launch_of(c),
            server_instructions_sha256=sha256_hex(c.instructions) if c.instructions else None,
        ))
    entries.sort(key=lambda e: e.key)
    return entries


def dump_lock(lock: Lockfile) -> str:
    return json.dumps(json.loads(lock.model_dump_json(exclude_none=True)), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def load_lock(text: str) -> Lockfile:
    """Read a lockfile in the current format or the first one (``entries``)."""
    return Lockfile.model_validate_json(text)


def tool_diff(old: dict, new: dict, name: str, max_lines: int = 60) -> str:
    a = json.dumps(old, indent=2, sort_keys=True, ensure_ascii=False).splitlines()
    b = json.dumps(new, indent=2, sort_keys=True, ensure_ascii=False).splitlines()
    diff = list(difflib.unified_diff(a, b, fromfile=f"locked/{name}", tofile=f"current/{name}", lineterm="", n=1))
    if len(diff) > max_lines:
        diff = diff[:max_lines] + [f"… ({len(diff) - max_lines} more lines)"]
    return visible_escape("\n".join(diff))


def diff_locks(old: Lockfile, new: Lockfile) -> list[dict[str, str]]:
    """What changed between two locks, one row per change (``baseline diff``)."""
    rows: list[dict[str, str]] = []
    a = {e.key: e for e in old.artifacts}
    b = {e.key: e for e in new.artifacts}
    for key in sorted(set(a) | set(b)):
        o, n = a.get(key), b.get(key)
        ident = (n or o).id or key  # type: ignore[union-attr]
        if o is None:
            rows.append({"artifact": ident, "change": "added", "detail": f"{n.type} at {n.root}"})  # type: ignore[union-attr]
            continue
        if n is None:
            rows.append({"artifact": ident, "change": "removed", "detail": f"{o.type} at {o.root}"})
            continue
        if (o.version or "") != (n.version or ""):
            rows.append({"artifact": ident, "change": "version", "detail": f"{o.version} → {n.version}"})
        of, nf = o.files or {}, n.files or {}
        for path in sorted(set(of) | set(nf)):
            if of.get(path) != nf.get(path):
                what = "file added" if path not in of else ("file removed" if path not in nf else "file changed")
                rows.append({"artifact": ident, "change": what, "detail": path})
        ot, nt = o.tools or {}, n.tools or {}
        for tool in sorted(set(ot) | set(nt)):
            if ot.get(tool) != nt.get(tool):
                what = "tool added" if tool not in ot else ("tool removed" if tool not in nt else "tool definition changed")
                rows.append({"artifact": ident, "change": what, "detail": tool})
        if (o.launch.sha256 if o.launch else "") != (n.launch.sha256 if n.launch else ""):
            rows.append({"artifact": ident, "change": "launch", "detail": "command, arguments or URL changed"})
        if (o.server_instructions_sha256 or "") != (n.server_instructions_sha256 or ""):
            rows.append({"artifact": ident, "change": "server instructions", "detail": "changed"})
        gained = sorted(set(n.capabilities) - set(o.capabilities))
        if gained:
            rows.append({"artifact": ident, "change": "capabilities gained", "detail": ", ".join(gained)})
        if o.risk_tier and n.risk_tier and o.risk_tier != n.risk_tier:
            rows.append({"artifact": ident, "change": "risk tier", "detail": f"{o.risk_tier} → {n.risk_tier}"})
        if o.verdict and n.verdict and o.verdict != n.verdict:
            rows.append({"artifact": ident, "change": "verdict", "detail": f"{o.verdict} → {n.verdict}"})
    return rows


__all__ = ["LOCK_VERSION", "TOOL_HASH_VERSION", "build_lock", "covered", "diff_locks", "dump_lock", "flow_capabilities",
           "launch_of", "load_lock", "lock_key", "tool_diff", "tool_hash", "canonical_json"]
