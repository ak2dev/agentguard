"""Dynamic analysis: the detonation tier (spec/sandbox.md).

The target is run inside a disposable container that has no route to the internet and no real
credentials, and what it does is recorded: the programs it starts, the decoy files it opens, what it
writes outside its own directory, and every request it sends to the sinkhole. Observations become
evidence for catalogue rules and are added to the static findings. A clean run clears nothing.

What this build runs: every script, hook and lifecycle command and install step found statically
(direct execution), local MCP servers (started, enumerated, called with harmless arguments and
fuzzed), files the run writes into the target (closure lift), and scripts again in a CI-like
environment and with the clock moved forward. What it does not run: an agent. Driving Claude Code or
OpenCode inside the container needs a model forwarding proxy that is not part of this build, so
instruction-only components are reported as having nothing that could be executed directly.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from ..core.models import ScanOptions
from ..core.tree import ArtifactTree
from .runtime import SandboxUnavailable

ADAPTERS = ("claude-code", "opencode", "none")


def new_ids() -> tuple[str, str]:
    """(nonce, marker) for one run: the nonce frames the result line, the marker names the files a served script leaves."""
    return os.urandom(16).hex(), "agm" + os.urandom(6).hex()


def detonate_into(tree: ArtifactTree, options: ScanOptions, config: Any = None, runtime: Any = None, notes: list[str] | None = None,
                  *, timeout: int | None = None, adapter: str | None = None, keep_trace: Path | None = None, pack: Any = None,
                  seed: bytes | None = None) -> dict[str, Any]:
    """Run the target in the sandbox and record what happened in `options` (evidence, facts, what was not reached)
    and in `tree` (files the run wrote into the target). Raises SandboxUnavailable instead of running anywhere else."""
    from .evidence import analyze
    from .honey import make_honey
    from .plan import build_plan
    from .runtime import default_runtime

    notes = notes if notes is not None else []
    dyn = getattr(config, "dynamic", None)
    timeout = int(timeout or getattr(dyn, "timeout_seconds", 0) or 900)
    adapter = (adapter or getattr(dyn, "agent_adapter", None) or "none").lower()
    if adapter not in ADAPTERS:
        raise SandboxUnavailable(f"unknown agent adapter {adapter!r} (choose from {', '.join(ADAPTERS)})")
    runtime = runtime if runtime is not None else default_runtime()
    honey = make_honey(seed)
    nonce, marker = new_ids()
    plan = build_plan(tree, honey, options, pack, timeout=timeout, nonce=nonce, marker=marker)
    if adapter != "none":
        notes.append(f"dynamic: the {adapter} agent adapter is not part of this build; scripts, hooks, install steps and local MCP "
                     "servers were run directly, and no agent was driven through the instructions")
    if not plan.job["entries"]:
        options.dynamic_ran = False
        options.dynamic_not_reached = sorted({*options.dynamic_not_reached, *plan.not_reached})
        notes.append("dynamic: nothing in the target can be executed directly (no script, hook command, install step or local MCP "
                     "server), so nothing was run in the sandbox")
        return {"ran": False, "entries": 0, "not_reached": dict(plan.not_reached)}
    result = runtime.run(plan.job, plan.tar)
    out = analyze(plan, result, honey)
    options.dynamic_ran = True
    options.dynamic_level = out.level
    options.dynamic_evidence = [*options.dynamic_evidence, *out.evidence]
    options.dynamic_not_reached = sorted({*options.dynamic_not_reached, *out.not_reached})
    for key, value in out.facts.items():
        options.facts[key] = {**(options.facts.get(key) or {}), **value}
    for rel, data in sorted(out.lifted.items()):
        if rel not in tree.files and tree.add(rel, data, options.limits):
            tree.hints[rel] = {"origin": "written by the target at run time, inside the sandbox"}
    notes.append(f"dynamic: {out.entries_run} run(s) of {len(plan.job['entries'])} entry point(s) in a container with no network and "
                 f"decoy credentials ({out.level} level, {out.seconds} s); {len(out.evidence)} observation(s), "
                 f"{len(out.not_reached)} path(s) not reached")
    notes += out.lines
    for path, why in sorted(out.not_reached.items())[:12]:
        notes.append(f"dynamic: not reached: {path} ({why})")
    if keep_trace is not None:
        keep_trace.mkdir(parents=True, exist_ok=True)
        entries = [e for e in result.get("entries", []) if isinstance(e, dict)] if isinstance(result, dict) else []
        (keep_trace / "trace.json").write_text(json.dumps([{k: e.get(k) for k in ("id", "variant", "status", "exit", "seconds", "events",
                                                                                   "marker_ran", "stdout", "stderr", "mcp")} for e in entries],
                                                          indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
        (keep_trace / "file-diff.json").write_text(json.dumps({f"{e.get('id')}:{e.get('variant')}": e.get("files") for e in entries},
                                                              indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
        with open(keep_trace / "network.jsonl", "w", encoding="utf-8", newline="\n") as fh:
            for rec in result.get("network", []) if isinstance(result, dict) else []:
                fh.write(json.dumps(rec, ensure_ascii=True) + "\n")
        notes.append(f"dynamic: trace, file diff and network log written to {keep_trace} (untrusted data: do not paste it into an agent)")
    return {"ran": True, "entries": len(plan.job["entries"]), "evidence": len(out.evidence), "not_reached": dict(out.not_reached)}


def detonate_target(target: str, *, timeout: int | None = None, adapter: str | None = None, keep_trace: Path | None = None,
                    cwd: Path | None = None, runtime: Any = None) -> Any:
    """`agentguard detonate`: dynamic analysis only. The report holds what was observed in the sandbox."""
    from ..runner import ScanRequest, run_scan

    req = ScanRequest(targets=[target], profile="quick", llm="off", dynamic="on", context="none", cwd=cwd or Path.cwd(),
                      sandbox=runtime, dynamic_timeout=timeout, agent_adapter=adapter, keep_trace=keep_trace, dynamic_only=True)
    return run_scan(req)


__all__ = ["ADAPTERS", "SandboxUnavailable", "detonate_into", "detonate_target", "new_ids"]
