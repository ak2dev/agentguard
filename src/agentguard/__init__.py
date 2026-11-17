"""Agent Guard: a security scanner for agent extensions (skills, plugins,
instruction files, agent settings and hooks, MCP servers and connectors).

Library API (spec/interfaces.md §12; also used by Agent Guard Web and the Pyodide build)::

    from agentguard import scan, ScanOptions

    report = scan("./skills/pdf-helper", ScanOptions(profile="standard", policy="strict"))
    report.verdict            # "ALLOW" | "REVIEW" | "BLOCK"
    for f in report.findings:
        print(f.id, f.location.file, f.location.start.line, f.fix.summary)

``scan`` takes a path or any other target string, or an ``ArtifactTree`` for a
pure in-memory scan (``ArtifactTree.from_mapping``, ``from_archive``). With a
tree it touches neither the filesystem nor the network.

The names below are loaded on first use, so that ``import agentguard.hooks``
(which an agent runs before every shell command) does not load the engine.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

__version__ = "0.1.0.dev0"

_LAZY = {
    "from_archive": ".core.archive",
    "ENGINE_VERSION": ".core.engine",
    "Finding": ".core.models",
    "Policy": ".core.models",
    "Report": ".core.models",
    "ScanOptions": ".core.models",
    "Verdict": ".core.models.enums",
    "render_cyclonedx": ".core.report.render",
    "render_json": ".core.report.render",
    "render_junit": ".core.report.render",
    "render_markdown": ".core.report.render",
    "render_sarif": ".core.report.render",
    "RulePack": ".core.rules.pack",
    "ArtifactTree": ".core.tree",
    "UsageError": ".runner",
    "scan": ".runner",
}

if TYPE_CHECKING:
    from .core.archive import from_archive
    from .core.engine import ENGINE_VERSION
    from .core.models import Finding, Policy, Report, ScanOptions
    from .core.models.enums import Verdict
    from .core.report.render import render_cyclonedx, render_json, render_junit, render_markdown, render_sarif
    from .core.rules.pack import RulePack
    from .core.tree import ArtifactTree
    from .runner import UsageError, scan


def __getattr__(name: str) -> Any:
    module = _LAZY.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    value = getattr(importlib.import_module(module, __name__), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(__all__)


__all__ = [
    "ENGINE_VERSION", "ArtifactTree", "Finding", "Policy", "Report", "RulePack", "ScanOptions", "UsageError", "Verdict",
    "__version__", "from_archive", "render_cyclonedx", "render_json", "render_junit", "render_markdown", "render_sarif",
    "scan",
]
