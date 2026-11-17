"""Units builder for parsed configuration (``inv.docs``).

Turns the files an agent or an editor loads as configuration into text the
rules can read, the way ``McpUnitsBuilder`` does for tool metadata:

* ``command`` units: what would be run. Hook commands, command-valued settings,
  helper commands, dev-container lifecycle commands, VS Code tasks, LSP and
  monitor launch commands, bundle launch commands (role ``config_command``);
  steps of CI workflows that run an agent (role ``ci_command``); Dockerfile
  ``RUN`` lines (role ``build_command``).
* prompt units: configuration values an agent reads as instructions
  (``developer_instructions``, ``initialPrompt``, descriptions an agent is
  shown), scanned as prose (scope ``body``, role ``config_prompt``).
* ``config_value`` units: every other string value (role ``config_text``).

The same records are kept in ``ctx.data["config_commands"]`` for the
configuration analyzers. Pure: no filesystem, no network.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, ClassVar

import regex

from ..artifacts import TextUnit
from ..inventory_surfaces import Doc, span_of
from ..mcp_config import SERVER_MAP_KEYS
from ..models import Span
from ..normalize.unicode import normalize
from ..textutil import TIMEOUT
from .base import Context

# Keys whose value is a command line, wherever they appear in an agent or editor configuration.
COMMAND_KEYS = frozenset({
    "command", "bash", "powershell", "pwsh", "cmd", "shell_command", "shellcommand",
    # Claude Code settings (each value is a shell command)
    "apikeyhelper", "awsauthrefresh", "awscredentialexport", "gcpauthrefresh", "otelheadershelper", "headershelper",
    # Codex
    "notify", "http_headers_helper",
    # dev containers
    "initializecommand", "oncreatecommand", "updatecontentcommand", "postcreatecommand", "poststartcommand",
    "postattachcommand",
})
# Keys an agent reads as instructions or shows to the model as a description of what to do.
PROMPT_KEYS = frozenset({
    "prompt", "initialprompt", "developer_instructions", "instructions", "systemprompt", "system_prompt",
    "base_instructions", "additionalcontext", "description", "summary", "text", "when_to_use", "agent_message",
    "user_message", "long_description",
})
_PROMPT_GROUPS = ("plugin", "marketplace", "agent", "command", "bundle", "descriptor", "hooks", "settings")
_VALUE_GROUPS = ("settings", "hooks", "plugin", "marketplace", "agent", "command", "bundle", "descriptor", "workspace", "ci",
                 "container", "env")
_LIFECYCLE = ("initializecommand", "oncreatecommand", "updatecontentcommand", "postcreatecommand", "poststartcommand",
              "postattachcommand")
MAX_UNITS_PER_DOC = 400
MAX_VALUE = 20_000
_GEMINI_SHELL = regex.compile(r"!\{((?:[^{}]|\{[^{}]*\})*)\}")
_DOCKER_INSTR = regex.compile(r"(?im)^[ \t]*(RUN|CMD|ENTRYPOINT|SHELL|HEALTHCHECK\s+CMD)[ \t]+")


@dataclass
class ConfigCommand:
    """One command a configuration file would run."""

    path: str
    component_id: str
    surface: str               # surface id, e.g. "claude.settings"
    keypath: tuple[str, ...]   # where in the document, e.g. ("hooks", "PreToolUse", "0", "hooks", "0", "command")
    text: str
    span: Span
    role: str = "config_command"
    event: str = ""            # hook event, lifecycle key or task label, when known
    entry: dict[str, Any] = field(default_factory=dict)   # the object the command sits in (hook handler, task…)

    @property
    def key(self) -> str:
        return self.keypath[-1] if self.keypath else ""


def _needle(doc: Doc, value: str) -> str:
    first = value.strip().split("\n", 1)[0][:60]
    if doc.fmt in ("json", "json5"):
        return json.dumps(first, ensure_ascii=False)[1:-1]
    return first


def locate_value(doc: Doc, keypath: tuple[str, ...], value: str) -> Span:
    """Span of a value: the value's own text when it can be found, else its key."""
    needle = _needle(doc, value)
    keys = [k for k in keypath if not k.isdigit()]
    text = doc.text
    if needle and keys:
        key_at = text.find(keys[-1])
        if key_at >= 0 and text.find(needle, key_at) >= 0:
            return span_of(text, keys[-1], needle, path=doc.path)
    if needle and needle in text:
        return span_of(text, needle, path=doc.path)
    if keys and keys[-1] in text:
        return span_of(text, keys[-1], path=doc.path)
    return Span(path=doc.path)


def _cmdline(value: Any, args: Any = None) -> str:
    """A command value as one line: a string, an argv list, or (dev containers) an object of named commands."""
    if isinstance(value, str):
        text = value
    elif isinstance(value, list) and all(isinstance(v, (str, int, float)) for v in value):
        text = " ".join(str(v) for v in value)
    elif isinstance(value, dict):
        text = "\n".join(_cmdline(v) for v in value.values() if isinstance(v, (str, list)))
    else:
        return ""
    if isinstance(args, list) and args and all(isinstance(a, (str, int, float)) for a in args):
        text = f"{text} " + " ".join(str(a) for a in args)
    return text.strip()


def _event_of(keypath: tuple[str, ...]) -> str:
    """The hook event a command belongs to (the key right under ``hooks``), or the nearest named key."""
    low = [k.lower() for k in keypath]
    if "hooks" in low:
        i = low.index("hooks")
        if i + 1 < len(keypath) and not keypath[i + 1].isdigit():
            return keypath[i + 1]
    return next((k for k in reversed(keypath[:-1]) if not k.isdigit()), keypath[-1] if keypath else "")


def _walk(doc: Doc, comp_id: str, out_cmds: list[ConfigCommand], out_vals: list[tuple[tuple[str, ...], str]],
          value: Any, keypath: tuple[str, ...], budget: list[int]) -> None:
    if budget[0] <= 0:
        return
    if isinstance(value, dict):
        for k, v in value.items():
            key = str(k)
            low = key.lower()
            if key in SERVER_MAP_KEYS and isinstance(v, dict):
                continue                           # MCP server entries are read by the MCP analyzers
            if low in COMMAND_KEYS and isinstance(v, (str, list, dict)) and not (low == "command" and isinstance(v, dict)):
                text = _cmdline(v, value.get("args") if low == "command" else None)
                if text and len(text) <= MAX_VALUE:
                    budget[0] -= 1
                    kp = (*keypath, key)
                    first = v if isinstance(v, str) else (str(v[0]) if isinstance(v, list) and v else text)
                    out_cmds.append(ConfigCommand(path=doc.path, component_id=comp_id, surface=doc.surface.id, keypath=kp,
                                                  text=text, span=locate_value(doc, kp, str(first)), event=_event_of(kp),
                                                  entry=value))
                    continue
            _walk(doc, comp_id, out_cmds, out_vals, v, (*keypath, key), budget)
    elif isinstance(value, list):
        for i, v in enumerate(value[:500]):
            _walk(doc, comp_id, out_cmds, out_vals, v, (*keypath, str(i)), budget)
    elif isinstance(value, str) and 0 < len(value) <= MAX_VALUE:
        budget[0] -= 1
        out_vals.append((keypath, value))


def _ci_steps(doc: Doc, comp_id: str) -> list[ConfigCommand]:
    """``run:`` steps of a GitHub workflow, and the script lists of a GitLab pipeline."""
    out: list[ConfigCommand] = []
    data = doc.data
    jobs = data.get("jobs") if isinstance(data.get("jobs"), dict) else {}
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        for i, step in enumerate(job.get("steps") or []):
            if isinstance(step, dict) and isinstance(step.get("run"), str) and step["run"].strip():
                kp = ("jobs", str(job_name), "steps", str(i), "run")
                out.append(ConfigCommand(path=doc.path, component_id=comp_id, surface=doc.surface.id, keypath=kp,
                                         text=step["run"], span=locate_value(doc, ("run",), step["run"]), role="ci_command",
                                         event=str(job_name), entry=step))
    if doc.surface.id == "ci.gitlab":
        for job_name, job in data.items():
            if not isinstance(job, dict):
                continue
            for key in ("before_script", "script", "after_script"):
                lines = job.get(key)
                lines = [lines] if isinstance(lines, str) else lines
                if isinstance(lines, list):
                    text = "\n".join(str(x) for x in lines if isinstance(x, (str, int, float)))
                    if text.strip():
                        out.append(ConfigCommand(path=doc.path, component_id=comp_id, surface=doc.surface.id,
                                                 keypath=(str(job_name), key), text=text, role="ci_command", event=str(job_name),
                                                 span=locate_value(doc, (str(job_name), key), text), entry=job))
    return out


def dockerfile_commands(path: str, text: str, comp_id: str) -> list[ConfigCommand]:
    """``RUN`` / ``CMD`` / ``ENTRYPOINT`` instructions, continuation lines joined."""
    out: list[ConfigCommand] = []
    try:
        heads = list(_DOCKER_INSTR.finditer(text, timeout=TIMEOUT))
    except TimeoutError:
        return out
    for m in heads[:300]:
        end = m.end()
        while True:
            nl = text.find("\n", end)
            line_end = len(text) if nl < 0 else nl
            if text[end:line_end].rstrip().endswith("\\") and nl >= 0:
                end = nl + 1
                continue
            end = line_end
            break
        body = regex.sub(r"\\\r?\n", " ", text[m.end():end]).strip()
        if not body:
            continue
        line = text.count("\n", 0, m.start()) + 1
        out.append(ConfigCommand(path=path, component_id=comp_id, surface="container.dockerfile",
                                 keypath=(m.group(1).upper().split()[0],), text=body, role="build_command",
                                 event=m.group(1).upper().split()[0],
                                 span=Span(path=path, start_line=line, start_col=1, end_line=text.count("\n", 0, end) + 1)))
    return out


def _unit(cmd_or_path: str, comp_id: str, role: str, scope: str, text: str, span: Span, label: str) -> TextUnit:
    return TextUnit(path=cmd_or_path, component_id=comp_id, role=role, scope=scope, text=text, norm=normalize(text),
                    base=None, anchor_span=span, label=label)


class ConfigUnitsBuilder:
    id: ClassVar[str] = "config.units"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = ()

    def run(self, ctx: Context) -> None:
        inv = ctx.inventory
        extra: list[TextUnit] = ctx.data.setdefault("extra_units", [])  # type: ignore[assignment]
        commands: list[ConfigCommand] = ctx.data.setdefault("config_commands", [])  # type: ignore[assignment]
        values: dict[str, list[tuple[tuple[str, ...], str, Span]]] = ctx.data.setdefault("config_values", {})  # type: ignore[assignment]
        for path in sorted(inv.docs):
            doc: Doc = inv.docs[path]
            art = inv.artifacts.get(path)
            if art is None or doc.value is None:
                continue
            group = doc.surface.group
            if group == "ci" and path not in inv.agentic_ci and doc.surface.id != "ci.copilot_setup":
                continue                           # an ordinary CI workflow is not an agent surface
            cmds: list[ConfigCommand] = []
            vals: list[tuple[tuple[str, ...], str]] = []
            if group == "ci":
                cmds = _ci_steps(doc, art.component_id)
                _walk(doc, art.component_id, [], vals, doc.value, (), [MAX_UNITS_PER_DOC])
            elif group in _VALUE_GROUPS:
                _walk(doc, art.component_id, cmds, vals, doc.value, (), [MAX_UNITS_PER_DOC])
            commands.extend(cmds)
            for c in cmds:
                extra.append(_unit(path, c.component_id, c.role, "command", c.text, c.span,
                                   f"{doc.surface.id}:{'.'.join(c.keypath)}"))
            located: list[tuple[tuple[str, ...], str, Span]] = []
            for keypath, text in vals:
                span = locate_value(doc, keypath, text)
                located.append((keypath, text, span))
                key = keypath[-1].lower() if keypath and not keypath[-1].isdigit() else next(
                    (k.lower() for k in reversed(keypath) if not k.isdigit()), "")
                label = f"{doc.surface.id}:{'.'.join(keypath)}"
                if key in PROMPT_KEYS and group in _PROMPT_GROUPS and len(text) >= 12:
                    extra.append(_unit(path, art.component_id, "config_prompt", "body", text, span, label))
                    if doc.surface.id == "gemini.command":
                        # `!{…}` in a Gemini custom command runs a shell command when the command is used.
                        for m in _GEMINI_SHELL.finditer(text):
                            cmd = ConfigCommand(path=path, component_id=art.component_id, surface=doc.surface.id,
                                                keypath=(*keypath, "!{}"), text=m.group(1).strip(), span=span, event="prompt")
                            commands.append(cmd)
                            extra.append(_unit(path, art.component_id, "config_command", "command", cmd.text, span,
                                               f"{label}:shell-injection"))
                else:
                    extra.append(_unit(path, art.component_id, "config_text", "config_value", text, span, label))
            values[path] = located
        # Files that are commands as a whole, and Dockerfiles (not parsed as documents).
        for path in sorted(inv.surfaces):
            surface = inv.surfaces[path]
            art = inv.artifacts.get(path)
            at = inv.texts.get(path)
            if art is None or at is None:
                continue
            if surface.id == "container.dockerfile":
                for c in dockerfile_commands(path, at.text, art.component_id):
                    commands.append(c)
                    extra.append(_unit(path, c.component_id, c.role, "command", c.text, c.span, f"dockerfile:{c.event}"))
            elif surface.id == "ws.envrc":
                span = Span(path=path, start_line=1)
                commands.append(ConfigCommand(path=path, component_id=art.component_id, surface=surface.id, keypath=("envrc",),
                                              text=at.text, span=span, event="directory-entry"))
                extra.append(TextUnit(path=path, component_id=art.component_id, role="config_command", scope="command",
                                      text=at.text, norm=normalize(at.text), base=0, label="envrc"))


def commands_of(ctx: Context, *surfaces: str) -> list[ConfigCommand]:
    """Recorded commands of the given surface ids (or id prefixes ending in ".")."""
    cmds: list[ConfigCommand] = ctx.data.get("config_commands", [])  # type: ignore[assignment]
    return [c for c in cmds if not surfaces or any(c.surface == s or (s.endswith(".") and c.surface.startswith(s))
                                                   for s in surfaces)]


__all__ = ["COMMAND_KEYS", "ConfigCommand", "ConfigUnitsBuilder", "commands_of", "dockerfile_commands", "locate_value"]
