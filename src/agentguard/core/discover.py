"""Discovery: what each file in a tree is (spec/ecosystems.md).

``surface_for`` classifies a path (and, where a path convention is not enough,
the shape of the content) into a *surface*: the fine-grained thing an agent
loads, such as Claude Code settings, a Cursor hook file or an agentic CI
workflow. Analyzers select the files they understand by surface id.

Status marks follow the specification: tier 1 and 2 surfaces were read from
vendor documentation; tier 3 paths come from secondary sources and are parsed
generically (instruction text or MCP config) until verified.

Pure: no filesystem, no network.
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass

import regex

from .models.enums import ArtifactRole, ComponentKind
from .parsers import undo_ascii_escapes
from .textutil import TIMEOUT

K, R = ComponentKind, ArtifactRole


@dataclass(frozen=True)
class Surface:
    id: str                      # e.g. "claude.settings"
    kind: ComponentKind          # the component a stand-alone file of this surface becomes
    role: ArtifactRole
    agent: str = "generic"       # claude-code | codex | cursor | gemini | copilot | openclaw | generic | <tier-3 agent>
    fmt: str = ""                # json | json5 | toml | yaml | md | text | xml | dockerfile
    tier: int = 1                # 1-2 verified, 3 secondary source / unverified
    group: str = ""              # instructions | settings | hooks | plugin | ci | workspace | container | descriptor | …


def _s(id_: str, kind: ComponentKind, role: ArtifactRole, agent: str = "generic", fmt: str = "", tier: int = 1,
       group: str = "") -> Surface:
    return Surface(id_, kind, role, agent, fmt, tier, group or id_.split(".", 1)[0])


def _inst(id_: str, agent: str, tier: int = 1) -> Surface:
    return _s(id_, K.instruction_file, R.instruction_md, agent, "md", tier, "instructions")


# Ordered: the first pattern that matches wins. Patterns run against the POSIX path, case-insensitively.
_PATH_RULES: tuple[tuple[str, Surface], ...] = (
    # ---- Claude Code (verified) ------------------------------------------------
    (r"(^|/)\.claude/settings(\.local)?\.json$", _s("claude.settings", K.settings, R.settings, "claude-code", "json", group="settings")),
    (r"(^|/)managed-settings\.json$", _s("claude.settings", K.settings, R.settings, "claude-code", "json", group="settings")),
    (r"(^|/)\.claude-plugin/plugin\.json$", _s("claude.plugin", K.plugin, R.plugin_manifest, "claude-code", "json", group="plugin")),
    (r"(^|/)\.claude-plugin/marketplace\.json$", _s("claude.marketplace", K.marketplace, R.marketplace_manifest, "claude-code", "json", group="marketplace")),
    (r"(^|/)(known_marketplaces|installed_plugins)\.json$", _s("claude.plugin_state", K.settings, R.settings, "claude-code", "json", group="settings")),
    (r"(^|/)hooks/hooks\.json$", _s("plugin.hooks", K.hook, R.hook_config, "claude-code", "json", group="hooks")),
    (r"(^|/)\.lsp\.json$", _s("claude.lsp", K.plugin, R.plugin_manifest, "claude-code", "json", group="plugin")),
    (r"(^|/)monitors/monitors\.json$", _s("claude.monitors", K.plugin, R.plugin_manifest, "claude-code", "json", group="plugin")),
    (r"(^|/)\.claude/agents/.+\.md$", _s("claude.agent", K.subagent, R.instruction_md, "claude-code", "md", group="agent")),
    (r"(^|/)\.claude/commands/.+\.md$", _s("claude.command", K.command, R.command_md, "claude-code", "md", group="command")),
    (r"(^|/)\.claude/rules/.+\.md$", _inst("claude.rule", "claude-code")),
    (r"(^|/)\.claude/(projects/[^/]+/)?memory/.+\.md$", _inst("claude.memory", "claude-code")),
    (r"(^|/)\.claude/output-styles/.+\.md$", _inst("claude.output_style", "claude-code")),
    (r"(^|/)(\.claude/)?CLAUDE(\.local)?\.md$", _inst("claude.instructions", "claude-code")),
    # ---- OpenAI Codex (verified) ------------------------------------------------
    (r"(^|/)\.?codex/([^/]+\.)?config\.toml$", _s("codex.config", K.settings, R.settings, "codex", "toml", group="settings")),
    (r"(^|/)\.codex/hooks\.json$", _s("codex.hooks", K.hook, R.hook_config, "codex", "json", group="hooks")),
    (r"(^|/)\.codex/agents/.+\.toml$", _s("codex.agent", K.subagent, R.settings, "codex", "toml", group="agent")),
    (r"(^|/)\.codex-plugin/plugin\.json$", _s("codex.plugin", K.plugin, R.plugin_manifest, "codex", "json", 2, "plugin")),
    (r"(^|/)agents/openai\.ya?ml$", _s("codex.skill_sidecar", K.settings, R.settings, "codex", "yaml", group="settings")),
    (r"(^|/)\.codex/prompts/.+\.md$", _s("codex.prompt", K.command, R.command_md, "codex", "md", group="command")),
    (r"(^|/)AGENTS\.override\.md$", _inst("codex.instructions", "codex")),
    # ---- Gemini CLI (verified) ---------------------------------------------------
    (r"(^|/)\.gemini/settings\.json$", _s("gemini.settings", K.settings, R.settings, "gemini", "json", group="settings")),
    (r"(^|/)gemini-?cli/settings\.json$", _s("gemini.settings", K.settings, R.settings, "gemini", "json", group="settings")),
    (r"(^|/)gemini-extension\.json$", _s("gemini.extension", K.plugin, R.plugin_manifest, "gemini", "json", group="plugin")),
    (r"(^|/)\.gemini/commands/.+\.toml$", _s("gemini.command", K.command, R.command_md, "gemini", "toml", group="command")),
    (r"(^|/)\.gemini/policies/.+\.toml$", _s("gemini.policy", K.settings, R.settings, "gemini", "toml", group="settings")),
    (r"(^|/)\.gemini/\.env$", _s("gemini.env", K.settings, R.env_file, "gemini", "text", group="env")),
    (r"(^|/)\.gemini/trustedFolders\.json$", _s("gemini.trust", K.settings, R.settings, "gemini", "json", group="settings")),
    (r"(^|/)GEMINI\.md$", _inst("gemini.instructions", "gemini")),
    # ---- Cursor (verified) ----------------------------------------------------------
    (r"(^|/)\.cursor/rules/.+\.mdc$", _inst("cursor.rule", "cursor")),
    (r"(^|/)\.cursor/rules/.+\.md$", _inst("cursor.rule_md", "cursor")),
    (r"(^|/)\.cursorrules$", _inst("cursor.legacy_rules", "cursor", 2)),
    (r"(^|/)\.cursor/hooks\.json$", _s("cursor.hooks", K.hook, R.hook_config, "cursor", "json", group="hooks")),
    (r"(^|/)\.cursor/cli(-config)?\.json$", _s("cursor.cli", K.settings, R.settings, "cursor", "json", group="settings")),
    (r"(^|/)\.cursor-plugin/plugin\.json$", _s("cursor.plugin", K.plugin, R.plugin_manifest, "cursor", "json", group="plugin")),
    (r"(^|/)\.cursor-plugin/marketplace\.json$", _s("cursor.marketplace", K.marketplace, R.marketplace_manifest, "cursor", "json", group="marketplace")),
    (r"(^|/)\.cursor/agents/.+\.md$", _s("cursor.agent", K.subagent, R.instruction_md, "cursor", "md", group="agent")),
    (r"(^|/)\.cursor/commands/.+\.md$", _s("cursor.command", K.command, R.command_md, "cursor", "md", 2, "command")),
    # ---- GitHub Copilot and VS Code (verified) -----------------------------------
    (r"(^|/)\.github/copilot-instructions\.md$", _inst("copilot.instructions", "copilot")),
    (r"(^|/)\.copilot/copilot-instructions\.md$", _inst("copilot.instructions", "copilot")),
    (r"(^|/)\.github/instructions/.+\.instructions\.md$", _inst("copilot.scoped_instructions", "copilot")),
    (r"(^|/)\.copilot/instructions/.+\.md$", _inst("copilot.scoped_instructions", "copilot")),
    (r"(^|/)REVIEW\.md$", _inst("copilot.review", "copilot")),
    (r"(^|/)(\.github|\.copilot)/agents/.+\.agent\.md$", _s("copilot.agent", K.subagent, R.instruction_md, "copilot", "md", group="agent")),
    (r"(^|/)(\.github|\.copilot)/hooks/.+\.json$", _s("copilot.hooks", K.hook, R.hook_config, "copilot", "json", group="hooks")),
    (r"(^|/)\.github/copilot/settings\.json$", _s("copilot.settings", K.settings, R.settings, "copilot", "json", group="settings")),
    (r"(^|/)\.github/prompts/.+\.prompt\.md$", _s("copilot.prompt", K.command, R.command_md, "copilot", "md", 2, "command")),
    (r"(^|/)\.github/workflows/copilot-setup-steps\.ya?ml$", _s("ci.copilot_setup", K.ci_workflow, R.workflow, "copilot", "yaml", group="ci")),
    # ---- OpenClaw (verified in part) -------------------------------------------------
    (r"(^|/)openclaw\.json5?$", _s("openclaw.config", K.settings, R.settings, "openclaw", "json5", 2, "settings")),
    (r"(^|/)openclaw\.plugin\.json$", _s("openclaw.plugin", K.plugin, R.plugin_manifest, "openclaw", "json", 2, "plugin")),
    (r"(^|/)hooks/[^/]+/HOOK\.md$", _s("openclaw.hook", K.hook, R.hook_config, "openclaw", "md", 2, "hooks")),
    (r"(^|/)(SOUL|USER|IDENTITY|BOOT|BOOTSTRAP)\.md$", _inst("openclaw.workspace_file", "openclaw", 2)),
    (r"(^|/)\.openclaw/workspace/memory/.+\.md$", _inst("openclaw.memory", "openclaw", 2)),
    (r"(^|/)\.clawhub/(lock|origin)\.json$", _s("openclaw.clawhub", K.settings, R.settings, "openclaw", "json", 2, "settings")),
    # ---- Shared and tier 3 instruction files --------------------------------------------
    (r"(^|/)AGENTS\.md$", _inst("agents.instructions", "generic")),
    (r"(^|/)AGENT\.md$", _inst("amp.instructions", "amp", 3)),
    (r"(^|/)MEMORY\.md$", _inst("memory.file", "generic", 2)),
    (r"(^|/)\.junie/guidelines\.md$", _inst("junie.guidelines", "junie", 3)),
    (r"(^|/)\.aiassistant/rules/.+\.md$", _inst("jetbrains.rules", "jetbrains-ai", 3)),
    (r"(^|/)\.continuerules$", _inst("continue.rules", "continue", 3)),
    (r"(^|/)\.continue/(rules|prompts)/.+\.(md|prompt|ya?ml)$", _inst("continue.rules", "continue", 3)),
    (r"(^|/)\.windsurf/rules/.+\.md$", _inst("windsurf.rules", "windsurf", 3)),
    (r"(^|/)\.windsurfrules$", _inst("windsurf.rules", "windsurf", 3)),
    (r"(^|/)\.clinerules(/.+)?$", _inst("cline.rules", "cline", 3)),
    (r"(^|/)\.roo/rules(-[^/]+)?/.+$", _inst("roo.rules", "roo-code", 3)),
    (r"(^|/)\.roorules$", _inst("roo.rules", "roo-code", 3)),
    (r"(^|/)\.kiro/steering/.+\.md$", _inst("kiro.steering", "kiro", 3)),
    (r"(^|/)\.rules$", _inst("zed.rules", "zed", 3)),
    (r"(^|/)\.goosehints$", _inst("goose.hints", "goose", 3)),
    (r"(^|/)CONVENTIONS\.md$", _inst("aider.conventions", "aider", 3)),
    (r"(^|/)\.aider\.conf\.ya?ml$", _s("aider.config", K.settings, R.settings, "aider", "yaml", 3, "settings")),
    (r"(^|/)[^/]+\.(instructions|agent|prompt)\.md$", _inst("generic.agent_file", "generic", 3)),
    (r"(^|/)[^/]+\.mdc$", _inst("generic.agent_file", "generic", 3)),
    (r"(^|/)\.[^/]+/(rules|skills|agents|commands|hooks|prompts)/[^/]+\.(md|mdc|txt)$", _inst("generic.agent_dir", "generic", 3)),
    # ---- Agentic CI --------------------------------------------------------------------------
    (r"(^|/)\.github/workflows/[^/]+\.ya?ml$", _s("ci.github", K.ci_workflow, R.workflow, "generic", "yaml", group="ci")),
    (r"(^|/)\.github/workflows/[^/]+\.md$", _s("ci.agentic_md", K.ci_workflow, R.workflow, "copilot", "md", 2, "ci")),
    (r"(^|/)\.gitlab-ci\.ya?ml$", _s("ci.gitlab", K.ci_workflow, R.workflow, "generic", "yaml", group="ci")),
    # ---- Workspace auto-execution ------------------------------------------------------------
    (r"(^|/)\.vscode/tasks\.json$", _s("ws.vscode_tasks", K.workspace, R.workspace_config, "copilot", "json5", group="workspace")),
    (r"(^|/)\.vscode/settings\.json$", _s("ws.vscode_settings", K.workspace, R.workspace_config, "copilot", "json5", group="workspace")),
    (r"(^|/)\.vscode/launch\.json$", _s("ws.ide_run", K.workspace, R.workspace_config, "copilot", "json5", group="workspace")),
    (r"(^|/)(\.devcontainer/([^/]+/)?devcontainer|\.devcontainer)\.json$", _s("ws.devcontainer", K.workspace, R.workspace_config, "generic", "json5", group="workspace")),
    (r"(^|/)\.envrc$", _s("ws.envrc", K.workspace, R.workspace_config, "generic", "text", group="workspace")),
    (r"(^|/)(\.tool-versions|\.?mise\.toml|\.mise/config\.toml)$", _s("ws.toolversions", K.workspace, R.workspace_config, "generic", "text", group="workspace")),
    (r"(^|/)\.gitattributes$", _s("ws.gitattributes", K.workspace, R.workspace_config, "generic", "text", group="workspace")),
    (r"(^|/)(\.githooks|\.husky)/[^/._][^/]*$", _s("ws.githook", K.workspace, R.script, "generic", "text", group="workspace")),
    (r"(^|/)\.git/hooks/[^/]+$", _s("ws.githook", K.workspace, R.script, "generic", "text", group="workspace")),
    (r"(^|/)(\.idea/runConfigurations/.+\.xml|\.run/.+\.run\.xml)$", _s("ws.ide_run", K.workspace, R.workspace_config, "generic", "xml", 2, "workspace")),
    (r"(^|/)\.gitmodules$", _s("git.modules", K.repository, R.other, "generic", "text", group="git")),
    # ---- Containers -----------------------------------------------------------------------------
    (r"(^|/)(Dockerfile|Containerfile)(\.[^/]+)?$", _s("container.dockerfile", K.container, R.dockerfile, "generic", "dockerfile", group="container")),
    (r"(^|/)[^/]+\.(dockerfile|containerfile)$", _s("container.dockerfile", K.container, R.dockerfile, "generic", "dockerfile", group="container")),
    (r"(^|/)(docker-)?compose(\.[^/]+)?\.ya?ml$", _s("container.compose", K.container, R.compose, "generic", "yaml", group="container")),
    # ---- Connector descriptors ---------------------------------------------------------------------
    (r"(^|/)ai-plugin\.json$", _s("descriptor.ai_plugin", K.connector, R.descriptor, "generic", "json", group="descriptor")),
    (r"(^|/)(openapi|swagger)(\.[^/]+)?\.(ya?ml|json)$", _s("descriptor.openapi", K.connector, R.descriptor, "generic", "", group="descriptor")),
    # ---- Environment files (loaded automatically by some agents) -------------------------------------
    (r"(^|/)\.env(\.(?!example$|sample$|template$|dist$)[^/]+)?$", _s("env.file", K.repository, R.env_file, "generic", "text", group="env")),
)
_COMPILED = tuple((regex.compile(p, regex.IGNORECASE), s) for p, s in _PATH_RULES)

OPENAPI = _s("descriptor.openapi", K.connector, R.descriptor, "generic", "", group="descriptor")
A2A_CARD = _s("descriptor.a2a", K.connector, R.descriptor, "generic", "json", group="descriptor")
MCPB_MANIFEST = _s("bundle.mcpb", K.bundle, R.bundle_manifest, "mcp", "json", group="bundle")
SETTINGS_BY_SHAPE = _s("claude.settings", K.settings, R.settings, "claude-code", "json", group="settings")

# A workflow is "agentic" when it runs a coding agent. The markers are action names and CLI invocations.
AGENT_CI_MARKERS = regex.compile(
    r"anthropics/claude-code(?:-base)?-action|anthropics/claude-code-security-review|\bclaude(?:-code)?\s+(?:-p\b|--print\b|--dangerously)"
    r"|@anthropic-ai/claude-code|openai/codex-action|\bcodex\s+(?:exec|e)\b|@openai/codex"
    r"|google-github-actions/run-gemini-cli|google-gemini/gemini-cli-action|\bgemini\s+(?:-p\b|--prompt\b|--yolo\b)|@google/gemini-cli"
    r"|github/gh-aw|\bgh\s+aw\b|\bcopilot\s+(?:-p\b|--prompt\b|--allow-all)|copilot-swe-agent|github/copilot"
    r"|cursor-agent\b|\bopencode\s+run\b|\baider\s+--|\bamp\s+(?:-x\b|--execute\b)|\bgoose\s+run\b",
    regex.IGNORECASE,
)
IMAGE_EXT = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tif", ".tiff", ".ico", ".avif", ".heic")
DOC_EXT = (".pdf", ".docx", ".docm", ".dotm", ".xlsx", ".xlsm", ".xlsb", ".pptx", ".pptm", ".doc", ".xls", ".ppt", ".odt",
           ".ods", ".odp", ".rtf", ".epub")
MEDIA_EXT = (".mp3", ".wav", ".ogg", ".flac", ".m4a", ".aac", ".mp4", ".mov", ".avi", ".mkv", ".webm", ".wmv")
LOCKFILE_NAMES = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb", "uv.lock",
                  "poetry.lock", "pipfile.lock", "cargo.lock", "go.sum", "composer.lock", "gemfile.lock", "pdm.lock")
MANIFEST_NAMES = ("package.json", "pyproject.toml", "setup.py", "setup.cfg", "pipfile", "go.mod", "cargo.toml", "gemfile",
                  "composer.json", "environment.yml")
_REQUIREMENTS = regex.compile(r"^requirements[^/]*\.(txt|in)$", regex.IGNORECASE)


def surface_for(path: str, head: bytes = b"") -> Surface | None:
    """The surface of a file, by path convention first and by content shape second
    (so a renamed or relocated file is still recognised)."""
    for rx, surface in _COMPILED:
        try:
            if rx.search(path, timeout=TIMEOUT):
                if surface.id == "descriptor.openapi" and not _looks_openapi(head):
                    continue
                return surface
        except TimeoutError:
            continue
    return shape_surface(path, head)


def shape_surface(path: str, head: bytes) -> Surface | None:
    lower = path.lower()
    if not head or not lower.endswith((".json", ".yaml", ".yml", ".jsonc", ".json5")):
        return None
    # A parser reads `"manifest_version"` as `manifest_version`, so the shape check must too.
    text = undo_ascii_escapes(head[:8192].decode("utf-8", "replace"))
    if lower.endswith((".json", ".jsonc", ".json5")):
        if '"manifest_version"' in text and '"server"' in text and ('"mcp_config"' in text or '"entry_point"' in text):
            return MCPB_MANIFEST
        if posixpath.basename(lower) in ("agent.json", "agent-card.json") or "/.well-known/agent" in "/" + lower:
            if '"skills"' in text and ('"url"' in text or '"capabilities"' in text or '"protocolVersion"' in text):
                return A2A_CARD
        if '"protocolVersion"' in text and '"skills"' in text and '"capabilities"' in text and '"url"' in text:
            return A2A_CARD
        if '"permissions"' in text and '"hooks"' in text and ('"PreToolUse"' in text or '"allow"' in text) \
                and posixpath.basename(lower).startswith("settings"):
            return SETTINGS_BY_SHAPE
    if _looks_openapi(head):
        return OPENAPI
    return None


def _looks_openapi(head: bytes) -> bool:
    text = head[:4096].decode("utf-8", "replace")
    try:
        return bool(regex.search(r'(?m)^\s*"?(openapi|swagger)"?\s*:\s*"?\d', text, timeout=TIMEOUT)) and "paths" in head[:200_000].decode("utf-8", "replace")
    except TimeoutError:
        return False


def is_agentic_ci(text: str) -> bool:
    try:
        return bool(AGENT_CI_MARKERS.search(text, timeout=TIMEOUT))
    except TimeoutError:
        return False


def generic_role(path: str, data: bytes, binary: str | None, language: str | None, markdown: bool) -> ArtifactRole:
    """The role of a file that belongs to no agent surface (the catch-all ``repository`` component)."""
    lower = path.lower()
    base = posixpath.basename(lower)
    if lower.endswith(".svg") or (not binary and data[:256].lstrip().startswith((b"<svg", b"<?xml")) and b"<svg" in data[:2048]):
        return R.image
    if lower.endswith(IMAGE_EXT) or binary in ("png", "jpeg", "gif", "webp", "bmp", "tiff"):
        return R.image
    if lower.endswith(DOC_EXT) or binary in ("pdf", "ole"):
        return R.document
    if lower.endswith(MEDIA_EXT):
        return R.media
    if lower.endswith(".ipynb"):
        return R.notebook
    if lower.endswith((".html", ".htm", ".xhtml")):
        return R.html
    if base in LOCKFILE_NAMES:
        return R.lockfile
    if base in MANIFEST_NAMES or _REQUIREMENTS.match(base):
        return R.package_manifest
    if binary in ("zip", "gzip", "7z", "rar", "bzip2", "xz", "tar"):
        return R.archive
    if binary:
        return R.binary
    if language:
        return R.repo_code
    if markdown:
        return R.repo_doc
    return R.other
