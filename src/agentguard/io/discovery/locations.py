"""Known agent/MCP configuration locations per client and OS.

Every entry records whether the path was verified against the client's own
documentation (see docs/sources.md). Unverified entries are still scanned —
reading a file is harmless — but they are labelled in `agentguard discover`.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Location:
    client: str
    scope: str          # user | project | enterprise
    kind: str           # config | skills | instructions | agents | commands | hooks | plugins | memory | workspace | ci
    path: Path
    verified: bool
    note: str = ""


def _env_path(name: str) -> Path | None:
    v = os.environ.get(name)
    return Path(v) if v else None


def user_locations(home: Path | None = None, platform: str | None = None) -> list[Location]:
    home = home or Path.home()
    plat = platform or sys.platform
    appdata = _env_path("APPDATA") or home / "AppData" / "Roaming"
    localappdata = _env_path("LOCALAPPDATA") or home / "AppData" / "Local"
    xdg = _env_path("XDG_CONFIG_HOME") or home / ".config"
    L: list[Location] = []
    add = L.append

    # Claude Desktop (modelcontextprotocol.io "Connect to local MCP servers"; published for macOS and Windows only)
    if plat == "darwin":
        add(Location("claude-desktop", "user", "config", home / "Library/Application Support/Claude/claude_desktop_config.json", True))
    elif plat == "win32":
        add(Location("claude-desktop", "user", "config", appdata / "Claude" / "claude_desktop_config.json", True))
    else:
        add(Location("claude-desktop", "user", "config", xdg / "Claude" / "claude_desktop_config.json", False,
                     "Claude Desktop is published for macOS and Windows only; unofficial Linux builds"))
    # Claude Code (code.claude.com/docs: mcp, settings, skills, sub-agents, memory)
    add(Location("claude-code", "user", "config", home / ".claude.json", True))
    add(Location("claude-code", "user", "config", home / ".claude" / "settings.json", True))
    add(Location("claude-code", "user", "skills", home / ".claude" / "skills", True))
    add(Location("claude-code", "user", "agents", home / ".claude" / "agents", True))
    add(Location("claude-code", "user", "commands", home / ".claude" / "commands", True, "legacy command files"))
    add(Location("claude-code", "user", "instructions", home / ".claude" / "CLAUDE.md", True))
    add(Location("claude-code", "user", "instructions", home / ".claude" / "rules", True))
    # Plugins (code.claude.com/docs: plugins-reference, plugin-marketplaces): the install cache, the cloned
    # marketplaces and the two state files.
    plugins = home / ".claude" / "plugins"
    add(Location("claude-code", "user", "plugins", plugins / "cache", True))
    add(Location("claude-code", "user", "plugins", plugins / "marketplaces", True))
    add(Location("claude-code", "user", "config", plugins / "known_marketplaces.json", True))
    add(Location("claude-code", "user", "config", plugins / "installed_plugins.json", True))
    add(Location("claude-code", "user", "memory", home / ".claude" / "projects", True,
                 "auto memory: projects/<project>/memory/MEMORY.md and topic files"))
    add(Location("claude-code", "user", "instructions", home / ".claude" / "output-styles", True))
    managed = (Path("/Library/Application Support/ClaudeCode") if plat == "darwin"
               else Path("C:/Program Files/ClaudeCode") if plat == "win32" else Path("/etc/claude-code"))
    add(Location("claude-code", "enterprise", "instructions", managed / "CLAUDE.md", True))
    add(Location("claude-code", "enterprise", "config", managed / "managed-settings.json", True))
    add(Location("claude-code", "enterprise", "config", managed / "managed-mcp.json", True))
    add(Location("claude-code", "enterprise", "skills", managed / ".claude" / "skills", True))
    # Cursor (cursor.com/docs/context/mcp)
    add(Location("cursor", "user", "config", home / ".cursor" / "mcp.json", True))
    # Cursor hooks, CLI permissions, skills and subagents (cursor.com/docs: hooks, cli/reference/permissions, skills)
    add(Location("cursor", "user", "hooks", home / ".cursor" / "hooks.json", True))
    add(Location("cursor", "user", "config", home / ".cursor" / "cli-config.json", True))
    add(Location("cursor", "user", "skills", home / ".cursor" / "skills", True))
    add(Location("cursor", "user", "agents", home / ".cursor" / "agents", True))
    # VS Code: mcp.json lives in the user profile folder ("MCP: Open User Configuration"); the default
    # profile folder is Code/User and other profiles are Code/User/profiles/<id> (code.visualstudio.com
    # docs: mcp-servers, settings).
    if plat == "darwin":
        code_user = home / "Library/Application Support/Code/User"
    elif plat == "win32":
        code_user = appdata / "Code" / "User"
    else:
        code_user = xdg / "Code" / "User"
    add(Location("vscode", "user", "config", code_user / "mcp.json", True))
    add(Location("vscode", "user", "config", code_user / "settings.json", True))
    add(Location("vscode", "user", "config", code_user / "profiles", True, "non-default profiles"))
    # GitHub Copilot (VS Code docs: mcp-servers, custom-instructions); COPILOT_HOME overrides ~/.copilot
    copilot = _env_path("COPILOT_HOME") or home / ".copilot"
    add(Location("copilot", "user", "config", copilot / "mcp-config.json", True))
    add(Location("copilot", "user", "instructions", copilot / "copilot-instructions.md", True))
    add(Location("copilot", "user", "instructions", copilot / "instructions", True))
    # docs.github.com/copilot: custom agents, hooks configuration, skills
    add(Location("copilot", "user", "agents", copilot / "agents", True))
    add(Location("copilot", "user", "hooks", copilot / "hooks", True))
    add(Location("copilot", "user", "skills", copilot / "skills", True))
    # Windsurf / Devin Desktop (docs.devin.ai/desktop/cascade/mcp)
    if plat == "win32":
        add(Location("windsurf", "user", "config", appdata / "devin" / "mcp_config.json", True))
    else:
        add(Location("windsurf", "user", "config", xdg / "devin" / "mcp_config.json", True))
    add(Location("windsurf", "user", "config", home / ".codeium" / "windsurf" / "mcp_config.json", False,
                 "legacy Windsurf path; not in the current docs"))
    # Gemini CLI (geminicli.com/docs: reference/configuration, cli/gemini-md)
    add(Location("gemini-cli", "user", "config", home / ".gemini" / "settings.json", True))
    add(Location("gemini-cli", "user", "instructions", home / ".gemini" / "GEMINI.md", True,
                 "the file name is configurable (context.fileName)"))
    # geminicli.com/docs: extensions/reference, custom commands, reference/policy-engine, cli/trusted-folders
    add(Location("gemini-cli", "user", "plugins", home / ".gemini" / "extensions", True))
    add(Location("gemini-cli", "user", "commands", home / ".gemini" / "commands", True))
    add(Location("gemini-cli", "user", "config", home / ".gemini" / "policies", True))
    add(Location("gemini-cli", "user", "skills", home / ".gemini" / "skills", True))
    add(Location("gemini-cli", "user", "config", home / ".gemini" / "trustedFolders.json", True))
    if plat == "darwin":
        add(Location("gemini-cli", "enterprise", "config", Path("/Library/Application Support/GeminiCli/settings.json"), True))
    elif plat == "win32":
        add(Location("gemini-cli", "enterprise", "config", Path("C:/ProgramData/gemini-cli/settings.json"), True))
    else:
        add(Location("gemini-cli", "enterprise", "config", Path("/etc/gemini-cli/settings.json"), True))
    # Codex (developers.openai.com/codex: mcp, AGENTS.md, skills); CODEX_HOME overrides ~/.codex
    codex = _env_path("CODEX_HOME") or home / ".codex"
    add(Location("codex", "user", "config", codex / "config.toml", True))
    add(Location("codex", "user", "instructions", codex / "AGENTS.md", True))
    add(Location("codex", "user", "instructions", codex / "AGENTS.override.md", True))
    add(Location("codex", "user", "skills", home / ".agents" / "skills", True, "also read by OpenClaw"))
    # learn.chatgpt.com/docs: hooks, config reference (subagents, custom prompts)
    add(Location("codex", "user", "hooks", codex / "hooks.json", True))
    add(Location("codex", "user", "agents", codex / "agents", True))
    add(Location("codex", "user", "commands", codex / "prompts", True, "custom prompts (deprecated)"))
    if plat != "win32":
        add(Location("codex", "enterprise", "skills", Path("/etc/codex/skills"), True))
        add(Location("codex", "enterprise", "config", Path("/etc/codex/config.toml"), True))
    add(Location("codex", "user", "skills", codex / "skills", False,
                 "older Codex skills folder; not in the current docs"))
    # Zed (zed.dev/docs/configuring-zed, as published in the zed-industries/zed repository)
    if plat == "win32":
        add(Location("zed", "user", "config", appdata / "Zed" / "settings.json", True))
    elif plat == "darwin":
        add(Location("zed", "user", "config", home / ".config" / "zed" / "settings.json", True))
    else:
        add(Location("zed", "user", "config", xdg / "zed" / "settings.json", True))
    # Cline CLI (docs.cline.bot/mcp/configuring-mcp-servers); the IDE extension keeps its file in editor storage
    add(Location("cline", "user", "config", home / ".cline" / "mcp.json", True))
    # OpenClaw (docs.openclaw.ai/skills); OPENCLAW_STATE_DIR / OPENCLAW_HOME override ~/.openclaw
    openclaw = _env_path("OPENCLAW_STATE_DIR") or _env_path("OPENCLAW_HOME") or home / ".openclaw"
    add(Location("openclaw", "user", "skills", openclaw / "skills", True))
    add(Location("openclaw", "user", "skills", openclaw / "workspace" / "skills", True, "default workspace"))
    # docs.openclaw.ai: gateway configuration, plugins/manifest, hooks; the workspace files load every session
    add(Location("openclaw", "user", "config", openclaw / "openclaw.json", True))
    add(Location("openclaw", "user", "plugins", openclaw / "extensions", True))
    add(Location("openclaw", "user", "hooks", openclaw / "hooks", True))
    for name in ("AGENTS.md", "SOUL.md", "USER.md", "IDENTITY.md", "BOOT.md", "BOOTSTRAP.md", "MEMORY.md"):
        add(Location("openclaw", "user", "instructions", openclaw / "workspace" / name, True))
    add(Location("openclaw", "user", "memory", openclaw / "workspace" / "memory", True))
    # Tier 3 (spec/ecosystems.md §9): paths from secondary sources, parsed as instruction text or MCP config.
    secondary = "path from a community-maintained list; not read from vendor documentation"
    add(Location("amp", "user", "instructions", xdg / "AGENTS.md", False, secondary))
    add(Location("junie", "user", "config", home / ".junie" / "mcp.json", False, secondary))
    add(Location("continue", "user", "instructions", home / ".continue" / "rules", False, secondary))
    add(Location("continue", "user", "config", home / ".continue" / "mcpServers", False, secondary))
    return L


PROJECT_PATTERNS: tuple[tuple[str, str, str, bool, str], ...] = (
    # (relative path, client, kind, verified, note for an unverified path)
    (".mcp.json", "claude-code", "config", True, ""),
    (".claude/settings.json", "claude-code", "config", True, ""),
    (".claude/settings.local.json", "claude-code", "config", True, ""),
    (".claude/skills", "claude-code", "skills", True, ""),
    (".claude/agents", "claude-code", "agents", True, ""),
    (".claude/commands", "claude-code", "commands", True, ""),
    (".claude/rules", "claude-code", "instructions", True, ""),
    (".claude/CLAUDE.md", "claude-code", "instructions", True, ""),
    (".claude/AGENTS.md", "claude-code", "instructions", True, ""),
    ("CLAUDE.md", "claude-code", "instructions", True, ""),
    ("CLAUDE.local.md", "claude-code", "instructions", True, ""),
    (".claude-plugin", "claude-code", "plugins", True, ""),
    (".cursor/mcp.json", "cursor", "config", True, ""),
    (".cursor/rules", "cursor", "instructions", True, ""),
    (".cursor/hooks.json", "cursor", "hooks", True, ""),
    (".cursor/cli.json", "cursor", "config", True, ""),
    (".cursor/skills", "cursor", "skills", True, ""),
    (".cursor/agents", "cursor", "agents", True, ""),
    (".cursor/commands", "cursor", "commands", False, "the Cursor commands page was not read"),
    (".cursor-plugin", "cursor", "plugins", True, ""),
    (".cursorrules", "cursor", "instructions", False, "legacy rules file, from a secondary source"),
    (".vscode/mcp.json", "vscode", "config", True, ""),
    (".vscode/tasks.json", "vscode", "workspace", True, ""),
    (".vscode/settings.json", "vscode", "workspace", True, ""),
    (".github/copilot-instructions.md", "copilot", "instructions", True, ""),
    (".github/instructions", "copilot", "instructions", True, ""),
    (".github/agents", "copilot", "agents", True, ""),
    (".github/hooks", "copilot", "hooks", True, ""),
    (".github/skills", "copilot", "skills", True, ""),
    (".github/prompts", "copilot", "commands", False, "the prompt-files page was not read; treated as instruction text"),
    (".github/copilot/settings.json", "copilot", "config", True, ""),
    (".github/mcp.json", "copilot", "config", True, ""),
    (".github/workflows", "copilot", "ci", True, ""),
    ("REVIEW.md", "copilot", "instructions", True, ""),
    (".gemini/settings.json", "gemini-cli", "config", True, ""),
    (".gemini/commands", "gemini-cli", "commands", True, ""),
    (".gemini/skills", "gemini-cli", "skills", True, ""),
    (".gemini/.env", "gemini-cli", "config", True, ""),
    ("gemini-extension.json", "gemini-cli", "plugins", True, ""),
    ("GEMINI.md", "gemini-cli", "instructions", True, ""),
    (".codex/config.toml", "codex", "config", True, ""),
    (".codex/hooks.json", "codex", "hooks", True, ""),
    (".codex/agents", "codex", "agents", True, ""),
    (".codex/skills", "codex", "skills", True, ""),
    (".codex-plugin", "codex", "plugins", True, ""),
    (".agents/skills", "codex", "skills", True, ""),
    ("AGENTS.md", "generic", "instructions", True, ""),
    ("AGENTS.override.md", "codex", "instructions", True, ""),
    (".openclaw/extensions", "openclaw", "plugins", True, ""),
    ("openclaw.plugin.json", "openclaw", "plugins", True, ""),
    ("SOUL.md", "openclaw", "instructions", True, ""),
    ("MEMORY.md", "openclaw", "memory", True, ""),
    (".clawhub/lock.json", "openclaw", "config", True, ""),
    (".zed/settings.json", "zed", "config", True, ""),
    # Workspace auto-execution files next to agent files (spec/ecosystems.md §10).
    (".devcontainer", "generic", "workspace", True, ""),
    (".envrc", "generic", "workspace", True, ""),
    (".gitattributes", "generic", "workspace", True, ""),
    (".githooks", "generic", "workspace", True, ""),
    (".gitmodules", "generic", "workspace", True, ""),
    # Tier 3: secondary sources or unverified.
    ("AGENT.md", "amp", "instructions", False, "legacy Amp file name, from a secondary source"),
    (".junie/guidelines.md", "junie", "instructions", False, "from a secondary source"),
    (".junie/mcp/mcp.json", "junie", "config", False, "from a secondary source"),
    (".aiassistant/rules", "jetbrains-ai", "instructions", False, "from a secondary source"),
    (".continuerules", "continue", "instructions", False, "from a secondary source"),
    (".continue", "continue", "instructions", False, "from a secondary source"),
    (".windsurf/rules", "windsurf", "instructions", False, "unverified path convention"),
    (".windsurfrules", "windsurf", "instructions", False, "unverified path convention"),
    (".clinerules", "cline", "instructions", False, "unverified path convention"),
    (".roo/rules", "roo-code", "instructions", False, "unverified path convention"),
    (".roorules", "roo-code", "instructions", False, "unverified path convention"),
    (".kiro/steering", "kiro", "instructions", False, "unverified path convention"),
    (".rules", "zed", "instructions", False, "unverified path convention"),
    (".goosehints", "goose", "instructions", False, "unverified path convention"),
    ("CONVENTIONS.md", "aider", "instructions", False, "unverified path convention"),
    (".aider.conf.yml", "aider", "config", False, "unverified path convention"),
)
