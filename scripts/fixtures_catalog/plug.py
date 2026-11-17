"""PLUG: plugins, extensions and marketplaces."""

from . import N, P, add, doc, j, merge

MK = ".claude-plugin/marketplace.json"
PJ = "tool/.claude-plugin/plugin.json"
SHA = "9b1c0f7e2d4a6b8c0e1f3a5b7c9d1e3f5a7b9c1d"
S256 = "3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855e"


def market(*plugins, name="team-tools", **top):
    return j(MK, {"name": name, "owner": {"name": "Example Team"}, "plugins": list(plugins), **top})


def plugin(description="Formats Python files.", name="tool", path=PJ, **fields):
    return j(path, {"name": name, "version": "1.0.0", "description": description, **fields})


HOOKS = {"hooks": {"PostToolUse": [{"matcher": "Edit", "hooks": [{"type": "command", "command": "ruff format ."}]}]}}

add("AG-PLUG-001",
    P("github-source-on-a-branch", market({"name": "fmt", "source": {"source": "github", "repo": "example-org/fmt", "ref": "main"}})),
    N("github-source-with-sha", market({"name": "fmt", "source": {"source": "github", "repo": "example-org/fmt", "ref": "v1.2.0", "sha": SHA}})),
    N("relative-path-source", market({"name": "fmt", "source": "./plugins/fmt"})))
add("AG-PLUG-002",
    P("npm-range", market({"name": "fmt", "source": {"source": "npm", "package": "@example/fmt-plugin", "version": "^1.2.0"}})),
    P("npm-latest", market({"name": "fmt", "source": {"source": "npm", "package": "@example/fmt-plugin", "version": "latest"}})),
    N("npm-exact", market({"name": "fmt", "source": {"source": "npm", "package": "@example/fmt-plugin", "version": "1.2.0"}})))
add("AG-PLUG-003",
    P("archive-without-hash", market({"name": "fmt", "source": {"source": "archive", "url": "https://downloads.example.invalid/fmt-1.2.0.tar.gz"}})),
    N("archive-with-hash", market({"name": "fmt", "source": {"source": "archive", "url": "https://downloads.example.invalid/fmt-1.2.0.tar.gz", "sha256": S256}})))
add("AG-PLUG-004",
    P("command-source", market({"name": "fmt", "source": {"source": "command", "command": "sh ./fetch-plugin.sh fmt"}})),
    N("git-source", market({"name": "fmt", "source": {"source": "github", "repo": "example-org/fmt", "sha": SHA}})))
add("AG-PLUG-005",
    P("entry-headers-helper", market({"name": "fmt", "source": {"source": "github", "repo": "example-org/fmt", "sha": SHA}, "headersHelper": "./tools/token.sh"})),
    N("no-helper", market({"name": "fmt", "source": {"source": "github", "repo": "example-org/fmt", "sha": SHA}})))
add("AG-PLUG-006",
    P("marketplace-auto-update", market({"name": "fmt", "source": "./plugins/fmt"}, autoUpdate=True)),
    P("settings-auto-update", j(".claude/settings.json", {"extraKnownMarketplaces": {"team-tools": {"source": {"source": "github", "repo": "example-org/claude-plugins"}, "autoUpdate": True}}})),
    N("auto-update-off", market({"name": "fmt", "source": "./plugins/fmt"}, autoUpdate=False)))
add("AG-PLUG-007",
    P("hooks-not-described", merge(plugin(), j("tool/hooks/hooks.json", HOOKS))),
    N("hooks-described", merge(plugin("Formats Python files with a hook that runs after each edit."), j("tool/hooks/hooks.json", HOOKS))),
    N("no-hooks", merge(plugin(), doc("tool/commands/format.md", "Format the file the user names with ruff.\n"))))
add("AG-PLUG-008",
    P("lsp-server-not-described", merge(plugin(), j("tool/.lsp.json", {"python": {"command": "pyright-langserver", "args": ["--stdio"]}}))),
    P("mcp-server-not-described", merge(plugin(), j("tool/.mcp.json", {"mcpServers": {"fmt": {"command": "node", "args": ["${CLAUDE_PLUGIN_ROOT}/server.js"]}}}),
                                        doc("tool/server.js", "console.log('ready')\n"))),
    N("server-described", merge(plugin("Formats Python files and adds the Pyright language server."),
                                j("tool/.lsp.json", {"python": {"command": "pyright-langserver", "args": ["--stdio"]}}))))
add("AG-PLUG-009",
    P("bin-not-described", merge(plugin(), doc("tool/bin/fmt-all", "#!/bin/sh\nruff format .\n"))),
    P("workflow-not-described", merge(plugin(), doc("tool/workflows/release.js", "export default async function run(ctx) {\n  return ctx.ask('Ready to release?');\n}\n"))),
    N("cli-described", merge(plugin("Formats Python files; adds the `fmt-all` command-line helper."), doc("tool/bin/fmt-all", "#!/bin/sh\nruff format .\n"))))
add("AG-PLUG-010",
    P("dependency-from-another-marketplace", plugin(dependencies=["secrets-helper@community-plugins"])),
    N("dependency-in-the-same-marketplace", plugin(dependencies=["shared-config"])))
add("AG-PLUG-011",
    P("commands-path-climbs-out", plugin(commands="../../shared/commands")),
    P("hooks-path-in-home", plugin(hooks="~/.claude/hooks/hooks.json")),
    N("paths-inside-the-plugin", plugin(commands="./custom/commands", hooks="./config/hooks.json")))
add("AG-PLUG-012",
    P("strict-false", market({"name": "fmt", "source": "./plugins/fmt", "strict": False, "commands": ["./overrides/fmt.md"]})),
    N("strict-default", market({"name": "fmt", "source": "./plugins/fmt"})))
add("AG-PLUG-013",
    P("reserved-marketplace-name", market({"name": "fmt", "source": "./plugins/fmt"}, name="claude-plugins-official"), verdict="BLOCK"),
    P("official-looking-name", market({"name": "fmt", "source": "./plugins/fmt"}, name="anthropic-tools-v2")),
    N("ordinary-name", market({"name": "fmt", "source": "./plugins/fmt"}, name="acme-internal-tools")))
add("AG-PLUG-014",
    P("status-line-command", merge(plugin(), j("tool/settings.json", {"subagentStatusLine": {"type": "command", "command": "node ${CLAUDE_PLUGIN_ROOT}/status.js"}}))),
    N("no-plugin-settings", plugin()))
add("AG-PLUG-015",
    P("api-key-not-sensitive", plugin(userConfig={"apiKey": {"title": "API key", "description": "Key for the formatting service", "type": "string"}})),
    N("api-key-sensitive", plugin(userConfig={"apiKey": {"title": "API key", "description": "Key for the formatting service", "type": "string", "sensitive": True}})),
    N("non-secret-field", plugin(userConfig={"lineLength": {"title": "Line length", "type": "number"}})))
add("AG-PLUG-016",
    P("plugin-dependency-from-a-url", merge(plugin(), j("tool/package.json", {"name": "tool", "version": "1.0.0", "dependencies": {"left-pad-fast": "https://packages.example.invalid/left-pad-fast.tgz"}}))),
    N("plugin-with-pinned-dependency", merge(plugin(), j("tool/package.json", {"name": "tool", "version": "1.0.0", "dependencies": {"prettier": "3.3.3"}}),
                                             j("tool/package-lock.json", {"name": "tool", "lockfileVersion": 3, "packages": {"node_modules/prettier": {"version": "3.3.3", "resolved": "https://registry.npmjs.org/prettier/-/prettier-3.3.3.tgz", "integrity": "sha512-i2tDNA0O5IrMO757lfrdQZCc2jPNDVntV0m/+4whiDfWaTKfMNgR7Qz0NAeGz/nRqF4m5/6CLzbP4/liHt12Ew=="}}}))))
add("AG-PLUG-018",
    P("bundle-url-without-hash", plugin(mcpServers={"weather": {"url": "https://downloads.example.invalid/weather-1.0.0.mcpb"}})),
    N("bundle-url-with-hash", plugin(mcpServers={"weather": {"url": "https://downloads.example.invalid/weather-1.0.0.mcpb", "sha256": S256}})),
    N("bundle-shipped-in-the-plugin", plugin(mcpServers="./servers/weather.mcpb")))
add("AG-PLUG-019",
    P("session-start-hook-phones-home", merge(plugin("Formats Python files with hooks."),
                                              j("tool/hooks/hooks.json", {"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "curl -s https://stats.example.invalid/ping?p=tool"}]}]}}))),
    N("session-start-hook-is-local", merge(plugin("Formats Python files with hooks."),
                                           j("tool/hooks/hooks.json", {"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "ruff --version"}]}]}}))))
add("AG-PLUG-020",
    P("renames-declared", market({"name": "fmt2", "source": "./plugins/fmt2"}, renames={"fmt": "fmt2"})),
    N("no-renames", market({"name": "fmt", "source": "./plugins/fmt"})))
add("AG-PLUG-021",
    P("open-channel", plugin("Bridges a chat channel into the session.", channels=[{"server": "chat-bridge"}])),
    N("channel-with-allow-list", plugin("Bridges a chat channel into the session.", channels=[{"server": "chat-bridge", "allowedSenders": ["ops-lead"]}])))
add("AG-PLUG-022",
    P("gemini-extension-redirects", j("gx/gemini-extension.json", {"name": "gx", "version": "0.3.0", "description": "Docs search.", "migratedTo": "https://github.com/someone-else/gx-next"})),
    P("cursor-plugin-bundles-hooks", merge(plugin("Formats Python files.", path="cx/.cursor-plugin/plugin.json"),
                                           j("cx/hooks/hooks.json", HOOKS))),
    N("gemini-extension-plain", j("gx/gemini-extension.json", {"name": "gx", "version": "0.3.0", "description": "Docs search.", "contextFileName": "GEMINI.md"})))
add("AG-PLUG-023",
    P("hooks-on-by-default", merge(plugin("Formats Python files with hooks.", enabledByDefault=True), j("tool/hooks/hooks.json", HOOKS))),
    N("commands-only-on-by-default", merge(plugin(enabledByDefault=True), doc("tool/commands/format.md", "Format the file the user names with ruff.\n"))))
