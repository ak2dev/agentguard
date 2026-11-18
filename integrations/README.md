# Agent hooks

These files make an agent call Agent Guard on its own, at three moments:

| When | What happens |
|---|---|
| Before a shell command runs | If the command installs a skill, a plugin, an extension or an MCP server, what it would install is scanned first. BLOCK denies the command. REVIEW asks you (or denies, where the agent cannot ask). Anything else runs as usual. |
| After an agent-facing file is written | The file (with the rest of its skill or plugin folder) is scanned again at once and the result is given to the agent. |
| At session start | The working directory is checked against `agentguard.lock`, and differences from what you approved are reported. |

All four use one program, `agentguard-hook`, which is installed with Agent Guard. It reads the event the agent passes on standard input and prints the decision in that agent's format. It returns rule ids, rule titles, file names and line numbers only. Text from the scanned files is never passed back to the agent; the full report is written to disk for you.

`agentguard-hook` must be on the `PATH` the agent runs commands with:

```bash
pip install agentguard-v1
```

## Claude Code

`claude-code/` is a plugin. Load it for one session:

```bash
claude --plugin-dir ./integrations/claude-code
```

or add this repository as a marketplace and install the plugin from it.

The pre-install hook sets `onFailure: "block"`, so a crash or a timeout of the check blocks the command instead of letting it through. That key needs Claude Code 2.1.295 or later; older versions ignore it and fail open.

## Cursor

Copy `cursor/hooks.json` to `.cursor/hooks.json` in a project, or to `~/.cursor/hooks.json` for every project. The pre-install hook sets `failClosed: true`.

Cursor documents no output for `afterFileEdit`, so the result of a re-scan is written to the hook log and to the report on disk; the agent is not told.

## Codex

Copy `codex/hooks.json` to `.codex/hooks.json` in a trusted project, or to `~/.codex/hooks.json`. Codex asks you to review and trust the hooks before they run (`/hooks`).

Codex has no "ask" decision for a pre-tool hook, so a REVIEW verdict denies the command; you can run the install yourself after reading the report. Codex does not document a fail-closed setting: if `agentguard-hook` is not installed, the command runs unchecked.

## Gemini CLI

Merge the `hooks` object of `gemini/settings.json` into `.gemini/settings.json` or `~/.gemini/settings.json`.

Gemini CLI has no "ask" decision either, so a REVIEW verdict denies the command. It fails open when a hook cannot start; the hook itself exits with code 2 (a block) when its own check fails.

## What counts as an install

- `git clone` into a skills, plugins, agents, commands, extensions, rules or hooks directory of an agent (`.claude/`, `.agents/`, `.codex/`, `.cursor/`, `.gemini/`, `.openclaw/`, `.github/`)
- copying, moving, unpacking or downloading into one of those directories
- `npx skills add`, `add-skill`
- `claude plugin marketplace add`, `claude plugin install`
- `claude mcp add`, `claude mcp add-json`, `codex mcp add`, `gemini mcp add`
- `gemini extensions install`
- `clawhub install`, `openclaw skills install`, `smithery install`

A GitHub repository, an archive or a local folder is fetched to quarantine and scanned the way `agentguard install --plan` does it. An MCP server entry is checked as configuration; values you pass with `--env` or `--header` are not scanned and not stored. A source that cannot be read before it is fetched (a marketplace plugin by name, a registry install) is put to you as a question.

## Limits

- A pre-tool hook sees the command line, not what the command does. An install hidden in a script the agent runs is not seen here; the file-change hook and a scan of the repository cover that.
- `--on-review ask|deny|allow` on the `pre-install` hook changes what a REVIEW verdict does. The default is `ask`.
- The hook formats were taken from each vendor's hook reference in November 2026. The Claude Code `FileChanged` and `ConfigChange` events were read in summary only and are the least certain part.
