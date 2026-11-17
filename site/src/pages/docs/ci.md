---
layout: ../../layouts/Doc.astro
title: CI integration
description: GitHub Action with pull-request mode and code-scanning alerts, pre-commit, and agent hooks.
---

# CI integration

## GitHub Action

```yaml
jobs:
  agentguard:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@<commit-sha>   # pin by SHA
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: ak2dev/agentguard@<release-sha>
        with:
          targets: .
          policy: balanced
          fail-on: block
```

On a pull request the action runs in **pull-request mode** (`pr-mode`, on by default): it scans with `--diff <base>..<head>`, so changed files are scanned in full and the rest of the repository supplies context, configuration is read from the base commit, and only findings whose fingerprints are new fail the job. It then:

- annotates the changed lines with the findings that decide the verdict;
- uploads SARIF to GitHub code scanning (`upload-sarif`);
- writes a Markdown summary to the job page;
- sets the outputs `verdict`, `score`, `exit-code`, `report` and `sarif`, and fails the step on the verdict.

| Input | Default | |
|---|---|---|
| `targets` | `.` | What to scan, separated by spaces |
| `diff` | | `<base>..<head>`; empty on a pull request means its own base and head |
| `policy` | `balanced` | A preset or a policy file |
| `profile` | `quick` | `standard` adds the triage model; no model is called unless you set `llm` |
| `llm` | `off` | `auto` or `always`, with the model's API key in the job's environment |
| `fail-on` | `block` | `block`, `review` or `severity:<level>` |
| `format`, `output` | `sarif`, `agentguard.sarif` | Another format to write |
| `annotations`, `upload-sarif` | `true` | |
| `check-hijackable` | `false` | Opt-in network check, below |

### Hijackable references (opt-in network check)

`check-hijackable: true` runs `--check-hijackable`: referenced GitHub owners, npm and PyPI packages, download domains and cloud-app hostnames are looked up to see whether anyone could claim them (AG-SUPPLY-004, AG-SUPPLY-012, AG-SUPPLY-015). It is off by default, so the action makes no network requests for the scan unless you turn it on, and the report lists every host contacted. When it is on, the workflow token is passed to the scan and sent to `api.github.com` only, for the owner lookups.

A static scan starts no process: git history is read by a pure-Python reader, so no repository hook, filter or configuration can run. The only program Agent Guard ever starts is Docker, for the `deep` profile's sandbox, and only with an exact, pre-authorized command line.

## pre-commit

```yaml
repos:
  - repo: https://github.com/ak2dev/agentguard
    rev: <release-tag>
    hooks:
      - id: agentguard
```

The hook runs `agentguard scan --profile quick --llm off --context none --fail-on review` when an agent-facing file changes (skills, instruction files, MCP configurations, agent settings and plugin folders).

## Agent hooks

`integrations/` holds hook files for Claude Code (a plugin), Cursor, Codex and Gemini CLI. They all call `agentguard-hook`:

- **before a shell command runs**, an install of a skill, plugin, extension or MCP server is scanned first; BLOCK denies the command, and REVIEW asks you (or denies, where the agent cannot ask). The Claude Code hook sets `onFailure: "block"`, so a crash does not let the install through;
- **after an agent-facing file is written**, its skill or plugin folder is scanned again and the result is given to the agent;
- **at session start**, the project is checked against `agentguard.lock` and drift is reported.

The hooks return rule IDs, titles, file names and line numbers only; text from the scanned files is never passed back to the agent.

## Other CI systems

```bash
agentguard scan . --diff "$BASE_SHA..$HEAD_SHA" --format json --output agentguard-report.json
agentguard report --input agentguard-report.json --format sarif --output agentguard.sarif
agentguard report --input agentguard-report.json --format md     # PR comment body
agentguard report --input agentguard-report.json --format junit --output agentguard.junit.xml
```
