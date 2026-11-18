---
layout: ../../layouts/Doc.astro
title: Configuration
description: The .agentguard.yaml file.
---

# Configuration

Agent Guard reads `.agentguard.yaml` from the directory you run it from (or `--config PATH`), then the one in your user configuration directory, then built-in defaults. A configuration file **inside a scanned third-party target is never read**, so a repository cannot relax its own checks. In `--diff` mode, when you run from the repository being diffed, the file is read from the base commit.

```yaml
version: 1
profile: standard          # quick | standard | deep
policy: balanced           # strict | balanced | permissive, or an inline policy (see Policy)
fail_on: block             # block | review | severity:<level>
context: installed         # installed | none | a path: what a candidate is composed with
ecosystems: [claude-code, cursor, codex, gemini, copilot, openclaw]
exclude:                   # directory names to skip
  - fixtures
popular_skills:            # extra names for typosquat checks ("name [publisher]")
  - internal-deploy acme
suppressions:              # see Suppressions
  - rule_id: AG-MCP-001
    path_glob: "sandbox/*"
    reason: Sandbox configs are rebuilt nightly from pinned images.
    expires: 2026-12-31
limits:
  max_file_bytes: 20000000
  max_archive_depth: 3
  max_archive_ratio: 100
  timeout_seconds: 600
llm:
  provider: anthropic      # anthropic | openai-compatible | ollama
  triage_model: claude-haiku-5-5
  judge_model: claude-opus-5-5
  consensus_runs: 1
  max_cost_usd: 2.00
  max_tokens: 400000
  redact_secrets: true
dynamic:
  runtime: docker
  agent_adapter: claude-code   # claude-code | opencode | none
  timeout_seconds: 900
intel:
  osv: off                 # online | mirror | off
  url_reputation: bundled
cache:
  dir: ~/.cache/agentguard
  ttl_days: 30
output:
  redact_snippets: false
```

The JSON Schema is available with `agentguard schema config`.

## Where things are kept

Agent Guard keeps its own data (the model answer cache, installed rule packs and updates, the audit log) under `AGENTGUARD_HOME`, which defaults to `%LOCALAPPDATA%\agentguard` on Windows and `~/.local/share/agentguard` elsewhere. `agentguard doctor` prints what each profile can use on your machine.
