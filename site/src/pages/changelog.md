---
layout: ../layouts/Doc.astro
title: Changelog
description: Release history.
---

# Changelog

## 0.1.0 (unreleased)

First public version. The full history is in `CHANGELOG.md` in the repository.

### Rebuilt to the full project plan (November 2026)

- **450 rules in 23 families**, all implemented, with unsafe and safe fixtures for every rule. Rules run in a lane: block (decides alone), evidence (counts when a second signal backs it) or hunt (advisory). The earlier rule ids still work as aliases.
- **One verdict per scan:** ALLOW, REVIEW or BLOCK with its reasons, a score, a risk tier and the coverage. Policy presets `strict`, `balanced` and `permissive`.
- **More targets:** GitHub repositories at any ref and pull requests, npm and PyPI packages, container images, archives and MCPB bundles, MCP registry entries, live MCP endpoints, OpenAPI and A2A descriptors, and the whole machine.
- **Every agent's files:** Claude Code, the Agent Skills specification, MCP, Codex, Cursor, Gemini CLI, GitHub Copilot and VS Code, OpenClaw, and generic agent files; plugins, marketplaces, settings and hooks, agentic CI and workspace auto-execution.
- **New engines:** media and documents (including text in images through an OCR engine or a vision model), container images, composition with what is already installed, least privilege, a local triage model and a bounded model adjudicator.
- **Dynamic tier:** detonation in a Docker sandbox with no network route, canary credentials and a sinkhole (`--profile deep`, `agentguard detonate`).
- **New commands:** `fix` (verified by re-scan; `--emit-policy`), `install` with a receipt, `baseline`, `inventory`, `mcp inspect` and `probe`, `detonate`, `serve` (MCP server and local HTTP API for agents), `rules import`, `update` (signed bundles), `doctor`.
- **Integrations:** agent hooks for Claude Code, Cursor, Codex and Gemini CLI; the GitHub Action with pull-request mode and inline annotations; the pre-commit hook. An audit log records installs, approvals, applied fixes and updates.
- **Benchmarks:** verdicts on the internal corpus, an evasion suite of sixteen operators, 23 incident reproductions, and runners for MalSkillBench and SkillTrustBench over a local copy.

### Earlier in 0.1.0

- The first rule pack (185 rules) across skills, instruction files, MCP configuration and metadata, code, toxic flows, supply chain, remote auth conformance, policy and coverage.
- Outputs: terminal, JSON, SARIF 2.1.0, Markdown, single-file HTML, CycloneDX 1.6.
- Opt-in `--check-hijackable` on the CLI and in the GitHub Action. A GitHub token, when set, goes to api.github.com only.
- A pure-Python engine that runs under Pyodide, and Agent Guard Web: links to GitHub, npm, PyPI, the MCP Registry and remote MCP servers scanned on a server in an isolated sandbox.
- Rules for MCP 2026-07-28 and its MCP Apps and Tasks extensions. The [MCP spec support](../docs/mcp-spec-support/) page lists the revisions each rule area covers.
