---
layout: ../../layouts/Doc.astro
title: Quickstart
description: Scan a skill, a repository, a package, an MCP server or your whole machine.
---

# Quickstart

```bash
# One skill folder, a repository, or a single MCP config file
agentguard scan ./skills/pdf-helper
agentguard scan https://github.com/acme/tools@v1.2.0
agentguard scan ~/.cursor/mcp.json

# A package, a container image, a registry entry or a live MCP endpoint
agentguard scan pkg:npm/@acme/mcp-server@1.4.2
agentguard scan oci://ghcr.io/acme/mcp@sha256:...
agentguard scan mcp+https://mcp.acme.example/mcp

# Everything this machine's agents can use
agentguard scan --machine

# Show evidence, decoded content and standards for each finding
agentguard scan ./skills -v

# Inventory only (no findings): agents, MCP servers, skills, instruction files, as an AI-BOM
agentguard inventory --format cyclonedx -o agents.cdx.json
```

## Reading the output

Every scan ends in one **verdict**:

| Verdict | Meaning |
|---|---|
| **BLOCK** | A finding strong enough to decide alone: a block-lane malice finding at high or critical severity, a critical finding with high confidence, a known indicator, a confirmed attack chain, or a policy deny entry |
| **REVIEW** | A high-severity finding, a malice finding with medium or high confidence, content that could not be analysed, a score of 40 or more, or a policy that requires a review |
| **ALLOW** | Nothing that counts towards the verdict matched. It does not mean safe |

Next to the verdict: a **score** from 0 to 100, the **risk tier** (L0 to L3, from what the components can do), and the **coverage** (how much of the content was analysed). The report lists the reasons for the verdict.

Each finding has a rule ID, severity, confidence and **lane**. A block-lane rule decides on its own; an evidence-lane rule counts only when a second signal backs it (another engine, a chain, hidden content, or the triage model in the standard profile); a hunt-lane rule is advisory. `agentguard explain AG-EXEC-001` explains any rule, and `agentguard explain <fingerprint>` any finding of the last scan.

## Profiles

| Profile | What runs | Needs |
|---|---|---|
| `quick` | Deterministic static analysis; sends nothing anywhere | Nothing |
| `standard` (default) | Adds the local triage model, and a gated model adjudicator when a model is configured | A model API key for the adjudicator (optional) |
| `deep` | Adds detonation in a sandbox and live MCP inspection | Docker |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ALLOW, or below `--fail-on` (default: `block`) |
| 1 | REVIEW at or above the threshold |
| 2 | BLOCK |
| 3 | Content could not be analysed and the policy requires full coverage |
| 64 | Usage or configuration error |
| 70 | Internal error |

## Fix, then pin what you reviewed

```bash
agentguard fix ./skills                 # a unified diff of the safe fixes; each one re-scanned
agentguard fix ./skills --apply         # write them
agentguard baseline create --approved-by you@example.org   # writes agentguard.lock
agentguard baseline verify              # later: drift, rug pulls and changed tool definitions
```
