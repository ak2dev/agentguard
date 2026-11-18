---
layout: ../../layouts/Doc.astro
title: Output formats
description: Terminal, JSON, SARIF, Markdown, HTML, JUnit, CycloneDX and agent-safe output.
---

# Output formats

| Format | Flag | Use |
|---|---|---|
| Terminal | default | Verdict, score, tier and coverage first; findings grouped by their effect on the verdict, then severity; `-v` adds evidence, decoded content and mappings |
| JSON | `-f json` | The versioned report schema (`schema_version: 1`), the contract between the engine and every other output |
| SARIF 2.1.0 | `-f sarif` | GitHub code scanning: `security-severity`, `precision`, code flows for traces, fixes, stable fingerprints |
| Markdown | `-f md` | Pull-request comments and job summaries; mentions, links and HTML are neutralized |
| HTML | `-f html` | A single self-contained file with filters and expandable traces, no external resources |
| JUnit | `-f junit` | One test case per rule, findings as failures, for CI dashboards |
| CycloneDX 1.6 | `-f cyclonedx` | An AI-BOM: one component per skill, plugin, server, hook, instruction file and model endpoint |

`-f` is repeatable; with several formats, `-o` names a directory. Convert a saved report without rescanning: `agentguard report --input report.json --format sarif`. `agentguard inventory --trust-cards` prints a short card per component: what it is, what it can do, where it came from, its verdict, and what would change it.

## The report

The top level carries the tool, rule-pack and intelligence versions, the target with the immutable identifier it was resolved to (commit, version and hash, image digest), the profile and policy, the **coverage** (files and bytes analysed, and what was not), the **verdict** with its reasons, the **score** (0 to 100), the **risk tier**, the components (`artifacts`, each with its capabilities, risk tier, verdict, triage probability and least-privilege proposal), the findings, the attack **chains**, and the model and sandbox accounting (`limits`).

## Every finding carries

- rule ID, variant and version, title, family and category (malice, vulnerability or hygiene);
- severity, confidence and lane, and whether it counts towards the verdict;
- a location: artifact, file, line and column, and the archive or image it is inside;
- evidence: a **redacted** snippet, invisible characters made visible, the decoded payload and the decoding steps, and every engine's own evidence;
- a trace from instruction to source to sink, and the chain it belongs to;
- a fix: its kind (auto, patch, guidance, do not install) and summary;
- standards mappings, the engines that reported it, the model review when one ran, references and a stable fingerprint.

Secrets are always shown as the first four characters plus a short hash (for example `ghp_…[1a2b3c4d]`), in every format.

## Agent-safe output

`--agent-safe` (always on in `agentguard serve`) withholds snippets and decoded payloads and strips control and invisible characters from names and paths, so a report handed to an agent cannot carry an injection back to it. The agent gets rule IDs, fixed rule wording, file and line, verdict and fix summary; the full report is written to disk for a person.

## Determinism

With the same input, engine and rule pack, static reports are byte-for-byte identical. Timestamps and timings are omitted unless you pass `--timestamps`.

Schemas: `agentguard schema report` (also `rule`, `lock`, `policy`, `config`).
