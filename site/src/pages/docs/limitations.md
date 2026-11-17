---
layout: ../../layouts/Doc.astro
title: Limitations
description: What Agent Guard does not do yet, stated plainly, and what comes next.
---

# Limitations

- **The static tier never runs what it scans.** Behaviour that only appears at run time (code downloaded later, a payload behind a date or environment check) is reached by the `deep` profile, which detonates the target in a Docker sandbox with no network route and canary credentials. Dynamic evidence adds to static findings and never clears them. Not built yet in the sandbox: driving a real agent inside the container (the Claude Code and OpenCode adapters) and the enhanced instrumentation level (eBPF, FUSE); scripts, hooks, install steps and local MCP servers are run directly.
- **Pattern rules can be evaded.** Paraphrased lures are the known weak spot. The evasion suite rewrites every malicious sample with sixteen published operators and keeps each at REVIEW or above, but an instruction written as an ordinary sentence with no tell-tale phrasing is reached only by the model adjudicator, when one is configured.
- **Text in raster images needs an OCR engine or a model.** With the `agentguard-v1[ocr]` extra installed, images and rendered PDF pages are read locally; without it, in the `standard` profile with a model, the model transcribes them. With neither, the report says how many images were not read. SVG, image metadata, PDF content streams, Office macros and notebooks are always read.
- **The triage model is small and agrees with the rules.** It is a gradient-boosted classifier over what the deterministic engines found, trained on Agent Guard's own corpus (dev split) and measured on the held-out split, where it separates benign from malicious components as the rules already do. It never decides a verdict alone and never lowers a finding. It does not use sentence embeddings of the instruction text, and the multilingual rules are phrase patterns in eleven languages, not embedding similarity.
- **Taint analysis has limits.** Python taint follows a tool parameter into helper functions in the same file and in imported modules of the package, up to three helpers deep; JavaScript and TypeScript taint is pattern-based. Installed packages are never followed. The `agentguard-v1[code]` extra adds tree-sitter analysis for JavaScript, TypeScript and shell.
- **YARA rules need the `agentguard-v1[yara]` extra.** The browser scanner runs neither native analyzer; reports list them as skipped.
- **Signatures and provenance are checked, not fully verified.** Package provenance checks find a missing attestation or a subject-digest mismatch, and image checks find whether a signature exists; neither performs full Sigstore certificate-chain verification. Rule and intelligence updates are verified with pinned Ed25519 release keys, not Sigstore: there is no transparency log.
- **Remote checks are read-only and unauthenticated by default.** Agent Guard never calls a tool on a remote MCP server and sends a token only to the one endpoint you scan, when you set `AGENTGUARD_MCP_TOKEN`.
- **Some agents' formats are unverified.** Tier 1 and 2 agents (Claude Code, the Agent Skills specification, MCP, Codex, Cursor, Gemini CLI, GitHub Copilot and VS Code, OpenClaw) were checked against vendor documentation; tier 3 agents are parsed generically from secondary sources. `agentguard inventory` labels unverified locations.
- **MITRE ATLAS mappings are not generated yet.** They are to be generated from MITRE's published data file, never typed by hand; the other standards are mapped for every rule.
- **Public benchmarks are not measured here.** The runners for MalSkillBench and SkillTrustBench read a local copy you download (their licences restrict redistribution and commercial use), and no figures from them are published on this site.
- **Benchmark caveats.** The malicious and adversarial items of the internal corpus are synthetic and written by the same people as the rules; the real benign items come from a handful of vendor repositories that the rules were tuned against. Real skills unlike them will produce more findings.

## Next

1. **First release.** Publish to PyPI and tag the GitHub Action, with signed artifacts and an SBOM.
2. **Agent adapters in the sandbox,** so a real agent is driven through a skill, and the enhanced tracing level on Linux.
3. **Independent malicious samples,** and the two public benchmarks measured under their licences.
4. **Sigstore verification** for provenance, images and updates.
5. **Runtime enforcement.** A gateway that checks tool definitions against `agentguard.lock` on every connection and enforces the least-privilege policy, so a rug pull is blocked rather than found at the next scan.
