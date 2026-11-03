# How Agent Guard compares

Coding agents install skills, follow instruction files and connect to MCP servers, and each one runs with the agent's access: files, shell, credentials, network. The model reads their text as instructions, and some of it runs before the model sees it (Claude Code's `!` commands and skill hooks). A skill can tell the agent to "install a prerequisite" that is malware, hide instructions in invisible Unicode, or read `~/.ssh` and post it to a webhook, often in plain language that no antivirus signature matches. A server can change its tools after you approve it (a rug pull), and a skill can depend on a GitHub account, package or domain anyone can now claim (SkillJacking).

**Gaps in current tools** (checked against each project's own docs on 2026-10-30; sources in [sources.md](sources.md)):

| Tool | Covers | Leaves open |
|---|---|---|
| [Snyk Agent Scan](https://github.com/snyk/agent-scan) | MCP servers, skills, agent configs | Starts stdio servers by running the commands in your config (with consent; `--dangerously-run-mcp-servers` in CI); sends configs, tool descriptions and skill files to the Snyk API and needs a token; no pinning of tool definitions described |
| [Cisco skill-scanner](https://github.com/cisco-ai-defense/skill-scanner) | Skills, with local static, bytecode and dataflow analyzers | Skills only; LLM, VirusTotal and AI Defense analyzers need API keys |
| [Cisco mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner) | MCP servers, tools, prompts, resources | MCP only; connects to live servers and launches stdio servers; LLM and AI Defense engines need keys |
| [ClawHub + VirusTotal](https://www.openclaw.ai/blog/virustotal-partnership) | Skills published to ClawHub, at publish and daily | One registry; uploads bundles to VirusTotal; by OpenClaw's own account, natural-language instructions won't trigger a virus signature |

Published bypasses got malicious skills past ClawHub, the skills.sh scanners and Cisco's skill-scanner ([Trail of Bits, June 2026](https://blog.trailofbits.com/2026/06/03/the-sorry-state-of-skill-distribution/)), and obfuscation and split payloads degraded commercial scanners ([Cloud Security Alliance](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-skill-scanner-bypass-20260610-csa/)).

**How Agent Guard closes them.**

| Gap | Agent Guard |
|---|---|
| Scanning by running | Parse-only; process creation is blocked. Tool definitions come from manifests, `server.json` and source; listing a live server is opt-in, read-only and remote only |
| Setup leaves the machine | Offline, no account, no telemetry; pasted input in the browser never leaves the device |
| Split coverage | One engine for skills, instruction files, client configs, tool metadata and server code, across ten agent clients |
| Signatures miss language | Instruction-layer and hidden-content rules, decoding and rescanning, an optional LLM judge capped below CRITICAL |
| Known bypasses | Reproduced inertly in the benchmark and covered; what is still missed is listed on the [limitations page](https://agentguard-ak2dev.vercel.app/docs/limitations/) |
| Per-component view | Toxic flows across everything active in one agent session |
| One point in time | `lock` / `verify` diffs, `--check-hijackable`, a signed IOC feed |
| False assurance | Never "safe"; skipped analyzers and content are listed; an analyzer error exits 2 |

Recheck this page against each project's docs before every release, and update the date above.
