# Threat model: Agent Guard CLI, engine and integrations

Scope: the CLI, the library, the agent hooks, the agent-facing server (`agentguard serve`) and the dynamic tier, which read untrusted skills, plugins, instruction files, agent settings, MCP configurations, server source, packages, images and live endpoints on a developer machine or CI runner, and write reports to the terminal, files, GitHub code scanning (SARIF), pull-request comments and calling agents. The hosted web service has its own threat model in `web/threat-model.md`.

## Assets

- **A1** Integrity of the host and CI runner, including its secrets (`GITHUB_TOKEN`, cloud credentials, model API keys).
- **A2** Correctness of results: no silent evasion, no fail-open.
- **A3** Secrets present *in* scanned targets.
- **A4** User privacy: what the user has installed.
- **A5** Agent Guard's supply chain: releases, rule pack, intelligence bundle.
- **A6** CI availability.
- **A7** The agent that calls Agent Guard (hooks, `serve`), which must not receive hostile text from a target.

## Adversaries

- **T1** Author of a malicious skill, plugin or server, who controls every scanned byte, including images and documents.
- **T2** Malicious pull-request contributor, who controls the repository including `.agentguard.yaml`, the lockfile and the baseline.
- **T3** Hostile remote MCP server or network attacker (opt-in network features and live targets only).
- **T4** Attacker on Agent Guard's dependencies, rule pack or intelligence feed.
- **T5** Third party reading public SARIF alerts or pull-request comments.
- **T6** Content written to manipulate a model that reviews it (the adjudicator, the vision transcriber) or the agent that reads the report.

## Threats and mitigations (as implemented)

| # | Threat | Mitigation | Where |
|---|---|---|---|
| TM-01 | Scanner executes target code | Parse-only static tier; an audit hook raises on every process-creation event; git history and diffs are read by a pure-Python reader, so no repository hook, filter or configuration runs; packages are unpacked, never installed. The one program ever started is Docker, for the `deep` profile, through `guard.allow_exact` with the exact argument vector | `io/guard.py`, `acquire/gitread.py`, `sandbox/runtime.py`, `tests/safety/` |
| TM-02 | Parser and resource attacks | `LoadLimits` (file size, total bytes, file count, depth, decompression ratio, decode depth); archives unpacked in memory to depth 3 with ratio and count caps; YAML custom tags rejected, and anchors and aliases rejected in frontmatter and read in configuration files only with each alias counted as the nodes it stands for (no billion laughs) and no alias to its own ancestor; regex per-call timeouts; tree-sitter skipped above 1 MB per file; YARA per-file timeouts; a parse failure is a finding (AG-EVADE-002), never a skip | `core/models/config.py`, `core/parsers/`, `core/archive.py`, `core/inventory.py`, `io/fs_loader.py` |
| TM-03 | Path escape | Scan-root confinement; symlinks, junctions and reparse points never followed and reported (AG-EVADE-005); archive members with `..`, absolute, drive-letter, UNC or ADS names rejected; `fix --apply` and `install` refuse to write outside their target | `core/tree.py`, `core/archive.py`, `io/fs_loader.py`, `fix/`, `install.py` |
| TM-04 | Injection aimed at a model | The adjudicator receives cited spans with minimal context, inside nonce-tagged data blocks after delimiter neutralization and secret redaction; it has no tools; its answer is a fixed schema and anything that does not validate, or cites no span it was given, is discarded. It may raise and add, lower a finding by one level at most, and never touch a deterministic block-lane finding; a dismissed finding stays in the report. The vision transcriber gets one image framed as data and returns a fixed schema. Text addressed to a scanner or reviewer is itself a finding (AG-EVADE-008). Answers are cached by content hash, model and rule-pack digest | `judge/`, `judge/vision.py`, `core/engine.py` (`_apply_adjudications`), `fixtures/judge/` |
| TM-05 | Evasion (Unicode, encodings, splitting, packing, paraphrase, media) | NFKC and confusable folding with offset maps; hidden characters decoded and reported; recursive decoding with every layer rescanned; token-assembly and decoder-stub detection; packed and gated payloads flagged (EVADE family); text recovered from images, PDFs and Office files analysed at the media file; an evasion suite of sixteen operators runs as a regression; misses are published | `core/normalize/`, `core/analyzers/`, `bench/evasion.py` |
| TM-06 | Fail-open on crash or limits | Analyzers isolated; an exception yields AG-EVADE-002 and reduces coverage; content that could not be analysed is a coverage finding that keeps the verdict from ALLOW under the strict policy (exit code 3 when full coverage is required); a scan that hits its time limit says which analyzers did not run; an internal error exits 70, never 0 | `core/engine.py`, `core/coverage.py`, `cli/app.py` |
| TM-07 | A change edits its own security configuration | In `--diff` mode, configuration, `agentguard.lock` and suppressions come from the base commit, and an inline ignore comment counts only if the base commit had it on the same line; AG-POL-010 when the configuration, the lock or the baseline change; a configuration inside a third-party target is never read; inline suppressions are honoured only in the user's own repository; suppressions need a reason and an expiry | `runner.py`, `core/policy/` |
| TM-08 | Diff-mode blind spot | Changed files are scanned in full and the rest of the repository supplies context, so a payload split into unchanged files is still linked | `acquire/diff.py`, `core/engine.py` (`_pr_filter`) |
| TM-09 | Secret leakage via reports or models | `RedactedText` is the only snippet type and always redacts (first 4 characters plus a short hash), in every output format; secrets are redacted before any model call, and the report lists exactly what was sent | `core/redact.py`, `judge/stage.py` |
| TM-10 | Output injection | Control characters rendered visibly; Rich markup escaped; Markdown escaped with @mentions and #refs neutralized; HTML escaped with a hash-based CSP and no scripts; the web scanner inserts report content as text nodes only | `core/textutil.py`, `cli/terminal.py`, `core/report/`, `site/public/js/scan-page.js` |
| TM-11 | Injection relayed to the calling agent | Agent-safe output (always on in `serve` and in the hooks): no snippets or decoded payloads, names and paths length-limited and stripped of control and invisible characters; the agent gets rule ids, fixed rule wording, file and line, verdict and fix summary, and the path of the full report | `core/report/agent_safe.py`, `serve.py`, `hooks.py` |
| TM-12 | SSRF and hostile remote servers | DNS resolved first; only globally routable addresses; IP pinned; redirects re-validated; HTTPS only; size and time caps; read-only MCP methods (no tool is ever called on a remote server); a token is sent only to the one endpoint being scanned, when the user sets it | `net/safe_http.py`, `net/remote.py`, `acquire/mcp_live.py` |
| TM-13 | Sandbox escape or credential exposure in the dynamic tier | One container with `--network none`, nothing mounted, the job and target passed over stdin; canary credentials generated per run; target code runs as an unprivileged user; a sinkhole inside the container answers every address; the tier refuses to run without its sandbox | `sandbox/`, `sandbox/guest/` |
| TM-14 | Privacy leakage | Network features and model calls are opt-in or gated; features, contacted hosts and material sent to a model listed in every report; no telemetry | `core/models/config.py`, `core/engine.py`, `judge/stage.py` |
| TM-15 | Agent Guard supply chain | Pinned dependencies; SHA-pinned GitHub Actions; Sigstore-signed releases with SBOM; rule and intelligence updates verified against pinned Ed25519 release keys, with rollback and expiry protection, and verified again each time an installed pack loads | `.github/workflows/`, `update.py`, `core/intel/`, `io/intel_store.py` |
| TM-16 | False assurance | Every scan ends in a verdict with its reasons; ALLOW is never called safe; coverage is in every report; limitations documented | `core/verdict.py`, `core/coverage.py`, `README.md` |
| TM-17 | TOCTOU between scan and install (rug pull) | `install` copies the scanned bytes, never a fresh download; `baseline create` / `verify` over file hashes, launch commands and normalized tool definitions (including output schemas); hooks re-scan agent-facing files when they change and check the lock at session start | `install.py`, `core/lock.py`, `hooks.py` |
| TM-18 | Governance records altered | The audit log is hash-chained (each entry carries the SHA-256 of the previous one); `agentguard doctor` reports a break | `audit.py`, `doctor.py` |

## Out of scope

A compromised host or Python interpreter; a compromised Docker daemon or kernel (the sandbox relies on them); attacks on the agent runtime itself; enforcing the least-privilege policy at run time (Agent Guard emits it; the agent enforces it).
