# Changelog

## 0.1.0 (unreleased)

First public version.

- Agent Guard Web server (`web/`, `agentguard-web`): paste a GitHub, npm, PyPI or MCP Registry link; it is pinned to an exact commit or version (registry digests verified), fetched through an allowlisted SSRF-hardened fetcher, scanned in a throwaway container with no network, and stored as an unlisted report with a permalink, downloads and drift against the previous scan. `docker compose up` runs it locally; CI tests the isolation against real containers.
- Web scanner (`/scan`): paste text, drop files or a .zip, or give a public GitHub repository, folder, file or gist link; scanned in the browser by the same engine under Pyodide, with zero network requests for pasted and dropped input (tested in CI). GitHub links are pinned to a commit and findings link to the exact file and line. Deployable to Vercel with `vercel.json` security headers.
- Commands: `scan`, `discover`, `lock`, `verify`, `rules` (`list`, `explain`, `export`), `report`, `bench`, `intel` (`status`, `update`), `schema`.
- Rule pack 0.1.0 with 185 rules across skills and instruction files, MCP client configuration, MCP metadata, code, toxic flows, supply chain and drift, remote auth conformance, policy, coverage, and the optional LLM judge. Every rule has an unsafe and a safe fixture.
- Outputs: terminal, JSON (schema v1), SARIF 2.1.0, Markdown, single-file HTML, CycloneDX 1.6 inventory.
- Opt-in network features: read-only remote MCP metadata, OAuth/TLS conformance, npm provenance, OSV, package age, hijackable dependencies, LLM judge (Anthropic, OpenAI-compatible, Ollama).
- GitHub Action with PR mode and SARIF upload; pre-commit hook.
- Pure-Python engine that runs under Pyodide.

### MCP 2026-07-28 rules

Built from the 2026-07-28 specification, its changelog and the official MCP Apps (2026-01-26) and Tasks (2026-07-28) extensions, read on 2026-11-03 (`docs/sources.md`).

- Tool schemas: AG-MCP-META-022 (a `$ref`, `$dynamicRef` or `$recursiveRef` that resolves to a network URI, also through an `$id` base; high for loopback, private and cloud-metadata addresses) and AG-MCP-META-023 (schemas nested over 48 levels, over 10,000 subschemas, or past 1,000,000 once local `$ref`s are followed; recursive schemas count each cycle once). A tool manifest nested past the 64-level JSON limit used to be skipped without a word; it is now reported by AG-MCP-META-023.
- AG-MCP-META-024: instructions to the model in a tool's `outputSchema` (descriptions, titles, enums, examples, defaults, consts at any depth). Hidden Unicode there is now reported by AG-MCP-META-001.
- MCP Apps: AG-MCP-META-025 (a `_meta.ui.csp` entry that allows any origin, a cleartext origin, or CSP syntax that adds directives; an omitted CSP is the spec's restrictive default and is not reported), AG-MCP-META-026 (a script from another origin without an integrity hash, noting whether its origin is declared) and AG-MCP-META-027 (a view that sends `tools/call`, `ui/message`, `ui/update-model-context` or `ui/open-link` with no user-action handler at all). UI resources delivered as a base64 `blob` are now read. AG-MCP-META-016 v2 leaves external scripts to AG-MCP-META-026.
- New area, MCP spec conformance (`AG-MCP-SPEC-*`, in server and client source): AG-MCP-SPEC-001 (task IDs from timestamps, counters or non-cryptographic randomness next to Tasks code), AG-MCP-SPEC-002 (deprecated Roots, Sampling and Logging at info; Sampling `includeContext` "thisServer"/"allServers" at low), and, in packages that use an MCP client outside their tests, AG-MCP-SPEC-003 (OAuth callback that never reads `iss`), AG-MCP-SPEC-004 (client credentials stored without the issuer, low confidence) and AG-MCP-SPEC-005 (authorization or token request without `resource`).
- Docs: an MCP spec support page lists which specification revisions and extensions each rule area covers. Six CWE entries added (CWE-340, 346, 400, 477, 522, 942).
- Benchmark: no item changed flags, maximum severity or benign hits. Four real servers (MCP `everything`, `filesystem`, `git` and playwright-mcp) now also carry AG-MCP-SPEC-002 at info for their Roots use. A first run reported AG-MCP-SPEC-005 at medium on supabase-mcp (a `grant_type` example in a generated API doc comment, in a server whose tests use an MCP client); test files and comment lines are now excluded, and a fixture keeps it that way.

### Roadmap Phase 0: trust before release

- `docs/roadmap.md`: the plan to industry grade, phase by phase. The README is rewritten (pre-release status, pinned install, a sample finding, release verification), and the competitor table moved to `docs/comparison.md`.
- Release workflow: a GitHub build-provenance attestation (`actions/attest-build-provenance`) for the wheel, sdist, SBOM and rule-pack bundle, so `gh attestation verify` works. PyPI now receives only the wheel and sdist; `twine check` rejects the other files in `dist/`, which would have failed the first release.
- Dependabot version updates for Actions, uv, npm, Docker and Compose, with a 7-day cooldown on new releases.
- `SECURITY.md` states the project's EU Cyber Resilience Act posture (non-commercial open source) and how to verify attestations. `CONTRIBUTING.md` adds the rule checklist and inert-sample rules, with a detection-bypass issue form.
- LLM judge: delimiter look-alikes (fullwidth and small brackets, confusable letters, zero-width padding, HTML entities, tags split across lines) are neutralized, file-path labels cannot leave their attribute, and the system prompt says the verdict can only add a finding. Prompt version 2, so cached verdicts are not reused. Adversarial fixtures in `fixtures/judge/` test that injected instructions stay inside their data block and that a judge obeying them leaves every deterministic finding unchanged.
- The PyPI package is `agentguard-v1`: PyPI treats `agentguard` as the existing, unrelated `agent-guard` and will not register it. The command, the import name and the GitHub Action are unchanged. The GitHub repository is now `ak2dev/agentguard` (renamed from `agentguard-v1`); links, verification identities, the SARIF `informationUri` and the HTTP user agent use the new name.
- Site: `/docs/install/` pins the commit the site was built from (`pipx install "git+https://github.com/ak2dev/agentguard@<commit>"`) instead of an unregistered PyPI name, and the home and scan pages no longer show `uvx agentguard`. HTML reports say how many of the pack's rules were applied ("140 of 174 rules applied" when this landed) instead of "140 rules evaluated".

### Site charts and diagrams

- Benchmarks page: corpus makeup, false positives on each round's held-out set, targets against actuals, and precision / recall / F1 by threshold. Rule catalog: rules by area. Coverage: a heatmap of rules per standard item with the gaps outlined. Sample report: findings by severity. How it works (now an Astro page): the scan pipeline, the lethal trifecta, a toxic-flow path and how lock / verify catches a rug pull.
- Static SVG drawn at build time from the generated data (no inline styles or scripts, so the CSP is unchanged), in a wide and a narrow drawing chosen by the card's width. Series colors and the heat ramp were checked for color-vision separation on the dark surface. `gen_site_data.py` also writes `sample.json` (the sample report's findings).

### Folded path joins and descriptions that run scripts (round 6)

- Paths built from parts are folded into one path for path rules: `path.join(os.homedir(), '.kube', 'config')` reads as `'~/.kube/config'`. Covers JS/TS `path.join`/`path.resolve`, Python `os.path.join`, `Path(...)`, `.joinpath(...)` and `Path.home() / ...`, Go `filepath.Join`, Ruby `File.join` and PowerShell `Join-Path`; only string-literal parts are joined. AG-SKL-CRED-001 v3 and the credential-access capability read the folded lines.
- AG-MCP-META-021 (new, CRITICAL): a tool, parameter, prompt or resource description, or the server's instructions, tells the agent to download and run a script (`curl | sh`, `iwr | iex`, LOLBins, download then run). Allowlisted vendor installers are reported at MEDIUM.
- AG-SKL-CRED-001 v3: its `unless` pattern ended in a literal `b` instead of `\b` and never matched; lines that name `.env.example`, `.env.sample`, `.env.template` or `.env.dist` are no longer reported.
- Benchmark round 6: `h2-cred-node-kube` and `h2-rugpull-exec` now reach CRITICAL (both moved to dev); 75 of 76 attacks reach their expected severity, all 54 CRITICAL-expected ones at CRITICAL. No benign item changed. See `docs/benchmark.md`.

### Cross-file tracing (round 5)

- AG-SKL-CRED-010 v3: credential access and network egress in two files of a skill are reported when the files are linked: one writes a file the other reads (paths normalized, including `Path.home() / ...`, `os.path.join` and `expanduser`), one script runs the other (also through `$(dirname "$0")`), or one imports the other. At most three links and one "runs" link; a SKILL.md that runs two scripts does not link them. Skills with more than 200 files are reported as `links_not_traced` instead.
- AG-CODE-001..008 (one version up each): a tool parameter passed to a helper of the same server is followed into it, up to three helpers deep. Python: same-file functions, relative, sibling and package imports, `self.` methods. JS/TS (pattern analyzer, so also in the browser): same-file functions and relative named, namespace and `require` imports. A sanitizer in the caller or the helper applies as in direct code; installed packages are never followed. The JS URL check now requires the scheme or host to be tainted, as the Python one does.
- Benchmark round 5: 16 new items (8 composition attacks, 8 look-alikes); all 8 attacks reach CRITICAL, `h2-split-cred-paste` too, and no real benign item changed. The cloudflare MCP servers moved to dev after a false positive on one of them was inspected and fixed; microsoft/skills is the remaining held-out real source. See `docs/benchmark.md`.

### Hijackable dependencies (SkillJacking)

- `scan --check-hijackable` (network, opt-in): GitHub owners, npm/PyPI package names and download/install domains referenced by skills, scripts, package manifests and MCP configs are looked up through the SSRF-hardened client (GitHub users API, npm and PyPI registries, IANA RDAP). New rules AG-SC-026 (GitHub account no longer exists), AG-SC-027 (package not registered or fully unpublished) and AG-SC-028 (domain unregistered, expired or not resolving). Offline scans and the benchmark are unchanged.
- GitHub Action input `check-hijackable` (default `false`) runs the check in CI. With `AGENTGUARD_GITHUB_TOKEN` or `GITHUB_TOKEN` set (the action passes the workflow token only when the input is on), GitHub owner lookups are authenticated, sent to `api.github.com` only, and capped at 500 per scan instead of 50; a rejected token falls back to anonymous lookups. The token is never logged; the CLI names the variable it used.
- AG-SC-028 v2 also reports freed cloud-app slots: a referenced `<app>.azurewebsites.net`, `*.trafficmanager.net`, `*.blob.core.windows.net`, `*.cloudapp.azure.com`, `<project>.pages.dev`, `*.workers.dev`, `<app>.fly.dev` or `*.elasticbeanstalk.com` hostname that no longer resolves (high, medium confidence: the app name may be free to claim). RDAP is not asked for these.

### Scanner-bypass techniques and standards refresh (2026-10-18)

- New rules for the skill-scanner bypasses Trail of Bits and the Cloud Security Alliance published in June 2026: AG-SKL-BND-006 (a `.pyc`, also in `__pycache__`, with no source or compiled from a different source than the `.py` beside it; a matching cache is not reported), AG-SKL-BND-007 (a docx/xlsx/pptx/OpenDocument/epub carries scripts or executables; only the zip directory is read) and AG-SKL-SE-012 (npm, yarn, pnpm, pip, uv, Go or RubyGems pointed at an unofficial registry). AG-SKL-SE-005 now covers `os.system`/`subprocess`/`exec` running base85/base32/hex/zlib-decoded data, including XOR-wrapped decodes. `__pycache__` is no longer skipped when loading files. No change in benchmark metrics or benign hits.
- Standards: mappings move to the OWASP Top 10 for LLM Applications 2026 (published 2026-08-03; System Prompt Leakage is now Hidden Context Exposure and the entries were re-ranked; every crosswalk id remapped one to one). CWE titles checked against CWE 4.20 (CWE-598 renamed upstream). ASI 2026, MCP Top 10 (still beta), AST 1.0 (still in public review) and the NSA MCP CSI re-checked unchanged. See `docs/sources.md`.

### Detection gaps: paraphrase, split payloads, CRITICAL calibration

- New rules: AG-SKL-SE-009 (download-and-run step written in plain words), AG-SKL-INJ-010 (instruction override in other words), AG-SKL-SE-010 (a downloaded file is executed, also from another script of the skill, linked by normalized path), AG-SKL-SE-011 and AG-MCP-CFG-025 (reverse shells), AG-MCP-CFG-024 (encoded server command).
- AG-SKL-SE-002 and AG-MCP-CFG-006 cover Windows binaries that run remote code (`mshta`, `regsvr32 /i:`, `rundll32 javascript:`, `msiexec /i <url>`); CFG-006 also reads decoded blobs. AG-SKL-CRED-001 matches whole credential directories (`tar czf ... ~/.ssh ~/.aws`). PowerShell `-EncodedCommand` (UTF-16LE base64) is decoded and rescanned.
- Benchmark: every attack records the severity it warrants; results report how many reach it and recall at CRITICAL among the attacks that warrant CRITICAL. 46 new synthetic items (32 attacks, 14 benign look-alikes); the held-out ones were scanned before the rules were written. Held-out: recall at HIGH 0.62 to 0.97, attacks at their expected severity 17 to 31 of 34, no new benign finding at any severity. Details and remaining misses: `docs/benchmark.md`.
- CI fails when `bench/results/latest.json` differs from what the current rules produce, and when a pull request makes any benchmark item worse than on the target branch.

### Real-world benchmark and false-positive tuning

- Benchmark: 163 real benign skills and MCP servers from anthropics/skills, openai/skills, modelcontextprotocol/servers, microsoft/playwright-mcp, huggingface/skills, supabase-mcp (dev) and microsoft/skills, cloudflare/mcp-server-cloudflare (held out), vendored at pinned commits with per-directory license checks (`bench/fetch_real.py`, `bench/NOTICE`). History and caveats: `docs/benchmark.md`.
- Rules can now report a match at lower severity instead of dropping it (`downgrade`: quoted mention in a reference doc, context pattern, or the skill's declared purpose). Negative fixtures can assert a ceiling (`max_severity` in `_case.yaml`).
- Environment copies handed only to a child process (`subprocess` `env=`, `spawn` `env:`) are no longer environment dumps; `AF_UNIX` and loopback sockets and same-origin `fetch("/api/...")` are no longer network egress.
- Tightened AG-SKL-EXF-004 (DNS exfiltration), AG-SKL-CRED-002, AG-SKL-INJ-003/005/007, AG-CODE-025 and AG-SKL-HID-009 (percent-encoding inside URLs). Instruction-layer rules report quoted and code-span mentions in reference docs at MEDIUM. AG-SKL-SE-007 reports quarantine removal under a package-manager prefix at MEDIUM.
- Fixed: JS/TS handler extraction treated an apostrophe in a `//` comment as a string, so a handler could swallow the rest of the file. JS path taint now honours containment checks (`validatePath(...)`), as Python taint already did.

### Standards and discovery

- NSA AISC CSI "Model Context Protocol (MCP): Security Design Considerations for AI-Driven Automation" (U/OO/6030316-26, May 2026) mapped for every rule. The CSI does not number its sections, so rules map to its own headings: 8 security concerns, 6 real-world examples, 9 recommendations. 98 rules map to at least one; skill and scanner-internal rules map to none (the CSI covers MCP only). Uncovered CSI items (inconsistent behaviors, audit logs, denial of service, unrestricted repository access, logging and detection) show as gaps on the coverage page.
- Client config paths re-checked against vendor documentation (`docs/sources.md`). Fixed: Zed's user settings are `~/.config/zed/settings.json` (macOS, Linux) and `%APPDATA%\Zed\settings.json` (Windows); discovery used Zed's data directories. Added: Claude Code managed `CLAUDE.md`, `CLAUDE.local.md`, `.claude/CLAUDE.md` and `rules/`; VS Code profile folders; Copilot `~/.copilot/mcp-config.json` and instructions; Codex `.agents/skills`, `~/.agents/skills`, `/etc/codex/skills`, `AGENTS.override.md` and `CODEX_HOME`; Cline CLI `~/.cline/mcp.json`; OpenClaw state-dir overrides. Four paths the vendors do not document stay unverified, and `agentguard discover` now says why.

### Agent Guard Web: Milestone 2 completed

- Remote MCP server URLs on the server: the dispatcher probes them read-only (discovery or initialize, the `*/list` methods, OAuth metadata; never `tools/call`, no credentials, query string dropped) through the SSRF-hardened client with a per-job request and time budget, and the recorded metadata is scanned in the sandbox. Reports are keyed by a fingerprint of the metadata, so changed tools give a new report and a drift diff. MCP Registry entries that only list a remote are probed too.
- Rescan a report's exact commit or version with the server's current rules; "scan the latest version" link.
- Maintainer responses: commit `.agentguard/response.md` naming the report to the project's GitHub repository (for npm/PyPI, the repository in the registry metadata) and ask the server to read it; shown as plain text with a link to the commit.
- README badges with factual counts at one version (`0 high · a1b2c3d`), never "safe".
- Bot protection: a self-hosted proof-of-work challenge on every request that starts work (HMAC-signed, single-use, solved in a Web Worker); `AGW_SECRET` and `AGW_POW_DIFFICULTY` are required in production.
- The report page draws each toxic flow as a diagram (source → reader → sink through the agent session).
- Terms page; privacy page covers the server; `agentguard-web dev` runs the API and dispatcher in one process for local development.

### Optional native analyzers

- `code.ts` (`agentguard-v1[code]`): tree-sitter taint for JavaScript/TypeScript tool handlers (nested destructuring, reassignment, `for … of`, handlers passed by name, `promisify` and import aliases of `child_process`, `fs` and `execa`) and for shell scripts (`$1`, `$@` and `read` into `eval`, `sh -c` and `source`). It adds findings to AG-CODE-001..008 and merges with the pattern analyzer's on the same line.
- `yara` (`agentguard-v1[yara]`): rules with `match: {type: yara}` are compiled from `rules/yara/*.yar` (includes disabled) and matched against raw file bytes. New rules AG-SKL-BND-004 (bundled binary combining credential-store paths with an exfiltration channel) and AG-SKL-BND-005 (download-and-execute command embedded in a binary).
- Without the extra, each analyzer is reported as skipped and its rules are not counted. Fixtures declare `requires:`; CI installs both extras (YARA on Python 3.12, which has wheels) and fails instead of skipping. Benchmark results with both installed are identical item by item.

### Fixes

- `agentguard lock` then `agentguard verify` inside a skill folder no longer reports the new `agentguard.lock` as drift (AG-SC-002, exit 1). The lockfile a command reads or writes is left out of the scan; any other file named `agentguard.lock` is still scanned.
- The Website workflow builds and checks the site as Vercel deploys it (`PUBLIC_FEATURE_SCAN=1`, root base path) and no longer tries to deploy to GitHub Pages, which failed on every push to `main`.
