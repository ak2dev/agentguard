# Agent Guard

**Check an agent skill, plugin, instruction file, MCP server or connector *before* your agent gets it.
You get one verdict (ALLOW, REVIEW or BLOCK), the file and line behind it, and the fix. Nothing you scan is ever executed
by a static scan.**

**[Scan now in your browser →](https://agentguard-ak2dev.vercel.app/scan/)** · [Website](https://agentguard-ak2dev.vercel.app) · [Sample report](https://agentguard-ak2dev.vercel.app/sample-report/) · [Rules](https://agentguard-ak2dev.vercel.app/rules/) · [Benchmarks](https://agentguard-ak2dev.vercel.app/benchmarks/) · [Roadmap](docs/roadmap.md)

<!-- Badges: add only the ones that are true today. Suggested: OpenSSF Scorecard, license,
     "rule pack 0.1.0", and PyPI version once it is published. Remove this comment when they exist. -->

> **Status:** the web scanner is live. The CLI, the GitHub Action, the agent hooks and the pre-commit hook work from
> source. Signed PyPI releases (package `agentguard-v1`, command `agentguard`) and a tagged Action arrive with 0.1.0.
> Other `agentguard` packages on PyPI and npm are not this project.

---

## Try it in 30 seconds (no install)

1. Open **[agentguard-ak2dev.vercel.app/scan](https://agentguard-ak2dev.vercel.app/scan/)**.
2. Give it something to check:
   - **Paste** a `SKILL.md` or an MCP config, or **drop** a folder or `.zip`. These are scanned on your device and never uploaded.
   - Or paste a **link**: a GitHub repo, folder, file or gist; `npm:@scope/server@1.2.0`; `pypi:name==1.0`; an MCP
     Registry name; or a remote server `https://…/mcp`. Links are pinned to an exact version and scanned in a sandbox
     with no network.
3. Read the verdict and its reasons, then the findings: each gives the file and line, the evidence, why it matters, and
   how to fix it.

The engine runs in your browser (Pyodide). The first scan downloads about 15 MB, and later scans reuse it.

Here is what a report looks like (abridged). It is a real scan of an inert malicious skill from the benchmark: a
"configuration helper" whose script posts your environment variables to a request-capture service.

```text
$ agentguard scan bench/corpus/malicious/envdump-python --profile quick
Agent Guard 0.2.0.dev0 · rule pack 0.1.0 · profile quick · policy balanced · 1 component · 2 files

Blocks: these decide the BLOCK verdict (5)

CRITICAL  AG-EXF-001  Secret or credential source flows to a network sink  confidence: high
  env-inspector/scripts/inspect.py:3:10 → 3:36  skill:env-inspector
  Risk   'env-inspector/scripts/inspect.py' both accesses credentials and sends data over the network.
  Trace  env-inspector/scripts/inspect.py:3 → env-inspector/scripts/inspect.py:4
  Fix    Remove the credential access or the network call. A skill that needs an API token should receive a
         scoped token from the user, not read local stores.
HIGH      AG-EXF-006  Known exfiltration sink  confidence: high
  env-inspector/scripts/inspect.py:4:24 → 4:36  skill:env-inspector
HIGH      AG-META-004  Description does not match what the code and instructions do  confidence: medium
  …

Attack chains
  chain-1 critical ends in network: AG-EXF-002 → AG-META-004 → AG-EXF-006 → AG-EXF-001

 BLOCK   score 100  ·  tier L2  ·  coverage 2/2 files (100%)  ·  6 finding(s)
```

ALLOW means nothing that counts towards the verdict matched. It never means safe.

## On your machine or in CI

```bash
# Until 0.1.0 is on PyPI: install from a pinned commit, not a moving branch
pipx install "git+https://github.com/ak2dev/agentguard@<commit-sha>"

agentguard scan ./skills/my-skill                  # a skill, a repository or an MCP config file
agentguard scan https://github.com/acme/tools@v1.2 # a GitHub repository at a ref, or a pull request
agentguard scan --machine                          # everything this machine's agents can use
agentguard scan . -f html -o report.html           # the same report as one offline file
agentguard doctor                                  # what each profile can use here
```

Exit codes: `0` ALLOW (or below `--fail-on`, default `block`), `1` REVIEW, `2` BLOCK, `3` content could not be analysed
and the policy requires full coverage, `64` usage error, `70` internal error. An analyzer that fails is **never** a
silent pass.

---

## What it scans

| Surface | Examples |
|---|---|
| **Skills** | `SKILL.md` with every file in the folder: scripts, references, assets, media and binaries |
| **Plugins and extensions** | Claude Code, Codex, Cursor, Gemini CLI and OpenClaw plugins: manifests, marketplaces, hooks, commands, agents, bundled servers, executables, shipped settings |
| **Instruction files** | `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, Cursor rules, Copilot instructions, OpenClaw workspace files, memory files, and everything they import |
| **Agent settings and hooks** | Permission rules, hook definitions, command-valued keys, environment overrides, sandbox and trust settings |
| **MCP servers** | Configuration, source code, registry entries, MCPB bundles, container images, and the running server (opt-in, read-only) |
| **Connectors** | Remote MCP endpoints (transport, authorization, tool surface, drift), OpenAPI actions, A2A agent cards |
| **Agentic CI and workspaces** | Workflows that run coding agents; editor tasks, dev containers, environment files |
| **Whole repositories and packages** | Any depth, at a pinned commit, with submodules and history; npm, PyPI and OCI packages; archives |

Tier 1 and 2 agents (Claude Code, the Agent Skills specification, MCP, Codex, Cursor, Gemini CLI, GitHub Copilot and
VS Code, OpenClaw) were checked against vendor documentation; other agents' files are parsed generically.

## What it finds

450 rules in 23 families, all implemented, each with unsafe and safe test fixtures (1,697 fixture cases):

| Families | Examples |
|---|---|
| Injection, manipulation (INJ, MANIP) | Override directives, forged delimiters, concealment, ClickFix lures, injection in eleven other languages and in encoded forms |
| Hidden content, media (OBF, MM) | Unicode tags, bidi and zero-width tricks, homoglyphs, encoded blobs (decoded and rescanned), text in images, hidden PDF text, Office macros, notebook outputs |
| Exfiltration, credentials, execution (EXF, CRED, EXEC) | Credential theft and egress, known exfiltration sinks, download-and-run, reverse shells, LOLBins, run-time installs |
| Persistence, impact, privilege (PERSIST, IMPACT, PRIV) | Writes to memory and instruction files, destructive and financial actions, wildcard tool grants, approval bypass |
| Settings, plugins, MCP (CFG, PLUG, MCP) | Pre-approved servers, approving hooks, `bin/` on `PATH`, marketplace command sources, tool poisoning and shadowing, rug pulls |
| Implementation, supply chain (VULN, SUPPLY, META) | Taint from tool parameters into shells, SQL and paths; unpinned and known-bad dependencies; typosquats; descriptions that misstate behaviour |
| Flows, CI, workspaces, images, connectors (FLOW, CI, WS, IMG, CONN) | Toxic flows and composition with installed skills, prompt-injectable workflows, auto-executing editor tasks, unpinned images, unauthenticated endpoints |
| Evasion, hygiene (EVADE, HYG) | Packing, size padding, gated triggers, content that could not be analysed, scanner-addressed text |

Rules map to the OWASP Agentic Skills Top 10, OWASP MCP Top 10, OWASP Top 10 for Agentic Applications, OWASP LLM Top 10,
the NSA MCP guidance (May 2026), CWE, and the SkillTrustBench and MalSkillBench categories. See the
[rule catalog](https://agentguard-ak2dev.vercel.app/rules/) and the [coverage matrix](https://agentguard-ak2dev.vercel.app/coverage/), which also lists the gaps.

## Guarantees

| Guarantee | What it means in practice |
|---|---|
| **A static scan never executes what it scans** | No `npx`, `uvx`, `pip install`, STDIO servers or bundled scripts, and git is read by a pure-Python reader. A process-wide audit hook blocks process creation; the one exception is Docker for the `deep` profile's sandbox, with an exact, pre-authorized command line. CI asserts no process starts across the fixture corpus. |
| **Offline by default** | No account, no telemetry. Every network feature is an opt-in flag, and every report lists the ones used. A model is called only in the `standard` profile when one is configured, with secrets redacted and the material sent listed in the report. |
| **Never says "safe"** | ALLOW means nothing that counts matched. Coverage is in every report, and content that could not be analysed is itself a finding. |
| **Deterministic** | Same input, engine and rule pack: byte-identical static report. |
| **Same answer everywhere** | CLI, GitHub Action, agent hooks, browser and web server run one engine and emit one report schema (`schemas/report.v1.json`). |

---

## Use it

```bash
agentguard scan . -v                          # evidence, decoded content and standards for each finding
agentguard scan . -f sarif -o ag.sarif        # also json, md, html, junit, cyclonedx
agentguard report -i ag.json -f html          # re-render a saved report, no rescan
agentguard fix . --apply                      # safe fixes, each kept only after a clean re-scan
agentguard fix . --emit-policy policy.json    # the least-privilege grant, permissions and sandbox per component
agentguard install https://github.com/acme/skills/tree/main/pdf --agent claude-code   # scan, receipt, then install
agentguard baseline create --approved-by you@example.org   # pin skills and tool definitions in agentguard.lock
agentguard baseline verify                    # catch rug pulls and drift between scans
agentguard inventory -f cyclonedx             # an AI-BOM of every agent component on this machine
agentguard mcp inspect mcp+https://mcp.example.org/mcp   # list a server's tools without calling them
agentguard detonate ./suspicious-skill        # dynamic analysis in the Docker sandbox
agentguard serve --mcp                        # let agents ask before they install (agent-safe output)
agentguard explain AG-EXEC-001                # what a rule detects, why, and how to fix it
agentguard update --from bundle.zip           # signed rule and intelligence updates, also offline
agentguard bench corpus                       # rerun the accuracy benchmark yourself
```

Profiles: `quick` (deterministic static analysis; sends nothing anywhere), `standard` (the default: adds the local
triage model, and a gated, bounded model adjudicator when a model is configured), `deep` (adds detonation in a
sandbox and live MCP inspection; needs Docker). Full command reference: [CLI docs](https://agentguard-ak2dev.vercel.app/docs/cli/).

Optional extras (without one, its analyzer is reported as **skipped**):

| Extra | Adds |
|---|---|
| `agentguard-v1[code]` | tree-sitter taint for JS/TS handlers and shell scripts |
| `agentguard-v1[yara]` | YARA over bundled binaries (wheels up to Python 3.13) |
| `agentguard-v1[ocr]` | Text in images and rendered PDF pages, and QR codes, read locally (RapidOCR on ONNX Runtime, pypdfium2, zxing-cpp) |
| `agentguard-v1[media]` | Low-contrast text detection in images (Pillow) |
| `agentguard-v1[judge]` | The Anthropic provider for the model adjudicator. An OpenAI-compatible endpoint or a local Ollama model works without an extra. Scanned text reaches a model only as delimited data, and a model may raise but never clear a deterministic block-lane finding |

Requires Python 3.12+.

### In CI and in your agent

```yaml
- uses: actions/checkout@<sha>
  with: { fetch-depth: 0, persist-credentials: false }
- uses: ak2dev/agentguard@<release-sha>
  with: { targets: ., policy: balanced, fail-on: block }
```

On pull requests the Action scans with `--diff base..head`: changed files in full, the rest as context, configuration
from the base commit, and only new findings fail. It annotates the changed lines, uploads SARIF to code scanning and
sets `verdict` and `score` outputs. A pre-commit hook is included (`.pre-commit-hooks.yaml`), and `integrations/` holds
hooks for Claude Code (a plugin), Cursor, Codex and Gemini CLI that scan an install before it runs and re-scan
agent-facing files when they change.

### In the browser

[/scan](https://agentguard-ak2dev.vercel.app/scan/) runs the same engine and rule pack as the CLI, in the `quick`
profile. A CI test asserts that pasted or dropped input causes zero network requests. Link scans go to the Agent Guard
web server; when it is unavailable, GitHub links are fetched and scanned in your browser instead. Details:
[web scanner docs](https://agentguard-ak2dev.vercel.app/docs/web-scanner/).

---

## How accurate is it?

`agentguard bench` runs four suites on `bench/`: the **corpus** (123 synthetic items, 76 of them attacks, and 163 real
benign skills and MCP servers from eight vendor repositories at pinned commits), the **evasion** suite (every attack
rewritten with sixteen published obfuscation and packing operators), the **incident** corpus (23 defanged reproductions
of published incidents, checked at their exact file and line), and runners for MalSkillBench and SkillTrustBench over a
local copy you download (never redistributed).

| Measure (quick profile; `bench/results/latest.json`) | Result | Target (CI fails below it) |
|---|---|---|
| Attacks caught (REVIEW or BLOCK) | 76 of 76; 70 of them blocked | ≥ 95% |
| Benign items flagged (REVIEW or BLOCK) | 1 of 210 (0.5%) | ≤ 2% |
| Precision at CRITICAL | 1.00 | ≥ 0.95 |
| Evasion rewrites at REVIEW or above / at their original verdict | 187 of 187 / 99.5% | 100% / ≥ 90% |
| Incidents caught at the right file and line | 23 of 23 | all |
| 100 skills + 20 server configs | 6.0 s | < 10 s |
| *Tuning diagnostics:* precision at HIGH; benign items with any HIGH finding (all / held-out) | 0.90; 3.8% / 1.3% | — |
| *Tuning diagnostics:* attacks at their expected severity; CRITICAL-worthy attacks at CRITICAL | 60 of 76; 39 of 54 | — |

The targets are the project plan's, stated in verdicts: a 2% false-positive budget (the plan's 80 in 4,000 for the
quick profile) and the recall it asks of the standard profile. The diagnostic rows count every finding, including
evidence-lane ones that do not count towards the verdict, so they read higher than the verdict rows. The CI gate also
fails when any item's verdict moves the wrong way. **Read these numbers with care.** The attack set is synthetic and was written by the
rule authors, and more than half of the real benign items were used for tuning. Expect more findings on skills unlike
the corpus, and treat MEDIUM as review material. Every tuning round, its held-out result and the items still missed are
on the [benchmarks page](https://agentguard-ak2dev.vercel.app/benchmarks/) and in [docs/benchmark.md](docs/benchmark.md).

## Limitations

The full list is on the [limitations page](https://agentguard-ak2dev.vercel.app/docs/limitations/). The ones most likely to matter to you:

- **Static analysis has a horizon.** Code fetched at run time and payloads behind a trigger are reached only by the
  `deep` profile's sandbox, which does not yet drive a real agent inside the container.
- **Patterns can be evaded.** Plain-language paraphrase without tell-tale phrasing is reached only by the model
  adjudicator, when one is configured. Agent Guard is open source and runs offline, so an attacker can test payloads
  against it repeatedly. Use it alongside an allowlist of approved sources, pinning, and least-privilege client settings.
- **Text in raster images** needs the `[ocr]` extra or a model; without either, the report says how many images were not read.
- **The triage model is small** (trained on the internal corpus) and advisory: it never decides a verdict alone.
- **Not built yet:** agent adapters and eBPF tracing in the sandbox, multilingual sentence embeddings, MITRE ATLAS
  mappings, and Sigstore verification of provenance, images and updates (updates use pinned Ed25519 keys).

## How it works

**Acquire** (pinned identifier, quarantine, nothing executed) → **discover** (every file classified, every byte
accounted for) → **normalize** (Unicode folding, recursive decoding, hidden Markdown, span-preserving parsers) →
**analyze** (text integrity, instructions, code and taint, manifests and config, supply chain, threat intelligence,
media and documents, container images, flow and composition, least privilege; plus the triage model and adjudicator in
`standard`, detonation and live inspection in `deep`) → **correlate** (chains, lanes and corroboration) → **decide**
(verdict, score, risk tier, policy) → **report and fix**.

```text
                Engine (agentguard.core): pure, no filesystem/network/clock
                rule pack · analyzers · correlation · verdict · renderers
                                       │
     ┌──────────────────┬──────────────┼─────────────────┬─────────────────────┐
 CLI + Action      agent hooks    Browser /scan      Web server (web/)   sandbox (deep)
 fix · install     pre-install    input stays        pinned fetch →      Docker, no network,
 baseline · serve  re-scan        on device          no-network container canary credentials
```

Repository layout: the rule catalogue and detection entries in `rules/`, fixtures in `fixtures/rules/` (generated from
`scripts/fixtures_catalog/`), standards in `mappings/`, benchmark in `bench/`, signed indicator feed in `intel/`, agent
hooks in `integrations/`, website in `site/`, web server in `web/`. Details:
[How it works](https://agentguard-ak2dev.vercel.app/docs/how-it-works/) · [threat model](docs/threat-model.md) ·
[v1 design](docs/design/v1-design.md) · [sources](docs/sources.md).

## How it compares

Other scanners make different trade-offs: some start STDIO servers to list their tools, some upload content to a
vendor API, some cover only skills or only MCP. A dated, sourced comparison is in [docs/comparison.md](docs/comparison.md).

## Trusting Agent Guard itself

A security scanner is a supply-chain target too. From 0.1.0:

- Releases are built in GitHub Actions and Sigstore-signed (keyless). Each one ships a CycloneDX SBOM, `SHA256SUMS`
  and a separately signed rule-pack bundle. Verify before you install:

  ```bash
  python -m sigstore verify identity \
    --cert-identity "https://github.com/ak2dev/agentguard/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
    --cert-oidc-issuer "https://token.actions.githubusercontent.com" \
    agentguard_v1-X.Y.Z-py3-none-any.whl
  ```
- Pin the Action and the CLI by commit SHA or exact version, never a moving tag.
- Rule and intelligence updates (`agentguard update`) and the indicator feed are Ed25519-signed with pinned release keys;
  unsigned bundles and rollbacks are refused.
- Installs, approvals, applied fixes and updates are written to a hash-chained audit log that `agentguard doctor` checks.
- Verification commands are on the [security page](https://agentguard-ak2dev.vercel.app/security/). Report
  vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## Contributing

New rules need unsafe and safe fixtures (defined as data in `scripts/fixtures_catalog/` and written with
`python scripts/bootstrap_fixtures_catalog.py`), a standards mapping, and a benchmark run that makes no item worse.
The most valuable contribution is a **detection bypass**: open an ordinary issue with an inert reproduction (reserved
domains such as `example.invalid`, no working payload). Vulnerabilities in Agent Guard itself go through a private
advisory, as described in [SECURITY.md](SECURITY.md).

## License

Apache-2.0.
