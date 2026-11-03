# Agent Guard: what "industry grade" means as of November 2026, and the plan to get there

*Written 2026-11-03. Spec versions, standards and incidents below were checked through web searches that day.
Most of those sources are secondary, and the ones I could not confirm against a primary source are marked (unverified).*

---

## 1. What changed in 2026

| Change | Why it matters for a scanner |
|---|---|
| **MCP spec 2026-07-28** is the current release. The core protocol is stateless (no `initialize` handshake, no `Mcp-Session-Id`). Tool `inputSchema`/`outputSchema` use full JSON Schema 2020-12. Tasks moved to an extension. MCP Apps (server-supplied HTML in sandboxed iframes) shipped. Roots, Sampling and Logging are deprecated. Auth: RFC 9207 `iss` checking, required `resource` parameter, OIDC `application_type` in DCR, and credentials bound to the issuer. | Rules and fixtures written against 2025-06-18 / 2025-11-25 miss the new surface: remote `$ref` in schemas (SSRF, fetch-on-validate), schema depth bombs, MCP Apps UI resources, and session checks that moved into the application layer. |
| **OWASP Agentic Skills Top 10 v1.0** was published 2026-08-17. | The AST mapping must target v1.0 IDs. It defines no severity scores yet (it waits for AIVSS v1). |
| **Agent Skills was donated to the Agentic AI Foundation** (AAIF, Linux Foundation) on 2026-10-22, alongside MCP. A2A joined AAIF too (reported as 2026-08-17). | Skills, MCP and A2A are now governed together, and buyers will expect one tool to cover all three. |
| **A2A v1.x has signed Agent Cards.** | Connectors are no longer only MCP. Agent Cards declare skills, endpoints and auth schemes, and a signature proves the card is intact, not that the agent behind it is trustworthy. |
| **The NSA CSI on MCP** (2026-05-20) and the **CoSAI MCP Security** taxonomy (2026-01-27, about 40 threats in 12 categories). | Enterprise buyers ask for mappings to both, alongside OWASP and CWE. |
| **Scanner bypasses are now public.** Trail of Bits (2026-06-03) bypassed ClawHub, Cisco's skill-scanner and all three skills.sh scanners. The CSA research note (2026-06-10) found the same. A PoC (nedlir/skills-scanner-bypass, 2026-08) claims evasion of LLM-based analysis too (unverified). | Static matching alone no longer meets the bar. Attackers can retry against an offline scanner as often as they like. |
| **Plugins and marketplaces are a large attack surface.** Claude Code plugin hooks run shell commands. Marketplace impersonation was demonstrated. Auto-update has been abused, for example the reported "Plugin4Shell" and CVE-2026-86063, a hash-pin bypass fixed in Claude Code 2.1.179 (unverified). | "Skill" is now too narrow. Plugins bundle skills, hooks, MCP servers, subagents and commands. |
| **Incidents hit AI tooling's own supply chain.** LiteLLM's malicious PyPI release (2026-10-21), Langflow treating MCP server settings as shell commands, an MCP TypeScript SDK OAuth credential leak to malicious servers, and reports of MCP servers that turn hostile after N calls (unverified). | IOC feeds, retro-hunting and drift detection are now baseline features. Single-scan tools miss delayed-trigger behaviour. |
| **EU Cyber Resilience Act:** reporting of actively exploited vulnerabilities applies from 2026-09-11. Full application is 2027-12-11. | If Agent Guard is offered commercially, it has CRA manufacturer duties, and customers will ask for its SBOM, CVD process and support period. |

---

## 2. The industry-grade bar

These are the capabilities a security team would expect before standardising on a scanner for agent skills, MCP and
connectors, grouped into ten areas. ✅ means the README already shows it, 🟡 means partly, ❌ means missing.

### A. Coverage of everything an agent loads
| Expectation | Agent Guard today |
|---|---|
| Skills (`SKILL.md` + scripts + assets + archives) | ✅ |
| Instruction and memory files across clients | ✅ |
| MCP client configs across major clients, with verified paths | ✅ (4 paths unverified) |
| MCP server source, packages and containers | 🟡 source and manifests, but container images are not unpacked |
| **Plugins and marketplaces** (Claude Code, Cursor, Codex, VS Code): hooks, bundled MCP, subagents, slash commands, marketplace sources, auto-update | 🟡 skill hooks only |
| **Connectors beyond MCP**: A2A Agent Cards, remote MCP "connectors" in chat apps, OpenAPI actions | ❌ |
| Subagent / agent definitions (tools, permissions, model routing) | ❌ |
| Client permission settings (allow/deny lists, auto-approve, sandbox flags) as part of the toxic-flow graph | 🟡 auto-approval only |

### B. Spec currency
| Expectation | Today |
|---|---|
| MCP 2026-07-28 (stateless core, JSON Schema 2020-12, MCP Apps, Tasks extension, auth changes) | 🟡 Apps UI risks and auth RFCs are covered, the rest is not stated |
| Published support matrix by spec version, with a 30-day SLA after each spec release | ❌ |

### C. Detection depth (defence in depth, not a single technique)
| Layer | Today |
|---|---|
| Deterministic static rules + Unicode/hidden-content + decoding | ✅ strong |
| Cross-file, **value-level** dataflow (not just file links) | 🟡 file-level links only |
| Semantic/LLM analysis that is **itself hardened against injection** | 🟡 judge exists, but its hardening is not documented |
| Sandboxed dynamic analysis with honeytokens, multiple calls and time/env triggers | ❌ planned |
| Runtime enforcement (lock checked on every connection, tool-response inspection) | ❌ planned |

### D. Robustness against evasion
| Expectation | Today |
|---|---|
| Independent malicious corpus (external authors, real incidents with payloads made inert) | ❌ the top weakness |
| Automated mutation testing (paraphrase, split, encode, re-order) that reports a robustness score per rule | ❌ |
| Public bypass programme with credit, and a time-to-rule SLA | ❌ |

### E. Accuracy you can audit
| Expectation | Today |
|---|---|
| Per-category precision, recall and FPR, with held-out results | ✅ excellent, ahead of most vendors |
| Results on a **third-party** benchmark | ❌ |
| MEDIUM noise low enough to be actionable (FPR < 0.05 on real code) | ❌ 0.15 |

### F. Lifecycle coverage
| Stage | Today |
|---|---|
| Pre-install (CLI, browser) | ✅ |
| PR / CI gate with SARIF | ✅ |
| Drift / rug pull between scans | ✅ `lock` / `verify` |
| Registry / marketplace gate (scan on publish, badges) | 🟡 web server, not yet hosted |
| Continuous monitoring and retro-hunting ("which repos and machines have skill X?") | ❌ |
| In-agent: pre-install hook, and an MCP tool the agent can call before it installs anything | ❌ |

### G. Enterprise operation
| Expectation | Today |
|---|---|
| Fleet inventory (MDM/osquery collection, central merge) | ❌ (single machine) |
| Policy as code, exceptions with owner + expiry + justification | 🟡 suppressions/baselines exist, Rego/CEL planned |
| Export allowlists to client managed settings (e.g. Claude Code managed marketplace/hook settings) | ❌ |
| SIEM-ready output (OCSF), AI-BOM (CycloneDX 1.6+), VEX | 🟡 CycloneDX 1.6 inventory only |
| Air-gapped operation with signed, offline rule updates | ✅ offline, Ed25519-signed IOC feed with rollback protection, Sigstore-signed rule-pack bundle |

### H. The scanner's own security
| Expectation | Today |
|---|---|
| Never executes scanned content | ✅ best in class |
| Signed releases, SLSA L3 provenance, SBOM, reproducible builds | 🟡 `release.yml` signs the wheel, sdist, SBOM, `SHA256SUMS` and rule-pack tarball with Sigstore, and publishes through PyPI trusted publishing. Missing: a GitHub build-provenance attestation (`actions/attest-build-provenance`), and nothing is released yet |
| LLM judge treats scanned text as data, uses structured output, can only *raise* severity, never lower it | 🟡 scanned text is wrapped in nonce-tagged `<untrusted_data>` blocks with delimiter neutralising (`judge/prompt.py`), and the judge is capped below CRITICAL. "Never lowers" is not stated, and there are no adversarial judge fixtures |
| OpenSSF Scorecard ≥ 8, pinned dependencies, 2FA, protected branches | ❓ not stated |

### I. Standards and evidence
| Expectation | Today |
|---|---|
| OWASP ASI 2026, MCP Top 10, **AST10 v1.0**, LLM Top 10, NSA CSI, CWE | ✅ (confirm AST IDs are v1.0) |
| **CoSAI MCP taxonomy**, **MITRE ATLAS** techniques | ❌ |
| Control evidence for audits (NIST AI RMF, ISO/IEC 42001, SOC 2 change-management) | ❌ |

### J. Product maturity
| Expectation | Today |
|---|---|
| A published, installable release | ❌ |
| Rule-pack SemVer, deprecation policy, changelog per rule | 🟡 |
| SECURITY.md with CVD, supported-versions table, CRA posture statement | 🟡 CVD (3-day acknowledgement, 90-day fix) and supported versions exist. No CRA posture statement and no CONTRIBUTING.md |
| A README that matches reality (see §3) | 🟡 |

---

## 3. Problems in the current README (fixed in the new [README.md](../README.md))

1. **It tells people to run an unpinned package.** `uvx agentguard scan` is exactly the pattern Agent Guard flags as
   HIGH in MCP configs (unpinned `uvx`). The new README installs from a pinned commit and shows how to verify releases.
2. **It contradicts itself on release status.** Install says `pipx install agentguard`, while "Next mile" says 0.1.0
   is not on PyPI yet. The new README says pre-release at the top.
3. **Register the PyPI name now. This is urgent.** On 2026-11-03, `https://pypi.org/pypi/agentguard/json` returned
   404, so the name is unregistered. Yet the website's install page (`/docs/install/`) tells visitors to run
   `uvx agentguard` and `pipx install agentguard`. Anyone who registers that name first gets code execution on every
   machine that follows your docs. That is the SkillJacking pattern your own `--check-hijackable` detects. Your
   `release.yml` already uses PyPI trusted publishing, so the clean fix is to add a **pending publisher** on pypi.org now.
   *Update, same day:* `agentguard` itself cannot be registered by anyone. PyPI ignores `-`, `_` and `.` and folds
   look-alike characters when comparing names, so it counts as the existing, unrelated `agent-guard`, and 67 projects
   already start with `agentguard`. The package is therefore published as **`agentguard-v1`** (the command and import
   stay `agentguard`): pending publisher for project `agentguard-v1`, owner `ak2dev`, repo `agentguard` (the GitHub
   repo was renamed from `agentguard-v1` that day), workflow `release.yml`, environment `release`.
   A pending publisher does **not** reserve the name on its own: PyPI creates the project only on the first upload,
   and if someone else registers the name first the pending publisher is invalidated
   ([PyPI docs](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/)). So publish through it
   soon after adding it. Until then, change the install page to a pinned `git+https` install.
4. **The competitor table belongs in docs.** It will go stale, it invites disputes, and it buries the quickstart.
   It moves to `docs/comparison.md` with dates and sources.
5. **There is no example output.** People decide in 30 seconds. The new README shows a finding and an exit code up front.
6. **Limitations are honest but too long for a README.** The new README keeps the four that change decisions and
   links the rest.
7. **It says nothing about trusting Agent Guard itself.** The new README adds release verification and pinning.

The README's website links were checked against the live site on 2026-11-03 (`/scan/`, `/rules/`, `/coverage/`,
`/benchmarks/`, `/security/`, `/sample-report/`, `/docs/limitations/`, `/docs/how-it-works/`, `/docs/web-scanner/`),
and its sample output comes from the real sample report. Its repo links were checked against `main` at `00bea16`
(`docs/benchmark.md`, `docs/threat-model.md`, `docs/design/v1-design.md`, `docs/sources.md`, `SECURITY.md`).
[`docs/comparison.md`](comparison.md) is new: it holds the old competitor table.
Its benchmark numbers come from `bench/results/latest.json` (2026-11-03, round 6).

Rule count: the repo, the README and `/scan/` all say 174. The sample report says "140 rules evaluated", which is
probably only the rules that apply to a skill. Label it that way ("140 of 174 rules applied") so readers don't see a
mismatch.

---

## 4. The plan

Ordering principle: **trust first, then currency, then robustness, then reach.** A scanner that is not released,
not current with the July MCP spec and only tested against its author's own attacks will not be adopted, however
many features it has.

### Phase 0: Ship and be trustworthy (now → end of November 2026)
| Work | Done when |
|---|---|
| Publish 0.1.0 to PyPI and tag the Action: Sigstore-signed, SLSA L3 provenance, CycloneDX SBOM, reproducible wheel | `gh attestation verify` passes on a clean machine, and two independent builds are byte-identical |
| **Today:** reserve `agentguard-v1` on PyPI (`agentguard` is blocked as too similar to `agent-guard`), then npm | Names owned, and `/docs/install/` never points at a name you don't control |
| Add `actions/attest-build-provenance` to `release.yml` next to the Sigstore step, so `gh attestation verify` also works | Attestation visible on the first release |
| SECURITY.md: add a CRA posture (non-commercial OSS vs. steward vs. manufacturer). Add CONTRIBUTING.md (rule checklist, inert-bypass issue template) | Published |
| OpenSSF Scorecard ≥ 8, all Actions SHA-pinned, Dependabot/Renovate on | Badge shows ≥ 8 |
| LLM judge: the nonce-delimited prompt already exists. Add JSON-schema output, a stated and tested rule that it can raise but **never lower** severity, and adversarial fixtures (scanned text that tries to instruct the judge) | Adversarial judge fixtures pass, documented in the threat model |
| README and docs swap (this PR) | Every README link resolves |

### Phase 1: Current with November 2026 (December 2026 → January 2027)
| Work | Done when |
|---|---|
| **MCP 2026-07-28 rules:** remote/`http` `$ref` in tool schemas, schema depth/size bombs, `outputSchema` abuse, MCP Apps UI resources (CSP, external scripts, `postMessage` actions bypassing consent), Tasks extension misuse, reliance on deprecated Roots/Sampling/Logging, missing `iss` validation and issuer-bound credentials in client code, missing `resource` parameter | Each has unsafe + safe fixtures. A spec-version support matrix is published |
| **Plugins and marketplaces** (Claude Code, Cursor, Codex, VS Code): parse plugin manifests; flag hooks (`PreToolUse`/`SessionStart` etc.) running network or shell, marketplace sources not on an allowlist, impersonated publisher names, auto-update without pinning, bundled MCP servers and subagents | Plugin is a first-class component in `discover`, `lock` and toxic flows |
| **Connectors:** A2A Agent Card parser (verify the signature when present, flag unsigned cards, broad skills, plain-HTTP endpoints and weak auth schemes), remote MCP connector configs with OAuth scopes, OpenAPI action specs | Cards and connectors show up in the capability graph |
| **Subagent definitions and client permission settings** feed the toxic-flow graph (allowed tools, auto-approve, sandbox off) | Toxic-flow paths cite the permission that enables them |
| Standards: switch to **AST10 v1.0** IDs, add **CoSAI MCP** taxonomy and **MITRE ATLAS** mappings | Coverage matrix updated, gaps listed |
| Container images: unpack OCI layers statically (no `docker run`) and scan entrypoints and bundled code | Scans `ghcr.io/...` images referenced in configs |
| Policy: **SLA of 30 days** from any MCP / Skills / A2A spec release to a rule-pack update | Written in docs |

### Phase 2: Robust against evasion (January → March 2027)
| Work | Done when |
|---|---|
| **Independent corpus:** recruit 3+ external red teamers, add public bypass PoCs (Trail of Bits, CSA, nedlir) and inert copies of real incidents (ClawHub malicious skills, LiteLLM-style loaders), keep 30% permanently held out | ≥ 150 attacks not written by the rule author. Held-out results published |
| **Mutation harness:** an automatic generator for paraphrase, synonym swap, split-across-files, encoding chains, whitespace/homoglyph and order shuffling. Report a per-rule robustness score | CI fails if robustness drops. Scores published per rule |
| **Value-level cross-file dataflow** (a relay file's *content* to a sink, not only the file link), paths joined from non-literal values (round 6 handles literal parts only), byte transforms, and JS default exports, re-exports and class methods | Those gaps are removed from Limitations |
| Fix the last attack below its expected severity (`rugpull-new-tool`) and bring held-out HIGH FPR (0.025) under the 0.02 target | Both met in `bench/results/latest.json` |
| Cut MEDIUM noise: FPR on real code from 0.15 to < 0.05 (confidence calibration, context-aware suppressions) | Measured on fresh vendor repos *before* tuning |
| **Bypass programme:** a public hall of fame and a 14-day time-to-rule target for valid bypasses | First external bypass fixed within SLA |
| Submit to any third-party benchmark that exists by then, or co-publish one with CoSAI or OWASP AST | Result published, good or bad |

### Phase 3: Behavioural analysis, opt-in (March → May 2027)
| Work | Done when |
|---|---|
| Sandbox runner on gVisor or Firecracker, **never on the user's machine by default**. No real credentials, honeytoken files (`~/.ssh`, `.env`, cloud creds), sinkholed DNS/HTTP, syscall/file/network recording | Runs in the web server and in a self-hosted Action, off by default |
| Multi-call and trigger exploration: call each tool N times with varied inputs, advance a fake clock, vary environment variables, and diff tool metadata between calls (catches rug pulls and "hostile on call 3") | Delayed-trigger fixtures detected |
| Dynamic findings are evidence attached to static findings, with their own severity ceiling and determinism caveat | Report schema v1.1 with `evidence.dynamic` |

### Phase 4: Runtime and in-agent (May → July 2027)
| Work | Done when |
|---|---|
| **Don't build a full gateway.** Publish the `agentguard.lock` format as an open spec and ship adapters for existing gateways and proxies (Docker MCP Gateway and others) that enforce it on every connection | Two gateway adapters merged upstream or published |
| Client hooks: a pre-install hook that scans a skill or plugin before it is enabled (where the client supports hooks), plus `agentguard mcp`, a read-only MCP server exposing `scan_path` so the agent can check before installing | Install of a fixture malicious skill is blocked in one supported client |
| Tool-*response* inspection rules (prompt injection in results), for use by gateways | Rule set + fixtures |

### Phase 5: Fleet and enterprise (from July 2027)
| Work | Done when |
|---|---|
| Fleet collection: `agentguard discover --json` via MDM/osquery, a central merge, and retro-hunting with the IOC feed ("which machines have plugin X@1.2?") | Demo across 100 simulated hosts |
| Policy as code (Rego, CEL): exceptions with owner, expiry, justification. Expired exceptions fail the scan | Policy docs + examples |
| Export **allowlists to client managed settings** (approved marketplaces, MCP servers, hooks) from the lockfile | Generates valid managed config for at least two clients |
| OCSF output for SIEMs, CycloneDX 1.7 AI-BOM, OpenVEX for suppressed findings | Formats validated against official schemas |
| AIVSS v1.0 once published, NIST AI RMF / ISO 42001 control evidence pack | Mapping docs |

---

## 5. Metrics to publish every release

| Metric | Now | Target by mid-2027 |
|---|---|---|
| CRITICAL precision (independent corpus) | 1.00 (author corpus) | ≥ 0.95 on the **independent** corpus |
| HIGH recall (independent corpus) | 0.99 (author corpus, round 6) | ≥ 0.85 independent. Expect this to drop at first, and publish it anyway |
| Benign FPR at HIGH | 0.019 overall, 0.025 held-out | ≤ 0.02 on repos never used for tuning |
| Benign FPR at MEDIUM | 0.15 real code, 0.15 overall | < 0.05 |
| Mean mutation-robustness score | n/a | ≥ 0.8 |
| Days from spec release to rule update | n/a | ≤ 30 |
| Days from valid bypass report to rule | n/a | ≤ 14 |
| Scan speed (100 skills + 20 configs) | ~2 s | < 10 s, including plugins and connectors |

## 6. Not doing (and why)

- **No default-on dynamic execution.** It would break the core promise. Behavioural analysis stays opt-in and remote.
- **No "safe" verdicts, trust scores or green badges.** Badges only state facts (rule pack, date, finding counts).
- **No proprietary runtime gateway.** Integrate with existing gateways through an open lock format instead.
- **No LLM-only CRITICALs.** The judge can only add evidence, never stand alone.

## 7. Risks

| Risk | Mitigation |
|---|---|
| Independent testing exposes much lower recall | Publish anyway. Honesty is the product's differentiator |
| Spec churn (MCP, A2A, Skills under AAIF) outpaces one maintainer | Spec-watch CI job on upstream repos, a 30-day SLA, and asking for community rule owners per ecosystem |
| Attackers iterate offline against open rules | Position Agent Guard as one layer next to allowlists, pinning and runtime controls, and add mutation hardening |
| Scanner itself becomes a supply-chain target | Phase 0 signing, Scorecard and reproducible builds before any growth push |
| CRA obligations if commercialised | Decide the posture now and document it in SECURITY.md |

---

## Sources (checked 2026-11-03)

- MCP 2026-07-28 release candidate: https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/
- Stateless MCP security analysis: https://equixly.com/blog/2026/08/05/stateless-mcp/
- Server readiness checklist for 2026-07-28: https://dev.to/gustavo_gated/the-2026-07-28-mcp-spec-a-server-readiness-checklist-14nf
- WorkOS on 2026 MCP auth changes: https://workos.com/blog/mcp-2026-spec-agent-authentication
- OWASP Agentic Skills Top 10: https://owasp.org/www-project-agentic-skills-top-10/ · v1.0 release note: https://kenhuangus.substack.com/p/for-immediate-release-owasp-publishes
- OWASP MCP Top 10: https://owasp.org/projects/mcp-top-10 · Client-side tool risk gating control: https://owasp.org/www-project-mcp-top-10/2025/recommended-controls/Client-Side-Tool-Risk-Gating
- NSA MCP CSI coverage: https://executivegov.com/articles/nsa-model-context-protocol-deployment
- CoSAI MCP Security white paper: https://www.oasis-open.org/2026/01/27/coalition-for-secure-ai-releases-extensive-taxonomy-for-model-context-protocol-security
- Trail of Bits, "The sorry state of skill distribution": https://blog.trailofbits.com/2026/06/03/the-sorry-state-of-skill-distribution/
- CSA, skill scanner bypasses: https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-skill-scanner-bypass-20260610-csa/
- Bypass PoC (unverified claims): https://github.com/nedlir/skills-scanner-bypass
- Agent Skills to AAIF: https://www.developersdigest.tech/blog/agent-skills-agentic-ai-foundation-what-changes-2026
- CSA on the AAIF agent stack: https://labs.cloudsecurityalliance.org/research/csa-research-note-aaif-agent-stack-standards-governance-2026/
- A2A signed Agent Cards critique: https://levelup.gitconnected.com/a2as-signed-agent-cards-prove-integrity-not-identity-2b1a017341ce
- Claude Code plugin security docs: https://code.claude.com/docs/en/plugins/security
- Marketplace plugin hijack research: https://promptarmor.com/resources/hijacking-claude-code-via-injected-marketplace-plugins
- CVE-2026-86063 entry (unverified): https://stack.watch/vuln/CVE-2026-86063/
- 2026 AI supply-chain attacks (LiteLLM etc.): https://quintai.dev/blog/supply-chain-attacks-on-ai-tools
- MCP/agent CVE list 2026: https://www.valyu.ai/blogs/mcp-ai-agent-vulnerabilities
- Rug-pull defenses and gateways overview: https://www.getmaxim.ai/articles/best-mcp-security-tools-in-2026.md
- EU CRA reporting from 2026-09-11: https://www.herodevs.com/blog-posts/cra-reporting-obligations-start-september-2026-what-eol-dependencies-mean-for-your-compliance
- OWASP AIVSS: https://aivss.owasp.org/
