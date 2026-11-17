---
layout: ../../layouts/Doc.astro
title: Policy
description: Presets, requirements, allow and deny lists, and severity overrides.
---

# Policy

Pass a preset or a policy file with `--policy`, or put one under `policy:` in `.agentguard.yaml`. A policy is applied last and can only tighten a verdict, except through recorded suppressions.

| Preset | Fails on | Also |
|---|---|---|
| `strict` | REVIEW | Hunt lane on; full coverage and pinned sources required; any unanalysed content keeps the verdict from ALLOW |
| `balanced` (default) | BLOCK | At least 80% of the content must be analysed, otherwise AG-EVADE-021 |
| `permissive` | BLOCK | For trusted internal sources |

```yaml
version: 1
extends: balanced
fail_on: block                     # block | review | severity:<level>
require:
  full_coverage: true              # exit code 3 when anything could not be analysed
  pinned_sources: true             # unpinned package runners and images are reported (AG-POL-003)
  signatures: warn                 # off | warn | require
  max_risk_tier: L2                # components above this need an approval record
  min_analyzability: 0.9           # share of the content that must have been analysed
allow:
  publishers: ["github.com/my-org/*"]
  registries: ["ghcr.io/my-org", "registry.npmjs.org"]
  domains: ["api.my-org.example"]
  servers: ["npx -y @modelcontextprotocol/*"]   # anything else is reported (AG-POL-002)
deny:
  capabilities: [financial-execution, host-elevated]
  rules: [AG-CFG-007, AG-EXEC-001]
  servers: ["*@attacker-example/*"]
  publishers: ["npm:@untrusted"]
severity_overrides:
  AG-HYG-002: info
lanes:
  hunt: off                        # advisory rules, and imported community rules, run in this lane
```

A matching `deny` entry makes the verdict BLOCK (AG-POL-001). Policy findings (`AG-POL-*`) are ordinary findings: they appear in every output format and count towards the exit code. The flat keys of the first policy format (`deny_servers`, `deny_publishers`, `allow_servers`, `require_pinning`) are still read.

## The least-privilege policy

`agentguard fix --emit-policy policy.json` writes, for every component, the smallest `allowed-tools` grant, the permission rules and the sandbox profile that cover what it was observed to do. It is a proposal for you to review and hand to the agent, which enforces it; Agent Guard does not.
