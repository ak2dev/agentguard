---
layout: ../../layouts/Doc.astro
title: Suppressions
description: Accepting a finding, with a reason and an expiry date.
---

# Suppressions

Every suppression needs a **reason** (at least 10 characters) and an **expiry date**. Select findings by rule (an id, an old alias, a family such as `INJ`, or a prefix), by fingerprint, by path glob, or a combination.

```yaml
suppressions:
  - rule_id: AG-EXEC-001/vendor-installer
    reason: The uv installer is reviewed and pinned by checksum in our setup docs.
    approved_by: security@my-org.example
    expires: 2027-03-31
  - fingerprint: 3f9a0c1d2e4b5a6978c0d1e2f3a4b5c6
    reason: Reviewed with the security team (ticket SEC-142).
    expires: 2026-12-01
```

- Suppressed findings are left out of the result but kept in the JSON report under `suppressed_findings`.
- An **expired** suppression no longer hides anything: the finding is reported again, together with an `AG-POL-005` notice.
- A suppression without a reason or an expiry is ignored and reported as `AG-POL-006`.
- In `--diff` mode, suppressions come from the base commit.

## Inline suppressions

In your own repository (and only there; never in a third-party target), a comment on the line before a finding suppresses it:

```markdown
<!-- agentguard-ignore: AG-SUPPLY-010 reason="pinned in the lockfile" until=2027-01-01 -->
```

## Baselines

To accept what is there now and be told only about changes, record a baseline: `agentguard baseline create --accept-findings --approved-by you@example.org` writes `agentguard.lock`, and later scans report only new findings and drift. Approvals, installs, applied fixes and updates are written to the audit log, which `agentguard doctor` checks.
