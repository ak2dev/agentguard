# Security policy

## Reporting a vulnerability

Please report vulnerabilities in Agent Guard privately through GitHub security advisories on this repository ("Report a vulnerability"). Do not open a public issue for vulnerabilities in the scanner itself.

We aim to acknowledge reports within 3 working days and to publish a fix and advisory within 90 days. Reporters who want credit are credited.

In scope, for example:

- any way for scanned content to execute code, read files outside the scan root, or make network requests when no network flag was given;
- secrets from scanned content appearing unredacted in any output format;
- output injection (terminal escape sequences, Markdown, HTML, SARIF) from scanned content;
- SSRF or credential exposure in the opt-in network features;
- bypasses of the rule-pack or IOC-feed signature checks, or of rollback protection.

Detection bypasses (a malicious sample Agent Guard misses) are welcome as ordinary issues with an **inert** reproduction: reserved domains such as `example.invalid`, no working payloads, no live malware.

## Supported versions

Only the latest release receives security fixes during 0.x.

## Verifying releases

Releases are built in GitHub Actions and signed with Sigstore (keyless). Each release includes a CycloneDX SBOM, a `SHA256SUMS` file and a separately signed rule-pack bundle:

```bash
python -m pip install sigstore
python -m sigstore verify identity \
  --cert-identity "https://github.com/ak2dev/agentguard/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  --cert-oidc-issuer "https://token.actions.githubusercontent.com" \
  agentguard_v1-X.Y.Z-py3-none-any.whl
```

The wheel, sdist, SBOM and rule-pack bundle also carry a GitHub build-provenance attestation (SLSA provenance, signed with Sigstore):

```bash
gh attestation verify agentguard_v1-X.Y.Z-py3-none-any.whl --repo ak2dev/agentguard
```

## EU Cyber Resilience Act

Agent Guard is free and open-source software, developed and offered outside any commercial activity: there is no paid edition, no paid support and no paid hosted service. Under the Cyber Resilience Act ([Regulation (EU) 2024/2847](https://eur-lex.europa.eu/eli/reg/2024/2847/oj)), free and open-source software that is not made available in the course of a commercial activity is not subject to the manufacturer obligations, so the maintainer does not act as a manufacturer or as an open-source software steward today.

If that changes (for example a paid hosted scanner, paid support, or a company stewarding the project), this section will be updated before it happens. The CRA's reporting obligations for actively exploited vulnerabilities apply from 11 September 2026 and the rest of the regulation from 11 December 2027.

Until then the project follows the practices the CRA expects anyway: the coordinated disclosure process and supported versions above, an SBOM, signatures and build provenance with every release, and security fixes free of charge. If you ship Agent Guard inside a product of your own, the SBOM, the attestations and the GitHub security advisories of this repository are the material for your own due diligence.

## IOC feed signing

The IOC feed is signed with Ed25519. Trusted public keys ship in `intel/keys/`. The bundled `sample-2026-09` key signs only the synthetic sample feed; its private key was discarded after signing. Production feeds are signed with a maintainer key held offline, and `agentguard intel update` refuses unsigned feeds and any feed older than the last one accepted.

## What Agent Guard itself does

- No telemetry. Network access only with explicit opt-in flags, through an SSRF-hardened client.
- Parses, never executes: no imports of scanned code, no package managers, no containers.
- Bounded, hardened loaders: size, count, depth and decompression limits; no symlink following; YAML without anchors, aliases or custom tags; regex timeouts.
- Dependencies are pinned (`uv.lock`), and each release ships an SBOM.
