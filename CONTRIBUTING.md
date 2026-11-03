# Contributing to Agent Guard

Thank you for helping. The most useful contributions, in order:

1. **Detection bypasses**: a malicious sample Agent Guard misses or reports too low. Open a
   [detection bypass issue](https://github.com/ak2dev/agentguard/issues/new?template=detection-bypass.yml).
2. **False positives** on real skills, instruction files or MCP servers, with a link to the pinned source.
3. **Rules** for techniques the [coverage matrix](https://agentguard-ak2dev.vercel.app/coverage/) lists as gaps.

Vulnerabilities in Agent Guard itself (a way for scanned content to run code, read outside the scan root, reach the
network without a flag, leak an unredacted secret or inject into an output format) are **not** issues. Report them
privately as described in [SECURITY.md](SECURITY.md).

## Keep every sample inert

Bypass reports, fixtures and benchmark items must never work as attacks:

- Use reserved names for every host: `example.invalid`, `example.com`, `*.test`, `192.0.2.0/24`. Exfiltration sinks
  the rules already name (for example `webhook.site`) are fine with a placeholder path such as `/0000-bench`.
- No working payloads, no live malware, no real credentials or tokens, no reverse shells pointed at a reachable host.
- Archives and binaries only when the technique needs them, and never with executable content that does anything.

A report that is not inert is closed, and the sample is deleted.

## Set up

```bash
python -m pip install "uv==0.12.23"
uv sync --frozen --group dev
uv run pytest -q                       # unit, rule-fixture and safety tests
uv run python scripts/check_pack.py    # every rule has fixtures and a crosswalk entry
uv run agentguard bench --output bench-results.json
uv run python scripts/check_bench.py bench-results.json bench/results/latest.json
```

With `--extra code` and `--extra yara` the native analyzers run too, and CI requires them. The site lives in `site/`
(`npm ci && npm run build`) and the web server in `web/` (see `web/README.md`).

## Rule checklist

Rules are YAML data in `rules/<area>/`. A pull request that adds or changes a rule needs all of these, and CI enforces
the first four:

- [ ] **Fixtures.** At least one unsafe case in `fixtures/rules/<RULE-ID>/positive/<case>/` and one safe look-alike
      in `fixtures/rules/<RULE-ID>/negative/<case>/`. The safe case should be the closest legitimate thing you can
      think of, not an empty file.
- [ ] **Crosswalk.** An entry in `mappings/crosswalk.yaml` for every framework: the item ids it maps to, `[]` when
      none applies, never a missing key.
- [ ] **Benchmark.** `agentguard bench` makes no item worse (`scripts/check_bench.py`). If the change is a tuning
      round, commit the new `bench/results/latest.json` and add the round to `docs/benchmark.md`, including the
      held-out result measured *before* tuning.
- [ ] **Generated files.** `uv run python scripts/gen_site_data.py` leaves no diff in `schemas/` or
      `site/src/data/generated/`.
- [ ] **Version.** A changed rule bumps its `version:` field.
- [ ] **Severity.** CRITICAL only with high confidence and deterministic evidence. The LLM judge never decides a
      CRITICAL on its own.
- [ ] **Remediation and why.** Both say what to do and why it matters to someone deciding whether to install.
- [ ] **Changelog.** A line in `CHANGELOG.md` under the unreleased version.
- [ ] **Never execute.** No rule, analyzer or test may run scanned content, start a package manager or container, or
      import scanned code. `tests/safety/` checks this.
- [ ] **Sources.** A new spec, client path or attack technique is checked against its primary source and dated in
      `docs/sources.md`.

## Pull requests

- One topic per pull request, with tests.
- Pin every new GitHub Action to a full commit SHA with a `# vX.Y.Z` comment, and every new dependency to an exact
  version in the lockfile.
- Describe what changed for a user and what you measured. Benchmark numbers in prose must match
  `bench/results/latest.json`.

By contributing you agree that your contribution is licensed under the Apache License 2.0, the license of this
repository.
