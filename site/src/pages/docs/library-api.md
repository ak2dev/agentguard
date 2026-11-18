---
layout: ../../layouts/Doc.astro
title: Library API
description: Use the engine from Python, a web worker or Pyodide.
---

# Library API

```python
from agentguard import ScanOptions, scan

report = scan("./skills/pdf-helper", ScanOptions(profile="standard", policy="strict"))
report.verdict             # "ALLOW" | "REVIEW" | "BLOCK" (a str enum)
for f in report.findings:  # typed objects mirroring the JSON schema
    print(f.id, f.location.file, f.location.start.line, f.fix.summary)
```

With a path or any other target string, `scan` acquires the target and scans it statically and offline unless the options ask for more: no configuration file is read, no installed context is added and no model is called.

For a pure, in-memory scan, pass a tree:

```python
from agentguard import ArtifactTree, ScanOptions, scan
from agentguard.core.report.render import render_sarif

tree = ArtifactTree.from_mapping({"my-skill/SKILL.md": skill_text})
report = scan(tree, ScanOptions())
sarif = render_sarif(report)
```

- `scan(tree, options)` is pure: no filesystem, network or clock access. The same engine runs in the CLI, in hosted workers and in the browser under Pyodide.
- Build trees with `ArtifactTree.from_mapping` (text you already have), `agentguard.from_archive(bytes)` (zip and tar, with bomb, symlink and path-escape protection) or `agentguard.io.fs_loader.load_path(path)` on the host.
- What needs the network, a model, OCR or the sandbox is collected outside the engine and passed in as data (`ScanOptions.facts`, `media_text`, `remote_probes`, `adjudications`, `dynamic_evidence`), so every rule is testable offline.
- `ScanOptions(context=tree)` scans a candidate together with what is already installed, for the composition rules.
- Renderers are pure functions of the report: `render_json`, `render_sarif`, `render_markdown`, `render_junit`, `render_cyclonedx` (in `agentguard.core.report.render`) and `agentguard.core.report.html.render_html`.
- `agentguard.fix.fix_tree(tree)` proposes fixes on an in-memory tree; each is kept only when a re-scan shows its finding gone and nothing new.
