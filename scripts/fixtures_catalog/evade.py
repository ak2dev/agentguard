"""EVADE: evasion, scanner targeting and coverage."""

from . import N, P, add, doc, j, merge, script, skill

_COUNT = "import csv, sys\nprint(sum(1 for _ in csv.reader(open(sys.argv[1]))))"
_PLAIN = "Read the CSV file the user names and summarize each column."

_WORKFLOW_ANCHORS = ("name: ci\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    env: &env\n      PYTHONUNBUFFERED: \"1\"\n"
                     "    steps:\n      - run: echo test\n  lint:\n    runs-on: ubuntu-latest\n    env: *env\n"
                     "    steps:\n      - run: echo lint\n")
_COMPOSE_ANCHORS = ("x-env: &env\n  LOG_LEVEL: info\nservices:\n  api:\n    image: example/api:1.4\n    environment:\n"
                    "      <<: *env\n      MODE: dev\n  worker:\n    image: example/worker:1.4\n    environment: *env\n")
# Nine levels of ten aliases each: a billion nodes once expanded (the loader stops at its node limit).
_ALIAS_BOMB = "a: &a [x, x, x, x, x, x, x, x, x, x]\n" + "".join(
    f"{n}: &{n} [{', '.join([f'*{p}'] * 10)}]\n" for p, n in zip("abcdefgh", "bcdefghi"))

add("AG-EVADE-002",
    P("settings-do-not-parse", doc(".claude/settings.json", '{"permissions": {"allow": ["Bash(ls)"]'), verdict="REVIEW"),
    P("hooks-file-truncated", doc(".cursor/hooks.json", '{"version": 1, "hooks": {"beforeShellExecution": [{"command": "./check.sh"}'),),
    P("yaml-aliases-past-the-node-limit", doc(".github/workflows/ci.yml", _ALIAS_BOMB)),
    N("settings-parse", j(".claude/settings.json", {"permissions": {"allow": ["Bash(ls)"]}})),
    N("json5-comments-are-fine", doc(".vscode/tasks.json", '{\n  // build task\n  "version": "2.0.0",\n  "tasks": [],\n}')),
    N("yaml-anchors-in-a-workflow", doc(".github/workflows/ci.yml", _WORKFLOW_ANCHORS)),
    N("yaml-anchors-in-a-compose-file", doc("compose.yaml", _COMPOSE_ANCHORS)))

add("AG-EVADE-006",
    P("script-in-hidden-directory", merge(skill("Run `.assets/loader.sh` before reading the file."),
                                          {"csv-tool/.assets/loader.sh": "#!/bin/sh\necho ready\n"})),
    P("opaque-blob-in-build-output", merge(skill(_PLAIN), {"csv-tool/target/stage2.dat": b"\x00\x13\x37" * 400})),
    N("script-in-scripts", script(_COUNT)),
    N("docs-are-documents", merge(skill(_PLAIN), {"csv-tool/docs/usage.md": "# Usage\n\nPass the path of a CSV file.\n"})))

add("AG-EVADE-016",
    P("budget-ran-out", skill(_PLAIN), llm_complete=False),
    N("model-stage-finished", skill(_PLAIN)))

add("AG-EVADE-017",
    P("script-not-reached", script(_COUNT), dynamic_ran=True, dynamic_not_reached=["csv-tool/scripts/run.py"]),
    N("every-path-reached", script(_COUNT), dynamic_ran=True))

_LFS = "version https://git-lfs.github.com/spec/v1\noid sha256:" + "4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393" + "\nsize 48213\n"
_MODULES = '[submodule "vendor/parser"]\n\tpath = vendor/parser\n\turl = https://github.com/example-org/parser.git\n'

add("AG-EVADE-018",
    P("lfs-pointer-not-fetched", merge(skill(_PLAIN), {"csv-tool/assets/model.bin": _LFS}), verdict="REVIEW"),
    P("submodule-directory-empty", merge(skill(_PLAIN), doc(".gitmodules", _MODULES))),
    N("asset-is-real-content", merge(skill(_PLAIN), {"csv-tool/assets/columns.txt": "name\nprice\nquantity\n"})),
    N("submodule-content-present", merge(skill(_PLAIN), doc(".gitmodules", _MODULES),
                                         doc("vendor/parser/README.md", "# parser\n\nA CSV dialect sniffer.\n"))))

add("AG-EVADE-021",
    P("mostly-opaque", merge(skill(_PLAIN), {"csv-tool/assets/weights.dat": b"\x00\x7f\x10\x9c" * 3000}), verdict="REVIEW"),
    N("all-text", merge(skill(_PLAIN), {"csv-tool/references/dialects.md": "# Dialects\n\nComma, semicolon and tab.\n"})),
    N("permissive-policy-has-no-minimum", merge(skill(_PLAIN), {"csv-tool/assets/weights.dat": b"\x00\x7f\x10\x9c" * 3000}),
      policy={"extends": "permissive"}))
