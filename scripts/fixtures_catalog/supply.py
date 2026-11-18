"""SUPPLY: supply chain and provenance."""

from . import N, P, add, doc, j, merge, script, skill

_COUNT = "import csv, sys\nprint(sum(1 for _ in csv.reader(open(sys.argv[1]))))"
_PLAIN = "Read the CSV file the user names and summarize each column."
SHA = "9b1c0f7e2d4a6b8c0e1f3a5b7c9d1e3f5a7b9c1d"
INTEGRITY = "sha512-" + "A" * 86 + "=="


def pkg(deps: dict, lock: dict | None = None, **top):
    files = merge(skill(_PLAIN), j("csv-tool/package.json", {"name": "csv-tool", "version": "1.0.0", "license": "MIT",
                                                               "dependencies": deps, **top}))
    if lock is not None:
        files.update(j("csv-tool/package-lock.json", lock))
    return files


def lock(entries: dict):
    return {"name": "csv-tool", "version": "1.0.0", "lockfileVersion": 3,
            "packages": {"": {"name": "csv-tool", "version": "1.0.0"}, **entries}}


_PAD = {"version": "1.3.0", "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz", "integrity": INTEGRITY}

add("AG-SUPPLY-002",
    P("known-malicious-npm-package", pkg({"flatmap-stream": "0.1.1"}), verdict="BLOCK"),
    P("known-malicious-version", pkg({"event-stream": "3.3.6"})),
    N("ordinary-dependency", pkg({"left-pad": "1.3.0"})),
    N("clean-version-of-a-listed-package", pkg({"event-stream": "4.0.1"})))

add("AG-SUPPLY-005",
    P("npm-range-no-lockfile", pkg({"left-pad": "^1.3.0"})),
    P("requirements-unpinned", merge(skill(_PLAIN), doc("csv-tool/requirements.txt", "pandas>=2.0\nrequests\n"))),
    N("npm-exact", pkg({"left-pad": "1.3.0"})),
    N("npm-range-with-lockfile", pkg({"left-pad": "^1.3.0"}, lock({"node_modules/left-pad": _PAD}))),
    N("requirements-pinned", merge(skill(_PLAIN), doc("csv-tool/requirements.txt", "pandas==2.2.3\nrequests==2.32.3\n"))))

add("AG-SUPPLY-006",
    P("npm-github-shorthand", pkg({"left-pad": "github:example-org/left-pad"})),
    P("pip-git-branch", merge(skill(_PLAIN), doc("csv-tool/requirements.txt", "csvkit @ git+https://github.com/example-org/csvkit.git@main\n"))),
    N("npm-github-at-commit", pkg({"left-pad": f"github:example-org/left-pad#{SHA}"})),
    N("pip-git-at-commit", merge(skill(_PLAIN), doc("csv-tool/requirements.txt", f"csvkit @ git+https://github.com/example-org/csvkit.git@{SHA}\n"))))

add("AG-SUPPLY-008",
    P("locked-dependency-with-install-script", pkg({"left-pad": "1.3.0"}, lock({"node_modules/left-pad": {**_PAD, "hasInstallScript": True}}))),
    N("no-install-scripts", pkg({"left-pad": "1.3.0"}, lock({"node_modules/left-pad": _PAD}))))

add("AG-SUPPLY-010",
    P("follow-a-document-on-main", skill("Follow the instructions at https://raw.githubusercontent.com/example-org/docs/main/setup.md before reading the file.")),
    N("document-at-a-commit", skill(f"Follow the instructions at https://raw.githubusercontent.com/example-org/docs/{SHA}/setup.md before reading the file.")),
    N("link-that-is-not-a-document", skill("The project home page is https://csv-tool.example.invalid/ for people who want to know more.")))

add("AG-SUPPLY-016",
    P("package-has-a-file-the-source-lacks", script(_COUNT),
      facts={"packages": {"npm/csv-tool": {"source_diff": {"ref": "v1.0.0", "only_in_package": ["scripts/run.py"], "changed": []}}}}),
    N("package-matches-source", script(_COUNT),
      facts={"packages": {"npm/csv-tool": {"source_diff": {"ref": "v1.0.0", "only_in_package": [], "changed": []}}}}))

add("AG-SUPPLY-018",
    P("source-archived", script(_COUNT), facts={"sources": {"https://github.com/example-org/csv-tool": {"archived": True}}}),
    P("no-commit-for-years", script(_COUNT), today="2026-11-12",
      facts={"sources": {"https://github.com/example-org/csv-tool": {"archived": False, "pushed_at": "2023-01-04T10:00:00Z"}}}),
    N("source-active", script(_COUNT), today="2026-11-12",
      facts={"sources": {"https://github.com/example-org/csv-tool": {"archived": False, "pushed_at": "2026-10-30T10:00:00Z"}}}))

_MOD = '[submodule "vendor/parser"]\n\tpath = vendor/parser\n\turl = {url}\n'
_VENDORED = doc("vendor/parser/README.md", "# parser\n\nA CSV dialect sniffer.\n")

add("AG-SUPPLY-020",
    P("submodule-over-plain-http", merge(skill(_PLAIN), doc(".gitmodules", _MOD.format(url="http://git.example.invalid/parser.git")), _VENDORED)),
    P("submodule-tracks-a-branch", merge(skill(_PLAIN), _VENDORED,
                                         doc(".gitmodules", _MOD.format(url="https://github.com/example-org/parser.git") + "\tbranch = main\n"))),
    N("https-submodule-present", merge(skill(_PLAIN), doc(".gitmodules", _MOD.format(url="https://github.com/example-org/parser.git")), _VENDORED)))

add("AG-SUPPLY-021",
    P("package-without-licence", merge(skill(_PLAIN), j("csv-tool/package.json", {"name": "csv-tool", "version": "1.0.0", "dependencies": {}}))),
    N("licence-declared", pkg({})),
    N("licence-file", merge(skill(_PLAIN), j("csv-tool/package.json", {"name": "csv-tool", "version": "1.0.0", "dependencies": {}}),
                            doc("csv-tool/LICENSE", "MIT License\n\nCopyright (c) Example Team\n"))))

_ELF = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 120

add("AG-SUPPLY-023",
    P("binary-without-source", merge(skill("Run `bin/csvstat` on the file the user names."), {"csv-tool/bin/csvstat": _ELF})),
    N("binary-with-source", merge(skill("Run `bin/csvstat` on the file the user names."), {"csv-tool/bin/csvstat": _ELF},
                                  doc("csv-tool/src/csvstat.c", "#include <stdio.h>\nint main(void) { puts(\"ok\"); return 0; }\n"))),
    N("no-binary", script(_COUNT)))

add("AG-SUPPLY-024",
    P("entry-resolved-from-a-raw-address", pkg({"left-pad": "1.3.0"}, lock({"node_modules/left-pad": {
        "version": "1.3.0", "resolved": "http://203.0.113.9/left-pad-1.3.0.tgz", "integrity": INTEGRITY}}))),
    P("entry-without-integrity", pkg({"left-pad": "1.3.0"}, lock({"node_modules/left-pad": {
        "version": "1.3.0", "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}}))),
    N("registry-with-integrity", pkg({"left-pad": "1.3.0"}, lock({"node_modules/left-pad": _PAD}))))

add("AG-SUPPLY-025",
    P("marketplace-says-warn", merge(skill(_PLAIN), j("csv-tool/.clawhub/origin.json", {"slug": "csv-tool", "version": "1.0.0", "audit": {"status": "Warn"}}))),
    P("marketplace-says-malicious", merge(skill(_PLAIN), j("csv-tool/.clawhub/origin.json", {"slug": "csv-tool", "securityStatus": "Malicious"}))),
    N("marketplace-says-pass", merge(skill(_PLAIN), j("csv-tool/.clawhub/origin.json", {"slug": "csv-tool", "version": "1.0.0", "audit": {"status": "Pass"}}))))


def _launch(*args: str) -> dict:
    return j(".mcp.json", {"mcpServers": {"tracker": {"command": "npx", "args": ["-y", *args]}}})


add("AG-SUPPLY-001/bundled-advisory",
    P("helper-pinned-to-an-affected-version", _launch("mcp-remote@0.1.14", "https://tracker.example.invalid/mcp")),
    P("server-pinned-to-an-affected-version", _launch("@modelcontextprotocol/server-filesystem@0.6.2", "/srv/data")),
    N("helper-at-the-fixed-version", _launch("mcp-remote@0.1.16", "https://tracker.example.invalid/mcp")),
    N("package-not-in-the-snapshot", _launch("@example/tracker-mcp@0.1.14")),
    N("no-version-pinned", _launch("mcp-remote", "https://tracker.example.invalid/mcp")))
