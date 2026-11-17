"""HYG: hygiene; plus the two rules the hygiene analyzer shares with other families."""

from . import N, P, add, doc, j, merge, script, skill

_COUNT = "import csv, sys\nprint(sum(1 for _ in csv.reader(open(sys.argv[1]))))"
_PLAIN = "Read the CSV file the user names and summarize each column."

add("AG-HYG-001",
    P("skill-directory-without-skill-md", doc(".claude/skills/csv-notes/notes.txt", "Column names are in the first row.\n")),
    N("skill-directory-with-skill-md", doc(".claude/skills/csv-notes/SKILL.md",
                                           "---\nname: csv-notes\ndescription: Notes on reading CSV files in this project.\n---\nColumn names are in the first row.\n")))

add("AG-HYG-002",
    P("no-licence-anywhere", skill(_PLAIN)),
    N("licence-in-frontmatter", skill(_PLAIN, fm="license: MIT\n")),
    N("licence-file", merge(skill(_PLAIN), doc("csv-tool/LICENSE.txt", "MIT License\n\nCopyright (c) Example Team\n"))))

add("AG-HYG-003",
    P("link-to-a-missing-reference", skill("Read the file, then see [the dialect guide](references/dialects.md) for odd separators.")),
    N("link-resolves", merge(skill("Read the file, then see [the dialect guide](references/dialects.md) for odd separators."),
                             doc("csv-tool/references/dialects.md", "# Dialects\n\nComma, semicolon and tab.\n"))),
    N("external-link", skill("Read the file. The format is described in [RFC 4180](https://www.rfc-editor.org/rfc/rfc4180).")))

add("AG-HYG-004",
    P("six-hundred-lines", skill("\n".join(f"{i}. Check column {i} for empty values." for i in range(1, 601)))),
    N("short-body", skill(_PLAIN)))

add("AG-HYG-006",
    P("description-too-short", skill(_PLAIN, description="CSV.")),
    P("almost-no-instructions", skill("Use it.")),
    N("described-and-instructed", skill(_PLAIN)))

add("AG-HYG-007",
    P("plugin-without-version", j("tool/.claude-plugin/plugin.json", {"name": "tool", "description": "Formats Python files."})),
    N("plugin-with-version", j("tool/.claude-plugin/plugin.json", {"name": "tool", "version": "1.0.0", "description": "Formats Python files."})),
    N("plugin-with-changelog", merge(j("tool/.claude-plugin/plugin.json", {"name": "tool", "description": "Formats Python files."}),
                                     doc("tool/CHANGELOG.md", "# Changelog\n\n## 2026-10-01\n\nFirst release.\n"))))

add("AG-HYG-009",
    P("unversioned-pip-install", skill("Install the helper first:\n\n```bash\npip install csvkit\n```\n\nThen read the file.")),
    P("latest-release-download", skill("Install the helper first:\n\n```bash\ncurl -LO https://github.com/example-org/csvstat/releases/latest/download/csvstat.tar.gz\n```")),
    N("pinned-pip-install", skill("Install the helper first:\n\n```bash\npip install csvkit==2.0.1\n```\n\nThen read the file.")))

_CRON = 'import subprocess\nsubprocess.run("(crontab -l; echo \'0 6 * * * csv-tool --refresh\') | crontab -", shell=True)'

add("AG-HYG-010",
    P("cron-entry-with-no-removal-notes", script(_CRON, body="Run `scripts/run.py` once to schedule the daily refresh.")),
    N("cron-entry-with-removal-notes", script(_CRON, body="Run `scripts/run.py` once to schedule the daily refresh.\n\n"
                                                         "To uninstall, run `crontab -e` and delete the `csv-tool --refresh` line.")),
    N("no-persistent-change", script(_COUNT)))

_CACHE = 'import json, os\npath = os.path.expanduser("~/.config/csv-tool/cache.json")\nwith open(os.path.expanduser("~/.config/csv-tool/cache.json"), "w") as fh:\n    json.dump({}, fh)'

add("AG-PERSIST-015",
    P("writes-to-home-with-no-cleanup", script(_CACHE)),
    N("writes-to-home-and-documents-cleanup", script(_CACHE, body="Run `scripts/run.py` on the file the user names.\n\n"
                                                                  "The script keeps a cache in `~/.config/csv-tool`; remove that directory to clean up.")),
    N("writes-nothing-outside", script(_COUNT)))

add("AG-EVADE-012",
    P("runs-a-script-that-is-not-shipped", skill("First run `scripts/bootstrap.sh`, then read the CSV file the user names.")),
    N("script-is-shipped", merge(skill("First run `scripts/bootstrap.sh`, then read the CSV file the user names."),
                                 {"csv-tool/scripts/bootstrap.sh": "#!/bin/sh\necho ready\n"})),
    N("names-a-file-it-will-write", skill("Read the CSV file and save the summary to `out/summary.md`.")))
