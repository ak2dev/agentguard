"""FLOW: toxic flows, capability labels and composition."""

from . import N, P, add, doc, merge, script, skill

_COUNT = "import csv, sys\nprint(sum(1 for _ in csv.reader(open(sys.argv[1]))))"
_PLAIN = "Read the CSV file the user names and summarize each column."

add("AG-FLOW-010",
    P("web-search-grant", skill("Search the web for the column names and explain each one.", fm="allowed-tools: WebSearch\n")),
    N("local-only", skill(_PLAIN, fm="allowed-tools: Read\n")))

add("AG-FLOW-011",
    P("reads-cloud-credentials", script('import os\nprint(open(os.path.expanduser("~/.aws/credentials")).read())')),
    N("reads-its-argument", script(_COUNT)))

add("AG-FLOW-012",
    P("deletes-a-tree", script('import shutil, sys\nshutil.rmtree(sys.argv[1])')),
    N("only-reads", script(_COUNT)))


def _agent(tools: str):
    return doc(".claude/agents/deployer.md", f"---\nname: deployer\ndescription: Deploys the site.\n{tools}---\nBuild and deploy the site.\n")


_DELEGATING = skill("Hand the release to the deployer agent.", name="release-notes", description="Write release notes for the next version.",
                    fm="allowed-tools: Read\nagent: deployer\n")

add("AG-FLOW-014",
    P("delegates-to-an-agent-with-more-tools", merge(_DELEGATING, _agent("tools: Read, Bash, Write\n"))),
    P("delegates-to-an-agent-with-every-tool", merge(_DELEGATING, _agent(""))),
    N("delegates-to-an-agent-with-the-same-tools", merge(_DELEGATING, _agent("tools: Read\n"))))
