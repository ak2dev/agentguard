"""CI: workflows that run a coding agent. Action refs use a made-up commit SHA; hosts end in .invalid."""

from . import N, P, add, doc, j, merge, workflow

SHA = "0123456789abcdef0123456789abcdef01234567"
ACTION = "anthropics/claude-code-action@" + SHA
CHECKOUT = "actions/checkout@" + SHA
KEY = "${{ secrets.ANTHROPIC_API_KEY }}"
READ = "permissions:\n  contents: read\n"


def wf(on: str, steps: str, perms: str = READ, job: str = "", runs_on: str = "ubuntu-latest", limit: bool = True,
       name: str = "agent.yml", job_name: str = "agent", tail: str = "") -> dict:
    """One workflow with one job. ``on`` and ``steps`` are YAML fragments (``steps`` indented six spaces)."""
    body = ("name: agent\non:\n" + on + perms + "jobs:\n  " + job_name + ":\n    runs-on: " + runs_on + "\n"
            + ("    timeout-minutes: 15\n" if limit else "") + job + "    steps:\n" + steps + tail)
    return workflow(body, name)


def agent(prompt: str = '"Summarize the open pull requests."', extra: str = "", uses: str = ACTION, sid: str = "") -> str:
    return ("      - " + ("id: " + sid + "\n        " if sid else "") + "uses: " + uses + "\n        with:\n          anthropic_api_key: " + KEY
            + "\n          prompt: " + prompt + "\n" + extra)


def checkout(ref: str = "") -> str:
    return "      - uses: " + CHECKOUT + "\n" + ("        with:\n          ref: " + ref + "\n" if ref else "")


ISSUES = "  issues:\n    types: [opened]\n"
COMMENT = "  issue_comment:\n    types: [created]\n"
PRT = "  pull_request_target:\n    types: [opened, synchronize]\n"
PR = "  pull_request:\n"
PUSH = "  push:\n    branches: [main]\n"
DISPATCH = "  workflow_dispatch:\n"
GATE = "    if: contains(fromJSON('[\"OWNER\",\"MEMBER\",\"COLLABORATOR\"]'), github.event.comment.author_association)\n"

add("AG-CI-001",
    P("issue-body-in-prompt", wf(ISSUES, agent('"Triage this issue: ${{ github.event.issue.body }}"'))),
    P("title-through-env", wf(ISSUES, "      - name: Summarize\n        env:\n          ANTHROPIC_API_KEY: " + KEY
                              + "\n          ISSUE_TITLE: ${{ github.event.issue.title }}\n"
                              + '        run: npx -y @anthropic-ai/claude-code@2.1.0 -p "Summarize $ISSUE_TITLE" --max-turns 3\n')),
    N("issue-number-only", wf(ISSUES, agent('"Triage issue #${{ github.event.issue.number }} by reading it with the gh tool."'))),
    N("fixed-prompt", wf(PUSH, agent())))

add("AG-CI-002",
    P("comment-trigger-default-token", wf(COMMENT, agent(), perms="")),
    P("pull-request-target-write-token", wf(PRT, agent(), perms="permissions:\n  contents: write\n  pull-requests: write\n")),
    N("gated-on-association", wf(COMMENT, agent(), perms="", job=GATE)),
    N("read-only-token", wf(PRT, agent())))

add("AG-CI-003",
    P("bash-on-comment", wf(COMMENT, agent(extra='          claude_args: --allowedTools "Bash,Read"\n'))),
    P("write-tools-on-issues", wf(ISSUES, agent(extra='          allowed_tools: "Edit,Write,Read"\n'))),
    N("read-only-tools", wf(COMMENT, agent(extra='          claude_args: --allowedTools "Read,Grep,Glob"\n'))),
    N("bash-on-manual-run", wf(DISPATCH, agent(extra='          claude_args: --allowedTools "Bash,Read"\n'))))

add("AG-CI-004",
    P("write-all", wf(PUSH, agent(), perms="permissions: write-all\n")),
    P("four-write-scopes", wf(PUSH, agent(), perms="permissions:\n  contents: write\n  pull-requests: write\n  issues: write\n  actions: write\n")),
    N("one-write-scope", wf(PUSH, agent(), perms="permissions:\n  contents: read\n  pull-requests: write\n")),
    N("read-all", wf(PUSH, agent(), perms="permissions: read-all\n")))

add("AG-CI-005",
    P("agent-action-on-tag", wf(PUSH, agent(uses="anthropics/claude-code-action@v1"))),
    P("agent-action-on-branch", wf(PUSH, "      - uses: openai/codex-action@main\n        with:\n          openai-api-key: ${{ secrets.OPENAI_API_KEY }}\n"
                                   "          prompt: Update the changelog.\n")),
    N("pinned-to-commit", wf(PUSH, agent())),
    N("cli-with-exact-version", wf(PUSH, "      - env:\n          ANTHROPIC_API_KEY: " + KEY
                                   + '\n        run: npx -y @anthropic-ai/claude-code@2.1.0 -p "Update the changelog." --max-turns 3\n')))

add("AG-CI-006",
    P("agent-output-in-run", wf(PUSH, agent(sid="plan") + "      - name: Apply\n        run: ${{ steps.plan.outputs.result }}\n")),
    P("job-output-in-script", workflow(
        "name: agent\non:\n" + PUSH + READ + "jobs:\n  plan:\n    runs-on: ubuntu-latest\n    timeout-minutes: 15\n"
        "    outputs:\n      commands: ${{ steps.a.outputs.result }}\n    steps:\n" + agent(sid="a")
        + "  apply:\n    needs: plan\n    runs-on: ubuntu-latest\n    steps:\n      - run: bash -c \"${{ needs.plan.outputs.commands }}\"\n")),
    N("output-through-env", wf(PUSH, agent(sid="plan") + "      - name: Save\n        env:\n          RESULT: ${{ steps.plan.outputs.result }}\n"
                               "        run: printf '%s' \"$RESULT\" > summary.md\n")),
    N("output-of-ordinary-step", wf(PUSH, "      - id: ver\n        run: echo \"v=1.2.3\" >> \"$GITHUB_OUTPUT\"\n"
                                    "      - run: echo \"${{ steps.ver.outputs.v }}\"\n" + agent())))

add("AG-CI-007",
    P("dangerously-skip-permissions", wf(PUSH, "      - env:\n          ANTHROPIC_API_KEY: " + KEY
                                         + '\n        run: npx -y @anthropic-ai/claude-code@2.1.0 -p "Fix the lint errors." --dangerously-skip-permissions\n')),
    P("gemini-yolo", wf(PUSH, "      - env:\n          GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}\n"
                        '        run: npx -y @google/gemini-cli@0.9.0 --yolo -p "Fix the lint errors."\n')),
    N("listed-tools", wf(PUSH, "      - env:\n          ANTHROPIC_API_KEY: " + KEY
                         + '\n        run: npx -y @anthropic-ai/claude-code@2.1.0 -p "Fix the lint errors." --max-turns 5 --allowedTools Read\n')),
    N("read-only-sandbox", wf(PUSH, "      - uses: openai/codex-action@" + SHA + "\n        with:\n          openai-api-key: ${{ secrets.OPENAI_API_KEY }}\n"
                              "          sandbox: read-only\n          prompt: Summarize the changes.\n")))

add("AG-CI-008",
    P("head-checkout-on-privileged-event", wf(PRT, checkout("${{ github.event.pull_request.head.sha }}") + agent('"Summarize the change."'))),
    P("pull-request-code-with-project-mcp", merge(
        wf(PR, checkout() + agent('"Summarize the change."')),
        j(".mcp.json", {"mcpServers": {"docs": {"command": "node", "args": ["tools/docs-server.js"]}}}))),
    N("base-checkout", wf(PRT, checkout() + agent('"Summarize pull request #${{ github.event.pull_request.number }}."'))),
    N("no-project-config", wf(PR, checkout() + agent('"Summarize the change."'))))

add("AG-CI-009",
    P("deploy-secrets-in-agent-env", wf(PUSH, agent(extra="        env:\n          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}\n"
                                                    "          DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}\n"))),
    P("all-secrets-as-json", wf(PUSH, agent(extra="        env:\n          ALL: ${{ toJSON(secrets) }}\n"))),
    N("model-key-and-token-only", wf(PUSH, agent(extra="        env:\n          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n"))),
    N("other-secrets-in-another-job", wf(PUSH, agent(), tail=(
        "  publish:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm publish\n        env:\n"
        "          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}\n          DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}\n"))))

add("AG-CI-010",
    P("reviewer-in-head-checkout", wf(PRT, checkout("${{ github.event.pull_request.head.sha }}") + agent('"Review this pull request."'))),
    P("reviewer-on-pull-request", wf(PR, checkout() + agent('"Review this pull request."'))),
    N("reviewer-on-base-checkout", wf(PRT, checkout() + agent('"Review pull request #${{ github.event.pull_request.number }} from its diff."'))),
    N("changelog-on-push", wf(PUSH, checkout() + agent('"Update the changelog."'))))

_SETUP_HEAD = "name: Copilot Setup Steps\non:\n  workflow_dispatch:\njobs:\n  copilot-setup-steps:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: read\n"
add("AG-CI-011",
    P("setup-pipes-download-to-shell", workflow(
        _SETUP_HEAD + "    steps:\n      - name: Install tools\n        run: curl -fsSL https://tools.example.invalid/install.sh | bash\n",
        "copilot-setup-steps.yml")),
    P("firewall-off", workflow(
        _SETUP_HEAD + "    env:\n      COPILOT_AGENT_FIREWALL_ENABLED: false\n    steps:\n      - run: npm ci\n", "copilot-setup-steps.yml")),
    N("locked-install", workflow(_SETUP_HEAD + "    steps:\n" + checkout() + "      - run: npm ci\n", "copilot-setup-steps.yml")),
    N("pinned-setup-action", workflow(
        _SETUP_HEAD + "    steps:\n      - uses: actions/setup-node@" + SHA + "\n        with:\n          node-version: 22\n",
        "copilot-setup-steps.yml")))

add("AG-CI-012",
    P("self-hosted-on-comment", wf(COMMENT, agent(), runs_on="self-hosted")),
    P("self-hosted-labels-on-pull-request", wf(PR, agent(), runs_on="[self-hosted, linux]")),
    N("hosted-runner", wf(COMMENT, agent())),
    N("self-hosted-manual-run", wf(DISPATCH, agent(), runs_on="self-hosted")))

_MD_BODY = "# Issue triage\n\nRead the new issue and add one label from the repository's label list.\n"
add("AG-CI-013",
    P("bash-wildcard", doc(".github/workflows/triage.md",
                           "---\non:\n  issues:\n    types: [opened]\npermissions:\n  contents: read\nengine: claude\ntools:\n  bash: [\"*\"]\n"
                           "timeout-minutes: 10\n---\n" + _MD_BODY)),
    P("network-wildcard", doc(".github/workflows/triage.md",
                              "---\non:\n  issues:\n    types: [opened]\npermissions:\n  contents: read\nengine: claude\nnetwork:\n  allowed: [\"*\"]\n"
                              "timeout-minutes: 10\n---\n" + _MD_BODY)),
    N("scoped-tools-and-safe-outputs", doc(".github/workflows/triage.md",
                                           "---\non:\n  issues:\n    types: [opened]\npermissions:\n  contents: read\nengine: claude\ntools:\n"
                                           "  bash: [\"gh issue view:*\"]\nnetwork: defaults\nsafe-outputs:\n  add-labels:\n    max: 1\n"
                                           "timeout-minutes: 10\n---\n" + _MD_BODY)),
    N("no-tools", doc(".github/workflows/triage.md",
                      "---\non:\n  issues:\n    types: [opened]\npermissions:\n  contents: read\nengine: claude\ntimeout-minutes: 10\n---\n" + _MD_BODY)))

add("AG-CI-014",
    P("no-limit-on-agent-step", wf(PUSH, agent(), limit=False)),
    P("agentic-workflow-without-timeout", doc(".github/workflows/triage.md",
                                             "---\non:\n  issues:\n    types: [opened]\npermissions:\n  contents: read\nengine: claude\n---\n" + _MD_BODY)),
    N("job-timeout", wf(PUSH, agent())),
    N("max-turns", wf(PUSH, agent(extra="          claude_args: --max-turns 5\n"), limit=False)))

add("AG-CI-015",
    P("artifact-from-triggering-run", workflow(
        "name: agent\non:\n  workflow_run:\n    workflows: [build]\n    types: [completed]\n" + READ
        + "jobs:\n  agent:\n    runs-on: ubuntu-latest\n    timeout-minutes: 15\n    steps:\n      - uses: actions/download-artifact@" + SHA
        + "\n        with:\n          run-id: ${{ github.event.workflow_run.id }}\n          name: report\n" + agent('"Summarize report.txt."'))),
    P("cache-keyed-on-branch", wf(PR, "      - uses: actions/cache@" + SHA + "\n        with:\n          path: .context\n"
                                  "          key: ctx-${{ github.head_ref }}\n" + agent('"Summarize the change."'))),
    N("artifact-of-same-run", wf(PUSH, "      - uses: actions/download-artifact@" + SHA + "\n        with:\n          name: report\n"
                                 + agent('"Summarize report.txt."'))),
    N("cache-keyed-on-lockfile", wf(PR, "      - uses: actions/cache@" + SHA + "\n        with:\n          path: node_modules\n"
                                    "          key: deps-${{ hashFiles('package-lock.json') }}\n" + agent('"Summarize the change."'))))

add("AG-SUPPLY-022",
    P("checkout-on-tag", wf(PUSH, "      - uses: actions/checkout@v4\n" + agent())),
    P("third-party-action-on-tag", wf(PUSH, "      - uses: acme-tools/setup-thing@v2\n" + agent())),
    N("all-pinned", wf(PUSH, checkout() + agent())),
    N("workflow-without-an-agent", workflow(
        "name: test\non:\n  push:\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: npm test\n",
        "test.yml")))
