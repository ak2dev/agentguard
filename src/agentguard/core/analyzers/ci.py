"""Agentic CI/CD (the CI family, and AG-SUPPLY-022).

Reads the workflows that run a coding agent (``inv.agentic_ci``), the Copilot
setup workflow and GitHub agentic-workflow Markdown files, and applies the
trust-boundary rules of spec/rules.md: who can trigger the agent, what text
reaches its prompt, which tools, secrets and token it holds, and which code and
configuration it loads.

A workflow is data here. Nothing is run and nothing is fetched.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar

import regex

from ..discover import AGENT_CI_MARKERS
from ..inventory_surfaces import Doc
from ..models import Span
from ..models.enums import EvidenceKind, Severity
from ..textutil import TIMEOUT
from .base import Context
from .settings import _DYN_EXEC, _NET

_F = regex.IGNORECASE
# Triggers anyone outside the repository can fire while the workflow runs with the base repository's rights.
PRIVILEGED = frozenset({"pull_request_target", "issue_comment", "workflow_run"})
UNTRUSTED = PRIVILEGED | {"issues", "pull_request", "pull_request_review", "pull_request_review_comment", "discussion",
                          "discussion_comment"}
# Text of an issue, pull request, comment, review or branch: written by whoever opened it.
_UNTRUSTED_EXPR = regex.compile(
    r"\$\{\{[^}\n]*?\b(?:github\.event\.(?:issue|pull_request|comment|review|review_comment|discussion)\.(?:title|body)"
    r"|github\.event\.pull_request\.head\.(?:ref|label)|github\.event\.head_commit\.message"
    r"|github\.event\.workflow_run\.(?:head_branch|display_title|head_commit\.message)|github\.head_ref)\b[^}\n]*\}\}", _F)
_GITLAB_UNTRUSTED = regex.compile(
    r"\$\{?(?:CI_MERGE_REQUEST_TITLE|CI_MERGE_REQUEST_DESCRIPTION|CI_COMMIT_MESSAGE|CI_COMMIT_TITLE|CI_COMMIT_DESCRIPTION"
    r"|CI_MERGE_REQUEST_SOURCE_BRANCH_NAME|CI_COMMIT_REF_NAME|CI_COMMIT_BRANCH)\}?")
_SECRET = regex.compile(r"\$\{\{\s*secrets\.([A-Za-z_]\w*)")
_ALL_SECRETS = regex.compile(r"toJSON\(\s*secrets\s*\)", _F)
# Secrets an agent step is expected to hold: the model credential and the repository token.
_EXPECTED_SECRET = regex.compile(
    r"^(?:GITHUB_TOKEN|GH_TOKEN|ANTHROPIC_\w+|CLAUDE_\w+|OPENAI_\w+|CODEX_\w+|GEMINI_\w+|GOOGLE_API_KEY|GOOGLE_GENAI\w*"
    r"|AZURE_OPENAI\w*|COPILOT_\w+|CURSOR_\w+|OPENROUTER_\w+|MISTRAL_\w+|APP_ID|APP_PRIVATE_KEY)$", _F)
_SHA_PIN = regex.compile(r"@[0-9a-f]{40}\b")
_DOCKER_DIGEST = regex.compile(r"@sha256:[0-9a-f]{64}\b")
_FIRST_PARTY = regex.compile(r"^(?:actions|github)/", _F)
BYPASS_FLAG = regex.compile(
    r"--dangerously-skip-permissions\b|--yolo\b|--dangerously-bypass-approvals-and-sandbox\b|--allow-all-tools\b"
    r"|--permission-mode[= ]+[\"']?bypassPermissions\b|--approval-mode[= ]+[\"']?yolo\b|--sandbox[= ]+[\"']?danger-full-access\b"
    r"|\bsandbox(?:[-_]mode)?\s*[:=]\s*[\"']?danger-full-access\b|--trust-all-tools\b|--force\s+--yes\b", _F)
_TOOLS_ARG = regex.compile(r"(?:--allowed[-_]?tools|\ballowed[-_]tools|\ballowedTools)\b\s*[:=]?\s*(?P<v>[^\n]*)", _F)
_OPEN_TOOL = regex.compile(r"\bBash\b(?!\s*\()|\bBash\(\s*(?:\*|:\*)?\s*\)|\b(?:Write|Edit|MultiEdit|NotebookEdit)\b(?!\s*\()")
_SCOPED_TOOL = regex.compile(r"\bBash\([^)\n]+\)|\b(?:Write|Edit|MultiEdit)\([^)\n]+\)")
_OTHER_GRANT = regex.compile(
    r"(?:--sandbox[= ]+[\"']?|\bsandbox(?:[-_]mode)?\s*[:=]\s*[\"']?)workspace-write\b|--full-auto\b"
    r"|--approval-mode[= ]+[\"']?auto_edit\b|--allow-tool\b|--permission-mode[= ]+[\"']?acceptEdits\b|\"coreTools\"", _F)
_HEAD_REF = regex.compile(
    r"github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref|refs/pull/|github\.event\.workflow_run\.head_(?:sha|branch)"
    r"|steps\.[\w-]+\.outputs\.(?:head[_-]?sha|head[_-]?ref|pr[_-]?sha|sha)\b", _F)
_HEAD_RUN = regex.compile(r"\bgh\s+pr\s+checkout\b|\bgit\s+fetch\s+\S+\s+\+?(?:refs/)?pull/|\bgit\s+checkout\s+[^\n]*(?:head\.sha|head_ref|FETCH_HEAD)", _F)
_GATE = regex.compile(r"author_association|github\.actor\s*[!=]=|github\.triggering_actor\s*[!=]=|sender\.login\s*[!=]=|\.permission\b"
                      r"|github\.event\.pull_request\.head\.repo\.full_name\s*==\s*github\.repository|head\.repo\.fork\s*==\s*false", _F)
_OPEN_TO_ALL = regex.compile(r"allowed_non_write_users\s*:\s*[\"']?\*|allowed_bots\s*:\s*[\"']?\*", _F)
_REVIEW = regex.compile(r"\breview\w*\b|security-review|/review\b", _F)
_LIMIT = regex.compile(r"--max-turns\b|\bmax[-_]turns\b|--max-budget\w*|\bmax[-_]budget\w*|--max-tokens\b|\bmax[-_]tokens\b|\bstop-after\b"
                       r"|--max-session-turns\b|\bmaxSessionTurns\b|\btimeout[-_]minutes\b", _F)
_STEP_OUTPUT = regex.compile(r"\$\{\{[^}\n]*?\bsteps\.([\w-]+)\.outputs\.[\w-]+[^}\n]*\}\}")
_NEEDS_OUTPUT = regex.compile(r"\$\{\{[^}\n]*?\bneeds\.([\w-]+)\.outputs\.[\w-]+[^}\n]*\}\}")
_ARTIFACT = regex.compile(r"actions/download-artifact|dawidd6/action-download-artifact|\bgh\s+run\s+download\b", _F)
_CACHE = regex.compile(r"^actions/cache(?:/restore)?@", _F)
_PR_KEY = regex.compile(r"github\.head_ref|github\.event\.pull_request\.(?:number|head)|github\.event\.number|github\.ref\b", _F)
_FIREWALL_OFF = regex.compile(r"COPILOT_AGENT_FIREWALL_ENABLED[\"']?\s*[:=]\s*[\"']?(?:false|0)\b", _F)
_FIREWALL_WIDE = regex.compile(r"COPILOT_AGENT_FIREWALL_ALLOW_LIST(?:_ADDITIONS)?[\"']?\s*[:=]\s*[\"']?[^\n\"']*(?:\*|0\.0\.0\.0)", _F)
_PROJECT_CONFIG = regex.compile(r"(?:^|/)(?:\.mcp\.json|\.claude/settings(?:\.local)?\.json|\.cursor/(?:hooks|mcp)\.json|\.codex/(?:hooks\.json|config\.toml)"
                                r"|\.gemini/settings\.json|\.vscode/mcp\.json|\.github/hooks/[^/]+\.json)$", _F)
_LOADS_CONFIG = regex.compile(r"--mcp-config[= ]+[\"']?(?!\$\{\{)[\w./-]+|\bmcp_config\s*:\s*[\"']?[\w./-]+\.json|\bsettings\s*:\s*[\"']?\.?[\w./-]+\.json", _F)
_ABSENT = object()


def _strs(value: Any) -> dict[str, str]:
    return {str(k): v for k, v in value.items() if isinstance(v, str)} if isinstance(value, dict) else {}


def _search(rx: regex.Pattern[str], text: str) -> regex.Match[str] | None:
    try:
        return rx.search(text, timeout=TIMEOUT)
    except TimeoutError:
        return None


def triggers_of(data: dict[Any, Any]) -> dict[str, Any]:
    """Events of a workflow. YAML 1.1 reads the key ``on`` as the boolean true."""
    on = data.get("on", data.get(True))
    if isinstance(on, str):
        return {on: None}
    if isinstance(on, list):
        return {str(x): None for x in on}
    if isinstance(on, dict):
        return {str(k): v for k, v in on.items()}
    return {}


def write_scopes(perms: Any) -> tuple[bool, list[str]]:
    """(everything writable, scopes granted write) of a ``permissions:`` value."""
    if isinstance(perms, str):
        return perms.strip().lower() == "write-all", []
    if isinstance(perms, dict):
        return False, sorted(str(k) for k, v in perms.items() if str(v).lower() == "write")
    return False, []


@dataclass
class Step:
    job: str
    index: int
    raw: dict[str, Any]
    start: int          # offset of the step in the file
    end: int
    agent: bool = False

    @property
    def uses(self) -> str:
        v = self.raw.get("uses")
        return v if isinstance(v, str) else ""

    @property
    def run(self) -> str:
        v = self.raw.get("run")
        return v if isinstance(v, str) else ""

    @property
    def inputs(self) -> dict[str, str]:
        w = self.raw.get("with")
        return {str(k): (v if isinstance(v, str) else str(v)) for k, v in w.items() if isinstance(v, (str, int, float, bool))} \
            if isinstance(w, dict) else {}

    @property
    def env(self) -> dict[str, str]:
        return _strs(self.raw.get("env"))

    @property
    def sid(self) -> str:
        v = self.raw.get("id")
        return v if isinstance(v, str) else ""

    def text(self) -> str:
        """Everything the step passes to the action or the shell."""
        return "\n".join([self.run, *(f"{k}: {v}" for k, v in self.inputs.items())])

    def label(self) -> str:
        name = self.raw.get("name")
        return (name if isinstance(name, str) and name else self.uses or self.run.strip().split("\n", 1)[0])[:70]


class CiAnalyzer:
    id: ClassVar[str] = "ci"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = (*(f"AG-CI-{i:03d}" for i in range(1, 16)), "AG-SUPPLY-022")

    def run(self, ctx: Context) -> None:
        self.ctx = ctx
        inv = ctx.inventory
        self.project_config = sorted(p for p in inv.artifacts if _search(_PROJECT_CONFIG, p))
        for path in sorted(inv.docs):
            doc: Doc = inv.docs[path]
            if doc.surface.group != "ci" or not isinstance(doc.value, dict):
                continue
            if doc.surface.id == "ci.copilot_setup":
                self._copilot_setup(doc)
            if path not in inv.agentic_ci:
                continue
            if doc.surface.id == "ci.gitlab":
                self._gitlab(doc)
            else:
                self._github(doc)
        for path in sorted(inv.surfaces):
            if inv.surfaces[path].id == "ci.agentic_md":
                self._agentic_md(path)

    # -- helpers ------------------------------------------------------------------------------------
    def _span(self, path: str, text: str, start: int, end: int | None = None) -> Span:
        at = self.ctx.inventory.texts.get(path)
        if at is not None and at.text == text:
            return at.span(start, end if end is not None else start)
        line = text.count("\n", 0, start) + 1
        return Span(path=path, start_line=line, start_col=start - (text.rfind("\n", 0, start) + 1) + 1)

    def _emit(self, rule: str, doc: Doc, start: int, message: str, *, end: int | None = None, key: str, snippet: str = "",
              severity: Severity | None = None, related: list[Span] | None = None, detail: str = "") -> None:
        art = self.ctx.inventory.artifacts.get(doc.path)
        text = doc.text
        if not snippet:
            ls = text.rfind("\n", 0, start) + 1
            le = text.find("\n", start)
            snippet = text[ls: le if le >= 0 else len(text)].strip()
        self.ctx.emit(rule, component_ids=[art.component_id] if art else [], span=self._span(doc.path, text, start, end),
                      snippet=snippet[:300], match=f"{doc.path}:{key}", kind=EvidenceKind.config, message=message, severity=severity,
                      related=related, detail=detail)

    def _find(self, doc: Doc, needle: str, start: int, end: int | None = None) -> int:
        """Offset of ``needle`` inside [start, end), else ``start``."""
        if needle:
            hit = doc.text.find(needle, start, end if end is not None else len(doc.text))
            if hit >= 0:
                return hit
        return start

    def _steps(self, doc: Doc, job_name: str, job: dict[str, Any]) -> list[Step]:
        text = doc.text
        m = _search(regex.compile(rf"(?m)^[ \t]+[\"']?{regex.escape(job_name)}[\"']?[ \t]*:"), text)
        pos = m.start() if m else 0
        raw_steps = [s for s in (job.get("steps") or []) if isinstance(s, dict)] if isinstance(job.get("steps"), list) else []
        if isinstance(job.get("uses"), str):               # a job that calls a reusable workflow
            raw_steps = [{"uses": job["uses"], "with": job.get("with"), "name": job_name, "secrets": job.get("secrets")}]
        steps: list[Step] = []
        for i, raw in enumerate(raw_steps):
            needle = ""
            if isinstance(raw.get("uses"), str):
                needle = raw["uses"]
            elif isinstance(raw.get("run"), str) and raw["run"].strip():
                needle = raw["run"].strip().split("\n", 1)[0][:60]
            elif isinstance(raw.get("name"), str):
                needle = raw["name"]
            hit = text.find(needle, pos) if needle else -1
            start = hit if hit >= 0 else pos
            steps.append(Step(job_name, i, raw, start, len(text)))
            pos = start + 1
        for a, b in zip(steps, steps[1:]):
            a.end = b.start
        for s in steps:
            s.agent = bool(_search(AGENT_CI_MARKERS, s.uses) or _search(AGENT_CI_MARKERS, s.run))
        return steps

    # -- GitHub Actions --------------------------------------------------------------------------------
    def _github(self, doc: Doc) -> None:
        data = doc.data
        text = doc.text
        triggers = triggers_of(data)
        names = set(triggers)
        untrusted = sorted(names & UNTRUSTED)
        privileged = sorted(names & PRIVILEGED)
        jobs = data.get("jobs") if isinstance(data.get("jobs"), dict) else {}
        wf_env = _strs(data.get("env"))
        wf_perms = data.get("permissions", _ABSENT)
        trigger_at = max(self._find(doc, untrusted[0], 0) if untrusted else 0, 0)
        all_steps: dict[str, list[Step]] = {}
        for job_name, job in jobs.items():
            if isinstance(job, dict):
                all_steps[str(job_name)] = self._steps(doc, str(job_name), job)
        agent_ids = {(j, s.sid) for j, steps in all_steps.items() for s in steps if s.agent and s.sid}
        agent_jobs = {j for j, steps in all_steps.items() if any(s.agent for s in steps)}
        if _search(_FIREWALL_OFF, text) or _search(_FIREWALL_WIDE, text):
            self._firewall(doc)
        for job_name, steps in all_steps.items():
            job = jobs[job_name]
            self._pins(doc, steps)
            self._agent_output(doc, job_name, steps, agent_ids, agent_jobs)
            agents = [s for s in steps if s.agent]
            if not agents:
                continue
            job_env = _strs(job.get("env"))
            perms = job.get("permissions", wf_perms)
            all_write, writes = write_scopes(perms) if perms is not _ABSENT else (False, [])
            gate = _search(_GATE, str(job.get("if") or ""))
            runs_on = job.get("runs-on")
            self_hosted = "self-hosted" in (runs_on if isinstance(runs_on, list) else [str(runs_on)] if isinstance(runs_on, str) else
                                            [str(x) for x in (runs_on.get("labels") or [])] if isinstance(runs_on, dict) and
                                            isinstance(runs_on.get("labels"), list) else
                                            [str(runs_on.get("labels") or runs_on.get("group") or "")] if isinstance(runs_on, dict) else [])
            job_limit = "timeout-minutes" in job
            head_at: int | None = None
            for s in steps:
                if head_at is None and ((s.uses.lower().startswith("actions/checkout@") and _search(_HEAD_REF, s.inputs.get("ref", "")))
                                        or _search(_HEAD_RUN, s.run)):
                    head_at = s.start
                if not s.agent:
                    continue
                stext = s.text()
                step_gate = gate or _search(_GATE, str(s.raw.get("if") or ""))
                open_to_all = bool(_search(_OPEN_TO_ALL, stext))
                gated = bool(step_gate) and not open_to_all
                tag = f"{job_name}:{s.index}"
                # -- AG-CI-001: untrusted text in the prompt -------------------------------------------
                env_all = {**wf_env, **job_env, **s.env}
                tainted_env = {k for k, v in env_all.items() if _search(_UNTRUSTED_EXPR, v)}
                seen_expr: set[str] = set()
                for m in _UNTRUSTED_EXPR.finditer(text, s.start, s.end):
                    line_start = text.rfind("\n", 0, m.start()) + 1
                    line = text[line_start: text.find("\n", m.start()) if text.find("\n", m.start()) >= 0 else len(text)]
                    if regex.match(r"\s*[A-Za-z_][\w-]*\s*:\s*\$\{\{", line) and line.split(":", 1)[0].strip() in s.env:
                        continue                       # an `env:` assignment; reported below if the prompt uses the variable
                    if m.group(0) in seen_expr:
                        continue
                    seen_expr.add(m.group(0))
                    self._emit("AG-CI-001", doc, m.start(), end=m.end(), key=f"001:{tag}:{m.group(0)}",
                               message=f"The agent step '{s.label()}' puts `{m.group(0)}` into what the agent reads. Whoever "
                                       "opened the issue, pull request or comment writes that text, so they write part of the "
                                       "agent's instructions.")
                for var in sorted(tainted_env):
                    use = _search(regex.compile(rf"\$\{{?{regex.escape(var)}\b|\benv\.{regex.escape(var)}\b"), stext)
                    if use and not seen_expr:
                        at = self._find(doc, f"${var}", s.start, s.end)
                        at = at if at != s.start else self._find(doc, var, s.start, s.end)
                        self._emit("AG-CI-001", doc, at, key=f"001:{tag}:env:{var}",
                                   message=f"The agent step '{s.label()}' reads `{var}`, which holds issue, pull-request or comment "
                                           "text. Passing it through an environment variable stops shell injection, but the text "
                                           "still reaches the agent as instructions.")
                # -- secrets and token -----------------------------------------------------------------
                scope_text = "\n".join([*env_all.values(), *s.inputs.values(), str(s.raw.get("secrets") or "")])
                secrets = sorted(set(_SECRET.findall(scope_text)))
                inherits = s.raw.get("secrets") == "inherit" or bool(_search(_ALL_SECRETS, scope_text))
                # -- AG-CI-002 ----------------------------------------------------------------------------
                if privileged and not gated and (secrets or inherits) and (all_write or writes or perms is _ABSENT):
                    token = "`permissions: write-all`" if all_write else f"write access to {', '.join(writes[:4])}" if writes else \
                        "no `permissions:` block, so the token has the repository default (often read and write)"
                    self._emit("AG-CI-002", doc, s.start, key=f"002:{tag}",
                               related=[self._span(doc.path, text, trigger_at)],
                               message=f"The agent in job '{job_name}' runs on `{privileged[0]}`, which outsiders can trigger, with "
                                       f"{'all secrets' if inherits else 'secrets (' + ', '.join(secrets[:3]) + ')'} and {token}. "
                                       "Text in the triggering issue, comment or pull request can steer the agent into using both.")
                # -- AG-CI-003 ----------------------------------------------------------------------------
                grant = self._tool_grant(s)
                if untrusted and grant and (not gated):
                    what, strong, at_text = grant
                    sev = None if strong else Severity.medium
                    if not privileged and "issues" not in names and not open_to_all:
                        sev = (sev or Severity.high).bump(-1)
                    self._emit("AG-CI-003", doc, self._find(doc, at_text, s.start, s.end), key=f"003:{tag}", severity=sev,
                               message=f"The agent step '{s.label()}' is given {what} and the workflow runs on "
                                       f"`{untrusted[0]}`, which people outside the repository can trigger.")
                # -- AG-CI-004 ----------------------------------------------------------------------------
                if perms is not _ABSENT and (all_write or len(writes) >= 4):
                    at = self._find(doc, "permissions", self._find(doc, job_name + ":", 0) if "permissions" in job else 0)
                    self._emit("AG-CI-004", doc, at, key=f"004:{job_name}",
                               message=f"Job '{job_name}' runs an agent with "
                                       f"{'`permissions: write-all`' if all_write else 'write access to ' + ', '.join(writes)}. The "
                                       "agent's token can change far more than the task needs.")
                # -- AG-CI-005 ----------------------------------------------------------------------------
                if s.uses and not s.uses.startswith(("./", "docker://")) and not _search(_SHA_PIN, s.uses):
                    self._emit("AG-CI-005", doc, s.start, end=s.start + len(s.uses), key=f"005:{tag}:{s.uses}", snippet=f"uses: {s.uses}",
                               message=f"The agent action `{s.uses}` is referenced by a tag or branch. Whoever controls that ref "
                                       "controls what runs with this job's secrets and token.")
                # -- AG-CI-007 ----------------------------------------------------------------------------
                for m in BYPASS_FLAG.finditer(text, s.start, s.end):
                    self._emit("AG-CI-007", doc, m.start(), end=m.end(), key=f"007:{tag}:{m.group(0).lower()}",
                               message=f"The agent is started with `{m.group(0)}`, which turns off its permission checks or "
                                       "sandbox for the whole run.")
                    break
                # -- AG-CI-008 / AG-CI-010: pull-request code and instructions -----------------------------------
                pr_code = head_at is not None and bool(privileged)
                plain_pr = not privileged and bool(names & {"pull_request", "pull_request_review", "pull_request_review_comment"})
                loads = _search(_LOADS_CONFIG, stext)
                if pr_code and not gated:
                    self._emit("AG-CI-008", doc, head_at if head_at is not None else s.start, key=f"008:{tag}",
                               related=[self._span(doc.path, text, s.start)],
                               message=f"Job '{job_name}' checks out the pull request's head on `{privileged[0]}` and then runs an "
                                       "agent in it. A headless agent treats the folder as trusted: hooks and MCP servers the "
                                       "pull request adds (`.claude/settings.json`, `.mcp.json`) start without a prompt.")
                elif plain_pr and (secrets or inherits) and (loads or self.project_config):
                    src = f"`{loads.group(0)}`" if loads else f"`{self.project_config[0]}`"
                    self._emit("AG-CI-008", doc, s.start, key=f"008:{tag}", severity=Severity.medium,
                               message=f"The agent in job '{job_name}' runs on pull-request code with secrets and loads project "
                                       f"configuration ({src}). A pull request can change that file, and a headless agent loads "
                                       "its hooks and MCP servers without asking.")
                if _search(_REVIEW, stext + " " + s.label() + " " + s.uses) and not gated:
                    if pr_code:
                        self._emit("AG-CI-010", doc, s.start, key=f"010:{tag}",
                                   message=f"The reviewing agent in job '{job_name}' works in the pull request's own checkout, so "
                                           "it reads its instruction files and skills (`CLAUDE.md`, `AGENTS.md`, `.claude/skills`) "
                                           "from the code under review. The author of the pull request writes the reviewer's rules.")
                    elif plain_pr:
                        self._emit("AG-CI-010", doc, s.start, key=f"010:{tag}", severity=Severity.medium,
                                   message=f"The reviewing agent in job '{job_name}' runs in the pull request's checkout and reads "
                                           "its instruction files and skills from the code under review.")
                # -- AG-CI-009 ----------------------------------------------------------------------------
                extra = [x for x in secrets if not _search(_EXPECTED_SECRET, x)]
                if inherits or len(extra) >= 2:
                    at = self._find(doc, "secrets." + extra[0], s.start, s.end) if extra else self._find(doc, "secrets", s.start, s.end)
                    if at == s.start and extra:
                        at = self._find(doc, "secrets." + extra[0], 0)
                    self._emit("AG-CI-009", doc, at, key=f"009:{tag}",
                               message=f"The agent step '{s.label()}' can read "
                                       f"{'every repository secret' if inherits else 'secrets it does not need to talk to the model (' + ', '.join(extra[:5]) + ')'}. "
                                       "Anything in the agent's environment can be printed or sent by an injected instruction.")
                # -- AG-CI-012 ----------------------------------------------------------------------------
                if self_hosted and untrusted and not gated:
                    self._emit("AG-CI-012", doc, self._find(doc, "self-hosted", 0), key=f"012:{job_name}",
                               message=f"Job '{job_name}' runs an agent on a self-hosted runner and is triggered by "
                                       f"`{untrusted[0]}`. The runner keeps its files, network position and credentials between "
                                       "jobs, so one steered run can affect later ones.")
                # -- AG-CI-014 ----------------------------------------------------------------------------
                if not job_limit and "timeout-minutes" not in s.raw and not _search(_LIMIT, stext):
                    self._emit("AG-CI-014", doc, s.start, key=f"014:{tag}",
                               message=f"The agent step '{s.label()}' has no turn, cost or time limit (`--max-turns`, "
                                       "`timeout-minutes`). A looping or steered agent runs until the platform's six-hour limit.")
                # -- AG-CI-015 ----------------------------------------------------------------------------
                for prev in steps[: s.index]:
                    if "workflow_run" in names and (_search(_ARTIFACT, prev.uses) or _search(_ARTIFACT, prev.run)):
                        self._emit("AG-CI-015", doc, prev.start, key=f"015:{tag}:artifact",
                                   message=f"Job '{job_name}' downloads an artifact produced by the triggering run and then runs "
                                           "an agent. On `workflow_run` that artifact comes from a run that may have built "
                                           "untrusted pull-request code, and its contents reach the agent as context.")
                        break
                    if untrusted and _search(_CACHE, prev.uses) and _search(_PR_KEY, " ".join(prev.inputs.values())):
                        self._emit("AG-CI-015", doc, prev.start, key=f"015:{tag}:cache",
                                   message=f"Job '{job_name}' restores a cache keyed on the pull request or branch before running "
                                           "an agent. A pull request can fill that cache with files the agent later reads.")
                        break

    def _tool_grant(self, s: Step) -> tuple[str, bool, str] | None:
        """(description, unrestricted, text to point at) when the step gives the agent shell or write tools."""
        best: tuple[str, bool, str] | None = None
        for key, value in [*s.inputs.items(), ("run", s.run)]:
            values = [value] if key.lower() in ("allowed_tools", "allowed-tools", "allowedtools") else \
                [m.group("v") for m in _TOOLS_ARG.finditer(value)]
            for v in values:
                m = _search(_OPEN_TOOL, v)
                if m:
                    return f"unrestricted `{m.group(0)}`", True, m.group(0)
                m = _search(_SCOPED_TOOL, v)
                if m and best is None:
                    best = (f"shell or write tools (`{m.group(0)[:60]}`)", False, m.group(0))
            m = _search(_OTHER_GRANT, value)
            if m and best is None:
                best = (f"write access (`{m.group(0)}`)", True, m.group(0))
            m = _search(BYPASS_FLAG, value)
            if m:
                return f"every tool (`{m.group(0)}`)", True, m.group(0)
        return best

    def _pins(self, doc: Doc, steps: list[Step]) -> None:
        for s in steps:
            u = s.uses
            if not u or s.agent or u.startswith("./") or "@" not in u and not u.startswith("docker://"):
                continue
            if _search(_SHA_PIN, u) or (u.startswith("docker://") and _search(_DOCKER_DIGEST, u)):
                continue
            first = bool(_search(_FIRST_PARTY, u))
            self._emit("AG-SUPPLY-022", doc, s.start, end=s.start + len(u), key=f"s022:{s.job}:{s.index}:{u}", snippet=f"uses: {u}",
                       severity=Severity.low if first else None,
                       message=f"`{u}` in a workflow that runs an agent is referenced by a tag or branch, not a commit. A moved "
                               "tag changes what runs next to the agent's secrets.")

    def _agent_output(self, doc: Doc, job_name: str, steps: list[Step], agent_ids: set[tuple[str, str]], agent_jobs: set[str]) -> None:
        text = doc.text
        for s in steps:
            script = s.run or (s.inputs.get("script", "") if "github-script" in s.uses else "")
            if not script or s.agent:
                continue
            hit = None
            for m in _STEP_OUTPUT.finditer(script):
                if (job_name, m.group(1)) in agent_ids:
                    hit = m
                    break
            if hit is None:
                for m in _NEEDS_OUTPUT.finditer(script):
                    if m.group(1) in agent_jobs:
                        hit = m
                        break
            if hit is None:
                continue
            at = text.find(hit.group(0), s.start)
            self._emit("AG-CI-006", doc, at if at >= 0 else s.start, end=(at + len(hit.group(0))) if at >= 0 else None,
                       key=f"006:{job_name}:{s.index}",
                       message=f"Step '{s.label()}' pastes the agent's output (`{hit.group(0)}`) into a script. The workflow "
                               "engine substitutes the text before the shell parses it, so whatever the agent was steered into "
                               "writing runs as code.")

    def _firewall(self, doc: Doc) -> None:
        for rx, what in ((_FIREWALL_OFF, "turns the Copilot agent firewall off"),
                         (_FIREWALL_WIDE, "widens the Copilot agent firewall's allow-list to any host")):
            m = _search(rx, doc.text)
            if m:
                self._emit("AG-CI-011", doc, m.start(), end=m.end(), key=f"011:fw:{m.group(0)[:40]}",
                           message=f"`{m.group(0)[:80]}` {what}, so the agent can send data anywhere.")

    def _copilot_setup(self, doc: Doc) -> None:
        if doc.path not in self.ctx.inventory.agentic_ci and (_search(_FIREWALL_OFF, doc.text) or _search(_FIREWALL_WIDE, doc.text)):
            self._firewall(doc)
        jobs = doc.data.get("jobs") if isinstance(doc.data.get("jobs"), dict) else {}
        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            for s in self._steps(doc, str(job_name), job):
                net, dyn = _search(_NET, s.run), _search(_DYN_EXEC, s.run)
                if net and dyn:
                    at = self._find(doc, dyn.group(0), s.start, s.end)
                    self._emit("AG-CI-011", doc, at, key=f"011:{job_name}:{s.index}",
                               message=f"Copilot setup step '{s.label()}' downloads content and runs it "
                                       f"(`{net.group(0)}` … `{dyn.group(0).strip()}`). Setup steps run before the agent's firewall "
                                       "applies and with the repository's secrets for the agent.")

    # -- GitLab CI -----------------------------------------------------------------------------------------
    def _gitlab(self, doc: Doc) -> None:
        text = doc.text
        for m in BYPASS_FLAG.finditer(text):
            self._emit("AG-CI-007", doc, m.start(), end=m.end(), key=f"007:gitlab:{m.group(0).lower()}",
                       message=f"The agent is started with `{m.group(0)}`, which turns off its permission checks or sandbox.")
            break
        for line_m in regex.finditer(r"(?m)^.*$", text):
            line = line_m.group(0)
            if not _search(AGENT_CI_MARKERS, line):
                continue
            m = _search(_GITLAB_UNTRUSTED, line)
            if m:
                self._emit("AG-CI-001", doc, line_m.start() + m.start(), end=line_m.start() + m.end(), key=f"001:gitlab:{m.group(0)}",
                           message=f"The agent's command line includes `{m.group(0)}`: merge-request or commit text written by "
                                   "the contributor becomes part of the agent's instructions.")

    # -- GitHub agentic workflows (Markdown with frontmatter) -------------------------------------------------
    def _agentic_md(self, path: str) -> None:
        inv = self.ctx.inventory
        at = inv.texts.get(path)
        art = inv.artifacts.get(path)
        if at is None or art is None or at.fm is None or not isinstance(at.fm.data, dict):
            return
        fm: dict[Any, Any] = at.fm.data
        text = at.text
        doc = Doc(path=path, surface=inv.surfaces[path], value=fm, fmt="md", text=text)
        tools = fm.get("tools") if isinstance(fm.get("tools"), dict) else {}
        problems: list[tuple[str, str]] = []
        bash = tools.get("bash")
        if bash is True or (isinstance(bash, list) and any(str(x).strip() in ("*", ":*") for x in bash)) or bash in ("*", ":*"):
            problems.append(("bash", "`tools.bash` allows every shell command"))
        gh = tools.get("github") if isinstance(tools.get("github"), dict) else {}
        if isinstance(gh.get("toolsets"), list) and "all" in [str(x).lower() for x in gh["toolsets"]]:
            problems.append(("toolsets", "`tools.github.toolsets` is `all`"))
        net = fm.get("network")
        allowed = net.get("allowed") if isinstance(net, dict) else None
        if net == "*" or (isinstance(allowed, list) and any(str(x).strip() == "*" for x in allowed)):
            problems.append(("network", "`network` allows every host"))
        all_write, writes = write_scopes(fm.get("permissions"))
        if (all_write or writes) and "safe-outputs" not in fm:
            problems.append(("permissions", "the agent job itself holds write permissions ("
                             + ("write-all" if all_write else ", ".join(writes)) + ") instead of using `safe-outputs`"))
        for needle, what in problems:
            self._emit("AG-CI-013", doc, self._find(doc, needle, 0), key=f"013:{needle}",
                       message=f"Agentic workflow: {what}. An agent that reads issues or pull requests with this much reach can be "
                               "steered into using it.")
        names = set(triggers_of(fm))
        if names & UNTRUSTED:
            for m in _UNTRUSTED_EXPR.finditer(text):
                self._emit("AG-CI-001", doc, m.start(), end=m.end(), key=f"001:md:{m.group(0)}",
                           message=f"The agentic workflow's instructions include `{m.group(0)}`: text written by whoever opened "
                                   "the issue or pull request becomes part of the agent's instructions.")
                break
        if not any(k in fm for k in ("timeout-minutes", "timeout_minutes", "stop-after")) and not _search(_LIMIT, at.fm.raw or ""):
            self._emit("AG-CI-014", doc, 0, key="014:md",
                       message="The agentic workflow sets no time, turn or cost limit (`timeout-minutes`, `stop-after`, "
                               "`max-turns`).")


__all__ = ["BYPASS_FLAG", "CiAnalyzer", "PRIVILEGED", "UNTRUSTED", "triggers_of", "write_scopes"]
