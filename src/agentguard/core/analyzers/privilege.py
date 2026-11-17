"""Least privilege (engine J): what a component can do, what it declares, and
the smallest grant that would cover what it does.

* extends the capability set with the labels the risk tier and the policy
  output need (shell, file read, file write inside and outside the workspace,
  financial execution, host-elevated execution);
* applies the PRIV rules to skill, command and subagent definitions;
* reports capability labels (FLOW-010 to 012) and delegation that widens a
  grant (FLOW-014);
* computes a minimal ``allowed-tools`` list, permission rules and a sandbox
  profile per component (``ctx.data["least_privilege"]``), which the report
  carries and ``agentguard fix`` proposes.

Pure: reads the inventory and the capabilities gathered so far.
"""

from __future__ import annotations

import posixpath
from typing import Any, ClassVar

import regex

from ..artifacts import ArtifactText
from ..models import Component, Span
from ..models.enums import ArtifactRole, CapLabel, ComponentKind, Confidence, EvidenceKind, Severity
from ..textutil import TIMEOUT
from .base import Context
from .heuristics import EXEC_CODE, finditer, search
from .skill import parse_allowed_tools

_F = regex.IGNORECASE | regex.MULTILINE
_CODE = (ArtifactRole.script, ArtifactRole.source_code)
_PROSE = (ArtifactRole.skill_md, ArtifactRole.instruction_md, ArtifactRole.command_md)
_HOME = r"(?:~|\$HOME|\$\{HOME\}|%USERPROFILE%|%APPDATA%|%LOCALAPPDATA%|\$env:(?:USERPROFILE|APPDATA|HOME))"
_SYSTEM = r"/(?:etc|usr|var|opt|Library|bin|sbin|root|boot|srv)\b|[A-Za-z]:\\(?:Windows|Program Files|ProgramData)"
_WRITE_OUTSIDE = regex.compile(
    rf"(?:>{{1,2}}|\btee\b(?:\s+-a)?|\bcp\b[^\n|;&]*|\bmv\b[^\n|;&]*|\binstall\b[^\n|;&]*|\bln\s+-s\w*[^\n|;&]*|\bmkdir\b(?:\s+-p)?|\btouch\b|\bOut-File\b[^\n|;&]*"
    rf"|\bSet-Content\b[^\n|;&]*|\bAdd-Content\b[^\n|;&]*|\bCopy-Item\b[^\n|;&]*)\s*[\"']?(?:{_HOME}[/\\]|{_SYSTEM})"
    rf"|\bopen\(\s*(?:os\.path\.expanduser\(\s*)?[\"'](?:~[/\\]|{_SYSTEM})[^\"']*[\"']\s*\)?\s*,\s*[\"'][wax+b]+[\"']"
    rf"|\b(?:Path\.home\(\)|os\.path\.expanduser\(\s*[\"']~)[^\n]{{0,120}}\b(?:write_text|write_bytes|mkdir|touch|open\([^)]*[\"'][wa])"
    rf"|\b(?:writeFile|writeFileSync|appendFile|appendFileSync|mkdirSync|copyFileSync|createWriteStream)\(\s*(?:path\.join\(\s*)?(?:os\.homedir\(\)|process\.env\.HOME|[\"'](?:~[/\\]|{_SYSTEM}))"
    rf"|\bshutil\.(?:copy\w*|move)\([^)\n]*(?:expanduser|Path\.home|[\"'](?:~[/\\]|{_SYSTEM}))", _F)
_WRITE_LOCAL = regex.compile(
    r"\bopen\([^)\n]*,\s*[\"'][wax+b]+[\"']|\.write_text\(|\.write_bytes\(|\b(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream)\("
    r"|\bjson\.dump\(|\bto_csv\(|\bsavefig\(|\.save\(|(?<![<>=|&0-9])>{1,2}\s*[\w./\"'$-]|\btee\b|\bsed\s+-i\b|\bcp\b|\bmv\b|\bmkdir\b|\btouch\b", _F)
_READ = regex.compile(r"\bopen\(|\.read_text\(|\.read_bytes\(|\b(?:readFile|readFileSync|createReadStream)\(|\bcat\b|\bhead\b|\btail\b|\bless\b"
                      r"|\bgrep\b|\bfind\b|\bglob\b|\bGet-Content\b|\bcsv\.reader\(|\bjson\.load\(|\bpd\.read_", _F)
_READ_OUTSIDE = regex.compile(
    rf"\b(?:open|read\w*|cat|ls|find|glob|walk|scandir|listdir|Get-ChildItem|Get-Content|readdir\w*|readFile\w*)\b[^\n]{{0,60}}?"
    rf"(?:{_HOME}[/\\](?!\.(?:ssh|aws|gnupg|kube|docker|config/gcloud|netrc|npmrc)\b)|os\.path\.expanduser\(\s*[\"']~[\"']?\s*\)|Path\.home\(\)(?!\s*/\s*[\"']\.(?:ssh|aws))"
    rf"|os\.homedir\(\)|[\"']/(?:home|Users)/)", _F)
_FINANCIAL = regex.compile(
    r"\bstripe\.(?:Charge|PaymentIntent|Transfer|Payout|Refund)s?\.create\b|\bstripe\.(?:charges|paymentIntents|transfers|payouts|refunds)\.create\b"
    r"|\bpaypal\b[^\n]{0,60}\b(?:payout|payment|capture)\b|\b(?:send|signAndSend|sendRaw)Transaction\(|\bweb3\.eth\.send|\beth_sendTransaction\b"
    r"|\b(?:place|submit|create)_?(?:market_?|limit_?)?order\(|\b(?:alpaca|binance|coinbase|kraken|ibkr|robinhood)\b[^\n]{0,80}\b(?:order|trade|buy|sell|withdraw)\b"
    r"|\bwire\s+transfer\b|\b(?:transfer|send|withdraw)\s+(?:funds|money|crypto|bitcoin|btc|eth|usdc?|tokens)\b|\bACH\s+(?:debit|credit|transfer)\b"
    r"|\b(?:make|submit|initiate|execute)\s+(?:a\s+|the\s+)?(?:payment|purchase|trade|transfer)\b|\bbuy\s+(?:now|shares|stock)\b", _F)
_ELEVATED = regex.compile(
    r"(?:^|[\s;&|(`])sudo\s+(?!-h\b|--help\b)\S|\brunas\s+/user|\bStart-Process\b[^\n]{0,80}-Verb\s+RunAs|\bdoas\s+\S|\bpkexec\b|\bsetcap\b|\bchmod\s+[ug]?\+s\b"
    r"|--privileged\b|--cap-add[=\s]+(?:ALL|SYS_ADMIN)|\bnsenter\b|\bsu\s+-\s*(?:root)?\s*-c\b", _F)
_ELEVATED_REQUEST = regex.compile(
    r"\b(?:must|needs?\s+to|has\s+to|should|requires?)\s+(?:be\s+)?(?:run|running|executed?|started)\s+(?:as\s+(?:root|administrator|admin|superuser)|with\s+sudo|on\s+the\s+host|outside\s+(?:of\s+)?the\s+sandbox|with(?:out)?\s+(?:the\s+)?sandbox(?:ing)?\s+(?:disabled|off)?)"
    r"|\b(?:run|execute|launch|start)\s+(?:this|it|the\s+\w+|these\s+commands?)\s+(?:as\s+(?:root|administrator)|with\s+(?:sudo|elevated|admin(?:istrator)?)\s*(?:privileges|rights|permissions)?|on\s+the\s+host|outside\s+(?:of\s+)?the\s+sandbox)"
    r"|\brequires?\s+(?:root|administrator|elevated|host)\s+(?:access|privileges|permissions|execution|rights)"
    r"|\bdangerouslyDisableSandbox\b|\b(?:set|use)\s+`?sandbox(?:_mode)?`?\s*(?:to|=|:)\s*`?[\"']?(?:false|off|none|danger-full-access)"
    r"|/elevated\s+(?:on|full)\b|\bexec\s+host\s*=\s*(?:gateway|node)\b", _F)
_UNTRUSTED_TOOLS = regex.compile(r"^(?:WebFetch|WebSearch|web_fetch|web_search|browser|fetch)\b", _F)
_SIDE_EFFECT_WORDS = regex.compile(
    r"\b(?:deploy(?:s|ing)?|publish(?:es|ing)?|releas(?:e|es|ing)|push(?:es|ing)?\s+(?:to|the)|merg(?:e|es|ing)|send(?:s|ing)?\s+(?:an?\s+)?(?:email|message|slack|notification|sms|tweet|post)"
    r"|post(?:s|ing)?\s+to|delet(?:e|es|ing)|drop(?:s|ping)?\s+(?:the\s+)?(?:table|database)|pay(?:s|ing|ment)?|transfer(?:s|ring)?|purchas(?:e|es|ing)"
    r"|commit(?:s|ting)?\s+(?:and\s+push|the\s+changes)|open(?:s|ing)?\s+a\s+pull\s+request|restart(?:s|ing)?|migrat(?:e|es|ing)\s+the\s+database)\b", _F)
_OTHER_AGENT_DIRS = regex.compile(
    rf"(?:{_HOME}|os\.path\.expanduser\(\s*[\"']~|Path\.home\(\)\s*/\s*[\"']|os\.homedir\(\)[^\n]{{0,20}}[\"'])[/\\]?\.(?:claude|codex|cursor|gemini|openclaw|agents|copilot|continue|windsurf)"
    rf"[/\\\"',\s]{{1,6}}(?:skills|agents|plugins|commands|rules|extensions|hooks)\b"
    r"|(?:^|[\s\"'=(])(?:\.\./)+(?:[\w.-]+/)*(?:skills|agents)/[\w.-]+/(?:SKILL\.md|scripts/)", _F)
_ENV_REQUEST = regex.compile(
    r"\b(?:export|set|setx)\s+([A-Z][A-Z0-9_]{3,})\s*=|\bos\.environ(?:\.get)?\s*[\[(]\s*[\"']([A-Z][A-Z0-9_]{3,})[\"']|\bos\.getenv\(\s*[\"']([A-Z][A-Z0-9_]{3,})[\"']"
    r"|\bprocess\.env\.([A-Z][A-Z0-9_]{3,})\b|\$\{?([A-Z][A-Z0-9_]{3,})\}?(?=[\s\"'/:)]|$)"
    r"|\b(?:requires?|needs?|set|provide|supply|export)\s+(?:the\s+|your\s+|an?\s+)?`([A-Z][A-Z0-9_]{3,})`", _F)
_SECRET_VAR = regex.compile(r"(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIALS?|PRIVATE)(?:_[A-Z0-9]+)?$|^(?:DATABASE_URL|AWS_SESSION_TOKEN)$")
_GENERIC_PREFIX = {"API", "APP", "SECRET", "ACCESS", "AUTH", "PRIVATE", "USER", "SERVICE", "CLIENT", "SESSION", "MY", "THE", "DB", "BASE"}
_SERVICE_WORDS = {
    "AWS": "aws|amazon|s3|ec2|lambda|bedrock|cloud", "GITHUB": "github|git\\b|repo|pull request|issue", "GH": "github|git\\b|repo|pull request",
    "GITLAB": "gitlab|git\\b|repo|merge request", "OPENAI": "openai|gpt|llm|model|ai\\b", "ANTHROPIC": "anthropic|claude|llm|model|ai\\b",
    "GEMINI": "gemini|google|llm|model", "GOOGLE": "google|gcp|gemini|drive|gmail|sheets|maps", "STRIPE": "stripe|payment|billing|invoice",
    "SLACK": "slack|chat|message|notif", "DISCORD": "discord|chat|message", "NPM": "npm|publish|package", "PYPI": "pypi|publish|package",
    "DATABASE": "database|sql|postgres|mysql|db\\b", "HF": "hugging ?face|model", "AZURE": "azure|microsoft", "TELEGRAM": "telegram|chat|message",
    "TWILIO": "twilio|sms|phone", "SENDGRID": "sendgrid|email|mail", "JIRA": "jira|atlassian|ticket|issue", "NOTION": "notion|notes|wiki",
    "LINEAR": "linear|ticket|issue",
}
_SHELL_FENCE = ("", "bash", "sh", "shell", "zsh", "console", "terminal", "powershell", "pwsh", "ps1", "bat", "cmd")
_BUILTINS = {"cd", "echo", "export", "if", "then", "fi", "for", "do", "done", "while", "case", "esac", "set", "unset", "source", "read",
             "true", "false", "exit", "return", "local", "function", "else", "elif", "printf", "test", "alias", "eval"}
_URL = regex.compile(r"https?://([A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?)", _F)
_PERMISSIVE_AGENT_MODES = {"bypasspermissions": "bypasses every permission check", "dontask": "never asks before a tool call",
                           "acceptedits": "accepts every file edit without asking", "auto": "approves tool calls automatically"}
_SENSITIVE = (CapLabel.code_exec, CapLabel.shell, CapLabel.external_egress, CapLabel.credential_access, CapLabel.destructive,
              CapLabel.persistence, CapLabel.financial, CapLabel.host_elevated, CapLabel.fs_write_outside)
_LABEL_RULES = ((CapLabel.ingests_untrusted_content, "AG-FLOW-010", "can bring untrusted third-party content into the conversation"),
                (CapLabel.reads_private_data, "AG-FLOW-011", "can read sensitive or workspace data"),
                (CapLabel.destructive, "AG-FLOW-012", "can modify or delete data irreversibly"))


def _fm(at: ArtifactText) -> dict[str, Any]:
    return at.fm.data if at.fm is not None and isinstance(at.fm.data, dict) else {}


def _fm_span(at: ArtifactText, key: str) -> Span:
    raw = at.fm.raw if at.fm is not None else ""
    pos = at.text.find(raw) if raw else -1
    m = regex.search(rf"(?m)^[ \t]*[\"']?{regex.escape(key)}[\"']?[ \t]*:", raw) if raw else None
    if m and pos >= 0:
        return at.span(pos + m.start(), pos + m.end())
    return Span(path=at.path, start_line=1)


def _tool_names(value: Any) -> list[str] | None:
    """Tool names of a subagent `tools` field (comma string or list); None when the field is absent (inherits everything)."""
    if value is None:
        return None
    if isinstance(value, str):
        return [t.strip() for t in regex.split(r"[,\s]+", value) if t.strip()]
    if isinstance(value, list):
        return [str(t).strip() for t in value if str(t).strip()]
    return []


def command_heads(at: ArtifactText) -> list[str]:
    """First words of the commands a markdown file shows in shell fences and load-time injections."""
    heads: list[str] = []
    blocks = [at.text[f.body_start:f.body_end] for f in at.fence_list if f.info.strip().lower().split(" ")[0] in _SHELL_FENCE]
    blocks += [b.command for b in at.bang]
    for block in blocks:
        for line in block.splitlines():
            line = regex.sub(r"^\s*(?:\$|>|PS>|#\s*)\s*", "", line).strip()
            if not line or line.startswith("#"):
                continue
            head = line.split()[0].strip("\"'`()")
            head = posixpath.basename(head) if "/" in head and not head.startswith(".") else head
            if head and head not in _BUILTINS and regex.fullmatch(r"[A-Za-z0-9_.+/-]{1,40}", head) and head not in heads:
                heads.append(head)
    return heads[:12]


class PrivilegeAnalyzer:
    id: ClassVar[str] = "privilege"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = (
        "AG-PRIV-003", "AG-PRIV-005", "AG-PRIV-006", "AG-PRIV-007", "AG-PRIV-008/skill-grant", "AG-PRIV-009", "AG-PRIV-010", "AG-PRIV-011",
        "AG-PRIV-012", "AG-PRIV-013", "AG-PRIV-014", "AG-FLOW-010", "AG-FLOW-011", "AG-FLOW-012", "AG-FLOW-014",
    )

    def run(self, ctx: Context) -> None:
        self.ctx = ctx
        inv = ctx.inventory
        self._capabilities()
        by_comp: dict[str, list[ArtifactText]] = {}
        for at in ctx.texts():
            by_comp.setdefault(at.artifact.component_id, []).append(at)
        plans: dict[str, dict[str, Any]] = ctx.data.setdefault("least_privilege", {})  # type: ignore[assignment]
        for comp in sorted(inv.components.values(), key=lambda c: c.id):
            texts = by_comp.get(comp.id, [])
            if comp.kind == ComponentKind.skill:
                md = next((t for t in texts if t.artifact.role == ArtifactRole.skill_md), None)
                if md is not None:
                    self._skill(comp, md, texts)
                    plans[comp.id] = minimal_grant(comp, texts)
            elif comp.kind == ComponentKind.subagent:
                md = next((t for t in texts if t.artifact.role == ArtifactRole.instruction_md), None)
                if md is not None:
                    self._subagent(comp, md)
            elif comp.kind in (ComponentKind.plugin, ComponentKind.command, ComponentKind.bundle, ComponentKind.mcp_server):
                if comp.labels():
                    plans[comp.id] = minimal_grant(comp, texts)
            if comp.kind in (ComponentKind.skill, ComponentKind.plugin, ComponentKind.command, ComponentKind.subagent, ComponentKind.bundle):
                self._shared(comp, texts)
            self._labels(comp)
        self._delegation(by_comp)

    # -- capability set --------------------------------------------------------------------------------
    def _capabilities(self) -> None:
        ctx = self.ctx
        for at in ctx.texts():
            role = at.artifact.role
            comp = ctx.inventory.components.get(at.artifact.component_id)
            if comp is None or role in (ArtifactRole.repo_code, ArtifactRole.repo_doc) or comp.kind in (
                    ComponentKind.mcp_client_config, ComponentKind.repository):
                continue
            code = role in _CODE
            if not code and role not in _PROSE:
                continue
            for unit in at.units:
                if unit.scope not in ("body", "code", "command"):
                    continue
                t = unit.norm.text
                explicit = code or unit.scope == "command"

                def cap(label: CapLabel, m: regex.Match[str], reason: str, prose_ok: bool = False) -> None:
                    start = t.rfind("\n", 0, m.start()) + 1
                    end = t.find("\n", m.start())
                    line = t[start:end if end >= 0 else len(t)]
                    if code and line.lstrip().startswith(("#", "//", "* ")) and not line.lstrip().startswith("#!"):
                        return
                    off = ctx.unit_abs(unit, m.start())
                    fenced = unit.base is not None and off is not None and at.in_code(off)
                    if not (explicit or fenced or prose_ok):
                        return
                    ctx.add_capability(comp.id, label, confidence=Confidence.high if explicit or fenced else Confidence.medium,
                                       span=ctx.unit_span(unit, m.start(), m.end()), snippet=line.strip()[:200], reason=reason,
                                       kind=EvidenceKind.ast if code else EvidenceKind.regex)

                for m in finditer(_WRITE_OUTSIDE, t)[:3]:
                    cap(CapLabel.fs_write_outside, m, "writes outside the workspace")
                if code:
                    for m in finditer(_WRITE_LOCAL, t)[:2]:
                        if not search(_WRITE_OUTSIDE, t[max(0, m.start() - 4):m.end() + 160].split("\n", 1)[0]):
                            cap(CapLabel.fs_write_workspace, m, "writes files")
                    for m in finditer(_READ, t)[:2]:
                        cap(CapLabel.fs_read, m, "reads files")
                    for m in finditer(EXEC_CODE, t)[:2]:
                        cap(CapLabel.shell, m, "starts processes")
                for m in finditer(_FINANCIAL, t)[:2]:
                    cap(CapLabel.financial, m, "moves money or places orders", prose_ok=True)
                for m in finditer(_ELEVATED, t)[:2]:
                    cap(CapLabel.host_elevated, m, "runs with elevated privileges")
            if role == ArtifactRole.skill_md or role in _PROSE:
                if command_heads(at):
                    first = at.fence_list[0] if at.fence_list else None
                    span = at.span(first.start) if first else Span(path=at.path)
                    ctx.add_capability(comp.id, CapLabel.shell, confidence=Confidence.medium, span=span,
                                       snippet=", ".join(command_heads(at)[:6]), reason="instructions show shell commands to run")
                declared = parse_allowed_tools(_fm(at).get("allowed-tools")) if at.fm is not None else []
                for tool in declared:
                    name = tool.split("(", 1)[0]
                    label = {"bash": CapLabel.shell, "write": CapLabel.fs_write_workspace, "edit": CapLabel.fs_write_workspace,
                             "multiedit": CapLabel.fs_write_workspace, "read": CapLabel.fs_read, "webfetch": CapLabel.external_egress,
                             "websearch": CapLabel.ingests_untrusted_content}.get(name.lower())
                    if label is not None:
                        ctx.add_capability(comp.id, label, observed=False, declared=True, confidence=Confidence.high,
                                           span=_fm_span(at, "allowed-tools"), snippet=tool, reason=f"declared tool grant {tool}")

    # -- skills (PRIV-005 to 008, 010 to 012) -------------------------------------------------------------
    def _skill(self, comp: Component, md: ArtifactText, texts: list[ArtifactText]) -> None:
        ctx = self.ctx
        fm = _fm(md)
        desc = str(fm.get("description") or "")
        body = md.fm.body if md.fm is not None else md.text
        purpose = f"{comp.name} {desc} " + " ".join(s.heading for s in md.section_list[:3])
        labels = {c.label for c in comp.capabilities if c.observed}
        sensitive = sorted(lab.spec_name for lab in labels if lab in _SENSITIVE)
        declared = parse_allowed_tools(fm.get("allowed-tools"))
        declared_names = {t.split("(", 1)[0].lower() for t in declared}
        meta = fm.get("metadata") if isinstance(fm.get("metadata"), dict) else {}
        claw = meta.get("openclaw") if isinstance(meta.get("openclaw"), dict) else {}
        # PRIV-005: secrets unrelated to the purpose.
        wanted: dict[str, Span] = {}
        requires = claw.get("requires") if isinstance(claw.get("requires"), dict) else {}
        for name in [*(requires.get("env") or []), claw.get("primaryEnv")]:
            if isinstance(name, str):
                wanted.setdefault(name, _fm_span(md, "metadata"))
        for at in texts:
            if at.artifact.role not in (*_CODE, *_PROSE):
                continue
            for m in finditer(_ENV_REQUEST, at.text)[:60]:
                name = next((g for g in m.groups() if g), "")
                if name:
                    wanted.setdefault(name, at.span(m.start(), m.end()))
        for name, span in sorted(wanted.items()):
            if not _SECRET_VAR.search(name):
                continue
            parts = [p for p in name.split("_") if p and p not in _GENERIC_PREFIX and not _SECRET_VAR.fullmatch(p)]
            prefix = parts[0] if parts else ""
            if not prefix:
                continue
            words = _SERVICE_WORDS.get(prefix, regex.escape(prefix.lower()))
            try:
                related = regex.search(rf"(?i)(?:{words})", purpose + " " + body[:1500], timeout=TIMEOUT) is not None
            except TimeoutError:
                related = True
            if not related:
                ctx.emit("AG-PRIV-005", component_ids=comp.id, span=span, snippet=name, kind=EvidenceKind.metadata, match=f"env:{name}",
                         message=f"The skill asks for `{name}`, and nothing in its stated purpose (\"{desc[:80]}\") involves "
                                 f"{prefix.title()}. A credential a skill does not need is one it can leak or misuse.")
        # PRIV-006: always loaded, or started by the model, while sensitive.
        always = claw.get("always") is True or fm.get("always") is True
        if always and sensitive:
            ctx.emit("AG-PRIV-006", component_ids=comp.id, span=_fm_span(md, "always" if "always" in fm else "metadata"),
                     snippet="always: true", kind=EvidenceKind.metadata, match="always",
                     message=f"The skill is loaded into every session (`always: true`) and can do sensitive things ({', '.join(sensitive[:5])}).")
        # PRIV-007: side effects, and the model may start it on its own.
        side = sorted(lab.spec_name for lab in labels if lab in (CapLabel.destructive, CapLabel.financial, CapLabel.persistence,
                                                                 CapLabel.fs_write_outside, CapLabel.host_elevated))
        verb = search(_SIDE_EFFECT_WORDS, desc)
        claude_skill = "/.claude/" in "/" + md.path or "disable-model-invocation" in fm or "user-invocable" in fm or "allowed-tools" in fm
        if (side or verb) and claude_skill and fm.get("disable-model-invocation") is not True:
            what = ", ".join(side[:4]) if side else f"its description says it {verb.group(0).lower()}"
            ctx.emit("AG-PRIV-007", component_ids=comp.id, span=_fm_span(md, "description"), kind=EvidenceKind.metadata,
                     snippet=f"description: {desc[:120]}", match="model-invocable",
                     message=f"The skill has side effects ({what}) and the model may start it without the user asking: "
                             "`disable-model-invocation` is not set.")
        # PRIV-008: the declared grant understates what the skill does.
        if declared:
            needs: list[str] = []
            runs = CapLabel.shell in labels or CapLabel.code_exec in labels or any(t.artifact.role == ArtifactRole.script for t in texts)
            if runs and "bash" not in declared_names and "*" not in declared_names:
                needs.append("it runs commands or scripts (needs Bash)")
            if CapLabel.external_egress in labels and not declared_names & {"webfetch", "bash", "*"}:
                needs.append("it makes network requests")
            if labels & {CapLabel.fs_write_workspace, CapLabel.fs_write_outside} and not declared_names & {"write", "edit", "multiedit", "bash", "*"}:
                needs.append("it writes files")
            if needs:
                ctx.emit("AG-PRIV-008/skill-grant", component_ids=comp.id, span=_fm_span(md, "allowed-tools"), kind=EvidenceKind.metadata,
                         snippet=f"allowed-tools: {' '.join(declared)}", match="understated",
                         message=f"The skill declares `allowed-tools: {' '.join(declared)[:80]}`, but {'; '.join(needs)}. The "
                                 "declaration makes it look narrower than it is.")
        # PRIV-010 / PRIV-011: grants beyond the workspace, or network with a local purpose.
        for tool in declared:
            if regex.match(r"(?i)(?:Read|Edit|Write|Glob|Grep)\(\s*(?:~|/|\$HOME|\*\*/\.\w|[A-Za-z]:[\\/])", tool):
                ctx.emit("AG-PRIV-010", component_ids=comp.id, span=_fm_span(md, "allowed-tools"), snippet=tool, kind=EvidenceKind.metadata,
                         match=f"grant:{tool}", message=f"The grant `{tool}` reaches files outside the workspace.")
        net_grant = next((t for t in declared if regex.fullmatch(r"(?i)WebFetch|WebSearch|WebFetch\(\s*(?:domain:\s*)?\*\s*\)|Bash\(\s*(?:curl|wget)\b[^)]*\)", t)), None)
        if net_grant and not regex.search(r"(?i)\b(?:api|http|web|url|online|remote|cloud|fetch|download|upload|search|internet|site|"
                                          r"service|sync|github|slack|email|server|endpoint|scrap|crawl|brows)", purpose):
            ctx.emit("AG-PRIV-011", component_ids=comp.id, span=_fm_span(md, "allowed-tools"), snippet=net_grant, kind=EvidenceKind.metadata,
                     match=f"net:{net_grant}", message=f"The skill is granted `{net_grant}` (network access to any host) and its "
                                                       f"stated purpose (\"{desc[:80]}\") is local.")
        # PRIV-012: straight to a tool, bypassing the model.
        if str(fm.get("command-dispatch") or "").lower() == "tool":
            tool = str(fm.get("command-tool") or "")
            ctx.emit("AG-PRIV-012", component_ids=comp.id, span=_fm_span(md, "command-dispatch"), kind=EvidenceKind.metadata,
                     snippet=f"command-dispatch: tool{'; command-tool: ' + tool if tool else ''}", match="dispatch",
                     message=f"The skill's command is dispatched straight to the tool `{tool or '(unnamed)'}`: the text after the "
                             "slash command reaches the tool without the model seeing or checking it.")

    # -- every instruction-bearing component (PRIV-009, 010, 013) ---------------------------------------------
    def _shared(self, comp: Component, texts: list[ArtifactText]) -> None:
        ctx = self.ctx
        done: set[str] = set()
        for at in texts:
            role = at.artifact.role
            if role not in (*_CODE, *_PROSE):
                continue
            code = role in _CODE
            if not code and "AG-PRIV-009" not in done:
                for unit in at.units:
                    if unit.scope not in ("body", "frontmatter"):
                        continue
                    m = search(_ELEVATED_REQUEST, unit.norm.text)
                    if m is None:
                        continue
                    span = ctx.unit_span(unit, m.start(), m.end())
                    line = unit.norm.text[unit.norm.text.rfind("\n", 0, m.start()) + 1:].split("\n", 1)[0]
                    if regex.search(r"(?i)\b(?:never|do not|don't|must not|avoid|without needing)\b", line[:max(0, m.start() - unit.norm.text.rfind(chr(10), 0, m.start()))]):
                        continue
                    done.add("AG-PRIV-009")
                    ctx.emit("AG-PRIV-009", component_ids=comp.id, span=span, snippet=line.strip()[:300], kind=EvidenceKind.regex,
                             match=f"elevated:{m.group(0).lower()[:60]}",
                             message="The component asks to run with elevated privileges, on the host, or with the sandbox off. "
                                     "What it then does is no longer confined.")
                    break
            if "AG-PRIV-010" not in done:
                m = search(_READ_OUTSIDE, at.text) if code else None
                if m is not None:
                    done.add("AG-PRIV-010")
                    ctx.emit("AG-PRIV-010", component_ids=comp.id, span=at.span(m.start(), m.end()), kind=EvidenceKind.ast,
                             snippet=at.line_text(m.start()).strip()[:300], match=f"read-outside:{at.path}",
                             message="The code reads files from the user's home directory, beyond the workspace it was asked to work in.")
            if "AG-PRIV-013" not in done:
                m = search(_OTHER_AGENT_DIRS, at.text)
                if m is not None and (code or at.in_code(m.start())):
                    done.add("AG-PRIV-013")
                    ctx.emit("AG-PRIV-013", component_ids=comp.id, span=at.span(m.start(), m.end()), kind=EvidenceKind.regex,
                             snippet=at.line_text(m.start()).strip()[:300], match=f"other-agents:{at.path}",
                             message="The component reaches into the directories where other skills, agents or plugins live. "
                                     "From there it can read their secrets or change what they do.")

    # -- subagents (PRIV-003, 014) ----------------------------------------------------------------------------
    def _subagent(self, comp: Component, md: ArtifactText) -> None:
        ctx = self.ctx
        fm = _fm(md)
        in_plugin = regex.search(r"(?:^|/)agents/[^/]+\.md$", md.path) is not None and "/.claude/" not in "/" + md.path \
            and "/.github/" not in "/" + md.path and "/.cursor/" not in "/" + md.path
        mode = str(fm.get("permissionMode") or "").lower()
        if mode in _PERMISSIVE_AGENT_MODES:
            note = " Claude Code ignores this field for plugin subagents; it still shows what the file is trying to do." if in_plugin else ""
            ctx.emit("AG-PRIV-003", component_ids=comp.id, span=_fm_span(md, "permissionMode"), kind=EvidenceKind.metadata,
                     snippet=f"permissionMode: {fm.get('permissionMode')}", match="permissionMode",
                     severity=Severity.medium if in_plugin else None,
                     message=f"The subagent '{comp.name}' runs with `permissionMode: {fm.get('permissionMode')}`, which "
                             f"{_PERMISSIVE_AGENT_MODES[mode]}.{note}")
        tools = _tool_names(fm.get("tools"))
        servers = fm.get("mcpServers") if "mcpServers" in fm else fm.get("mcp-servers")
        inline = []
        if isinstance(servers, dict):
            inline = [str(k) for k, v in servers.items() if isinstance(v, dict) and (v.get("command") or v.get("url"))]
        elif isinstance(servers, list):
            for item in servers:
                if isinstance(item, dict):
                    inline += [str(k) for k, v in item.items() if isinstance(v, dict) and (v.get("command") or v.get("url"))]
        surface = ctx.inventory.surfaces.get(md.path)
        if inline and (tools is None or "*" in tools) and not (surface is not None and surface.id == "copilot.agent"):
            ctx.emit("AG-PRIV-014", component_ids=comp.id, span=_fm_span(md, "mcpServers" if "mcpServers" in fm else "mcp-servers"),
                     kind=EvidenceKind.metadata, snippet=f"tools: {'(all)' if tools is None else tools}; mcpServers: {', '.join(inline[:4])}",
                     match="all-tools-own-server",
                     message=f"The subagent '{comp.name}' has every tool (no `tools` list) and defines its own MCP server(s) "
                             f"({', '.join(inline[:4])}), which nobody approved separately.")

    # -- capability labels (FLOW-010 to 012) --------------------------------------------------------------------
    def _labels(self, comp: Component) -> None:
        if comp.kind in (ComponentKind.mcp_client_config, ComponentKind.repository):
            return
        for label, rule, text in _LABEL_RULES:
            cap = next((c for c in comp.capabilities if c.label == label and (c.observed or c.declared)), None)
            if cap is None:
                continue
            ev = cap.evidence[0] if cap.evidence else None
            span = ev.location if ev is not None and ev.location is not None else (
                comp.server.config_span if comp.server and comp.server.config_span else Span(path=comp.root or comp.name))
            self.ctx.emit(rule, component_ids=comp.id, span=span, snippet=str(ev.snippet)[:200] if ev else comp.name,
                          kind=EvidenceKind.metadata, match=f"label:{label.value}", confidence=cap.confidence,
                          message=f"The {comp.kind.spec_type} '{comp.name}' {text} ({cap.reason or 'see evidence'}).")

    # -- delegation (FLOW-014) -------------------------------------------------------------------------------------
    def _delegation(self, by_comp: dict[str, list[ArtifactText]]) -> None:
        ctx, inv = self.ctx, self.ctx.inventory
        agents: dict[str, tuple[Component, list[str] | None]] = {}
        for comp in inv.of_kind(ComponentKind.subagent):
            md = next((t for t in by_comp.get(comp.id, []) if t.artifact.role == ArtifactRole.instruction_md), None)
            if md is not None:
                name = str(_fm(md).get("name") or comp.name).lower()
                agents[name] = (comp, _tool_names(_fm(md).get("tools")))
        for comp in sorted(inv.of_kind(ComponentKind.skill, ComponentKind.command), key=lambda c: c.id):
            md = next((t for t in by_comp.get(comp.id, []) if t.artifact.role in (ArtifactRole.skill_md, ArtifactRole.instruction_md,
                                                                                   ArtifactRole.command_md)), None)
            if md is None:
                continue
            fm = _fm(md)
            target = str(fm.get("agent") or "").lower()
            declared = parse_allowed_tools(fm.get("allowed-tools"))
            if not target or target not in agents or not declared:
                continue
            agent, tools = agents[target]
            mine = {t.split("(", 1)[0].lower() for t in declared}
            if "*" in mine:
                continue
            extra = ["every tool"] if tools is None or "*" in tools else sorted({t for t in tools if t.split("(", 1)[0].lower() not in mine})
            if extra:
                ctx.emit("AG-FLOW-014", component_ids=[comp.id, agent.id], span=_fm_span(md, "agent"), kind=EvidenceKind.metadata,
                         snippet=f"agent: {fm.get('agent')}; allowed-tools: {' '.join(declared)[:120]}", match=f"delegates:{target}",
                         related=[Span(path=agent.root)] if agent.root else None,
                         message=f"'{comp.name}' is limited to {' '.join(declared)[:60]} and hands its work to the subagent "
                                 f"'{agent.name}', which has {', '.join(extra[:6])}. The delegation widens the grant.")


def minimal_grant(comp: Component, texts: list[ArtifactText]) -> dict[str, Any]:
    """The smallest tool grant, permission rules and sandbox profile that cover what a component was observed to do."""
    labels = {c.label for c in comp.capabilities if c.observed}
    tools = ["Read"]
    allow: list[str] = []
    hosts: list[str] = []
    heads: list[str] = []
    scripts = sorted(t.path for t in texts if t.artifact.role == ArtifactRole.script)
    for at in texts:
        if at.artifact.role in _PROSE:
            for h in command_heads(at):
                if h not in heads:
                    heads.append(h)
        for m in finditer(_URL, at.text)[:200]:
            host = m.group(1).lower()
            if host not in hosts and "." in host and not host.endswith((".invalid", ".example", ".test", ".localhost")) \
                    and host not in ("localhost", "127.0.0.1", "example.com"):
                hosts.append(host)
    if labels & {CapLabel.fs_write_workspace, CapLabel.fs_write_outside}:
        tools += ["Write", "Edit"]
    if labels & {CapLabel.shell, CapLabel.code_exec} or scripts or heads:
        root = comp.root.rstrip("/")
        for path in scripts[:8]:
            rel = path[len(root) + 1:] if root and path.startswith(root + "/") else path
            runner = {"py": "python3", "js": "node", "mjs": "node", "ts": "npx tsx", "sh": "bash", "ps1": "pwsh", "rb": "ruby"}.get(
                rel.rsplit(".", 1)[-1].lower(), "")
            allow.append(f"Bash({runner + ' ' if runner else ''}{rel}:*)")
        for h in heads[:8]:
            rule = f"Bash({h}:*)"
            if rule not in allow and not any(a.startswith(f"Bash({h} ") for a in allow):
                allow.append(rule)
        if not allow:
            allow.append("Bash")
    network = CapLabel.external_egress in labels
    if network:
        allow += [f"WebFetch(domain:{h})" for h in hosts[:8]] or ["WebFetch"]
    grant = [*tools, *allow]
    deny = ["Read(~/.ssh/**)", "Read(~/.aws/**)", "Read(**/.env)"] if CapLabel.credential_access not in labels else []
    return {
        "allowed_tools": grant,
        "permissions": {"allow": [g for g in grant if g != "Read"], "deny": deny},
        "sandbox": {"enabled": True, "network": {"allowedDomains": hosts[:8] if network else []},
                    "filesystem": {"allowWrite": ["."] if labels & {CapLabel.fs_write_workspace} else []}},
        "observed": sorted(lab.spec_name for lab in labels),
    }


__all__ = ["PrivilegeAnalyzer", "command_heads", "minimal_grant"]
