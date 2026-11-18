"""Capability evidence (labels for the toxic-flow graph) from skills,
instruction files and bundled scripts, plus the deterministic
description/behavior mismatch rule (AG-META-004)."""

from __future__ import annotations

from typing import ClassVar

import regex

from ..models.enums import ArtifactRole, CapLabel, ComponentKind, Confidence, EvidenceKind
from .base import Context
from .envcopy import env_dumps
from .heuristics import (
    CREDENTIAL_PATH,
    DESTRUCTIVE,
    EGRESS_CODE,
    EXEC_CODE,
    INSTRUCTION_FILES,
    PERSISTENCE,
    READ_VERB,
    TOKEN_ENV,
    finditer,
    search,
)
from .regex_rules import is_quoted

# Content sources: unambiguous on their own, or a generic noun ("messages",
# "issues", "PDFs") only when the skill acts on it ("summarize the issues",
# "read incoming emails"). Bare nouns ("commit message format", "output .pdf
# files", `messages.create`) do not make a skill ingest third-party content.
_UNTRUSTED_SOURCES = regex.compile(
    r"\b(?:web ?pages?|websites?|brows(?:e|es|ing)\s+(?:the\s+)?(?:web|internet|sites?|pages?|urls?)|crawl(?:s|ing)?|scrap(?:e|es|ing)|"
    r"search results?|(?:the\s+user'?s\s+)?inbox|user[- ](?:supplied|provided|submitted)\s+(?:content|text|files?|documents?|urls?|data)|"
    r"untrusted\s+(?:content|input|text|data|documents?|sources?)|rss\s+feeds?|documents?\s+from\s+(?:the\s+)?(?:web|internet|users?|customers?|third[- ]part(?:y|ies)))\b"
    r"|\b(?:fetch(?:es|ing)?|read(?:s|ing)?|process(?:es|ing)?|summari[sz](?:e|es|ing)|pars(?:e|es|ing)|triag(?:e|es|ing)|"
    r"review(?:s|ing)?|analy[sz](?:e|es|ing)|ingest(?:s|ing)?|download(?:s|ing)?|open(?:s|ing)?|"
    r"(?:respond(?:s|ing)?|repl(?:y|ies|ying))\s+to|extract(?:s|ing)?\s+(?:\w+\s+){0,2}from)\s+"
    r"(?:(?:the|a|an|any|all|incoming|new|unread|recent|their|user'?s?|customer|github|gitlab|slack|discord|jira|linear|external|remote|uploaded|open)\s+){0,3}"
    r"(?:urls?|links?|emails?|e-mails?|mail|issues?|comments?|pull\s+requests?|prs|tickets?|messages?|chats?|threads?|"
    r"documents?|pdfs?|uploads?|attachments?|posts?|web\s+content|feeds?|articles?)\b",
    regex.IGNORECASE,
)
_PRIVATE_SOURCES = regex.compile(
    r"\b(?:private|internal|confidential|secrets?|credentials?|database|customer|employee|payroll|medical|"
    r"repositor(?:y|ies)|files? on disk|local files?|home directory|filesystem|file system|emails?|inbox|calendar|"
    r"drive|notion|crm)\b",
    regex.IGNORECASE,
)
_NETWORK_WORDS = regex.compile(
    r"\b(?:api|http|web|url|online|remote|cloud|service|upload|download|fetch|send|post|sync|webhook|slack|github|gitlab|"
    r"jira|email|notify|network|internet|server|endpoint|publish|deploy|telemetry|analytics|report(?:s|ing)? to)\b",
    regex.IGNORECASE,
)
_SECRET_WORDS = regex.compile(
    r"\b(?:env(?:ironment)?|credential|secret|token|key|auth|login|password|config(?:uration)?|ssh|aws|cloud|deploy)\b",
    regex.IGNORECASE,
)


class CapabilityAnalyzer:
    id: ClassVar[str] = "capabilities"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = ("AG-META-004",)

    def run(self, ctx: Context) -> None:
        for at in ctx.texts():
            role = at.artifact.role
            cid = at.artifact.component_id
            comp = ctx.inventory.components.get(cid)
            if comp is None or comp.kind == ComponentKind.mcp_client_config:
                continue
            # Files of the catch-all are not agent-run code or agent instructions: they carry no capability.
            if role in (ArtifactRole.repo_code, ArtifactRole.repo_doc):
                continue
            code = role in (ArtifactRole.script, ArtifactRole.source_code)
            for unit in at.units:
                if unit.scope not in ("body", "code", "command", "hidden", "decoded", "frontmatter", "resolved"):
                    continue
                t = unit.norm.text
                explicit = code or unit.scope == "command"

                def cap(label: CapLabel, m: regex.Match[str], reason: str, c: Confidence | None = None) -> None:
                    if code and _is_comment(_line(t, m.start())):
                        return                                # a comment describes, it does not do
                    if c is None:
                        abs_off = ctx.unit_abs(unit, m.start())
                        in_fence = unit.base is not None and abs_off is not None and at.in_code(abs_off)
                        c = Confidence.high if explicit or in_fence else Confidence.medium
                    ctx.add_capability(cid, label, confidence=c, span=ctx.unit_span(unit, m.start(), m.end()),
                                       snippet=_line(t, m.start()), reason=reason,
                                       kind=EvidenceKind.ast if code else EvidenceKind.regex)

                def cred_paths() -> None:
                    for m in finditer(CREDENTIAL_PATH, t)[:3]:
                        line = _line(t, m.start())
                        if code or search(READ_VERB, line):
                            cap(CapLabel.credential_access, m, "reads a credential store")
                            cap(CapLabel.reads_private_data, m, "reads a credential store")

                if unit.scope == "resolved":  # a folded path join adds only the path
                    cred_paths()
                    continue
                for m in finditer(EGRESS_CODE, t)[:3]:
                    cap(CapLabel.external_egress, m, "network request")
                for m in finditer(EXEC_CODE, t)[:3]:
                    cap(CapLabel.code_exec, m, "process/eval execution")
                for m in env_dumps(t, at.artifact.language if code else None)[:2]:
                    cap(CapLabel.credential_access, m, "dumps the environment")
                    cap(CapLabel.reads_private_data, m, "dumps the environment")
                cred_paths()
                for m in finditer(TOKEN_ENV, t)[:2]:
                    if code:
                        cap(CapLabel.credential_access, m, "reads a token environment variable", Confidence.medium)
                for m in finditer(PERSISTENCE, t)[:2]:
                    cap(CapLabel.persistence, m, "writes a persistence location", Confidence.medium)
                for m in finditer(INSTRUCTION_FILES, t)[:2]:
                    line = _line(t, m.start())
                    if regex.search(r"(?i)\b(write|append|modify|edit|update|add|echo|>>|tee|insert)\b", line):
                        cap(CapLabel.persistence, m, "modifies agent instruction/memory files", Confidence.medium)
                for m in finditer(DESTRUCTIVE, t)[:2]:
                    cap(CapLabel.destructive, m, "destructive operation")
                if role in (ArtifactRole.skill_md, ArtifactRole.instruction_md) and unit.scope == "body":
                    for m in finditer(_UNTRUSTED_SOURCES, t)[:8]:
                        if _not_the_agent(t, m):
                            continue
                        cap(CapLabel.ingests_untrusted_content, m, "processes external/untrusted content", Confidence.medium)
                        break
        self._mismatch(ctx)

    def _mismatch(self, ctx: Context) -> None:
        for comp in ctx.inventory.of_kind(ComponentKind.skill):
            md = next((t for t in ctx.texts("skill_md") if t.artifact.component_id == comp.id), None)
            if md is None or not md.fm or not md.fm.data:
                continue
            desc = str(md.fm.data.get("description") or "")
            if not desc:
                continue
            # What the skill *declares*: its description plus the visible SKILL.md body.
            body = next((u.norm.text for u in md.units if u.scope == "body"), "")
            declared = f"{desc}\n{body}"
            script_caps = [
                cap for cap in comp.capabilities
                if cap.observed and any(ev.location and _is_script(ctx, ev.location.path) for ev in cap.evidence)
            ]
            issues: list[tuple[str, object]] = []
            for cap in script_caps:
                if cap.label == CapLabel.external_egress and not search(_NETWORK_WORDS, declared):
                    issues.append(("makes network requests", cap))
                elif (cap.label == CapLabel.credential_access
                      and any(e.detail in _HARVEST_REASONS and not _names_its_tool(str(e.snippet), declared)
                              for e in cap.evidence)
                      and not search(_SECRET_WORDS, declared)):
                    issues.append(("reads credentials or dumps the environment", cap))
                elif cap.label == CapLabel.persistence and not regex.search(
                        r"(?i)\b(install|setup|config|startup|profile|cron|schedul)", declared):
                    issues.append(("writes persistence locations", cap))
            seen: set[str] = set()
            for what, cap in issues:
                if what in seen:
                    continue
                seen.add(what)
                ev = next(e for e in cap.evidence  # type: ignore[attr-defined]
                          if e.location and _is_script(ctx, e.location.path))
                ctx.emit("AG-META-004", component_ids=comp.id, span=ev.location, snippet=str(ev.snippet),
                         match=f"{what}", kind=EvidenceKind.metadata,
                         message=f"Description (\"{desc[:80]}\") does not mention it, but a bundled script {what}.")


_HARVEST_REASONS = {"dumps the environment", "reads a credential store"}

# A tool's own configuration file, and the words by which a description names that tool. A skill that
# says it lists Kubernetes contexts has declared that it reads the kube config; the same file read by a
# "format my notes" skill has not. Key files and token stores are not here: naming SSH does not declare
# reading a private key.
_TOOL_CONFIG = (
    (regex.compile(r"\.kube\b"), regex.compile(r"(?i)\b(?:kube(?:rnetes|ctl|config)?|k8s|helm)\b")),
    (regex.compile(r"\.ssh[/\\]config\b"), regex.compile(r"(?i)\bssh\b")),
    (regex.compile(r"\.aws[/\\]config\b"), regex.compile(r"(?i)\b(?:aws|amazon\s+web\s+services)\b")),
    (regex.compile(r"\.docker[/\\]config\.json\b"), regex.compile(r"(?i)\bdocker\b")),
    (regex.compile(r"\.config[/\\]gcloud\b"), regex.compile(r"(?i)\b(?:gcloud|google\s+cloud|gcp)\b")),
)


def _names_its_tool(line: str, declared: str) -> bool:
    return any(path.search(line) and words.search(declared) for path, words in _TOOL_CONFIG)


_USER_DOES_IT = regex.compile(r"(?i)\b(?:users?|you|they|them|customers?|people|someone)\s+(?:(?:to|can|could|should|must|will|may|might|then)\s+){0,2}$")


def _not_the_agent(text: str, m: regex.Match[str]) -> bool:
    """A phrase that reads like the skill taking in outside content but is not the agent doing so: a quoted
    example ("Extract text from PDF" in a list of sample prompts), or something the user is asked to do
    ("ask the user to open the URL")."""
    start = text.rfind("\n", 0, m.start()) + 1
    end = text.find("\n", m.end())
    line = text[start: end if end >= 0 else len(text)]
    if is_quoted(line, m.start() - start, m.end() - start):
        return True
    return bool(_USER_DOES_IT.search(text[max(start, m.start() - 60): m.start()]))


def _is_script(ctx: Context, path: str) -> bool:
    art = ctx.inventory.artifacts.get(path)
    return bool(art and art.role in (ArtifactRole.script, ArtifactRole.source_code))


def _line(text: str, offset: int) -> str:
    s = text.rfind("\n", 0, offset) + 1
    e = text.find("\n", offset)
    return text[s : e if e >= 0 else len(text)]


def _is_comment(line: str) -> bool:
    return line.lstrip().startswith(("#", "//", "/*", "* ", "<!--")) and not line.lstrip().startswith("#!")


__all__ = ["CapabilityAnalyzer", "TOKEN_ENV"]
