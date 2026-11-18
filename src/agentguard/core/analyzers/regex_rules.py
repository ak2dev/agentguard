"""Generic evaluator for data-defined regex rules (``match.type: regex``)."""

from __future__ import annotations

import bisect
from functools import lru_cache
from typing import ClassVar

import regex

from ..artifacts import TextUnit
from ..models import Detector, RegexMatch
from ..models.rule import Downgrade
from ..models.enums import Confidence, EvidenceKind
from ..textutil import TIMEOUT
from .base import Context


@lru_cache(maxsize=4096)
def _compile(pattern: str, ignore_case: bool) -> regex.Pattern[str]:
    flags = regex.MULTILINE | (regex.IGNORECASE if ignore_case else 0)
    return regex.compile(pattern, flags)


def _line_starts(text: str) -> list[int]:
    starts = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            starts.append(i + 1)
    return starts


def _window(text: str, starts: list[int], start: int, end: int, lines: int) -> str:
    li = bisect.bisect_right(starts, start) - 1
    le = bisect.bisect_right(starts, max(start, end - 1)) - 1
    a = starts[max(0, li - lines)]
    b_line = le + lines + 1
    b = starts[b_line] if b_line < len(starts) else len(text)
    return text[a:b]


_OPEN_CLOSE = (("“", "”"), ("«", "»"))


def is_quoted(line: str, start: int, end: int) -> bool:
    """True when line[start:end] sits inside "double quotes", “curly quotes”,
    an inline `code span`, or 'single quotes' directly around it (a mention or
    a literal, not a directive). Other single quotes are too often apostrophes."""
    before, after = line[:start], line[end:]
    for q in ('"', "`"):
        if before.count(q) % 2 == 1 and q in after:
            return True
    if before.endswith("'") and after.startswith("'"):
        return True
    return any(before.rfind(o) > before.rfind(c) and c in after for o, c in _OPEN_CLOSE)


def _description(ctx: Context, component_id: str) -> str:
    cache: dict[str, str] = ctx.data.setdefault("_declared_descriptions", {})  # type: ignore[assignment]
    if component_id not in cache:
        md = next((t for t in ctx.texts("skill_md") if t.artifact.component_id == component_id), None)
        data = md.fm.data if md is not None and md.fm and isinstance(md.fm.data, dict) else {}
        cache[component_id] = str(data.get("description") or "")
    return cache[component_id]


# Families whose rules describe what code does. In a script or source file a
# comment does nothing, so a match inside one is not a finding for them.
BEHAVIOUR_FAMILIES = frozenset({"CRED", "EXF", "EXEC", "PERSIST", "IMPACT", "VULN"})
_LINE_COMMENT = regex.compile(r"^\s*(?://|#(?!!)|\*(?:\s|/|$)|/\*|--\s|<!--|;;|(?i:REM)\s|::)")


def in_comment(line: str, col: int) -> bool:
    """True when ``line[col]`` is inside a comment: a whole-line comment, or
    text after a trailing ``//`` or ``#`` marker that is outside any string."""
    if _LINE_COMMENT.match(line):
        return True
    head = line[:col]
    for marker in ("//", "#"):
        i = head.rfind(marker)
        while i > 0:
            before = head[:i]
            if before[-1] in " \t" and before.count('"') % 2 == 0 and before.count("'") % 2 == 0 and before.count("`") % 2 == 0:
                return True
            i = head.rfind(marker, 0, i)
    return False


def _downgrade(ctx: Context, m: RegexMatch, unit: TextUnit, text: str, starts: list[int], s: int, e: int) -> Downgrade | None:
    for dg in m.downgrade:
        if dg.roles and unit.role not in dg.roles:
            continue
        if dg.in_code:
            at = ctx.inventory.texts.get(unit.path)
            abs_off = ctx.unit_abs(unit, s)
            if at is None or abs_off is None or unit.base is None or not at.in_code(abs_off):
                continue
        if dg.declared:
            desc = _description(ctx, unit.component_id)
            try:
                if not desc or not any(_compile(p, True).search(desc, timeout=TIMEOUT) for p in dg.declared):
                    continue
            except TimeoutError:
                continue
        if dg.quoted:
            ls = starts[bisect.bisect_right(starts, s) - 1]
            le = text.find("\n", s)
            le = len(text) if le < 0 else le
            if e > le or not is_quoted(text[ls:le], s - ls, e - ls):
                continue
        if dg.patterns:
            win = _window(text, starts, s, e, m.window if dg.window is None else dg.window)
            try:
                if not any(_compile(p, m.ignore_case).search(win, timeout=TIMEOUT) for p in dg.patterns):
                    continue
            except TimeoutError:
                continue
        return dg
    return None


_CODE_SCOPES = ("code", "resolved", "command")
_CODE_ROLES = ("script", "source_code", "hook_config", "workflow", "dockerfile", "config_command", "ci_command",
               "build_command")


def engine_for(unit: TextUnit) -> str:
    """Which engine a regex match belongs to: prose is the instruction engine,
    scripts, commands and source are the code engine."""
    if unit.scope == "media_text":
        return "instruction"
    if unit.scope in _CODE_SCOPES or unit.role in _CODE_ROLES:
        return "code"
    return "instruction"


def _path_ok(m: RegexMatch, path: str) -> bool:
    try:
        if m.paths and not any(_compile(p, True).search(path, timeout=TIMEOUT) for p in m.paths):
            return False
        if m.not_paths and any(_compile(p, True).search(path, timeout=TIMEOUT) for p in m.not_paths):
            return False
    except TimeoutError:
        return False
    return True


def units_for(ctx: Context) -> list[TextUnit]:
    units: list[TextUnit] = []
    for at in ctx.texts():
        units.extend(at.units)
    units.extend(ctx.data.get("extra_units", []))  # type: ignore[arg-type]
    return units


class RegexRuleAnalyzer:
    id: ClassVar[str] = "regex"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = ()  # evaluates every rule with match.type == regex

    def run(self, ctx: Context) -> None:
        rules = [d for d in ctx.pack.detectors.values() if isinstance(d.match, RegexMatch) and ctx.rule_enabled(d.key)]
        units = units_for(ctx)
        max_len = ctx.options.limits.max_line_length_for_regex
        for unit in units:
            text = unit.norm.text
            if not text.strip():
                continue
            starts: list[int] | None = None
            for rule in rules:
                m: RegexMatch = rule.match  # type: ignore[assignment]
                if unit.scope not in m.scopes:
                    continue
                if rule.applies_to and unit.role not in rule.applies_to:
                    continue
                if (m.paths or m.not_paths) and not _path_ok(m, unit.path):
                    continue
                starts = starts or _line_starts(text)
                self._eval(ctx, rule, m, unit, text, starts, max_len)

    def _eval(self, ctx: Context, rule: Detector, m: RegexMatch, unit: TextUnit, text: str, starts: list[int], max_len: int) -> None:
        at = ctx.inventory.texts.get(unit.path)
        seen_lines: set[int] = set()
        count = 0
        skip_comments = (unit.scope in ("code", "resolved")
                         and not (m.comments if m.comments is not None else rule.family not in BEHAVIOUR_FAMILIES))
        for pattern in m.patterns:
            rx = _compile(pattern, m.ignore_case)
            try:
                hits = list(rx.finditer(text, timeout=TIMEOUT))
            except TimeoutError:
                continue
            for hit in hits:
                s, e = hit.span()
                if e - s > max_len:
                    continue
                line_no = bisect.bisect_right(starts, s)
                if line_no in seen_lines:
                    continue
                if skip_comments:
                    ls = starts[line_no - 1]
                    le = text.find("\n", ls)
                    if in_comment(text[ls:len(text) if le < 0 else le], s - ls):
                        continue
                abs_off = ctx.unit_abs(unit, s)
                if m.sections:
                    if at is None or abs_off is None or unit.base is None:
                        continue
                    heads = at.headings_at(abs_off)
                    if not any(regex.search(sp, h, regex.IGNORECASE, timeout=TIMEOUT) for sp in m.sections for h in heads):
                        continue
                if m.require or m.unless:
                    win = _window(text, starts, s, e, m.window)
                    try:
                        if m.require and not all(_compile(p, m.ignore_case).search(win, timeout=TIMEOUT) for p in m.require):
                            continue
                        if m.unless and any(_compile(p, m.ignore_case).search(win, timeout=TIMEOUT) for p in m.unless):
                            continue
                    except TimeoutError:
                        continue
                confidence = rule.confidence
                if m.lower_confidence_in_code and at is not None and abs_off is not None and unit.base is not None and at.in_code(abs_off):
                    confidence = confidence.lower()
                severity = None
                mention = False
                dg = _downgrade(ctx, m, unit, text, starts, s, e)
                if dg is not None and dg.severity.rank < rule.severity.rank:
                    severity, mention = dg.severity, True
                    confidence = dg.confidence if dg.confidence is not None else confidence.lower()
                seen_lines.add(line_no)
                line = _window(text, starts, s, e, 0).strip("\n")
                ctx.emit(
                    rule.key,
                    engine=engine_for(unit),
                    component_ids=unit.component_id,
                    span=ctx.unit_span(unit, s, e),
                    snippet=line if len(line) <= 300 else text[max(0, s - 80) : e + 80],
                    match=hit.group(0).lower(),
                    detail=f"matched in {unit.scope}{' (' + unit.label + ')' if unit.label else ''}",
                    kind=EvidenceKind.regex,
                    severity=severity,
                    confidence=confidence if confidence != rule.confidence else None,
                    hidden=unit.hidden,
                    hidden_kind=unit.hidden_kind,
                    decode_path=unit.decode_path,
                    tags=["mention"] if mention else None,
                )
                count += 1
                if count >= m.max_matches:
                    return


__all__ = ["RegexRuleAnalyzer", "units_for", "Confidence"]
