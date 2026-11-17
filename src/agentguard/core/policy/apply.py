"""Suppressions (config, policy and inline), baselines (post-processing)."""

from __future__ import annotations

import datetime as dt
import fnmatch
from typing import TYPE_CHECKING

import regex

from ..models import Finding, ScanOptions, Suppression, SuppressionState
from ..textutil import TIMEOUT

if TYPE_CHECKING:
    from ..inventory import Inventory
    from ..rules.pack import RulePack

# <!-- agentguard-ignore: AG-SUPPLY-010 reason="pinned in lockfile" until=2027-01-01 -->
# Also after `#` or `//`. `agentguard-ignore-file:` covers the whole file.
_INLINE = regex.compile(
    r"agentguard-ignore(?P<file>-file)?:\s*(?P<rules>AG-[A-Z0-9-]+(?:\s*,\s*AG-[A-Z0-9-]+)*)"
    r"(?:\s+reason=(?:\"(?P<reason>[^\"\n]*)\"|(?P<reason2>\S+)))?"
    r"(?:\s+until=(?P<until>\d{4}-\d{2}-\d{2}))?",
)


def _rule_matches(pack: RulePack | None, selector: str, f: Finding) -> bool:
    if pack is None:
        return selector == f.id or selector == f.key
    key = pack.resolve_key(selector)
    if key is not None and "/" in key:
        return f.key == key                       # an id/variant key or the alias of one variant
    return f.id in pack.canonical_ids(selector)


def _matches(s: Suppression, f: Finding, pack: RulePack | None) -> bool:
    if s.rule_id and not _rule_matches(pack, s.rule_id, f):
        return False
    if s.fingerprint and s.fingerprint != f.fingerprint:
        return False
    if s.path_glob:
        path = f.primary.path if f.primary else ""
        if not fnmatch.fnmatchcase(path, s.path_glob):
            return False
    return True


def apply_suppressions(
    findings: list[Finding], options: ScanOptions, pack: RulePack | None = None,
    suppressions: list[Suppression] | None = None,
) -> tuple[list[Finding], list[Finding], list[tuple[Suppression, str]]]:
    """Return (kept, suppressed, problems). Expired suppressions do not hide
    findings; the finding resurfaces tagged ``suppression-expired``. Invalid
    suppressions (no reason / no expiry / unknown rule) are ignored and reported."""
    today = options.today or dt.date.today()
    kept: list[Finding] = []
    suppressed: list[Finding] = []
    problems: list[tuple[Suppression, str]] = []
    valid: list[Suppression] = []
    for s in (options.suppressions if suppressions is None else suppressions):
        if not s.is_valid():
            problems.append((s, "missing reason (>= 10 chars) or expires date"))
        elif s.rule_id and pack is not None and not pack.canonical_ids(s.rule_id):
            problems.append((s, f"'{s.rule_id}' is not a rule id, alias or family"))
        else:
            valid.append(s)
    for f in findings:
        hit = next((s for s in valid if _matches(s, f, pack)), None)
        if hit is None:
            kept.append(f)
            continue
        assert hit.expires is not None
        state = SuppressionState(status="active", reason=hit.reason, expires=hit.expires.isoformat(),
                                 approved_by=hit.approved_by)
        if hit.expires < today:
            state.status = "expired"
            f.suppression = state
            f.tags = sorted({*f.tags, "suppression-expired"})
            kept.append(f)
        else:
            f.suppression = state
            suppressed.append(f)
    return kept, suppressed, problems


def inline_suppressions(text: str) -> list[tuple[int, bool, list[str], str, str]]:
    """``(line, whole_file, rule ids, reason, until)`` for each ignore comment."""
    out = []
    for i, line in enumerate(text.split("\n"), start=1):
        if "agentguard-ignore" not in line:
            continue
        try:
            m = _INLINE.search(line, timeout=TIMEOUT)
        except TimeoutError:
            continue
        if m:
            rules = [r.strip() for r in m.group("rules").split(",")]
            out.append((i, bool(m.group("file")), rules, m.group("reason") or m.group("reason2") or "", m.group("until") or ""))
    return out


def apply_inline_suppressions(findings: list[Finding], inv: Inventory, options: ScanOptions,
                              pack: RulePack) -> tuple[list[Finding], list[Finding]]:
    """Inline ignore comments, honoured only in the user's own repository (the
    caller checks ``options.own_repo``; a scanned third-party target can never
    suppress its own findings). A comment covers its own line and the next one."""
    today = options.today or dt.date.today()
    cache: dict[str, list[tuple[int, bool, list[str], str, str]]] = {}
    kept: list[Finding] = []
    suppressed: list[Finding] = []
    for f in findings:
        loc = f.primary
        if loc is None or f.suppression is not None:
            kept.append(f)
            continue
        if loc.path not in cache:
            at = inv.texts.get(loc.path)
            cache[loc.path] = inline_suppressions(at.text) if at is not None else []
        hit = None
        for line, whole, rules, reason, until in cache[loc.path]:
            if not (whole or line in (loc.start_line, loc.start_line - 1)):
                continue
            if any(_rule_matches(pack, r, f) for r in rules):
                hit = (reason, until)
                break
        if hit is None:
            kept.append(f)
            continue
        reason, until = hit
        try:
            expires = dt.date.fromisoformat(until) if until else None
        except ValueError:
            expires = None
        if len(reason.strip()) < 10 or expires is None:
            f.tags = sorted({*f.tags, "inline-suppression-invalid"})
            kept.append(f)
            continue
        state = SuppressionState(status="active", reason=reason, expires=expires.isoformat(), kind="inline")
        f.suppression = state
        if expires < today:
            state.status = "expired"
            f.tags = sorted({*f.tags, "suppression-expired"})
            kept.append(f)
        else:
            suppressed.append(f)
    return kept, suppressed


def apply_baseline(findings: list[Finding], options: ScanOptions) -> list[Finding]:
    if options.baseline is None:
        return findings
    out = []
    for f in findings:
        if f.fingerprint in options.baseline:
            f.baseline_state = "unchanged"
            continue
        f.baseline_state = "new"
        out.append(f)
    return out
