"""`agentguard rules import`: community rule packs (PLAN §4 feature 55).

Two formats are read:

* **Agent Threat Rules** (ATR, YAML). Only rules a file scanner can evaluate are imported: pattern
  rules that target skills or MCP definitions. Rules for live agent traffic, behavioural thresholds,
  model judges, signature feeds and trace invariants are skipped, each with a counted reason.
* **YARA** sources.

An imported rule never becomes a rule of its own. It becomes a *variant* of the catalogue rule its
category corresponds to, in the advisory ``hunt`` lane with low confidence, and its severity is capped
at the catalogue rule's. So a community pack can add recall, but it cannot produce a verdict alone and
it cannot invent a severity the catalogue does not have.

A pack is untrusted input until it has been imported: its YAML is read with the hardened loader, every
pattern is compiled and probed for catastrophic backtracking, a rule is kept only if it agrees with its
own test cases, and the result is loaded together with the built-in pack before anything is written.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
from pathlib import Path
from typing import Any

import regex
import yaml

from .core.models.enums import Lane, Severity
from .core.models.rule import RegexMatch, RuleVariant
from .core.parsers.safe_yaml import safe_load
from .core.rules.pack import RulePack, RulePackError, data_dirs
from .packs import installed_pack_files, pack_name, packs_home
from .runner import UsageError

FORMATS = ("atr", "yara")
MAX_SOURCE_BYTES = 2_000_000
MAX_RULES = 5000
MAX_PATTERN = 4000
MAX_PATTERNS_PER_RULE = 40
ALL_WINDOW = 40          # lines: how far apart the parts of an `all` condition may sit
PROBE_TIMEOUT = 0.25

# ATR `tags.category` -> the catalogue rule an imported rule is filed under, for file content and for MCP definitions.
ATR_HEADS: dict[str, tuple[str, str]] = {
    "prompt-injection": ("AG-INJ-001", "AG-MCP-020"),
    "tool-poisoning": ("AG-INJ-010", "AG-MCP-020"),
    "context-exfiltration": ("AG-EXF-010", "AG-MCP-024"),
    "agent-manipulation": ("AG-INJ-012", "AG-MCP-020"),
    "privilege-escalation": ("AG-PRIV-009", "AG-MCP-020"),
    "excessive-autonomy": ("AG-INJ-021", "AG-MCP-020"),
    "data-poisoning": ("AG-PERSIST-009", "AG-MCP-029"),
    "model-abuse": ("AG-MANIP-007", "AG-MCP-020"),
    "skill-compromise": ("AG-SUPPLY-009", "AG-MCP-003"),
}
# What a YARA source is filed under, from words in its rule names, tags and meta text.
YARA_HEADS: tuple[tuple[str, str], ...] = (
    (r"steal|harvest|credential|exfil|keylog|wallet|cookie|token", "AG-EXF-001"),
    (r"miner|xmrig|coinhive|cryptonight", "AG-IMPACT-003"),
    (r"ransom|wiper|locker", "AG-IMPACT-002"),
    (r"backdoor|reverse.?shell|bind.?shell|\brat\b|beacon|\bc2\b", "AG-EXEC-004"),
    (r"download|dropper|stager|loader", "AG-EXEC-001"),
    (r"prompt|injection|jailbreak", "AG-INJ-001"),
)
YARA_DEFAULT_HEAD = "AG-EXEC-007"

FILE_SCOPES = ["body", "hidden", "decoded", "frontmatter", "code", "command"]
TOOL_SCOPES = ["tool_text", "server_instructions"]
# Fields that only exist while an agent is running; a condition on one of them cannot be evaluated on files.
RUNTIME_FIELDS = {"agent_output", "tool_response", "tool_result", "model_output", "response", "assistant_output"}
TOOL_FIELDS = {"tool_description", "tool_name", "tool_args", "tool_schema", "tool_input", "server_instructions", "mcp_description"}
SKILL_SOURCES = {"skill_lifecycle", "skill_permission", "skill_chain"}
MCP_SOURCES = {"mcp_exchange", "tool_call"}
_SEVERITY = {"critical": Severity.critical, "high": Severity.high, "medium": Severity.medium, "low": Severity.low,
             "informational": Severity.info, "info": Severity.info}
# Long runs that end in something that cannot match: the shapes nested quantifiers blow up on.
_PROBES = ("a" * 4000, " " * 4000, "ignore " * 600, "a=" * 2000 + "!", "<" * 3000, "x" * 2000 + "\n" + "y" * 2000,
           "http://" + "a." * 1500, "\\" * 2000, "1" * 3000 + "x", "a" * 3000 + "!", "0" * 3000 + "!", " " * 3000 + "!",
           "ab" * 1500 + "!", "a " * 1500 + "!", "a.b" * 1000 + "!", "A" * 3000 + "!\n", "-" * 3000 + "x", "/" * 3000 + "\0",
           "a" * 40 + "!", "x" * 28 + "\n" + "x" * 28 + "!")
_CONTROL = regex.compile(r"[\p{Cc}\p{Cf}\p{Co}\p{Cs}\p{Zl}\p{Zp}]")
_YARA_RULE = re.compile(r"(?m)^\s*(?:(?:private|global)\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]{0,127})\b")
_YARA_INCLUDE = re.compile(r'(?m)^\s*include\s+"')
_ATR_ID = re.compile(r"^[A-Z][A-Z0-9]{1,15}-\d{4}-\d{5}$")


class _Skip(Exception):
    """This rule is not imported; the message is the counted reason."""


def _clean(text: Any, limit: int) -> str:
    """Text from a community pack as it is stored: one line, no control or invisible characters, bounded."""
    s = _CONTROL.sub(" ", str(text or ""))
    return re.sub(r"\s+", " ", s).strip()[:limit]


def _compile(pattern: str, ignore_case: bool = False) -> regex.Pattern[str]:
    return regex.compile(pattern, regex.MULTILINE | (regex.IGNORECASE if ignore_case else 0))


def _checked(pattern: str) -> str:
    """The pattern, if this engine can run it safely. Raises _Skip otherwise."""
    if not isinstance(pattern, str) or not pattern.strip():
        raise _Skip("a condition has no pattern")
    if len(pattern) > MAX_PATTERN:
        raise _Skip(f"a pattern is longer than {MAX_PATTERN} characters")
    try:
        rx = _compile(pattern)
    except (regex.error, RecursionError, OverflowError):
        raise _Skip("a pattern does not compile with this regex engine") from None
    try:
        if rx.search("", timeout=PROBE_TIMEOUT) is not None:
            raise _Skip("a pattern matches empty text, so it would match every file")
        for probe in _PROBES:
            rx.search(probe, timeout=PROBE_TIMEOUT)
    except TimeoutError:
        raise _Skip("a pattern is too slow on a probe text (possible catastrophic backtracking)") from None
    return pattern


def _as_regex(operator: str, value: str, case_sensitive: bool) -> str:
    op = (operator or "regex").lower()
    if op == "regex":
        return value if case_sensitive or value.lstrip().startswith("(?i") else f"(?i){value}"
    lit = regex.escape(value, special_only=True)
    flag = "" if case_sensitive else "(?i)"
    if op == "contains":
        return f"{flag}{lit}"
    if op == "exact":
        return f"{flag}^[ \\t]*{lit}[ \\t]*$"
    if op == "starts_with":
        return f"{flag}^[ \\t]*{lit}"
    raise _Skip(f"condition operator {op!r} is not supported")


def _alternation(patterns: list[str]) -> str:
    return patterns[0] if len(patterns) == 1 else "|".join(f"(?:{p})" for p in patterns)


def _groups(detection: dict[str, Any], target: str) -> tuple[list[list[str]], bool]:
    """The rule's conditions as groups of alternative patterns, and whether a tool-definition field is read.
    A group holds; the rule's `condition` says whether one group or every group must match."""
    conditions = detection.get("conditions")
    groups: list[list[str]] = []
    unusable = 0
    tool_field = False

    def field_ok(field: Any) -> bool:
        nonlocal tool_field
        name = str(field or "content").lower()
        if name in RUNTIME_FIELDS:
            return False
        tool_field = tool_field or name in TOOL_FIELDS
        return True

    if isinstance(conditions, list):
        for cond in conditions:
            if not isinstance(cond, dict) or not isinstance(cond.get("value"), str):
                unusable += 1
                continue
            if not field_ok(cond.get("field")):
                unusable += 1
                continue
            # The array form has no case switch; patterns say `(?i)` themselves, literals are compared loosely.
            op = str(cond.get("operator") or "regex").lower()
            groups.append([_checked(_as_regex(op, cond["value"], case_sensitive=(op == "regex")))])
    elif isinstance(conditions, dict):
        for _name, cond in sorted(conditions.items(), key=lambda kv: str(kv[0])):
            if not isinstance(cond, dict) or not isinstance(cond.get("patterns"), list) or not field_ok(cond.get("field")) \
                    or any(k in cond for k in ("metric", "threshold", "steps", "within")):
                unusable += 1
                continue
            sensitive = bool(cond.get("case_sensitive", False))
            pats = [_checked(_as_regex(str(cond.get("match_type") or "regex"), p, sensitive))
                    for p in cond["patterns"][:MAX_PATTERNS_PER_RULE] if isinstance(p, str)]
            if pats:
                groups.append(pats)
            else:
                unusable += 1
    else:
        raise _Skip("the rule has no conditions")
    if not groups:
        raise _Skip("every condition reads live agent traffic or a metric, not file content")
    mode = str(detection.get("condition") or "any").strip().lower()
    words = set(re.findall(r"[a-z_]+", mode))
    if mode in ("any", "or") or (words and "and" not in words and "not" not in words and "or" in words):
        return groups, tool_field          # any group: conditions that could not be used only narrow recall
    if mode in ("all", "and") or (words and "or" not in words and "not" not in words and "and" in words):
        if unusable:
            raise _Skip("the rule needs every condition, and one of them reads live agent traffic or a metric")
        return groups, tool_field
    raise _Skip("the rule's condition is a boolean expression, which is not supported")


def _match_spec(detection: dict[str, Any], target: str) -> tuple[RegexMatch, bool]:
    groups, tool_field = _groups(detection, target)
    mode = str(detection.get("condition") or "any").strip().lower()
    every = mode in ("all", "and") or ("and" in re.findall(r"[a-z_]+", mode) and "or" not in re.findall(r"[a-z_]+", mode))
    if every and len(groups) > 1:
        patterns, require, window = [_alternation(groups[0])], [_alternation(g) for g in groups[1:]], ALL_WINDOW
    else:
        patterns, require, window = [p for g in groups for p in g][:MAX_PATTERNS_PER_RULE], [], 0
    scopes = TOOL_SCOPES if target == "mcp" else FILE_SCOPES + (TOOL_SCOPES if target == "both" or tool_field else [])
    return RegexMatch(patterns=patterns, require=require, window=window, scopes=scopes, ignore_case=False, max_matches=3), tool_field


def matches(spec: RegexMatch, text: str) -> bool:
    """Whether a regex detector fires on a text, by the rules the regex analyzer uses (window in lines)."""
    lines = text.split("\n")
    starts, pos = [], 0
    for ln in lines:
        starts.append(pos)
        pos += len(ln) + 1
    for pattern in spec.patterns:
        try:
            hits = list(_compile(pattern, spec.ignore_case).finditer(text, timeout=2))
        except TimeoutError:
            continue
        for hit in hits:
            if not spec.require:
                return True
            first = max(0, sum(1 for s in starts if s <= hit.start()) - 1 - spec.window)
            last = min(len(lines), sum(1 for s in starts if s <= max(hit.start(), hit.end() - 1)) + spec.window)
            window = "\n".join(lines[first:last])
            try:
                if all(_compile(p, spec.ignore_case).search(window, timeout=2) for p in spec.require):
                    return True
            except TimeoutError:
                continue
    return False


def _self_test(spec: RegexMatch, doc: dict[str, Any]) -> int:
    """Run the rule's own test cases. Returns how many were run; raises _Skip when the rule disagrees with one."""
    cases = doc.get("test_cases") if isinstance(doc.get("test_cases"), dict) else {}
    ran = 0
    for key, expect in (("true_positives", True), ("true_negatives", False)):
        for case in cases.get(key) or []:
            if not isinstance(case, dict):
                continue
            # A case for a runtime field says nothing about file content.
            text = case.get("input") if isinstance(case.get("input"), str) else None
            if text is None:
                continue
            ran += 1
            if matches(spec, text) != expect:
                raise _Skip("the rule does not match its own true-positive test case with this engine" if expect
                            else "the rule matches its own true-negative test case with this engine")
    return ran


def _target(doc: dict[str, Any]) -> str:
    tags = doc.get("tags") if isinstance(doc.get("tags"), dict) else {}
    target = str(tags.get("scan_target") or doc.get("scan_target") or "").lower()
    if target in ("skill", "both", "mcp"):
        return target
    if target == "runtime":
        raise _Skip("the rule targets live agent traffic (scan target `runtime`), which a file scanner does not see")
    source = doc.get("agent_source") if isinstance(doc.get("agent_source"), dict) else {}
    kind = str(source.get("type") or target).lower()
    if kind in SKILL_SOURCES:
        return "skill"
    if kind in MCP_SOURCES:
        return "mcp"
    raise _Skip("the rule names no scan target a file scanner covers (skill, mcp or both)")


def atr_entry(doc: dict[str, Any], pack: RulePack, lane: Lane, source_name: str) -> tuple[dict[str, Any], int]:
    """One ATR rule as a detection entry (a variant of a catalogue rule), and how many of its test cases ran."""
    rule_id = str(doc.get("id") or "")
    if not _ATR_ID.match(rule_id) or not isinstance(doc.get("detection"), dict):
        raise _Skip("not a rule in the Agent Threat Rules format (no id or no detection block)")
    if str(doc.get("status") or "").lower() == "deprecated" or str(doc.get("maturity") or "").lower() == "deprecated":
        raise _Skip("the rule is deprecated")
    detection = doc["detection"]
    method = str(detection.get("method") or doc.get("detection_tier") or "pattern").lower()
    if method != "pattern":
        raise _Skip(f"detection method `{_clean(method, 20)}` is not pattern matching (it needs a runtime, a model or a signature feed)")
    target = _target(doc)
    tags = doc.get("tags") if isinstance(doc.get("tags"), dict) else {}
    category = str(tags.get("category") or "").lower()
    if category not in ATR_HEADS:
        raise _Skip(f"category `{_clean(category, 40) or 'none'}` has no corresponding catalogue rule")
    spec, _tool_field = _match_spec(detection, target)
    ran = _self_test(spec, doc)
    head = pack.rules[ATR_HEADS[category][1 if target == "mcp" else 0]]
    severity = _SEVERITY.get(str(doc.get("severity") or "").lower(), Severity.medium)
    if severity.rank > head.severity.rank:
        severity = head.severity
    refs = doc.get("references") if isinstance(doc.get("references"), dict) else {}
    research = [r for r in (refs.get("research") or []) if isinstance(r, str) and r.startswith("https://")][:5]
    title = _clean(doc.get("title"), 200) or rule_id
    entry: dict[str, Any] = {
        "id": head.id,
        "variant": rule_id.lower(),
        "title": f"{title} ({rule_id})",
        "description": _clean(doc.get("description"), 600) or f"Community rule {rule_id}.",
        "why": f"Community rule {rule_id} from the pack `{source_name}`. It runs in the advisory lane with low confidence: "
               "it can point a reviewer at a line, but it cannot produce a verdict alone.",
        "severity": severity.value,
        "confidence": "low",
        "lane": lane.value,
        "applies_to": [],
        "remediation": "Read the matched text in context. If it does what the rule describes and the component's stated purpose "
                       "does not need it, remove it; if it is a false match, suppress this finding with a reason.",
        "tags": ["community", "atr", f"source:{rule_id}"],
        "match": spec.model_dump(exclude_defaults=True) | {"type": "regex", "scopes": spec.scopes},
    }
    if research:
        entry["references"] = research
    RuleVariant.model_validate({**{k: v for k, v in entry.items() if k not in ("id", "variant")}, "key": entry["variant"]})
    return entry, ran


def _yara_head(text: str) -> str:
    names = " ".join(_YARA_RULE.findall(text))
    meta = " ".join(re.findall(r'(?m)^\s*(?:description|threat|category|malware_family|family|tags?)\s*=\s*"([^"\n]{0,200})"', text))
    hay = f"{names} {meta}".lower().replace("_", " ")
    return next((head for words, head in YARA_HEADS if re.search(words, hay)), YARA_DEFAULT_HEAD)


def yara_entry(file_name: str, text: str, pack: RulePack, lane: Lane, name: str, compiler: Any) -> dict[str, Any]:
    """One YARA source file as a detection entry. `compiler` is the yara module, or None when it is not installed."""
    rules = _YARA_RULE.findall(text)
    if not rules:
        raise _Skip("no YARA rule found in the file")
    if _YARA_INCLUDE.search(text):
        raise _Skip("the file uses `include`, which is disabled (a rule must not read other files)")
    if compiler is not None:
        try:
            compiler.compile(source=text, includes=False)
        except Exception:  # noqa: BLE001 - yara raises its own error types
            raise _Skip("the file does not compile with the installed YARA") from None
    head = pack.rules[_yara_head(text)]
    severity = Severity.high if head.severity.rank > Severity.high.rank else head.severity
    stem = re.sub(r"[^a-z0-9]+", "-", file_name.rsplit(".", 1)[0].lower()).strip("-")[:28] or "rules"
    shown = ", ".join(rules[:6]) + (f" and {len(rules) - 6} more" if len(rules) > 6 else "")
    return {
        "id": head.id,
        "variant": f"yara-{stem}"[:40],
        "title": f"Community YARA signature match ({_clean(file_name, 80)})",
        "description": f"The file matches a YARA rule from the community pack `{name}` ({_clean(shown, 300)}).",
        "why": "A community signature matched the raw bytes of this file. Signatures are precise about what they match and say "
               "nothing about intent, so this runs in the advisory lane with low confidence.",
        "severity": severity.value,
        "confidence": "low",
        "lane": lane.value,
        "category": "malice",
        "applies_to": [],
        "remediation": "Check what the matched file is and where it came from. Remove it if the component does not need it.",
        "tags": ["community", "yara"],
        "match": {"type": "yara", "rule_file": f"rules/yara/{name}-{file_name}"},
    }


def _sources(source: Path) -> list[Path]:
    if source.is_file():
        return [source]
    if not source.is_dir():
        raise UsageError(f"rules import: {source} is not a file or a directory")
    skip = {"node_modules", ".git", "dist", "spec", "tests", "test", "__pycache__"}
    out = [p for p in sorted(source.rglob("*")) if p.is_file() and p.suffix.lower() in (".yaml", ".yml", ".yar", ".yara")
           and not (set(p.relative_to(source).parts[:-1]) & skip)]
    return out[: MAX_RULES * 2]


def _docs(path: Path) -> list[Any]:
    """The YAML documents of one file, read with the hardened loader (no aliases, no tags, bounded)."""
    raw = path.read_bytes()
    if len(raw) > MAX_SOURCE_BYTES:
        raise _Skip(f"the file is larger than {MAX_SOURCE_BYTES} bytes")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise _Skip("the file is not UTF-8 text") from None
    docs = []
    for part in re.split(r"(?m)^---[ \t]*$", text):
        if not part.strip():
            continue
        res = safe_load(part, max_nodes=20_000)
        if res.error:
            raise _Skip("the file is not valid YAML, or uses YAML features that are refused (aliases, tags)")
        docs.extend(res.value if isinstance(res.value, list) else [res.value])
    return docs


def _base_files() -> dict[str, bytes]:
    rules_dir, mappings_dir = data_dirs()
    out: dict[str, bytes] = {}
    for root, prefix in ((rules_dir, "rules"), (mappings_dir, "mappings")):
        for p in sorted(root.rglob("*")):
            if p.is_file() and not p.name.startswith("."):
                out[f"{prefix}/{p.relative_to(root).as_posix()}"] = p.read_bytes()
    return out


def import_pack(source: Path, fmt: str | None = None, name: str | None = None, lane: str = "hunt", licence: str | None = None,
                out_dir: Path | None = None) -> dict[str, Any]:
    """Import a community pack. Returns counts, the pack's name and directory, and the reasons rules were skipped."""
    source = Path(source)
    if fmt is not None and fmt.lower() not in FORMATS:
        raise UsageError(f"rules import: --format must be one of {', '.join(FORMATS)}")
    fmt = fmt.lower() if fmt else None
    try:
        the_lane = Lane(lane.lower())
    except ValueError:
        raise UsageError("rules import: --lane must be hunt or evidence") from None
    if the_lane == Lane.block:
        raise UsageError("rules import: imported rules cannot run in the block lane; a community rule never produces a verdict "
                         "alone (use hunt, the default, or evidence)")
    files = _sources(source)
    yaml_files = [p for p in files if p.suffix.lower() in (".yaml", ".yml")] if fmt in (None, "atr") else []
    yara_files = [p for p in files if p.suffix.lower() in (".yar", ".yara")] if fmt in (None, "yara") else []
    if not yaml_files and not yara_files:
        raise UsageError(f"rules import: no {'rule' if fmt is None else fmt.upper()} files found under {source}")

    meta: dict[str, Any] = {}
    pkg = (source if source.is_dir() else source.parent) / "package.json"
    if pkg.is_file():
        try:
            loaded = json.loads(pkg.read_text(encoding="utf-8"))
            meta = loaded if isinstance(loaded, dict) else {}
        except (OSError, ValueError):
            meta = {}
    default_name = meta.get("name") if isinstance(meta.get("name"), str) else (source.stem if source.is_file() else source.name)
    pack_id = re.sub(r"[^A-Za-z0-9._-]+", "-", str(name or default_name or "community").strip()).strip("-.")[:60] or "community"
    target_dir = Path(out_dir) if out_dir is not None else packs_home() / pack_id

    base = RulePack.default()
    skip_reasons: dict[str, int] = {}
    notes: list[str] = []
    entries: list[dict[str, Any]] = []
    yara_out: dict[str, bytes] = {}
    seen: set[str] = set()
    digest = hashlib.sha256()
    tested = cases = 0

    def skipped(reason: str) -> None:
        skip_reasons[reason] = skip_reasons.get(reason, 0) + 1

    for path in yaml_files:
        try:
            docs = _docs(path)
        except (_Skip, OSError) as exc:
            skipped(str(exc) if isinstance(exc, _Skip) else "the file could not be read")
            continue
        for doc in docs:
            if not isinstance(doc, dict) or "detection" not in doc:
                continue                                   # schema files, indexes and other YAML that is not a rule
            if len(entries) >= MAX_RULES:
                skipped(f"more than {MAX_RULES} rules; the rest were not imported")
                continue
            try:
                entry, ran = atr_entry(doc, base, the_lane, pack_id)
            except _Skip as exc:
                skipped(str(exc))
                continue
            except (ValueError, TypeError):
                skipped("the rule could not be expressed as a detection entry")
                continue
            key = f"{entry['id']}/{entry['variant']}"
            if key in seen:
                skipped("the same rule id appears twice in the pack")
                continue
            seen.add(key)
            entries.append(entry)
            tested += 1 if ran else 0
            cases += ran
            digest.update(json.dumps(entry, sort_keys=True).encode())

    compiler = None
    if yara_files:
        try:
            import yara as compiler  # type: ignore[no-redef]
        except ImportError:
            notes.append("YARA sources were checked for structure only, not compiled: yara-python is not installed "
                         "(pip install 'agentguard-v1[yara]'). They are matched only where it is installed.")
    for path in yara_files:
        try:
            raw = path.read_bytes()
            if len(raw) > MAX_SOURCE_BYTES:
                raise _Skip(f"the file is larger than {MAX_SOURCE_BYTES} bytes")
            text = raw.decode("utf-8")
            file_name = re.sub(r"[^A-Za-z0-9._-]+", "-", path.name)
            file_name = file_name if file_name.endswith(".yar") else file_name.rsplit(".", 1)[0] + ".yar"
            entry = yara_entry(file_name, text, base, the_lane, pack_id, compiler)
        except _Skip as exc:
            skipped(str(exc))
            continue
        except (OSError, UnicodeDecodeError):
            skipped("the file could not be read as UTF-8 text")
            continue
        key = f"{entry['id']}/{entry['variant']}"
        if key in seen or file_name in yara_out:
            skipped("two YARA files have the same name")
            continue
        seen.add(key)
        entries.append(entry)
        yara_out[file_name] = text.replace("\r\n", "\n").encode("utf-8")
        digest.update(file_name.encode() + b"\0" + yara_out[file_name])

    if not entries:
        reasons = "; ".join(f"{n} × {r}" for r, n in sorted(skip_reasons.items())) or "no rules found"
        raise UsageError(f"rules import: nothing could be imported from {source} ({reasons})")

    entries.sort(key=lambda e: (e["id"], e["variant"]))
    header = (f"# Imported by `agentguard rules import` from the community pack `{pack_id}`.\n"
              "# Every entry is a variant of a catalogue rule, in the advisory lane. Do not edit by hand; import again.\n")
    rules_yaml = (header + yaml.safe_dump({"rules": entries}, sort_keys=False, allow_unicode=True, width=10_000,
                                          default_flow_style=False)).encode("utf-8")

    # Load the result together with the built-in pack (and the other installed packs) before anything is written.
    combined = _base_files()
    if out_dir is None:
        combined.update({k: v for k, v in installed_pack_files().items()
                         if not k.startswith((f"rules/ext/{pack_id}/", f"rules/yara/{pack_id}-", f"rules/data/{pack_id}-"))})
    combined[f"rules/ext/{pack_id}/imported.yaml"] = rules_yaml
    for file_name, data in yara_out.items():
        combined[f"rules/yara/{pack_id}-{file_name}"] = data
    try:
        RulePack.from_files(combined)
    except RulePackError as exc:
        detail = str(exc).splitlines()[1].strip() if len(str(exc).splitlines()) > 1 else str(exc)
        raise UsageError(f"rules import: the imported pack does not load with the rule pack, so nothing was written: {detail[:300]}. "
                         "If the rule is already installed under another name, import with the same --name to replace it.") from exc

    # Only this command's own files are written or replaced; nothing else in the directory is touched.
    (target_dir / "rules").mkdir(parents=True, exist_ok=True)
    previous: dict[str, Any] = {}
    if (target_dir / "pack.json").is_file():
        try:
            loaded = json.loads((target_dir / "pack.json").read_text(encoding="utf-8"))
            previous = loaded if isinstance(loaded, dict) else {}
        except (OSError, ValueError):
            previous = {}
    for old in previous.get("yara_files") or []:
        stale = target_dir / "yara" / str(old)
        if isinstance(old, str) and "/" not in old and "\\" not in old and old not in yara_out and stale.is_file():
            stale.unlink()
    (target_dir / "rules" / "imported.yaml").write_bytes(rules_yaml)
    if yara_out:
        (target_dir / "yara").mkdir(exist_ok=True)
        for file_name, data in sorted(yara_out.items()):
            (target_dir / "yara" / file_name).write_bytes(data)
    licence_text = licence or (meta.get("license") if isinstance(meta.get("license"), str) else None)
    if not licence_text:
        notes.append("No licence was recorded for this pack (pass --licence). Check that its licence allows your use.")
    manifest = {
        "name": pack_id,
        "version": _clean(meta.get("version"), 40) or "0",
        "format": "+".join(f for f, n in (("atr", len(entries) - len(yara_out)), ("yara", len(yara_out))) if n),
        "source": str(source),
        "licence": _clean(licence_text, 80) or None,
        "sha256": digest.hexdigest(),
        "signed_by": None,
        "lane": the_lane.value,
        "rules": len(entries),
        "yara_files": sorted(yara_out),
        "imported_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    (target_dir / "pack.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    if tested:
        notes.append(f"{tested} imported rule(s) were run against {cases} of their own test cases and agree with all of them.")
    heads: dict[str, int] = {}
    for e in entries:
        heads[e["id"]] = heads.get(e["id"], 0) + 1
    return {"imported": len(entries), "skipped": sum(skip_reasons.values()), "name": pack_name(target_dir), "dir": str(target_dir),
            "skip_reasons": dict(sorted(skip_reasons.items())), "notes": notes, "heads": dict(sorted(heads.items())),
            "installed": out_dir is None}


__all__ = ["ATR_HEADS", "FORMATS", "atr_entry", "import_pack", "matches", "yara_entry"]
