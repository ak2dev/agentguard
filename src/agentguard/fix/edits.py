"""The safe, deterministic edits behind ``agentguard fix``: one function per
``fix_action`` a rule can name. Each takes the file's text and the finding and
returns the character ranges to replace. Nothing here decides whether an edit is
right: every edit is checked afterwards by a re-scan, and one that leaves its
finding in place, adds a finding or breaks parsing is rolled back.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Callable

from ..core.models import Finding
from ..core.normalize.unicode import _CONFUSABLES
from ..core.textutil import is_invisible
from .locate import (
    LocateError,
    Node,
    find_path,
    frontmatter_lines,
    innermost,
    line_span,
    line_starts,
    offset_of,
    parse_json,
    parse_toml,
    yaml_block,
)


class NoFix(Exception):
    """This finding cannot be fixed by a deterministic edit; the message says why."""


@dataclass(frozen=True)
class Edit:
    start: int
    end: int
    text: str = ""


@dataclass
class Target:
    """What an action works on."""

    path: str
    text: str
    finding: Finding
    arg: str = ""                       # the part of the action after ':'
    resolve: Callable[[str, str], str | None] | None = None   # (kind, subject) -> value, for pinning

    @property
    def line(self) -> int:
        return self.finding.location.start.line if self.finding.location else 1

    @property
    def col(self) -> int:
        return self.finding.location.start.column if self.finding.location else 1

    @property
    def end_line(self) -> int:
        loc = self.finding.location
        return loc.end.line if loc and loc.end else self.line

    @property
    def end_col(self) -> int | None:
        loc = self.finding.location
        return loc.end.column if loc and loc.end else None

    @property
    def key_path(self) -> str:
        for ev in self.finding.evidence.items:
            if ev.detail.startswith("key: "):
                return ev.detail[5:].strip()
        return ""

    def span(self) -> tuple[int, int]:
        """Offsets of the located span; a finding with no end column covers its line."""
        starts = line_starts(self.text)
        start = offset_of(self.text, self.line, self.col, starts)
        if self.end_col is None:
            _, end = line_span(self.text, self.line, starts)
            return start, end - 1 if self.text[start:end].endswith("\n") else end
        return start, max(offset_of(self.text, self.end_line, self.end_col, starts), start)

    def line_text(self) -> tuple[int, int, str]:
        s, e = line_span(self.text, self.line)
        return s, e, self.text[s:e]


# --------------------------------------------------------------- helpers --
def _is_toml(path: str) -> bool:
    return path.lower().endswith(".toml")


def _is_json(path: str) -> bool:
    low = path.lower()
    return low.endswith((".json", ".json5", ".jsonc", ".code-workspace", ".mcpb.json")) or low.rsplit("/", 1)[-1] in (".claude.json",)


def _tree(t: Target) -> Node:
    try:
        if _is_toml(t.path):
            return parse_toml(t.text)
        if _is_json(t.path) or t.text.lstrip("\ufeff \t\r\n")[:1] in "{[":
            return parse_json(t.text)
    except LocateError as exc:
        raise NoFix(f"the file could not be read as structured data ({exc})") from exc
    raise NoFix("not a JSON or TOML file")


def _member(t: Target, root: Node | None = None) -> Node:
    """The member a finding is about: by its key path when the finding carries one, else by position."""
    root = root or _tree(t)
    path = t.key_path
    if path:
        node = find_path(root, path)
        if node is not None and node.parent is not None:
            return node
    start, _ = t.span()
    while start < len(t.text) and t.text[start] in " \t":
        start += 1                          # a location at column 1 means "this line"
    node = innermost(root, start)
    if node is None:
        raise NoFix("could not find the setting in the file")
    # The evidence often names the key (`envFile: …`, `"left-pad": …`): prefer that member inside what was located.
    m = re.match(r"^[\"']?([\w.$@/-]+)[\"']?\s*[:=@]", str(t.finding.evidence.snippet))
    if m and node.kind == "object" and str(node.key) != m.group(1):
        queue = list(node.children)
        while queue:
            cand = queue.pop(0)
            if str(cand.key) == m.group(1):
                return cand
            queue.extend(cand.children)
    return node


def _whole_lines(text: str, start: int, end: int) -> tuple[int, int]:
    """Widen a range to whole lines when nothing else is on them."""
    ls = text.rfind("\n", 0, start) + 1
    le = text.find("\n", end)
    le = len(text) if le < 0 else le
    if text[ls:start].strip() == "" and text[end:le].strip() == "":
        return ls, min(le + 1, len(text))
    return start, end


def _remove_member(text: str, node: Node, toml_inline: bool = False) -> Edit:
    """Remove ``"key": value`` (or an array element) with the comma that separates it."""
    parent = node.parent
    assert parent is not None
    start, end = node.member_start, node.end
    j = end
    while j < len(text) and text[j] in " \t\r\n":
        j += 1
    if j < len(text) and text[j] == ",":
        end = j + 1
        s, e = _whole_lines(text, start, end)
        if (s, e) == (start, end) and end < len(text) and text[end] == " ":
            e = end + 1
        return Edit(s, e)
    # Last member: take the comma before it, if any.
    k = start - 1
    while k >= 0 and text[k] in " \t\r\n":
        k -= 1
    if k >= 0 and text[k] == "," and len(parent.children) > 1:
        return Edit(k, end)
    s, e = _whole_lines(text, start, end)
    return Edit(s, e)


def _literal(value: str) -> str:
    """A JSON literal for ``true`` / ``false`` / a number, else a quoted string."""
    if value in ("true", "false", "null") or re.fullmatch(r"-?\d+(?:\.\d+)?", value):
        return value
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _indent_of(text: str, offset: int) -> str:
    ls = text.rfind("\n", 0, offset) + 1
    line = text[ls:offset]
    return line[: len(line) - len(line.lstrip(" \t"))]


def _set_member(text: str, obj: Node, key: str, literal: str) -> Edit:
    existing = obj.child(key)
    if existing is not None:
        return Edit(existing.start, existing.end, literal)
    if not obj.children:
        return Edit(obj.start + 1, obj.start + 1, f'"{key}": {literal}')
    last = obj.children[-1]
    if "\n" in text[obj.start:obj.end]:
        return Edit(last.end, last.end, f',\n{_indent_of(text, last.member_start)}"{key}": {literal}')
    return Edit(last.end, last.end, f', "{key}": {literal}')


# --------------------------------------------------------------- actions --
def remove_key(t: Target) -> list[Edit]:
    root = _tree(t)
    node = _member(t, root)
    if _is_toml(t.path) and node.parent is not None and node.parent.kind == "object" and node.key_start is not None \
            and t.text[node.parent.start:node.parent.start + 1] != "{":
        s, e = _whole_lines(t.text, node.key_start, node.end)
        return [Edit(s, e)]
    return [_remove_member(t.text, node)]


def remove_list_item(t: Target) -> list[Edit]:
    root = _tree(t)
    start, _ = t.span()
    node = innermost(root, start)
    while node is not None and not (node.parent is not None and node.parent.kind == "array"):
        node = node.parent
    if node is None:
        raise NoFix("could not find the list item")
    return [_remove_member(t.text, node)]


def set_sibling(t: Target) -> list[Edit]:
    key, _, value = t.arg.partition("=")
    if not key or not value:
        raise NoFix("the rule names no value to set")
    if _is_toml(t.path):
        raise NoFix("adding a key to a TOML table is not automated")
    node = _member(t)
    obj = node if node.kind == "object" else node.parent
    if obj is None or obj.kind != "object":
        raise NoFix("the entry is not an object a key can be added to")
    return [_set_member(t.text, obj, key, _literal(value))]


def set_value(t: Target) -> list[Edit]:
    node = _member(t)
    if node.kind != "scalar":
        raise NoFix("the setting is not a single value")
    return [Edit(node.start, node.end, _literal(t.arg))]


def remove_line(t: Target) -> list[Edit]:
    starts = line_starts(t.text)
    s, _ = line_span(t.text, t.line, starts)
    _, e = line_span(t.text, max(t.end_line, t.line), starts)
    return [Edit(s, e)]


def remove_import(t: Target) -> list[Edit]:
    s, e, line = t.line_text()
    m = re.search(r"(?<![\w`])@(?:~|\.{0,2}/|[A-Za-z]:[\\/]|[\w.-]+/)[^\s`)\]]*", line)
    if m is None:
        return [Edit(s, e)]
    rest = (line[: m.start()] + line[m.end():]).strip()
    if rest == "" or re.fullmatch(r"[\w \t-]{0,40}:?", rest):
        return [Edit(s, e)]            # the line was only the import (and perhaps a label)
    return [Edit(s + m.start(), s + m.end())]


def remove_match(t: Target) -> list[Edit]:
    start, end = t.span()
    if end <= start:
        raise NoFix("the finding has no extent to remove")
    if end < len(t.text) and start > 0 and t.text[start - 1] == " " and t.text[end:end + 1] == " ":
        end += 1
    return [Edit(start, end)]


def https_url(t: Target) -> list[Edit]:
    start, end = t.span()
    s, e, line = t.line_text()
    window_start = start if t.text.startswith("http://", start) else s
    idx = t.text.find("http://", window_start, max(end, e))
    if idx < 0:
        raise NoFix("no http:// URL at the location")
    return [Edit(idx, idx + 7, "https://")]


_ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_])|\x1b|\x9b[0-?]*[ -/]*[@-~]")
_SPACE_LIKE = {0x00A0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200A,
               0x202F, 0x205F, 0x3000}


def _line_range(t: Target) -> tuple[int, int]:
    starts = line_starts(t.text)
    s, _ = line_span(t.text, t.line, starts)
    _, e = line_span(t.text, max(t.end_line, t.line), starts)
    return s, e


def _rewrite(t: Target, fn: Callable[[str], str]) -> list[Edit]:
    """Rewrite the located line(s). In a JSON file, when those lines need no change, the whole entry the
    location belongs to is tried: a finding about a server or a hook points at its first line."""
    s, e = _line_range(t)
    old = t.text[s:e]
    new = fn(old)
    if new == old and _is_json(t.path):
        try:
            node = _member(t)
        except NoFix:
            node = None
        for cand in (node, node.parent if node is not None else None):
            if cand is None or cand.parent is None:
                continue
            s, e = cand.member_start, cand.end
            old = t.text[s:e]
            new = fn(old)
            if new != old:
                break
    if new == old:
        raise NoFix("nothing to change at the location")
    return [Edit(s, e, new)]


_U_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})")


def _strippable(ch: str) -> bool:
    cp = ord(ch)
    if ch in "\n\r\t":
        return False
    return is_invisible(ch) or unicodedata.category(ch) in ("Cf", "Co", "Cn") or 0xE0000 <= cp <= 0xE0FFF or cp in _SPACE_LIKE


def strip_codepoints(t: Target) -> list[Edit]:
    def strip(chunk: str) -> str:
        chunk = "".join(ch for ch in chunk if not _strippable(ch))
        if _is_json(t.path):      # the same characters written as \uXXXX escapes
            chunk = _U_ESCAPE.sub(lambda m: "" if _strippable(chr(int(m.group(1), 16))) else m.group(0), chunk)
        return chunk

    return _rewrite(t, strip)


def strip_escapes(t: Target) -> list[Edit]:
    return _rewrite(t, lambda chunk: _ANSI.sub("", chunk))


def fold_confusables(t: Target) -> list[Edit]:
    def fold(chunk: str) -> str:
        chunk = "".join(_CONFUSABLES.get(ch, ch) for ch in chunk)
        if _is_json(t.path):
            chunk = _U_ESCAPE.sub(lambda m: _CONFUSABLES.get(chr(int(m.group(1), 16)), m.group(0)), chunk)
        return chunk

    return _rewrite(t, fold)


def normalize_nfkc(t: Target) -> list[Edit]:
    return _rewrite(t, lambda chunk: unicodedata.normalize("NFKC", chunk))


def collapse_padding(t: Target) -> list[Edit]:
    """Runs of blank lines, and of spaces inside a line, that only push text out of view."""
    text = t.text
    new = re.sub(r"(?m)^[ \t\xa0]{40,}(?=\S)", "", text)          # a line pushed far to the right
    new = re.sub(r"(?m)[ \t\xa0]{40,}(?=\r?$)", "", new)           # spaces to the end of a line, or a line of nothing else
    new = re.sub(r"(?:[ \t]*\r?\n){4,}", "\n\n", new)
    new = re.sub(r"(?<=\S)[ \t\xa0]{40,}(?=\S)", " ", new)
    if new == text:
        raise NoFix("no padding found")
    return [Edit(0, len(text), new)]


def blank_env_values(t: Target) -> list[Edit]:
    s, e, line = t.line_text()
    m = re.match(r"^(\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.-]*\s*=)(.*?)(\r?\n?)$", line, re.S)
    if m is None or m.group(2).strip() == "":
        raise NoFix("not a NAME=value line")
    return [Edit(s + len(m.group(1)), s + len(m.group(1)) + len(m.group(2)))]


def remove_frontmatter_key(t: Target) -> list[Edit]:
    fm = frontmatter_lines(t.text)
    if fm is None or not (fm[0] <= t.line <= fm[1]):
        raise NoFix("the finding is not in the frontmatter")
    s, e = yaml_block(t.text, t.line)
    return [Edit(s, e)]


def set_frontmatter(t: Target) -> list[Edit]:
    key, _, value = t.arg.partition("=")
    fm = frontmatter_lines(t.text)
    if not key or fm is None:
        raise NoFix("the file has no frontmatter to add the key to")
    starts = line_starts(t.text)
    for n in range(fm[0], fm[1] + 1):
        s, e = line_span(t.text, n, starts)
        if re.match(rf"^{re.escape(key)}\s*:", t.text[s:e]):
            bs, be = yaml_block(t.text, n)
            return [Edit(bs, be, f"{key}: {value}\n")]
    s, _ = line_span(t.text, fm[1] + 1, starts)      # the closing fence
    return [Edit(s, s, f"{key}: {value}\n")]


_TLS_REWRITES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?<=\s)(?:-k|--insecure|--no-check-certificate|--no-verify-ssl|--disable-ssl-verification)(?=\s|$|`)\s?"), ""),
    (re.compile(r"\bverify\s*=\s*False\b"), "verify=True"),
    (re.compile(r"\bverify_ssl\s*=\s*False\b"), "verify_ssl=True"),
    (re.compile(r"(\brejectUnauthorized\s*:\s*)false\b"), r"\1true"),
    (re.compile(r"(\bstrictSSL\s*:\s*)false\b"), r"\1true"),
    (re.compile(r"(\bInsecureSkipVerify\s*:\s*)true\b"), r"\1false"),
    (re.compile(r"(\bNODE_TLS_REJECT_UNAUTHORIZED\s*=\s*)[\"']?0[\"']?"), r"\g<1>1"),
    (re.compile(r"(\bPYTHONHTTPSVERIFY\s*=\s*)[\"']?0[\"']?"), r"\g<1>1"),
    (re.compile(r"(\bGIT_SSL_NO_VERIFY\s*=\s*)[\"']?(?:1|true)[\"']?"), r"\g<1>false"),
    (re.compile(r"(\bhttp\.sslVerify\s+)false\b"), r"\1true"),
    (re.compile(r"(\bstrict-ssl\s*=?\s*)false\b"), r"\1true"),
    (re.compile(r"\s-SkipCertificateCheck\b"), ""),
    (re.compile(r"\bssl\._create_unverified_context\b"), "ssl.create_default_context"),
)


def enable_tls_verification(t: Target) -> list[Edit]:
    def fix(chunk: str) -> str:
        for rx, repl in _TLS_REWRITES:
            chunk = rx.sub(repl, chunk)
        return chunk

    return _rewrite(t, fix)


_INSECURE_DEFAULT = re.compile(
    r"(?P<name>\b(?:AUTH(?:ENTICATION)?_?(?:REQUIRED|ENABLED)|REQUIRE_?AUTH\w*|VERIFY_?\w*|VALIDATE_?\w*|CHECK_?\w*|ENFORCE_?\w*|SANDBOX\w*|"
    r"SECURE\w*|TLS_?\w*|CSRF_?\w*|auth_?required|require_?auth\w*|verify\w*|validate\w*|sandbox\w*|secure\w*|enforce\w*)\s*[:=]\s*)"
    r"(?P<val>False|false|0|\"(?:off|no|false|disabled)\"|'(?:off|no|false|disabled)'|off|no)\b")
_SECURE_VALUE = {"False": "True", "false": "true", "0": "1", "off": "on", "no": "yes"}


def secure_default(t: Target) -> list[Edit]:
    def fix(chunk: str) -> str:
        def repl(m: re.Match[str]) -> str:
            val = m.group("val")
            if val[:1] in "\"'":
                inner = {"off": "on", "no": "yes", "false": "true", "disabled": "enabled"}[val[1:-1]]
                return m.group("name") + val[0] + inner + val[-1]
            return m.group("name") + _SECURE_VALUE[val]

        chunk = _INSECURE_DEFAULT.sub(repl, chunk)
        chunk = re.sub(r"(\b(?:debug|DEBUG|use_debugger|use_reloader)\s*=\s*)True\b", r"\1False", chunk)
        chunk = re.sub(r"(\bDANGEROUSLY_OMIT_AUTH\s*=\s*[\"']?)(?:1|true)", r"\g<1>false", chunk)
        return chunk

    return _rewrite(t, fix)


def _env_name(*parts: str) -> str:
    raw = "_".join(p for p in parts if p)
    raw = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", raw)
    name = re.sub(r"[^A-Za-z0-9]+", "_", raw).strip("_").upper()
    return name or "SECRET"


def replace_with_env_reference(t: Target) -> list[Edit]:
    """A literal secret becomes a reference to an environment variable. The secret itself must still be rotated:
    it has been in the file, and in its history."""
    low = t.path.lower()
    if _is_toml(t.path) or _is_json(t.path):
        root = _tree(t)
        node = _member(t, root)
        key = str(node.key)
        if key.lower() in ("envfile", "env_file"):
            raise NoFix("which variables the server needs is a judgement call; list them by hand")
        if node.kind != "scalar":
            raise NoFix("the secret is not a single value")
        owner = node.parent.key if node.parent is not None and isinstance(node.parent.key, str) else ""
        if _is_toml(t.path):
            # Codex: a literal Authorization header becomes `bearer_token_env_var` on the server's table.
            table = node.parent.parent if node.parent is not None else None
            if key.lower() == "authorization" and owner == "http_headers" and table is not None and table.key_start is not None:
                var = _env_name(str(table.key), "TOKEN")
                line = f'bearer_token_env_var = "{var}"\n'
                ls = t.text.rfind("\n", 0, node.parent.member_start) + 1
                if len(node.parent.children) > 1:
                    return [_remove_member(t.text, node), Edit(ls, ls, line)]
                le = t.text.find("\n", node.parent.end)
                return [Edit(ls, len(t.text) if le < 0 else le + 1, line)]
            raise NoFix("TOML has no variable interpolation; move the secret to the variable the agent documents for it")
        var = _env_name(key if key.lower() not in ("value", "token", "key", "secret", "password") else f"{owner}_{key}")
        prefix = ""
        m = re.match(r"^[\"'](Bearer|Basic|token)\s", t.text[node.start:node.end], re.I)
        if m:
            prefix = m.group(1) + " "
        ref = "${env:%s}" % var if "/.cursor/" in "/" + low or low.endswith(".vscode/mcp.json") else "${%s}" % var
        return [Edit(node.start, node.end, _literal(prefix + ref))]
    s, e, line = t.line_text()
    if low.endswith((".yaml", ".yml")):
        y = re.match(r"^(?P<lead>\s*(?:-\s+)?)(?P<name>[A-Za-z_][\w.-]*)\s*:\s*(?P<val>[^\s#|>&*!][^#\n]*?)\s*(?:#.*)?\r?\n?$", line)
        if y is None or y.group("val").startswith(("${", "$(")):
            raise NoFix("could not find the literal on the line")
        return [Edit(s + y.start("val"), s + y.end("val"), '"${%s}"' % _env_name(y.group("name")))]
    m = re.search(r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?P<op>[:=])\s*(?P<q>[\"'])(?P<val>[^\"'\n]{6,})(?P=q)", line)
    if m is None:
        raise NoFix("could not find the literal on the line")
    var = _env_name(m.group("name"))
    vs, ve = s + m.start("q"), s + m.end("val") + 1
    if low.endswith(".py"):
        edits = [Edit(vs, ve, f'os.environ["{var}"]')]
        if not re.search(r"^\s*import\s+os\b|^\s*from\s+os\s+import\b", t.text, re.M):
            edits.append(Edit(0, 0, "import os\n"))
        return edits
    if low.endswith((".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx")):
        return [Edit(vs, ve, f"process.env.{var}")]
    if low.endswith((".sh", ".bash", ".zsh")) or "/.env" in "/" + low:
        return [Edit(vs, ve, '"${%s}"' % var)]
    raise NoFix("no environment-reference syntax is known for this file type")


# ----------------------------------------------------------------- pinning --
_USES = re.compile(r"(?P<pre>\buses:\s*[\"']?)(?P<repo>[\w.-]+/[\w.-]+)(?P<path>(?:/[\w./-]+)?)@(?P<ref>[\w./-]+)")
_NPX = re.compile(r"(?P<pre>\b(?:npx|bunx|pnpm\s+dlx|yarn\s+dlx)\s+(?:-y\s+|--yes\s+|-q\s+)*)(?P<pkg>(?:@[\w.-]+/)?[\w.-]+)(?P<ver>@[\w.^~*-]+)?")
_UVX = re.compile(r"(?P<pre>\b(?:uvx|pipx\s+run)\s+)(?P<pkg>[A-Za-z0-9][\w.-]*)(?P<ver>==[\w.]+)?")


def _need(t: Target, kind: str, subject: str) -> str:
    if t.resolve is None:
        raise NoFix(f"pinning needs a lookup of the current {kind}; run `agentguard fix --network`, or pin it by hand")
    value = t.resolve(kind, subject)
    if not value:
        raise NoFix(f"could not look up the {kind} for {subject}")
    return value


_GIT_URL = re.compile(r"git\+https://github\.com/(?P<repo>[\w.-]+/[\w.-]+?)(?:\.git)?(?:@(?P<ref>[\w./-]+))?(?=[#\s\"']|$)")
_PIP = re.compile(r"(?P<pre>\bpip[\d.]*\s+install\s+(?:-[\w-]+\s+)*|[\"']install[\"']\s*,\s*[\"'])(?P<pkg>[A-Za-z0-9][\w.-]*)(?P<ver>==[\w.]+)?")
_REQ_LINE = re.compile(r"^(?P<pkg>[A-Za-z0-9][\w.-]*)(?P<extras>\[[\w, -]*\])?(?P<spec>\s*(?:[<>~!=]=?|===)[^#;\n]*)?(?=\s*(?:[#;]|$))")


def pin_commit(t: Target) -> list[Edit]:
    s, e, line = t.line_text()
    m = _USES.search(line)
    if m is not None:
        if re.fullmatch(r"[0-9a-f]{40}", m.group("ref")):
            raise NoFix("already pinned to a commit")
        sha = _need(t, "commit", f"{m.group('repo')}@{m.group('ref')}")
        return [Edit(s + m.start("ref"), s + m.end("ref"), f"{sha} # {m.group('ref')}")]
    g = _GIT_URL.search(line)
    if g is not None and not re.fullmatch(r"[0-9a-f]{40}", g.group("ref") or ""):
        sha = _need(t, "commit", f"{g.group('repo')}@{g.group('ref') or 'HEAD'}")
        if g.group("ref"):
            return [Edit(s + g.start("ref"), s + g.end("ref"), sha)]
        return [Edit(s + g.end(), s + g.end(), f"@{sha}")]
    if _is_json(t.path):
        node = _member(t)
        if node.kind == "object":
            repo = node.child("repo") or node.child("repository") or node.child("url")
            if repo is not None:
                name = t.text[repo.start:repo.end].strip("\"'")
                name = re.sub(r"^https?://github\.com/|\.git$", "", name)
                ref = node.child("ref")
                current = t.text[ref.start:ref.end].strip("\"'") if ref is not None else "HEAD"
                sha = _need(t, "commit", f"{name}@{current}")
                return [_set_member(t.text, node, "sha", _literal(sha))]
        if node.kind == "scalar":
            raw = t.text[node.start:node.end].strip("\"'")
            m2 = re.fullmatch(r"(?:github:)?(?P<repo>[\w.-]+/[\w.-]+)(?:#(?P<ref>[\w./-]+))?", raw)
            if m2 is not None:
                sha = _need(t, "commit", f"{m2.group('repo')}@{m2.group('ref') or 'HEAD'}")
                head = raw.split("#", 1)[0]
                return [Edit(node.start, node.end, _literal(f"{head}#{sha}"))]
    raise NoFix("could not find a repository reference to pin")


def pin_version(t: Target) -> list[Edit]:
    s, e, line = t.line_text()
    for rx, eco, sep in ((_NPX, "npm", "@"), (_UVX, "pypi", "==")):
        m = rx.search(line)
        if m is not None:
            ver = m.group("ver") or ""
            if re.fullmatch(r"(?:@|==)\d[\w.+-]*", ver):
                continue
            version = _need(t, "version", f"{eco}/{m.group('pkg')}")
            end = m.end("ver") if m.group("ver") else m.end("pkg")
            return [Edit(s + m.end("pkg"), s + end, f"{sep}{version}")]
    p = _PIP.search(line)
    if p is not None and not p.group("ver"):
        return [Edit(s + p.end("pkg"), s + p.end("pkg"), "==" + _need(t, "version", f"pypi/{p.group('pkg')}"))]
    base = t.path.rsplit("/", 1)[-1].lower()
    if base.endswith(".txt") and ("requirements" in base or "constraints" in base):
        # One finding covers the file: pin every requirement that is not pinned to an exact version.
        edits, offset = [], 0
        for raw in t.text.split("\n"):
            r = _REQ_LINE.match(raw.strip("\r"))
            if r is not None and not raw.lstrip().startswith(("#", "-")) and not (r.group("spec") or "").strip().startswith("=="):
                version = _need(t, "version", f"pypi/{r.group('pkg')}")
                end = r.end("spec") if r.group("spec") else (r.end("extras") if r.group("extras") else r.end("pkg"))
                start = r.end("extras") if r.group("extras") else r.end("pkg")
                edits.append(Edit(offset + start, offset + end, f"=={version}"))
            offset += len(raw) + 1
        if edits:
            return edits
    if _is_json(t.path):
        node = _member(t)
        if node.kind == "object" and str(node.key) in ("dependencies", "devDependencies", "optionalDependencies"):
            names = [part.strip("\"' ") for part in str(t.finding.evidence.snippet).split(", ")]
            names = [n[: n.rfind("@")] if n.rfind("@") > 0 else n for n in names]
            edits = []
            for child in node.children:
                raw = t.text[child.start:child.end].strip("\"'")
                if str(child.key) in names and child.kind == "scalar" and not re.fullmatch(r"\d[\w.+-]*", raw):
                    edits.append(Edit(child.start, child.end, _literal(_need(t, "version", f"npm/{child.key}"))))
            if not edits:
                raise NoFix("could not find the dependency to pin")
            return edits
        if node.kind == "scalar":
            raw = t.text[node.start:node.end].strip("\"'")
            if isinstance(node.key, str) and re.fullmatch(r"[\^~>=<* ]*[\dx*][\w.*+ -]*|latest|next|\*", raw) and \
                    node.parent is not None and str(node.parent.key) in ("dependencies", "devDependencies", "optionalDependencies"):
                version = _need(t, "version", f"npm/{node.key}")
                return [Edit(node.start, node.end, _literal(version))]
            m3 = re.fullmatch(r"(?P<pkg>(?:@[\w.-]+/)?[\w.-]+)(?:@(?P<ver>[\w.^~*-]+))?", raw)
            if m3 is not None:
                version = _need(t, "version", f"npm/{m3.group('pkg')}")
                return [Edit(node.start, node.end, _literal(f"{m3.group('pkg')}@{version}"))]
        if node.kind == "object":
            pkg = node.child("package") or node.child("name")
            if pkg is not None:
                name = t.text[pkg.start:pkg.end].strip("\"'").rsplit("@", 1)[0] or t.text[pkg.start:pkg.end].strip("\"'")
                version = _need(t, "version", f"npm/{name}")
                return [_set_member(t.text, node, "version", _literal(version))]
    raise NoFix("could not find a package reference to pin")


def add_sha256(t: Target) -> list[Edit]:
    if not _is_json(t.path):
        raise NoFix("recording a hash is automated for JSON manifests only")
    node = _member(t)
    url_node = node
    if node.kind == "object":
        url_node = node.child("url") or node.child("source") or node
    raw = t.text[url_node.start:url_node.end].strip("\"'")
    m = re.search(r"https?://[^\s\"']+", raw)
    if m is None:
        raise NoFix("could not find the download URL")
    digest = _need(t, "sha256", m.group(0))
    if node.kind == "object":
        return [_set_member(t.text, node, "sha256", _literal(digest))]
    if node.parent is not None and node.parent.kind == "object":
        return [Edit(node.start, node.end, '{"url": %s, "sha256": %s}' % (_literal(raw), _literal(digest)))]
    raise NoFix("nowhere to record the hash")


ACTIONS: dict[str, Callable[[Target], list[Edit]]] = {
    "remove-key": remove_key,
    "remove-list-item": remove_list_item,
    "set-sibling": set_sibling,
    "set-value": set_value,
    "remove-line": remove_line,
    "remove-import": remove_import,
    "remove-match": remove_match,
    "https-url": https_url,
    "strip-codepoints": strip_codepoints,
    "strip-escapes": strip_escapes,
    "fold-confusables": fold_confusables,
    "normalize-nfkc": normalize_nfkc,
    "collapse-padding": collapse_padding,
    "blank-env-values": blank_env_values,
    "remove-frontmatter-key": remove_frontmatter_key,
    "set-frontmatter": set_frontmatter,
    "enable-tls-verification": enable_tls_verification,
    "secure-default": secure_default,
    "replace-with-env-reference": replace_with_env_reference,
    "pin-commit": pin_commit,
    "pin-version": pin_version,
    "add-sha256": add_sha256,
}


# ----------------------------------------------------------------- binary --
def strip_image_metadata(data: bytes) -> bytes:
    """Drop text and metadata blocks from a PNG or JPEG; the picture itself is untouched."""
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        out, i = [data[:8]], 8
        while i + 8 <= len(data):
            length = int.from_bytes(data[i:i + 4], "big")
            ctype = data[i + 4:i + 8]
            end = i + 12 + length
            if end > len(data):
                raise NoFix("the PNG is truncated")
            if ctype not in (b"tEXt", b"zTXt", b"iTXt", b"eXIf", b"tIME"):
                out.append(data[i:end])
            i = end
            if ctype == b"IEND":
                break
        return b"".join(out)             # anything after IEND (trailing data) is dropped too
    if data[:2] == b"\xff\xd8":
        out, i = [data[:2]], 2
        while i + 4 <= len(data) and data[i] == 0xFF:
            marker = data[i + 1]
            if marker == 0xDA:           # start of scan: the rest is image data
                eoi = data.rfind(b"\xff\xd9")
                out.append(data[i:eoi + 2] if eoi >= i else data[i:])
                return b"".join(out)
            if marker in (0x01, 0xD9) or 0xD0 <= marker <= 0xD7:
                out.append(data[i:i + 2])
                i += 2
                if marker == 0xD9:
                    break
                continue
            length = int.from_bytes(data[i + 2:i + 4], "big")
            if length < 2:
                raise NoFix("the JPEG is malformed")
            seg = data[i:i + 2 + length]
            keep = not (marker == 0xFE or 0xE1 <= marker <= 0xEF) or (marker == 0xEE and seg[4:9] == b"Adobe") \
                or (marker == 0xE2 and seg[4:15] == b"ICC_PROFILE")
            if keep:
                out.append(seg)
            i += 2 + length
        new = b"".join(out)
        if new == data:
            raise NoFix("no metadata to remove")
        return new
    raise NoFix("metadata removal is automated for PNG and JPEG files only")


_SVG_STRIP = (
    re.compile(r"<script\b[^>]*>.*?</script\s*>|<script\b[^>]*/>", re.I | re.S),
    re.compile(r"<foreignObject\b[^>]*>.*?</foreignObject\s*>", re.I | re.S),
    re.compile(r"<(?:image|use|feImage|a|iframe|embed|object)\b[^>]*?\b(?:xlink:)?href\s*=\s*[\"'](?:https?:|//|data:text/html|javascript:)[^\"']*[\"'][^>]*?"
               r"(?:/>|>(?:(?!<(?:image|use|feImage|a|iframe|embed|object)\b).)*?</(?:image|use|feImage|a|iframe|embed|object)\s*>)", re.I | re.S),
    re.compile(r"\s+on[a-z]+\s*=\s*(?:\"[^\"]*\"|'[^']*')", re.I),
    re.compile(r"\s+(?:xlink:)?href\s*=\s*[\"']\s*javascript:[^\"']*[\"']", re.I),
    re.compile(r"<!ENTITY\b[^>]*>", re.I),
    re.compile(r"@import\s+(?:url\()?[\"']?https?://[^;]*;", re.I),
)


def strip_svg_active_content(text: str) -> str:
    new = text
    for rx in _SVG_STRIP:
        new = rx.sub("", new)
    if new == text:
        raise NoFix("no active content found")
    return new


BINARY_ACTIONS: dict[str, Callable[[bytes], bytes]] = {"strip-image-metadata": strip_image_metadata}
TEXT_ACTIONS: dict[str, Callable[[str], str]] = {"strip-svg-active-content": strip_svg_active_content}


def plan_edits(action: str, path: str, text: str, finding: Finding, resolve: Any = None) -> list[Edit]:
    name, _, arg = action.partition(":")
    fn = ACTIONS.get(name)
    if fn is None:
        raise NoFix(f"no automated edit for '{name}'")
    try:
        edits = fn(Target(path=path, text=text, finding=finding, arg=arg, resolve=resolve))
    except LocateError as exc:
        raise NoFix(str(exc)) from exc
    if not edits:
        raise NoFix("nothing to change")
    return edits


def apply_edits(text: str, edits: list[Edit]) -> str:
    out = text
    for ed in sorted(edits, key=lambda e: (e.start, e.end), reverse=True):
        out = out[: ed.start] + ed.text + out[ed.end:]
    return out
