"""Commands and strings that are put together at run time, folded back into what they spell.

Published evasion tests break a command or a path into pieces so that no line of the file contains it:
shell variables spliced together (``${A}${B}``), a command name produced by a command substitution
(``$(echo curl)``), strings built from character codes (``''.join(map(chr, [...]))``,
``String.fromCharCode(...)``, ``bytes([...])``, ``bytes.fromhex(...)``), short string literals
concatenated or reversed, and one command spread over several lines with continuations.

``derived_lines`` returns, for each logical line that reads differently once those are undone, the
folded text and the techniques that were undone. Only literals written in the file are folded;
nothing is evaluated and values computed elsewhere are left as written.

A fold is reported only when it reveals something: the folded line contains a command, path or URL
token that the line as written does not. Lines that were merely continued are returned too (with the
single technique ``line-continuation``), so that rules which read one line at a time see the whole
command.
"""

from __future__ import annotations

import regex

from ..textutil import TIMEOUT

_F = regex.IGNORECASE
_MAX_LINE = 4000
_MAX_LINES = 400            # derived lines per file
CONTINUATION = "line-continuation"

# Tokens whose appearance after folding means the assembly was hiding something.
SENSITIVE = regex.compile(
    r"curl|wget|/bin/(?:ba)?sh|bash|eval|exec|system|popen|subprocess|powershell|base64|netcat|\bnc\b|chmod|child_process|os\.system"
    r"|\.ssh|id_rsa|authorized_keys|\.aws|credentials|\.env\b|/etc/passwd|shadow|api[_-]?key|https?://|rm\s+-rf|__import__|Invoke-Expression"
    r"|\.npmrc|\.kube|\.netrc|\.docker/config|keychain|mshta|certutil|bitsadmin|\bsh\b|\bpython3?\b|\bnode\b", _F)

_QUICK = regex.compile(r"\\\r?\n|\$\{?[A-Za-z_]\w*\}?\$|\$[A-Za-z_{]|(?:\$\(|`)\s*(?:echo|printf)\b|\bchr\b|fromCharCode|fromhex|bytes\(|bytearray\("
                       r"|Buffer\.from\(\s*\[|[\"']\s*\+\s*[\"']|\[::-1\]|reverse\(\)")
_CONT = regex.compile(r"[ \t]*\\\r?\n[ \t]*")
_ASSIGN = regex.compile(r"(?m)(?:^|[;\s])(?:export\s+|local\s+|readonly\s+)?([A-Za-z_]\w{0,23})=([\"']?)([\w./:\-${}]{0,48})\2(?=[;\s]|$)")   # an empty value is a piece too
_VAR = regex.compile(r"\$\{([A-Za-z_]\w{0,23})\}|\$([A-Za-z_]\w{0,23})")
_SPLICE = regex.compile(r"(?:\$\{[A-Za-z_]\w{0,23}\}|\$[A-Za-z_]\w{0,23}){2,}")
_AT_COMMAND = regex.compile(r"(?m)(^[ \t]*|[|;&(]\s*|\bthen\s+|\bdo\s+|\bsudo\s+)(\$\{[A-Za-z_]\w{0,23}\}|\$[A-Za-z_]\w{0,23})(?=[ \t])")
_SUBST = regex.compile(
    r"\$\(\s*(?:echo|printf)\s+(?:-[neE]+\s+)?(?:[\"']%s[\"']\s+)?([\"']?)([\w./:\-]{1,48})\1\s*\)"
    r"|`\s*(?:echo|printf)\s+(?:-[neE]+\s+)?(?:[\"']%s[\"']\s+)?([\"']?)([\w./:\-]{1,48})\3\s*`")
_NUMS = r"((?:\s*(?:0x[0-9a-fA-F]{1,4}|\d{1,5})\s*,?){2,400})"
_CODES = (
    regex.compile(r"(?:''|\"\")\.join\(\s*map\(\s*chr\s*,\s*[\[(]" + _NUMS + r"[\])]\s*\)\s*\)"),
    regex.compile(r"(?:''|\"\")\.join\(\s*\[?\s*chr\(\s*\w+\s*\)\s+for\s+\w+\s+in\s+[\[(]" + _NUMS + r"[\])]\s*\]?\s*\)"),
    regex.compile(r"(?:''|\"\")\.join\(\s*\[((?:\s*chr\(\s*(?:0x[0-9a-fA-F]{1,4}|\d{1,5})\s*\)\s*,?){2,400})\]\s*\)"),
    regex.compile(r"((?:chr\(\s*(?:0x[0-9a-fA-F]{1,4}|\d{1,5})\s*\)\s*\+\s*){1,400}chr\(\s*(?:0x[0-9a-fA-F]{1,4}|\d{1,5})\s*\))"),
    regex.compile(r"String\.fromCharCode\(" + _NUMS + r"\)"),
    regex.compile(r"(?:bytes|bytearray)\(\s*\[" + _NUMS + r"\]\s*\)(?:\.decode\([^)\n]{0,24}\))?"),
    regex.compile(r"Buffer\.from\(\s*\[" + _NUMS + r"\]\s*\)(?:\.toString\([^)\n]{0,24}\))?"),
)
_NUM = regex.compile(r"0x[0-9a-fA-F]{1,4}|\d{1,5}")
_FROMHEX = regex.compile(r"(?:bytes|bytearray)\.fromhex\(\s*[\"']([0-9a-fA-F\s]{4,800})[\"']\s*\)(?:\.decode\([^)\n]{0,24}\))?")
_PIECE = r"(?:'[^'\\\n]{0,24}'|\"[^\"\\\n]{0,24}\")"
_CONCAT = regex.compile(_PIECE + r"(?:\s*\+\s*" + _PIECE + r"){1,24}")
_ONE = regex.compile(_PIECE)
_REVERSED = regex.compile(r"([\"'])([^\"'\\\n]{3,200})\1(?:\[::-1\]|\.split\(\s*(?:''|\"\")\s*\)\.reverse\(\)\.join\(\s*(?:''|\"\")\s*\))")


def _quote(s: str) -> str:
    return "'" + s.replace("\\", "\\\\").replace("'", "\\'").replace("\n", " ") + "'"


def _from_codes(body: str) -> str | None:
    try:
        chars = [int(n, 16) if n.lower().startswith("0x") else int(n) for n in _NUM.findall(body)]
        if not chars or any(c < 9 or c > 0x10FFFF for c in chars):
            return None
        return "".join(chr(c) for c in chars)
    except (ValueError, OverflowError):
        return None


def shell_values(text: str) -> dict[str, str]:
    """Literal values of shell variables assigned once in ``text`` (references to other such variables resolved)."""
    seen: dict[str, set[str]] = {}
    try:
        for m in _ASSIGN.finditer(text, timeout=TIMEOUT):
            seen.setdefault(m.group(1), set()).add(m.group(3))
    except TimeoutError:
        return {}
    values = {name: next(iter(vals)) for name, vals in seen.items() if len(vals) == 1}
    for _ in range(3):
        changed = False
        for name, value in list(values.items()):
            if "$" not in value:
                continue
            new = _VAR.sub(lambda m: values.get(m.group(1) or m.group(2), m.group(0)) if (m.group(1) or m.group(2)) != name else m.group(0), value)
            if new != value:
                values[name], changed = new, True
        if not changed:
            break
    return {k: v for k, v in values.items() if "$" not in v and "{" not in v}


def fold(line: str, values: dict[str, str] | None = None) -> tuple[str, tuple[str, ...]]:
    """``line`` with run-time assembly undone, and the techniques that were undone (in a fixed order)."""
    how: list[str] = []
    out = line

    def note(name: str, new: str) -> str:
        nonlocal out
        if new != out:
            out = new
            if name not in how:
                how.append(name)
        return out

    if values and "$" in out:
        def splice(m: regex.Match[str]) -> str:
            names = [a or b for a, b in _VAR.findall(m.group(0))]
            return "".join(values[n] for n in names) if all(n in values for n in names) else m.group(0)

        def command(m: regex.Match[str]) -> str:
            name = m.group(2).strip("${}")
            return m.group(1) + values[name] if name in values else m.group(0)

        note("shell-variable-splicing", _SPLICE.sub(splice, out, timeout=TIMEOUT))
        note("shell-variable-splicing", _AT_COMMAND.sub(command, out, timeout=TIMEOUT))
    if ("$(" in out or "`" in out) and ("echo" in out or "printf" in out):
        note("command-substitution", _SUBST.sub(lambda m: m.group(2) or m.group(4), out, timeout=TIMEOUT))
    if "chr" in out or "fromCharCode" in out or "bytes" in out or "Buffer.from" in out or "bytearray" in out:
        for rx in _CODES:
            def codes(m: regex.Match[str]) -> str:
                word = _from_codes(m.group(1))
                return _quote(word) if word is not None else m.group(0)

            note("character-codes", rx.sub(codes, out, timeout=TIMEOUT))

        def fromhex(m: regex.Match[str]) -> str:
            try:
                return _quote(bytes.fromhex(m.group(1)).decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                return m.group(0)

        note("character-codes", _FROMHEX.sub(fromhex, out, timeout=TIMEOUT))
    if "[::-1]" in out or "reverse()" in out:
        note("reversed-string", _REVERSED.sub(lambda m: _quote(m.group(2)[::-1]), out, timeout=TIMEOUT))
    if "+" in out and ("'" in out or '"' in out):
        def joined(m: regex.Match[str]) -> str:
            return _quote("".join(p[1:-1] for p in _ONE.findall(m.group(0))))

        for _ in range(2):
            before = out
            note("string-concatenation", _CONCAT.sub(joined, out, timeout=TIMEOUT))
            if out == before:
                break
    return out, tuple(how)


def _reveals(folded: str, original: str) -> bool:
    """True when ``folded`` holds a sensitive token that ``original`` does not hold as a word of its own."""
    low = original.lower()
    for m in SENSITIVE.finditer(folded, timeout=TIMEOUT):
        token = m.group(0).lower()
        if len(token) < 2:
            continue
        pos, standalone = low.find(token), False
        while pos >= 0:
            before = low[pos - 1] if pos else " "
            after = low[pos + len(token)] if pos + len(token) < len(low) else " "
            if not (before.isalnum() or before == "_") and not (after.isalnum() or after == "_"):
                standalone = True
                break
            pos = low.find(token, pos + 1)
        if not standalone:
            return True
    return False


def _substituted_command(line: str) -> bool:
    """A command substitution prints a sensitive word: ``$(echo nc)`` shows ``nc``, but as an argument of
    ``echo``, so the line as written never has it where a command is read."""
    return any(SENSITIVE.search(m.group(2) or m.group(4) or "") for m in _SUBST.finditer(line, timeout=TIMEOUT))


def derived_lines(text: str) -> list[tuple[int, int, str, tuple[str, ...]]]:
    """(start, end, folded text, techniques) for each logical line of ``text`` that reads differently once
    run-time assembly is undone. ``start``/``end`` are offsets of the physical lines it came from."""
    if len(text) > 4_000_000 or not _QUICK.search(text):
        return []
    values = shell_values(text) if "$" in text and "=" in text else {}
    out: list[tuple[int, int, str, tuple[str, ...]]] = []
    # Logical lines: physical lines ending in a backslash are joined with the next one.
    pos, n = 0, len(text)
    while pos < n and len(out) < _MAX_LINES:
        end = text.find("\n", pos)
        end = n if end < 0 else end
        start = pos
        continued = False
        while end < n and end > pos and text[end - 1 - (1 if text[end - 1] == "\r" else 0)] == "\\" and end - start < _MAX_LINE:
            continued = True
            nxt = text.find("\n", end + 1)
            end = n if nxt < 0 else nxt
        raw = text[start:end]
        pos = end + 1
        if len(raw) > _MAX_LINE or not raw.strip():
            continue
        line = _CONT.sub(" ", raw) if continued else raw
        try:
            folded, how = fold(line, values)
            if how and not _reveals(folded, raw) and not ("command-substitution" in how and _substituted_command(line)):
                folded, how = line, ()
        except TimeoutError:
            folded, how = line, ()
        if continued:
            how = (CONTINUATION, *how)
        if how:
            out.append((start, end, folded, how))
    return out


__all__ = ["CONTINUATION", "SENSITIVE", "derived_lines", "fold", "shell_values"]
