"""Paths built from parts, folded into one literal so path rules can read them.

``path.join(os.homedir(), '.kube', 'config')`` names ``~/.kube/config`` without
ever writing it. Lines with such calls get a ``resolved`` view in which each
call is replaced by the quoted path: home-directory expressions become ``~``,
string-literal segments are joined with ``/``, and any other first argument is
kept as written. Covered: JS/TS ``path.join``/``path.resolve``, Python
``os.path.join``, ``Path(...)``, ``.joinpath(...)`` and ``Path.home() / ...``,
Go ``filepath.Join`` and PowerShell ``Join-Path``. Folding repeats so nested
calls resolve. Only string literals are joined; values computed elsewhere are not.
"""

from __future__ import annotations

import regex

from ..textutil import TIMEOUT

_MAX_LINE = 2000
_PASSES = 3

_Q = r"""(?:'[^'\n\\]*'|"[^"\n\\]*"|`[^`\n\\$]*`)"""
_ENV = r"""(?:HOME|USERPROFILE)"""
_HOME = (
    r"(?:os\.homedir\(\)|(?<![\w.])homedir\(\)"
    rf"|process\.env\.{_ENV}\b|process\.env\[['\"]{_ENV}['\"]\]"
    r"|(?:os\.path\.)?expanduser\(\s*['\"]~['\"]\s*\)|(?:pathlib\.)?Path\.home\(\)"
    rf"|os\.environ\[['\"]{_ENV}['\"]\]|os\.(?:environ\.get|getenv)\(\s*['\"]{_ENV}['\"]\s*\)"
    r"|os\.UserHomeDir\(\)|Dir\.home\b|ENV\[['\"]HOME['\"]\]|['\"]~['\"])"
)
_FIRST = rf"(?:{_HOME}|str\(\s*{_HOME}\s*\)|{_Q}|[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)"
_CALLEE = (
    r"(?:\b(?:path|os\.path|posixpath|ntpath|upath|filepath|File)\.(?:join|Join|resolve)"
    r"|(?<![\w.$])(?:join|resolve|Path|PurePath|PosixPath|WindowsPath|PurePosixPath|PureWindowsPath))"
)
_CALL = regex.compile(rf"{_CALLEE}\(\s*(?P<first>{_FIRST})\s*(?P<rest>(?:,\s*{_Q}\s*)+),?\s*\)")
_JOINPATH = regex.compile(rf"(?P<first>{_HOME}|{_Q})\.joinpath\(\s*(?P<rest>{_Q}(?:\s*,\s*{_Q})*),?\s*\)")
_DIV = regex.compile(rf"(?P<first>{_HOME}|{_Q})(?P<rest>(?:\s*/\s*{_Q})+)")
_PS_SEG = r"""(?:'[^'\n]*'|"[^"\n$]*"|[^\s'"`$|;(){}]+)"""
_PS_JOIN = regex.compile(
    rf"(?i)\bJoin-Path\s+(?:-Path\s+)?(?P<first>\$HOME\b|\$env:{_ENV}\b|~|{_PS_SEG})"
    rf"(?P<rest>(?:\s+(?:-ChildPath\s+|-AdditionalChildPath\s+)?(?!-){_PS_SEG})+)"
)
_SEG = regex.compile(_Q)
_PS_SEGS = regex.compile(_PS_SEG)
_QUICK = regex.compile(r"(?i)join|resolve|path|home")


def _home(expr: str) -> bool:
    return regex.fullmatch(rf"{_HOME}|str\(\s*{_HOME}\s*\)", expr.strip(), timeout=TIMEOUT) is not None


def _unquote(s: str) -> str:
    s = s.strip()
    return s[1:-1] if len(s) >= 2 and s[0] == s[-1] and s[0] in "'\"`" else s


def _join(first: str, segments: list[str]) -> str:
    ps_home = first.strip().lower() in ("$home", "~") or first.strip().lower().startswith("$env:")  # _PS_JOIN admits only HOME/USERPROFILE
    head = "~" if ps_home or _home(first) else _unquote(first)
    tail = "/".join(s.strip("/\\") for s in segments if s.strip("/\\"))
    path = (head.rstrip("/\\") + "/" + tail if tail else head) if head else tail
    return "'" + path.replace("\\", "/") + "'"


def _fold(line: str) -> str:
    out = line
    for _ in range(_PASSES):
        before = out
        out = _CALL.sub(lambda m: _join(m["first"], [_unquote(s) for s in _SEG.findall(m["rest"])]), out, timeout=TIMEOUT)
        out = _JOINPATH.sub(lambda m: _join(m["first"], [_unquote(s) for s in _SEG.findall(m["rest"])]), out, timeout=TIMEOUT)
        out = _DIV.sub(lambda m: _join(m["first"], [_unquote(s) for s in _SEG.findall(m["rest"])]), out, timeout=TIMEOUT)
        out = _PS_JOIN.sub(
            lambda m: _join(m["first"], [_unquote(s) for s in _PS_SEGS.findall(regex.sub(r"(?i)-(?:Additional)?ChildPath\b", " ", m["rest"]))]),
            out,
            timeout=TIMEOUT,
        )
        if out == before:
            break
    return out


def resolved_lines(text: str) -> list[tuple[int, int, str]]:
    """(start, end, folded line) for each line of ``text`` that has a path built
    from parts; lines without one are left out."""
    out: list[tuple[int, int, str]] = []
    pos = 0
    for line in text.split("\n"):
        start, pos = pos, pos + len(line) + 1
        if len(line) > _MAX_LINE or not _QUICK.search(line):
            continue
        try:
            folded = _fold(line)
        except TimeoutError:
            continue
        if folded != line:
            out.append((start, start + len(line), folded))
    return out


__all__ = ["resolved_lines"]
