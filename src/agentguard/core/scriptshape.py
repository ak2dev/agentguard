"""Files that are run as scripts whatever their name says.

A file is a script when something runs it with an interpreter (``python notes.dat``, ``bash logo.png``,
``cat data.csv | sh``) and its content has the shape of one. The inventory uses this to analyse such a
file as code, and AG-EVADE-007 reports the disguise.
"""

from __future__ import annotations

import regex

from .textutil import TIMEOUT

_F = regex.IGNORECASE
HARMLESS_EXT = r"(?:txt|md|markdown|dat|log|png|jpe?g|gif|csv|tsv|json|cfg|conf|bak|tmp|pdf|svg|ico|css|html?|rst|lst|data|bin\.txt)"
RUN_AS_SCRIPT = regex.compile(
    r"\b(?P<how>bash|sh|zsh|dash|ksh|python3?|node|deno|bun|ruby|perl|pwsh|powershell(?:\.exe)?|source|exec|osascript)\s+(?:-[\w-]+\s+)*"
    r"[\"']?(?P<file>[\w./${}~-]+\." + HARMLESS_EXT + r")\b"
    r"|\b(?P<how2>chmod\s+\+x|\.)\s+[\"']?(?P<file2>(?:\./|[\w${}~-]+/)[\w./${}~-]*\." + HARMLESS_EXT + r")\b"
    r"|\bcat\s+[\"']?(?P<file3>[\w./${}~-]+\." + HARMLESS_EXT + r")[\"']?\s*\|\s*(?P<how3>(?:ba|z)?sh|python3?|node)\b", _F)
SCRIPT_LINE = regex.compile(
    r"(?m)^\s*(?:import\s+\w|from\s+[\w.]+\s+import\s|def\s+\w+\(|class\s+\w+[(:]|function\s+\w+\s*\(|(?:const|let|var)\s+\w+\s*=|require\("
    r"|set\s+-[eux]|if\s+\[|echo\s|curl\s|wget\s|export\s+\w+=|\$\(|subprocess\.|os\.system|eval\s|exec\s|fi$|done$|#!/"
    r"|print\(|console\.\w+\(|with\s+open\(|for\s+\w+\s+in\s|while\s+[\w(!\[]|try:|[\w.\[\]\"']+\s*=\s*[\w.]+\(|[A-Za-z_][\w.]*\.\w+\([^\n]*\)\s*;?\s*$)")
# Interpreter name -> language of the file it runs.
LANGUAGE = {
    "python": "python", "python3": "python", "node": "javascript", "deno": "typescript", "bun": "javascript",
    "bash": "shell", "sh": "shell", "zsh": "shell", "dash": "shell", "ksh": "shell", "source": "shell", ".": "shell", "exec": "shell",
    "chmod +x": "shell", "pwsh": "powershell", "powershell": "powershell", "powershell.exe": "powershell", "ruby": "ruby", "perl": "perl",
    "osascript": "applescript",
}


def script_shape(data: bytes) -> tuple[bool, int]:
    """(starts with an interpreter line, number of lines that read as script) for the first 64 KiB."""
    head = data[:65536].decode("utf-8", "replace")
    try:
        lines = sum(1 for _ in SCRIPT_LINE.finditer(head, timeout=TIMEOUT))
    except TimeoutError:
        lines = 0
    return data.startswith(b"#!"), lines


def is_script(data: bytes) -> bool:
    shebang, lines = script_shape(data)
    return shebang or lines >= 2


def language_of_run(how: str) -> str:
    return LANGUAGE.get(regex.sub(r"\s+", " ", how.strip().lower()), "shell")


# Extensions under which a complete program is read as the program it is, with nothing having to run it.
# Documentation formats are left out: a page of examples is not a program.
PROGRAM_SNIFF_EXT = (".txt", ".dat", ".data", ".log", ".csv", ".tsv", ".bak", ".tmp", ".lst", ".cfg", ".conf", ".bin")
# Of those, the ones where code is never expected, so the disguise itself is reported (AG-OBF-021).
DATA_ONLY_EXT = tuple(e for e in PROGRAM_SNIFF_EXT if e != ".txt")
_PY_START = regex.compile(r"(?m)^(?:import\s+[\w.]+|from\s+[\w.]+\s+import\s)")
_JS_START = regex.compile(r"(?m)^(?:(?:const|let|var)\s+[\w{}\s,]+=\s*require\(|import\s+[\w{}\s,*]+\s+from\s+[\"']|module\.exports\s*=|"
                          r"export\s+(?:default|const|function|async)\b|(?:async\s+)?function\s+\w+\s*\()")
_JS_LINE_END = (";", "{", "}", ",", "(", ")", "=>", "[", "]")


def program_language(data: bytes) -> str | None:
    """The language of ``data`` when the whole of it is a program, judged from the content alone.

    Python must parse and hold an import beside other statements; prose, tables and logs do not parse.
    JavaScript has no parser here, so it needs module-level statements and code-shaped lines throughout.
    Shell is recognised only by an interpreter line: a list of commands is also what notes look like."""
    if not data or len(data) > 512 * 1024 or b"\0" in data[:4096]:
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    try:
        if _PY_START.search(text, timeout=TIMEOUT):
            import ast
            import warnings

            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    body = ast.parse(text).body
            except (SyntaxError, ValueError, RecursionError, MemoryError):
                body = []
            if len(body) >= 2 and any(isinstance(n, (ast.Import, ast.ImportFrom)) for n in body):
                return "python"
        if len(_JS_START.findall(text, timeout=TIMEOUT)) >= 2:
            lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
            code = sum(1 for ln in lines if ln.endswith(_JS_LINE_END) or ln.startswith(("//", "/*", "*")))
            if len(lines) >= 3 and code / len(lines) >= 0.6:
                return "javascript"
    except TimeoutError:
        return None
    return None


__all__ = ["DATA_ONLY_EXT", "HARMLESS_EXT", "LANGUAGE", "PROGRAM_SNIFF_EXT", "RUN_AS_SCRIPT", "SCRIPT_LINE", "is_script",
           "language_of_run", "program_language", "script_shape"]
