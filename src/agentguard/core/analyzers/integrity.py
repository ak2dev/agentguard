"""Text and file integrity beyond the hidden-content analyzer (engine A).

* ``TextIntegrityAnalyzer``: confusable characters in commands, URLs and names
  (AG-OBF-004), variation selectors and invisible separators that carry data
  (AG-OBF-006), terminal escape sequences (AG-OBF-009), nested encodings
  (AG-OBF-011), text that changes under normalisation (AG-OBF-023),
  instructions in YAML comments and unused frontmatter keys (AG-OBF-024), and
  padding (AG-EVADE-013).
* ``FileIntegrityAnalyzer``: minified or packed scripts (AG-OBF-019), content
  that does not match its extension and polyglots (AG-OBF-021), data after a
  file's end marker (AG-OBF-022).
* ``CodeObfuscationAnalyzer``: decoder stubs beside opaque data (AG-OBF-013),
  sensitive tokens assembled from fragments (AG-OBF-014) or split across lines
  (AG-OBF-016).

Pure: works on the bytes and prepared text of the tree.
"""

from __future__ import annotations

import math
import posixpath
import struct
import unicodedata
from typing import ClassVar

import regex

from ..artifacts import ArtifactText, binary_kind
from ..models import Span
from ..models.enums import ArtifactRole, ComponentKind, EvidenceKind, Severity
from ..normalize.unicode import _CONFUSABLES
from ..scriptshape import DATA_ONLY_EXT, program_language
from ..textutil import TIMEOUT
from .base import Context
from .heuristics import AGENT_DIRECTED, search, word_count
from .skill import PLATFORM_FIELDS, SPEC_FIELDS

_F = regex.IGNORECASE


def _cls(*ranges: tuple[int, int]) -> str:
    """A regex character class built from code-point ranges (keeps invisible characters out of the source)."""
    return "[" + "".join(chr(a) if a == b else f"{chr(a)}-{chr(b)}" for a, b in ranges) + "]"


_URL = regex.compile(r"\bhttps?://[^\s<>\"'`)\]]+", _F)
_INLINE_CODE = regex.compile(r"`([^`\n]{2,200})`")
_TOKEN = regex.compile(r"[^\s\"'`<>()\[\]{},;=|&]+")
# A backslash escape in source text (`\s`, `\n`, `\x41`, `\u0435`): its letters are syntax, not part of a name.
_BACKSLASH_ESCAPE = regex.compile(r"\\(?:x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|N\{[^}\n]{0,80}\}|.)")
_VS = regex.compile(_cls((0xFE00, 0xFE0F), (0xE0100, 0xE01EF)) + "{2,}|" + _cls((0xE0100, 0xE01EF)))
_INVISIBLE_RUN = regex.compile(_cls(*((c, c) for c in (0x200B, 0x200C, 0x200D, 0x2060, 0x2062, 0x2063, 0x2064, 0xFEFF,
                                                             0x034F, 0x00AD, 0x115F, 0x1160, 0x3164, 0xFFA0))) + "{8,}")
_ESC = regex.compile(r"\x1b(?:\[[0-9;?]*[ -/]*[@-~]|\][^\x07\x1b]{0,200}(?:\x07|\x1b\\)?|[@-Z\\^_])|\x9b[0-9;?]*[@-~]")
_PADDING = regex.compile(r"(?:[ \t\r]*\n){200,}|[ \t\r\n]{5000,}")
_FOLDABLE = regex.compile(_cls((0xFF10, 0xFF19), (0xFF21, 0xFF3A), (0xFF41, 0xFF5A), (0x1D400, 0x1D7FF), (0x24B6, 0x24E9),
                                (0x1F130, 0x1F189)) + "{3,}")
_CJK = regex.compile(_cls((0x3040, 0x30FF), (0x3400, 0x9FFF), (0xAC00, 0xD7AF)))
_YAML_COMMENT = regex.compile(r"(?m)(?:^|[ \t])#[ \t]*(\S[^\n]*)$")
_OTHER_AGENT_FIELDS = frozenset({
    "tools", "disallowedtools", "permissionmode", "maxturns", "skills", "mcpservers", "memory", "omitclaudemd", "isolation",
    "initialprompt", "globs", "alwaysapply", "applyto", "excludeagent", "mcp-servers", "color", "title", "tags", "author", "homepage",
    "repository", "keywords", "category", "icon", "trigger", "triggers", "command-dispatch", "user_invocable", "os", "requires",
})
_SENSITIVE = regex.compile(
    r"curl|wget|/bin/(?:ba)?sh|bash|eval|exec|system|popen|subprocess|powershell|base64|netcat|\bnc\b|chmod|child_process|os\.system"
    r"|\.ssh|id_rsa|authorized_keys|\.aws|credentials|\.env\b|/etc/passwd|shadow|api[_-]?key|https?://|rm\s+-rf|__import__|Invoke-Expression", _F)
_CONCAT = regex.compile(r"([\"'])((?:(?!\1)[^\\\n]){1,16})\1(?:\s*\+\s*([\"'])((?:(?!\3)[^\\\n]){1,16})\3){1,12}")
_CONCAT_PIECE = regex.compile(r"([\"'])((?:(?!\1)[^\\\n]){0,16})\1")
_JOIN_LIST = regex.compile(r"(?:(?:''|\"\")\.join\(\s*\[((?:\s*[\"'][^\"'\n]{0,8}[\"']\s*,?){3,})\s*\]\s*\)"
                           r"|\[((?:\s*[\"'][^\"'\n]{0,8}[\"']\s*,?){3,})\s*\]\.join\(\s*(?:''|\"\")\s*\))")
_CHR_CHAIN = regex.compile(r"(?:chr\(\s*(?:0x[0-9a-f]{2}|\d{2,3})\s*\)\s*\+?\s*){3,}", _F)
_FROM_CHAR = regex.compile(r"String\.fromCharCode\(\s*((?:(?:0x[0-9a-f]{2}|\d{2,3})\s*,?\s*){3,})\)", _F)
_BYTES_LIST = regex.compile(r"bytes\(\s*\[\s*((?:(?:0x[0-9a-f]{2}|\d{2,3})\s*,?\s*){3,})\]\s*\)", _F)
_SH_ASSIGN = regex.compile(r"(?m)(?:^|[;\s])([A-Za-z_]\w{0,12})=([\"']?)([\w./:\-]{1,12})\2(?=[;\s]|$)")
_SH_SPLICE = regex.compile(r"(?:\$\{?[A-Za-z_]\w{0,12}\}?){2,}")
_SH_VAR = regex.compile(r"\$\{?([A-Za-z_]\w{0,12})\}?")
_BACKSLASH_SPLIT = regex.compile(r"[A-Za-z0-9./_-]+(?:\\\r?\n[ \t]*[A-Za-z0-9./_-]+)+")
_ADJ_LITERALS = regex.compile(r"([\"'])((?:(?!\1)[^\\\n]){1,16})\1(?:[ \t]*\r?\n[ \t]*([\"'])((?:(?!\3)[^\\\n]){1,16})\3){1,8}")
_DECODE_STEP = regex.compile(
    r"\bbase64\s+(?:-d|-D|--decode)\b|\bbase64\.(?:b64decode|b32decode|a85decode|decodebytes)\(|\b(?:zlib|gzip|lzma|bz2)\.decompress\("
    r"|\bmarshal\.loads\(|\bbytes\.fromhex\(|\bcodecs\.decode\(|\bopenssl\s+enc\s+-d\b|\bopenssl\s+\w+\s+-d\b|\bxxd\s+-r\b|\bgpg\s+(?:-d|--decrypt)\b"
    r"|\btar\s+-?[a-z]*x[a-z]*\b|\bunzip\s|\b7z\s+x\b|\bgunzip\b|\bBuffer\.from\([^)\n]*[\"']base64[\"']|\batob\(|\bFromBase64String\("
    r"|\bcertutil\s+-decode\b", _F)
_RUN_STEP = regex.compile(
    r"\|\s*(?:ba|z)?sh\b|\b(?:ba|z)?sh\s+[\w./$~-]+|\bexec\(|\beval\(|\bos\.system\(|\bsubprocess\.|\bchmod\s+\+x\b|\bsource\s+\S|\bpython3?\s+[\w./$~-]+"
    r"|\bnode\s+[\w./$~-]+|\bnew\s+Function\(|\bchild_process\b|\bInvoke-Expression\b|\biex\b|(?:^|[;&]\s*)\./[\w./-]+|\bimportlib\b|\b__import__\(", _F | regex.MULTILINE)
# The decoded content is written out as files (the stub rebuilds the package instead of running the payload itself).
_WRITE_STEP = regex.compile(
    r"\.write_bytes\(|\.write_text\(|\bopen\([^)\n]*,\s*[\"'][wax]b?\+?[\"']|\bwriteFileSync\(|\bfs\.writeFile\(|\bSet-Content\b|\bOut-File\b"
    r"|\bWriteAll(?:Bytes|Text)\(|\s>\s*[\"']?[\w./$~{}-]*\.\w{1,6}\b|\btee\s+[\"']?[\w./$~{}-]+", _F)
# A decoded picture, font or sound is an asset being restored, not a package being rebuilt.
_MEDIA_NAME = regex.compile(r"\.(?:png|jpe?g|gif|webp|ico|bmp|tiff?|pdf|ttf|otf|woff2?|mp[34]|wav|ogg)\b", _F)
_B64_RUN = regex.compile(r"[A-Za-z0-9+/_-]{48,}={0,2}")
_PACKER = regex.compile(r"eval\(function\(p,a,c,k,e,[dr]\)|\bString\.fromCharCode\([^)]{200,}\)|\bunescape\(\s*[\"']%[0-9a-f]{2}", _F)
_HEX_IDENT = regex.compile(r"\b_0x[0-9a-f]{4,6}\b", _F)
_PACKAGE_KINDS = (ComponentKind.skill, ComponentKind.plugin, ComponentKind.bundle)
_CODE_ROLES = (ArtifactRole.script, ArtifactRole.source_code)
_PROSE_ROLES = (ArtifactRole.skill_md, ArtifactRole.instruction_md, ArtifactRole.command_md, ArtifactRole.reference)
_SIG_START = (b"MCPB_SIG_V1", b"DXT_SIG_V1")
_SIG_END = (b"MCPB_SIG_END", b"DXT_SIG_END")
# What the bytes of a file with this extension may be (None: text).
_ZIP_EXT = (".zip", ".docx", ".docm", ".dotx", ".dotm", ".xlsx", ".xlsm", ".xlsb", ".pptx", ".pptm", ".jar", ".whl", ".mcpb", ".dxt",
            ".skill", ".vsix", ".epub", ".odt", ".ods", ".odp", ".apk", ".nupkg", ".plugin", ".crx")
_EXPECT: dict[str, tuple[str | None, ...]] = {
    ".png": ("png",), ".jpg": ("jpeg",), ".jpeg": ("jpeg",), ".gif": ("gif",), ".webp": ("webp",), ".pdf": ("pdf",),
    ".tif": ("tiff",), ".tiff": ("tiff",), ".gz": ("gzip",), ".tgz": ("gzip",), ".bz2": ("bzip2",), ".xz": ("xz",), ".7z": ("7z",),
    ".rar": ("rar",), ".tar": ("tar",), ".doc": ("ole",), ".xls": ("ole",), ".ppt": ("ole",), ".msi": ("ole",), ".wasm": ("wasm",),
    **{e: ("zip",) for e in _ZIP_EXT},
    **{e: (None,) for e in (".md", ".mdc", ".txt", ".json", ".jsonc", ".json5", ".yaml", ".yml", ".toml", ".csv", ".tsv", ".ini", ".cfg",
                            ".xml", ".html", ".htm", ".svg", ".py", ".js", ".mjs", ".cjs", ".ts", ".sh", ".bash", ".ps1", ".rb", ".css",
                            ".env", ".log", ".rst", ".lock")},
}
_IMAGE_KINDS = ("png", "jpeg", "gif", "webp")


def _search(rx: regex.Pattern[str], text: str, pos: int = 0) -> regex.Match[str] | None:
    try:
        return rx.search(text, pos, timeout=TIMEOUT)
    except TimeoutError:
        return None


def _finditer(rx: regex.Pattern[str], text: str) -> list[regex.Match[str]]:
    try:
        return list(rx.finditer(text, timeout=TIMEOUT))
    except TimeoutError:
        return []


def entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def decode_selectors(run: str) -> str:
    """Bytes smuggled in variation selectors (VS1-16 are 0-15, VS17-256 are 16-255), as text."""
    out = bytearray()
    for ch in run:
        cp = ord(ch)
        if 0xFE00 <= cp <= 0xFE0F:
            out.append(cp - 0xFE00)
        elif 0xE0100 <= cp <= 0xE01EF:
            out.append(cp - 0xE0100 + 16)
    text = out.decode("utf-8", "replace")
    return text if sum(c.isprintable() or c in "\n\t" for c in text) >= max(1, len(text) * 0.8) and chr(0xFFFD) not in text else ""


def decode_binary_run(run: str) -> str:
    """Text hidden as bits in a run that uses exactly two invisible characters."""
    kinds = sorted(set(run))
    if len(kinds) != 2 or len(run) < 16:
        return ""
    for zero, one in ((kinds[0], kinds[1]), (kinds[1], kinds[0])):
        bits = "".join("0" if c == zero else "1" for c in run)
        data = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) - len(bits) % 8, 8))
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if text and all(c.isprintable() or c in "\n\t" for c in text):
            return text
    return ""


def end_of_content(data: bytes, kind: str) -> int | None:
    """Offset where the format says the file ends, or None when it cannot be told."""
    try:
        if kind == "png":
            pos = 8
            while pos + 12 <= len(data):
                length, ctype = struct.unpack(">I4s", data[pos:pos + 8])
                pos += 12 + length
                if ctype == b"IEND":
                    return pos if pos <= len(data) else None
            return None
        if kind == "jpeg":
            end = data.rfind(b"\xff\xd9")
            return end + 2 if end > 0 else None
        if kind == "gif":
            pos = 13
            flags = data[10]
            if flags & 0x80:
                pos += 3 * (2 << (flags & 7))
            while pos < len(data):
                block = data[pos]
                if block == 0x3B:
                    return pos + 1
                if block == 0x21:
                    pos += 2
                elif block == 0x2C:
                    local = data[pos + 9]
                    pos += 10
                    if local & 0x80:
                        pos += 3 * (2 << (local & 7))
                    pos += 1
                else:
                    return None
                while pos < len(data) and data[pos] != 0:
                    pos += data[pos] + 1
                pos += 1
            return None
        if kind == "pdf":
            end = data.rfind(b"%%EOF")
            return end + 5 if end >= 0 else None
        if kind == "zip":
            eocd = data.rfind(b"PK\x05\x06")
            if eocd < 0 or eocd + 22 > len(data):
                return None
            comment = struct.unpack("<H", data[eocd + 20:eocd + 22])[0]
            return min(eocd + 22 + comment, len(data))
    except (IndexError, struct.error):
        return None
    return None


def is_signature_block(tail: bytes) -> bool:
    """An MCPB (or older DXT) signature block appended after the archive: not hidden data."""
    stripped = tail.strip(b"\r\n\x00 ")
    return stripped.startswith(_SIG_START) and stripped.endswith(_SIG_END)


class TextIntegrityAnalyzer:
    id: ClassVar[str] = "text.integrity"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = ("AG-OBF-004", "AG-OBF-006", "AG-OBF-009", "AG-OBF-011", "AG-OBF-023", "AG-OBF-024",
                                        "AG-EVADE-013")

    def run(self, ctx: Context) -> None:
        for at in ctx.texts():
            if at.text.isascii():
                self._ascii_only(ctx, at)
                continue
            self._confusables(ctx, at)
            self._carriers(ctx, at)
            self._normalisation(ctx, at)
            self._ascii_only(ctx, at)
        for comp in sorted(ctx.inventory.components.values(), key=lambda c: c.id):
            for tool in comp.tools:
                bad = [c for c in tool.name if c in _CONFUSABLES]
                if bad:
                    ctx.emit("AG-OBF-004", component_ids=comp.id, span=tool.span, snippet=tool.name, match=f"tool:{comp.name}:{tool.name}",
                             kind=EvidenceKind.metadata, decoded="".join(_CONFUSABLES.get(c, c) for c in tool.name),
                             message=f"Tool name `{tool.name}` contains {len(bad)} look-alike character(s) "
                                     f"({', '.join(f'U+{ord(c):04X}' for c in bad[:3])}); it reads as "
                                     f"`{''.join(_CONFUSABLES.get(c, c) for c in tool.name)}` but is a different name.")

    # -- rules that apply to plain ASCII text as well -------------------------------------------------
    def _ascii_only(self, ctx: Context, at: ArtifactText) -> None:
        cid = at.artifact.component_id
        text = at.text
        if "\x1b" in text or "\x9b" in text:
            hits = _finditer(_ESC, text)
            if hits:
                m = hits[0]
                ctx.emit("AG-OBF-009", component_ids=cid, span=at.span(m.start(), m.end()), snippet=at.line_text(m.start())[:200],
                         match=f"esc:{at.path}:{len(hits)}", kind=EvidenceKind.regex,
                         message=f"{len(hits)} terminal escape sequence(s) in this file. Shown in a terminal they can hide, recolour or "
                                 "overwrite text, so what a reviewer sees is not what the agent reads.")
        seen: set[tuple[int, int]] = set()
        for unit in at.units:
            if unit.scope == "decoded" and unit.anchor is not None and len(unit.decode_path) >= 2 and unit.anchor not in seen \
                    and word_count(unit.text) >= 3:
                seen.add(unit.anchor)
                layers = " → ".join(unit.decode_path)
                ctx.emit("AG-OBF-011", component_ids=cid, span=at.span(*unit.anchor), snippet=unit.text[:200],
                         match=f"layers:{at.text[unit.anchor[0]:unit.anchor[1]][:120]}", decode_path=unit.decode_path,
                         decoded=unit.text[:400], detail=f"decoded via {layers}",
                         message=f"Content is wrapped in {len(unit.decode_path)} encoding layers ({layers}). Stacked encodings have no "
                                 "use in instructions or configuration except to get past filters that decode once.")
        if len(text) >= 5000 or text.count("\n") >= 200:
            m = _search(_PADDING, text)
            if m and len(text[m.end():].strip()) >= 20 and len(text[:m.start()].strip()) >= 1:
                lines = text.count("\n", m.start(), m.end())
                ctx.emit("AG-EVADE-013", component_ids=cid, span=at.span(m.end()), snippet=at.line_text(m.end())[:200],
                         match=f"padding:{at.path}:{m.start()}", kind=EvidenceKind.regex,
                         message=f"{lines} blank lines ({m.end() - m.start()} bytes of whitespace) separate the top of this file from "
                                 f"the content on line {at.index.line_col(m.end())[0]}. Padding like this pushes text past the part a "
                                 "reviewer scrolls through or a scanner with a size window reads.")
        self._yaml_comments(ctx, at)

    def _yaml_comments(self, ctx: Context, at: ArtifactText) -> None:
        cid = at.artifact.component_id
        fm = at.fm
        if fm is not None and fm.has_frontmatter and fm.raw:
            base = max(at.text.find(fm.raw), 0)
            for m in _finditer(_YAML_COMMENT, fm.raw):
                comment = m.group(1).strip()
                if word_count(comment) >= 4 and search(AGENT_DIRECTED, comment):
                    ctx.emit("AG-OBF-024", component_ids=cid, span=at.span(base + m.start(1), base + m.end(1)), snippet=comment[:240],
                             match=f"fm-comment:{comment[:120]}", kind=EvidenceKind.regex, hidden=True, hidden_kind="yaml-comment",
                             message="A YAML comment in the frontmatter carries text addressed to the agent. Tools that show parsed "
                                     "metadata drop comments; an agent given the raw file reads them.")
                    break
            data = fm.data if isinstance(fm.data, dict) else {}
            known = {k.lower() for k in (*SPEC_FIELDS, *PLATFORM_FIELDS)} | _OTHER_AGENT_FIELDS
            for key, value in data.items():
                if str(key).lower() in known or not isinstance(value, str):
                    continue
                if word_count(value) >= 5 and search(AGENT_DIRECTED, value):
                    at_key = fm.raw.find(str(key))
                    ctx.emit("AG-OBF-024", component_ids=cid, span=at.span(base + max(at_key, 0)), snippet=f"{key}: {value}"[:240],
                             match=f"fm-key:{key}:{value[:100]}", kind=EvidenceKind.regex, hidden=True, hidden_kind="unused-frontmatter-key",
                             message=f"The frontmatter key `{key}` is not one any agent uses, and its value is text addressed to the "
                                     "agent. Listings show name and description; the whole frontmatter is what gets loaded.")
                    break
        elif at.path.lower().endswith((".yaml", ".yml")) and at.artifact.role not in (ArtifactRole.lockfile,):
            for m in _finditer(_YAML_COMMENT, at.text):
                comment = m.group(1).strip()
                if word_count(comment) >= 5 and _directive(comment):
                    ctx.emit("AG-OBF-024", component_ids=cid, span=at.span(m.start(1), m.end(1)), snippet=comment[:240],
                             match=f"yaml-comment:{comment[:120]}", kind=EvidenceKind.regex, hidden=True, hidden_kind="yaml-comment",
                             message="A YAML comment carries instructions addressed to an agent. The parser ignores comments; an "
                                     "agent reading the file does not.")
                    break

    # -- non-ASCII text ---------------------------------------------------------------------------------
    def _confusables(self, ctx: Context, at: ArtifactText) -> None:
        cid = at.artifact.component_id
        text = at.text
        code = at.artifact.role in (*_CODE_ROLES, ArtifactRole.repo_code, ArtifactRole.client_config, ArtifactRole.settings,
                                    ArtifactRole.hook_config, ArtifactRole.workflow, ArtifactRole.dockerfile)
        spans: list[tuple[int, int, str]] = []          # (start, end, where)
        for m in _finditer(_URL, text):
            host_end = text.find("/", m.start() + 8, m.end())
            spans.append((m.start(), host_end if host_end > 0 else m.end(), "URL"))
        if code:
            spans += [(m.start(), m.end(), "command or identifier") for m in _finditer(_TOKEN, text)]
        else:
            spans += [(m.start(1), m.end(1), "command") for m in _finditer(_INLINE_CODE, text)]
            for s, e in at.code_ranges:
                spans.append((s, e, "command"))
        seen_lines: set[int] = set()
        for start, end, where in spans:
            chunk = text[start:end]
            if chunk.isascii():
                continue
            for tok in _finditer(_TOKEN, chunk):
                word = tok.group(0)
                bad = [c for c in word if c in _CONFUSABLES]
                # Latin letters that are part of an escape (`не\s+обращай` in a regular expression) do not make a
                # word of another script look like a Latin name.
                letters = _BACKSLASH_ESCAPE.sub("", word) if "\\" in word else word
                if not bad or sum(c.isascii() and c.isalpha() for c in letters) < 2:
                    continue
                line = at.index.line_col(start + tok.start())[0]
                if line in seen_lines:
                    continue
                seen_lines.add(line)
                folded = "".join(_CONFUSABLES.get(c, c) for c in word)
                ctx.emit("AG-OBF-004", component_ids=cid, span=at.span(start + tok.start(), start + tok.end()),
                         snippet=at.line_text(start + tok.start())[:200], match=f"confusable:{word}", kind=EvidenceKind.regex,
                         decoded=folded,
                         message=f"The {where} `{word[:60]}` contains {len(bad)} look-alike character(s) "
                                 f"({', '.join(f'U+{ord(c):04X}' for c in bad[:3])}). It reads as `{folded[:60]}` but names something "
                                 "else.")
                if len(seen_lines) >= 5:
                    return

    def _carriers(self, ctx: Context, at: ArtifactText) -> None:
        cid = at.artifact.component_id
        text = at.text
        runs = _finditer(_VS, text)
        total = sum(len(m.group(0)) for m in runs)
        long = [m for m in runs if len(m.group(0)) >= 2]
        if long or total >= 3:
            m = max(runs, key=lambda r: len(r.group(0)))
            joined = "".join(r.group(0) for r in runs)
            decoded = decode_selectors(m.group(0)) or decode_selectors(joined)
            ctx.emit("AG-OBF-006", component_ids=cid, span=at.span(m.start(), m.end()), snippet=at.line_text(m.start())[:200],
                     match=f"vs:{at.path}:{total}", kind=EvidenceKind.regex, decoded=decoded, hidden=True,
                     hidden_kind="variation-selectors",
                     message=f"{total} variation-selector characters, in runs of up to {len(m.group(0))}, are attached to visible "
                             "text here. They display as nothing and can each carry a byte"
                             + (f"; decoded they read \"{decoded[:80]}\"." if decoded else "."))
        for m in _finditer(_INVISIBLE_RUN, text)[:1]:
            decoded = decode_binary_run(m.group(0))
            ctx.emit("AG-OBF-006", component_ids=cid, span=at.span(m.start(), m.end()), snippet=at.line_text(m.start())[:200],
                     match=f"invisible-run:{at.path}:{m.start()}", kind=EvidenceKind.regex, decoded=decoded, hidden=True,
                     hidden_kind="invisible-separators",
                     message=f"A run of {len(m.group(0))} invisible characters sits in this line. A run this long is an encoding, "
                             "not typography" + (f"; read as bits it says \"{decoded[:80]}\"." if decoded else "."))

    def _normalisation(self, ctx: Context, at: ArtifactText) -> None:
        text = at.text
        if _search(_CJK, text):
            return                                # fullwidth Latin is ordinary typography in CJK text
        for m in _finditer(_FOLDABLE, text)[:3]:
            folded = unicodedata.normalize("NFKC", m.group(0))
            if not folded.isascii():
                continue
            ctx.emit("AG-OBF-023", component_ids=at.artifact.component_id, span=at.span(m.start(), m.end()),
                     snippet=at.line_text(m.start())[:200], match=f"nfkc:{m.group(0)}", kind=EvidenceKind.regex, decoded=folded,
                     message=f"`{m.group(0)[:40]}` is written in compatibility characters (fullwidth, mathematical or enclosed "
                             f"letters). After Unicode normalisation it is `{folded[:40]}`, so a filter looking for that word "
                             "does not see it and a model reading the text does.")


def _directive(text: str) -> bool:
    from .connectors import DIRECTIVE

    return _search(DIRECTIVE, text) is not None


class FileIntegrityAnalyzer:
    id: ClassVar[str] = "file.integrity"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = ("AG-OBF-019", "AG-OBF-021", "AG-OBF-022")

    def run(self, ctx: Context) -> None:
        inv = ctx.inventory
        tree = inv.tree
        if tree is None:
            return
        for path in sorted(tree.files):
            if "!/" in path and path.rsplit("!/", 1)[1].startswith("_rels/"):
                continue
            data = tree.files[path].data
            if not data:
                continue
            art = inv.artifacts.get(path)
            cid = [art.component_id] if art else []
            kind = binary_kind(data)
            ext = posixpath.splitext(path.lower())[1]
            base = posixpath.basename(path)
            expect = _EXPECT.get(ext)
            if expect is not None and kind not in expect and not (kind == "binary" and expect != (None,)):
                is_text = kind is None
                actual = "text" + (" starting with a script interpreter line" if data.startswith(b"#!") else "") if is_text else \
                    {"pe": "a Windows executable", "elf": "a Linux executable", "macho": "a macOS executable", "zip": "a zip archive",
                     "binary": "binary data"}.get(kind or "", f"{kind} data")
                wanted = "text" if expect == (None,) else f"{expect[0]} data"
                # A text file holding only printable text under a media extension is common for placeholders; a script is not.
                if not (is_text and expect != (None,) and not data.startswith(b"#!") and len(data) < 64):
                    ctx.emit("AG-OBF-021", component_ids=cid, span=Span(path=path), snippet=f"{base}: {actual}", match=f"mismatch:{path}",
                             kind=EvidenceKind.loader,
                             message=f"`{path}` has the extension `{ext}` but its content is {actual}, not {wanted}. A file that is "
                                     "not what its name says is skipped by tools that trust the name.")
            elif kind is None and ext in DATA_ONLY_EXT and (language := program_language(data)):
                first = next((n for n, ln in enumerate(data[:65536].decode("utf-8", "replace").splitlines(), start=1) if ln.strip()), 1)
                ctx.emit("AG-OBF-021", component_ids=cid, span=Span(path=path, start_line=first), snippet=f"{base}: a {language} program",
                         match=f"program:{path}", kind=EvidenceKind.loader,
                         message=f"`{path}` has the extension `{ext}` but the whole file is a {language} program. Tools that choose "
                                 "what to analyse by extension read it as data; it is analysed here as the code it is.")
            elif kind in _IMAGE_KINDS and b"PK\x03\x04" in data and b"PK\x05\x06" in data[-65600:]:
                ctx.emit("AG-OBF-021", component_ids=cid, span=Span(path=path), snippet=f"{base}: {kind} + zip", match=f"polyglot:{path}",
                         kind=EvidenceKind.loader,
                         message=f"`{path}` is a valid {kind} image and also a zip archive (a polyglot): an image viewer shows a "
                                 "picture, an unzip tool extracts files from the same bytes.")
            if kind in ("png", "jpeg", "gif", "pdf", "zip"):
                end = end_of_content(data, kind)
                if end is not None and len(data) - end >= (4 if kind in ("png", "gif", "zip") else 16):
                    tail = data[end:]
                    if tail.strip(b"\r\n\x00 \t") and not (kind == "zip" and is_signature_block(tail)):
                        what = "a zip archive" if tail.lstrip().startswith(b"PK\x03\x04") else \
                            "text" if binary_kind(tail) is None else f"{binary_kind(tail)} data"
                        ctx.emit("AG-OBF-022", component_ids=cid, span=Span(path=path), snippet=f"{base}: {len(tail)} bytes after the end",
                                 match=f"trailing:{path}:{len(tail)}", kind=EvidenceKind.loader,
                                 message=f"`{path}` carries {len(tail)} bytes ({what}) after the point where its {kind} content ends. "
                                         "Viewers ignore them; a script told to read the file's tail does not.")
            if art is not None and art.role in _CODE_ROLES and kind is None:
                comp = inv.components.get(art.component_id)
                if comp is not None and comp.kind in _PACKAGE_KINDS:
                    self._minified(ctx, path, data, cid)

    def _minified(self, ctx: Context, path: str, data: bytes, cid: list[str]) -> None:
        if len(data) < 1500:
            return
        text = data.decode("utf-8", "replace")
        lines = text.split("\n")
        longest = max(len(ln) for ln in lines)
        avg = len(text) / max(len(lines), 1)
        ws = sum(text.count(c) for c in " \t\n") / len(text)
        packer = _search(_PACKER, text)
        hex_ids = len(set(_HEX_IDENT.findall(text)))
        why = ""
        if packer:
            why = f"it starts a known packer (`{packer.group(0)[:40]}`)"
        elif hex_ids >= 12:
            why = f"it uses {hex_ids} machine-generated identifiers (`_0x…`), the mark of an obfuscator"
        elif (longest >= 2000 or avg >= 400) and ws < 0.12:
            why = f"its longest line has {longest} characters and {ws:.0%} of it is whitespace"
        if why:
            line = text.count("\n", 0, packer.start()) + 1 if packer else 1
            ctx.emit("AG-OBF-019", component_ids=cid, span=Span(path=path, start_line=line), snippet=lines[line - 1][:160],
                     match=f"minified:{path}", kind=EvidenceKind.regex,
                     message=f"`{path}` is minified or packed: {why}. A script an agent runs should be readable; this one cannot "
                             "be reviewed as shipped.")


class CodeObfuscationAnalyzer:
    id: ClassVar[str] = "code.obfuscation"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = ("AG-OBF-013", "AG-OBF-014", "AG-OBF-016")

    def run(self, ctx: Context) -> None:
        for at in ctx.texts():
            role = at.artifact.role
            if role in _CODE_ROLES or role in _PROSE_ROLES or role in (ArtifactRole.repo_code, ArtifactRole.hook_config):
                self._assembled(ctx, at)
                self._split(ctx, at)
        self._stubs(ctx)

    # -- AG-OBF-014 -----------------------------------------------------------------------------------
    @staticmethod
    def _fragmented(parts: list[str]) -> str:
        """The sensitive token a list of fragments spells, when no single fragment holds it."""
        whole = "".join(parts)
        for m in _finditer(_SENSITIVE, whole):
            token = m.group(0)
            if len(token) >= 2 and not any(token.lower() in p.lower() for p in parts):
                return token
        return ""

    def _assembled(self, ctx: Context, at: ArtifactText) -> None:
        text = at.text
        cid = at.artifact.component_id
        found: list[tuple[int, int, str, str]] = []           # start, end, assembled, how
        for m in _finditer(_CONCAT, text):
            parts = [p.group(2) for p in _CONCAT_PIECE.finditer(m.group(0))]
            if self._fragmented(parts):
                found.append((m.start(), m.end(), "".join(parts), "string concatenation"))
        for m in _finditer(_JOIN_LIST, text):
            parts = [p.group(2) for p in _CONCAT_PIECE.finditer(m.group(1) or m.group(2))]
            if self._fragmented(parts):
                found.append((m.start(), m.end(), "".join(parts), "a joined list of fragments"))
        for rx, how in ((_CHR_CHAIN, "chr() calls"), (_FROM_CHAR, "String.fromCharCode"), (_BYTES_LIST, "a byte list")):
            for m in _finditer(rx, text):
                nums = regex.findall(r"0x[0-9a-f]{2}|\d{2,3}", m.group(0), _F)
                try:
                    word = "".join(chr(int(n, 16) if n.lower().startswith("0x") else int(n)) for n in nums)
                except ValueError:
                    continue
                if _search(_SENSITIVE, word):
                    found.append((m.start(), m.end(), word, how))
        if "$" in text and "=" in text:
            values = {m.group(1): m.group(3) for m in _finditer(_SH_ASSIGN, text)}
            if values:
                for m in _finditer(_SH_SPLICE, text):
                    names = _SH_VAR.findall(m.group(0))
                    if all(n in values for n in names):
                        parts = [values[n] for n in names]
                        if self._fragmented(parts):
                            found.append((m.start(), m.end(), "".join(parts), "shell variables spliced together"))
        seen: set[int] = set()
        for start, end, word, how in sorted(found)[:5]:
            line = at.index.line_col(start)[0]
            if line in seen:
                continue
            seen.add(line)
            ctx.emit("AG-OBF-014", component_ids=cid, span=at.span(start, end), snippet=at.line_text(start)[:200],
                     match=f"assembled:{word[:80]}", kind=EvidenceKind.ast, decoded=word[:200],
                     message=f"`{word[:60]}` is built at run time from {how}. The pieces mean nothing alone, so a search for the "
                             "command or path finds nothing in this file.")

    # -- AG-OBF-016 -----------------------------------------------------------------------------------
    def _split(self, ctx: Context, at: ArtifactText) -> None:
        text = at.text
        cid = at.artifact.component_id
        for m in _finditer(_BACKSLASH_SPLIT, text)[:50]:
            parts = regex.split(r"\\\r?\n[ \t]*", m.group(0))
            token = CodeObfuscationAnalyzer._fragmented(parts)
            if token:
                ctx.emit("AG-OBF-016", component_ids=cid, span=at.span(m.start(), m.end()), snippet=m.group(0)[:160],
                         match=f"split:{''.join(parts)[:80]}", kind=EvidenceKind.regex, decoded="".join(parts)[:200],
                         message=f"`{''.join(parts)[:60]}` is split across lines in the middle of the word (`{token}` appears only "
                                 "once the lines are joined).")
                return
        for m in _finditer(_ADJ_LITERALS, text)[:50]:
            parts = [p.group(2) for p in _CONCAT_PIECE.finditer(m.group(0))]
            token = CodeObfuscationAnalyzer._fragmented(parts)
            if token:
                ctx.emit("AG-OBF-016", component_ids=cid, span=at.span(m.start(), m.end()), snippet=m.group(0)[:160],
                         match=f"adjacent:{''.join(parts)[:80]}", kind=EvidenceKind.regex, decoded="".join(parts)[:200],
                         message=f"Adjacent string pieces on separate lines join into `{''.join(parts)[:60]}`; `{token}` is not "
                                 "visible on any one line.")
                return

    # -- AG-OBF-013 -----------------------------------------------------------------------------------
    def _stubs(self, ctx: Context) -> None:
        inv = ctx.inventory
        tree = inv.tree
        if tree is None:
            return
        by_comp: dict[str, list[str]] = {}
        for path, art in inv.artifacts.items():
            by_comp.setdefault(art.component_id, []).append(path)
        for cid in sorted(by_comp):
            comp = inv.components.get(cid)
            if comp is None or comp.kind not in (*_PACKAGE_KINDS, ComponentKind.repository, ComponentKind.package, ComponentKind.mcp_server):
                continue
            paths = sorted(by_comp[cid])
            opaque: dict[str, str] = {}
            for p in paths:
                blob = tree.files.get(p)
                if blob is None or blob.size < 64:           # a packed skill can be a few lines long
                    continue
                why = self._opaque(p, blob.data, inv.artifacts[p].role)
                if why:
                    opaque[p] = why
            if not opaque:
                continue
            for p in paths:
                at = inv.texts.get(p)
                if at is None or p in opaque or at.artifact.role not in (*_CODE_ROLES, *_PROSE_ROLES, ArtifactRole.hook_config):
                    continue
                for dm in _finditer(_DECODE_STEP, at.text)[:20]:
                    line_no = at.index.line_col(dm.start())[0]
                    # The data file is usually opened a few lines before the decode call and used a few lines after it.
                    window = at.text[max(dm.start() - 600, 0): dm.end() + 600]
                    target = next((o for o in opaque if posixpath.basename(o) in window), None)
                    if target is None:
                        continue
                    if _search(_RUN_STEP, window):
                        then = "and then runs the result"
                    elif self._rebuilds(window):
                        then = "and writes the result out as files"
                    else:
                        continue
                    ctx.emit("AG-OBF-013", component_ids=cid, span=at.span(dm.start(), dm.end()), snippet=at.line_text(dm.start())[:200],
                             match=f"stub:{p}:{target}", kind=EvidenceKind.ast, related=[Span(path=target)],
                             message=f"`{p}` (line {line_no}) decodes or unpacks `{target}` ({opaque[target]}) {then}. "
                                     "This is the self-extracting pattern: what is reviewed is the stub, and the real "
                                     "instructions or code only exist after the first run.")
                    break

    @staticmethod
    def _rebuilds(window: str) -> bool:
        """The decoded data is written to a file, other than a picture, font or sound named on that line."""
        for m in _finditer(_WRITE_STEP, window):
            start = window.rfind("\n", 0, m.start()) + 1
            end = window.find("\n", m.end())
            if not _search(_MEDIA_NAME, window[start: end if end != -1 else len(window)]):
                return True
        return False

    @staticmethod
    def _opaque(path: str, data: bytes, role: ArtifactRole) -> str:
        """Why a file is opaque data (not reviewable as shipped), or ""."""
        kind = binary_kind(data)
        if role in (ArtifactRole.image, ArtifactRole.document, ArtifactRole.media) and kind in ("png", "jpeg", "gif", "webp", "pdf"):
            return ""
        if kind in ("zip", "gzip", "7z", "rar", "bzip2", "xz", "tar"):
            return f"a {kind} archive"
        if kind is not None:
            return "binary data"
        sample = data[:65536]
        text = sample.decode("utf-8", "replace")
        dense = regex.sub(r"\s+", "", text)
        if len(dense) >= 64 and regex.fullmatch(r"[A-Za-z0-9+/=_-]+", dense) and " " not in text.strip()[:200] and _B64_RUN.search(text):
            return "one block of base64 text"
        if len(dense) >= 512 and regex.fullmatch(r"[0-9a-fA-F]+", dense):
            return "one block of hex"
        # Records of encoded data (a name and a base64 run per line): most of the file is long base64 runs.
        if len(dense) >= 64 and sum(len(m.group(0)) for m in _B64_RUN.finditer(text)) >= 0.7 * len(dense):
            return "encoded text (long base64 runs)"
        if entropy(sample) >= 5.9 and len(sample) >= 512 and sum(c.isspace() for c in text) / max(len(text), 1) < 0.05:
            return f"high-entropy data ({entropy(sample):.1f} bits per byte)"
        return ""


__all__ = ["CodeObfuscationAnalyzer", "FileIntegrityAnalyzer", "TextIntegrityAnalyzer", "decode_selectors", "end_of_content", "entropy",
           "is_signature_block"]
