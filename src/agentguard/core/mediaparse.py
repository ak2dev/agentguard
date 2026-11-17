"""Structural readers for media and documents (engine G, the deterministic part).

Pure Python and read-only: nothing here renders, executes or follows a reference. Each reader takes bytes or text
and returns what a reviewer cannot see by opening the file: metadata strings, hidden text, active content. Readers
never raise on malformed input; they return what they could read and say whether the container was understood.

Pixels are not interpreted here. Text inside the picture itself (OCR), QR codes and rendered-page comparison come
from the host as recorded facts (``ScanOptions.media_text`` and ``ScanOptions.facts["media"]``).
"""

from __future__ import annotations

import binascii
import io
import struct
import zipfile
import zlib
from dataclasses import dataclass, field

import regex

MAX_INFLATE = 8_000_000
MAX_STREAMS = 400
_PRINTABLE = regex.compile(rb"[\x20-\x7e]{8,}")
_UTF16_RUN = regex.compile(rb"(?:[\x20-\x7e]\x00){8,}")
_TAG = regex.compile(r"<[^>]{0,2000}>")
_WS = regex.compile(r"\s+")


def _inflate(data: bytes, limit: int = MAX_INFLATE) -> bytes | None:
    try:
        d = zlib.decompressobj()
        out = d.decompress(data, limit)
        return out
    except zlib.error:
        return None


def printable_runs(data: bytes) -> list[str]:
    """ASCII and UTF-16LE strings of eight or more characters found in binary data."""
    out = [m.group(0).decode("ascii") for m in _PRINTABLE.finditer(data)]
    out += [m.group(0).decode("utf-16-le", "replace") for m in _UTF16_RUN.finditer(data)]
    return out


def strip_tags(markup: str) -> str:
    return _WS.sub(" ", _TAG.sub(" ", markup)).strip()


# ---------------------------------------------------------------------------------------------------------------
# Images
# ---------------------------------------------------------------------------------------------------------------
_PNG_SIG = b"\x89PNG\r\n\x1a\n"
_PNG_KNOWN = {b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"cHRM", b"gAMA", b"iCCP", b"sBIT", b"sRGB", b"cICP", b"mDCV", b"cLLI",
              b"tEXt", b"zTXt", b"iTXt", b"bKGD", b"hIST", b"pHYs", b"sPLT", b"eXIf", b"tIME", b"acTL", b"fcTL", b"fdAT", b"oFFs",
              b"pCAL", b"sCAL", b"sTER", b"vpAg", b"caNv", b"orNT", b"iDOT"}


@dataclass
class ImageInfo:
    kind: str
    parsed: bool = False
    width: int = 0
    height: int = 0
    metadata: list[tuple[str, str]] = field(default_factory=list)   # (where, text)
    private_chunks: list[tuple[str, int]] = field(default_factory=list)   # PNG chunk types that are not registered, with size
    lsb: str = ""                                                    # why the least significant bits look like a payload


def png_chunks(data: bytes) -> list[tuple[bytes, bytes]]:
    out: list[tuple[bytes, bytes]] = []
    pos = len(_PNG_SIG)
    while pos + 12 <= len(data) and len(out) < 10000:
        (length,) = struct.unpack(">I", data[pos:pos + 4])
        kind = data[pos + 4:pos + 8]
        if pos + 12 + length > len(data):
            break
        out.append((kind, data[pos + 8:pos + 8 + length]))
        pos += 12 + length
        if kind == b"IEND":
            break
    return out


def _png(data: bytes) -> ImageInfo:
    info = ImageInfo("png")
    if not data.startswith(_PNG_SIG):
        return info
    chunks = png_chunks(data)
    if not chunks or chunks[0][0] != b"IHDR" or len(chunks[0][1]) < 13:
        return info
    info.parsed = True
    info.width, info.height = struct.unpack(">II", chunks[0][1][:8])
    for kind, body in chunks:
        name = kind.decode("latin-1")
        if kind == b"tEXt":
            key, _, value = body.partition(b"\x00")
            info.metadata.append((f"tEXt:{key.decode('latin-1')[:40]}", value.decode("latin-1")))
        elif kind == b"zTXt":
            key, _, rest = body.partition(b"\x00")
            raw = _inflate(rest[1:]) if rest else None
            if raw is not None:
                info.metadata.append((f"zTXt:{key.decode('latin-1')[:40]}", raw.decode("latin-1")))
        elif kind == b"iTXt":
            key, _, rest = body.partition(b"\x00")
            if len(rest) >= 2:
                compressed = rest[0] == 1
                parts = rest[2:].split(b"\x00", 2)
                if len(parts) == 3:
                    raw = _inflate(parts[2]) if compressed else parts[2]
                    if raw is not None:
                        info.metadata.append((f"iTXt:{key.decode('latin-1')[:40]}", raw.decode("utf-8", "replace")))
        elif kind == b"eXIf":
            info.metadata.extend(("EXIF", s) for s in printable_runs(body))
        elif kind not in _PNG_KNOWN and len(body) >= 64:
            info.private_chunks.append((name, len(body)))
    info.lsb = png_lsb_anomaly(chunks)
    return info


def png_lsb_anomaly(chunks: list[tuple[bytes, bytes]], max_pixels: int = 400_000) -> str:
    """Flat artwork whose lowest bit plane is noise: the classic trace of data hidden in the least significant bits.

    Only 8-bit, non-interlaced greyscale, RGB and RGBA images are read. Photographs are noisy in every bit plane and
    are not reported; the signal is noise in the lowest plane of an image that is flat without it.
    """
    head = chunks[0][1]
    width, height, depth, colour, _comp, _filt, interlace = struct.unpack(">IIBBBBB", head[:13])
    channels = {0: 1, 2: 3, 6: 4}.get(colour)
    if depth != 8 or channels is None or interlace or width * height > max_pixels or width * height < 4096:
        return ""
    raw = _inflate(b"".join(body for kind, body in chunks if kind == b"IDAT"), (width * channels + 1) * height + 16)
    stride = width * channels
    if raw is None or len(raw) < (stride + 1) * height:
        return ""
    prev = bytearray(stride)
    flips = same = total = ones = 0
    for row in range(height):
        base = row * (stride + 1)
        ftype = raw[base]
        line = bytearray(raw[base + 1:base + 1 + stride])
        if ftype == 1:
            for i in range(channels, stride):
                line[i] = (line[i] + line[i - channels]) & 0xFF
        elif ftype == 2:
            for i in range(stride):
                line[i] = (line[i] + prev[i]) & 0xFF
        elif ftype == 3:
            for i in range(stride):
                left = line[i - channels] if i >= channels else 0
                line[i] = (line[i] + ((left + prev[i]) >> 1)) & 0xFF
        elif ftype == 4:
            for i in range(stride):
                a = line[i - channels] if i >= channels else 0
                b = prev[i]
                c = prev[i - channels] if i >= channels else 0
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                line[i] = (line[i] + (a if pa <= pb and pa <= pc else b if pb <= pc else c)) & 0xFF
        elif ftype != 0:
            return ""
        step = max(1, stride // 2048) * channels            # sample: enough for a stable ratio, bounded work per row
        for i in range(channels, stride, step):
            total += 1
            ones += line[i] & 1
            if (line[i] ^ line[i - channels]) & 1:
                flips += 1
            if (line[i] >> 1) == (line[i - channels] >> 1):
                same += 1
        prev = line
    if total < 2000:
        return ""
    flat, flip, bias = same / total, flips / total, ones / total
    if flat >= 0.9 and 0.4 <= flip <= 0.6 and 0.4 <= bias <= 0.6:
        return (f"{flat:.0%} of neighbouring samples are equal above the lowest bit, and the lowest bit changes between "
                f"{flip:.0%} of them")
    return ""


def _jpeg(data: bytes) -> ImageInfo:
    info = ImageInfo("jpeg")
    if not data.startswith(b"\xff\xd8"):
        return info
    pos = 2
    while pos + 2 <= len(data):
        if data[pos] != 0xFF:
            break
        marker = data[pos + 1]
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            pos += 2
            continue
        if marker in (0xDA, 0xD9):
            info.parsed = True
            break
        if pos + 4 > len(data):
            break
        (length,) = struct.unpack(">H", data[pos + 2:pos + 4])
        body = data[pos + 4:pos + 2 + length]
        if marker == 0xFE:
            info.metadata.append(("COM", body.decode("utf-8", "replace")))
        elif marker == 0xE1 and body.startswith(b"Exif\x00\x00"):
            info.metadata.extend(("EXIF", s) for s in printable_runs(body[6:]))
        elif marker == 0xE1 and body.startswith(b"http://ns.adobe.com/xap/1.0/\x00"):
            info.metadata.append(("XMP", body[29:].decode("utf-8", "replace")))
        elif marker == 0xED:
            info.metadata.extend(("IPTC", s) for s in printable_runs(body))
        elif 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC) and len(body) >= 5:
            info.height, info.width = struct.unpack(">HH", body[1:5])
        if length < 2:
            break
        pos += 2 + length
    return info


def _gif(data: bytes) -> ImageInfo:
    info = ImageInfo("gif")
    if len(data) < 13 or data[:6] not in (b"GIF87a", b"GIF89a"):
        return info
    info.parsed = True
    info.width, info.height = struct.unpack("<HH", data[6:10])
    pos = 0
    for _ in range(64):
        pos = data.find(b"\x21\xfe", pos)
        if pos < 0:
            break
        pos += 2
        parts = []
        while pos < len(data) and data[pos] != 0:
            size = data[pos]
            parts.append(data[pos + 1:pos + 1 + size])
            pos += 1 + size
        text = b"".join(parts)
        if text and sum(32 <= b < 127 or b in (9, 10, 13) for b in text) >= 0.9 * len(text):
            info.metadata.append(("comment", text.decode("latin-1")))
    return info


def image_info(data: bytes, kind: str | None) -> ImageInfo:
    try:
        if kind == "png":
            return _png(data)
        if kind == "jpeg":
            return _jpeg(data)
        if kind == "gif":
            return _gif(data)
        if kind in ("webp", "tiff"):
            info = ImageInfo(kind, parsed=True)
            info.metadata.extend(("metadata", s) for s in printable_runs(data[:262144]) if len(s) >= 16)
            return info
    except (struct.error, IndexError, ValueError):
        pass
    return ImageInfo(kind or "")


# ---------------------------------------------------------------------------------------------------------------
# SVG
# ---------------------------------------------------------------------------------------------------------------
_SVG_ACTIVE = (
    ("script element", regex.compile(r"<\s*script\b", regex.I)),
    ("foreignObject element", regex.compile(r"<\s*foreignObject\b", regex.I)),
    ("event handler attribute", regex.compile(r"""\son[a-z]{3,20}\s*=\s*["']""", regex.I)),
    ("external reference", regex.compile(r"""(?<![\w:])(?:xlink:href|href|src)\s*=\s*["']\s*(?:https?:)?//[^"'\s>]+""", regex.I)),
    ("javascript: reference", regex.compile(r"""(?:href|src)\s*=\s*["']\s*javascript:""", regex.I)),
    ("external stylesheet or font", regex.compile(r"""(?:@import\s+(?:url\()?|url\()\s*["']?\s*(?:https?:)?//[^"')\s]+""", regex.I)),
    ("external entity", regex.compile(r"<!ENTITY\s+[^>]{0,200}\bSYSTEM\b", regex.I)),
)
_SVG_TEXT = regex.compile(r"<\s*(text|tspan|title|desc)\b([^>]*)>(.*?)<\s*/\s*\1\s*>", regex.I | regex.S)
_SVG_HIDDEN = (
    ("opacity 0", regex.compile(r"""(?:fill-)?opacity\s*[=:]\s*["']?\s*0(?:\.0+)?(?![\d.])""", regex.I)),
    ("font size under 2", regex.compile(r"""font-size\s*[=:]\s*["']?\s*(?:0|[01](?:\.\d+)?)(?:px|pt)?(?![\d.])""", regex.I)),
    ("display none", regex.compile(r"""display\s*[=:]\s*["']?\s*none""", regex.I)),
    ("visibility hidden", regex.compile(r"""visibility\s*[=:]\s*["']?\s*hidden""", regex.I)),
    ("white text", regex.compile(r"""fill\s*[=:]\s*["']?\s*(?:#fff(?:fff)?\b|white\b|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\))""", regex.I)),
    ("no fill", regex.compile(r"""fill\s*[=:]\s*["']?\s*(?:none|transparent)\b""", regex.I)),
)
_SVG_DARK_RECT = regex.compile(r"""<\s*rect\b[^>]*fill\s*[=:]\s*["']?\s*(?!#fff(?:fff)?\b|white\b|none\b|transparent\b)[#\w(]""", regex.I)


@dataclass
class SvgReport:
    active: list[tuple[str, int, str]] = field(default_factory=list)     # (what, offset, matched text)
    hidden: list[tuple[str, int, str]] = field(default_factory=list)     # (why, offset, text)
    text: list[tuple[int, str]] = field(default_factory=list)            # (offset, visible text)


def svg_scan(text: str) -> SvgReport:
    rep = SvgReport()
    for what, rx in _SVG_ACTIVE:
        for m in rx.finditer(text):
            if what == "external reference" and regex.search(r"xmlns(?::\w+)?\s*=\s*[\"']?$", text[max(0, m.start() - 20):m.start() + 1]):
                continue
            rep.active.append((what, m.start(), m.group(0).strip()[:160]))
            if len(rep.active) >= 20:
                break
    dark = bool(_SVG_DARK_RECT.search(text))
    for m in _SVG_TEXT.finditer(text):
        body = strip_tags(m.group(3))
        if len(body) < 3 or m.group(1).lower() == "tspan" and not m.group(2).strip():
            continue
        why = ""
        if m.group(1).lower() in ("text", "tspan"):
            for label, rx in _SVG_HIDDEN:
                if rx.search(m.group(2)) and not (label == "white text" and dark):
                    why = label
                    break
        if why:
            rep.hidden.append((why, m.start(), body))
        else:
            rep.text.append((m.start(), body))
    return rep


# ---------------------------------------------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------------------------------------------
_PDF_STREAM = regex.compile(rb"(?<!end)stream\r?\n")   # the keyword that opens a stream, not the tail of `endstream`
_PDF_NAME_ESC = regex.compile(rb"#([0-9A-Fa-f]{2})")
_PDF_ACTIVE = (
    (b"/JavaScript", "JavaScript"), (b"/JS", "JavaScript"), (b"/Launch", "a launch action"), (b"/EmbeddedFile", "an embedded file"),
    (b"/RichMedia", "rich media"), (b"/XFA", "an XFA form"), (b"/SubmitForm", "a form submission action"),
    (b"/ImportData", "a data import action"), (b"/GoToR", "a jump to a remote file"), (b"/GoToE", "a jump into an embedded file"),
)
_PDF_AUTO = (b"/OpenAction", b"/AA")
_PDF_MEDIABOX = regex.compile(rb"/MediaBox\s*\[\s*(-?[\d.]+)\s+(-?[\d.]+)\s+(-?[\d.]+)\s+(-?[\d.]+)\s*\]")
_PDF_TOKEN = regex.compile(
    rb"\((?:[^()\\]|\\.|\((?:[^()\\]|\\.)*\))*\)"         # literal string, one level of nesting
    rb"|<[0-9A-Fa-f\s]*>"                                  # hex string
    rb"|\[|\]|<<|>>"
    rb"|/[^\s/\[\]()<>{}%]*"                               # name
    rb"|[+-]?(?:\d+\.?\d*|\.\d+)"                          # number
    rb"|[A-Za-z'\"*]+"                                     # operator
    rb"|%[^\r\n]*", regex.S)
_PDF_ESC = {ord("n"): "\n", ord("r"): "\r", ord("t"): "\t", ord("b"): "\b", ord("f"): "\f", ord("("): "(", ord(")"): ")", ord("\\"): "\\"}


@dataclass
class PdfReport:
    parsed: bool = False
    encrypted: bool = False
    active: list[str] = field(default_factory=list)
    automatic: bool = False
    text: list[str] = field(default_factory=list)
    hidden: list[tuple[str, str]] = field(default_factory=list)   # (why, text)
    streams: int = 0
    unread_streams: int = 0


def _pdf_string(tok: bytes) -> str:
    if tok.startswith(b"<"):
        hexa = bytes(c for c in tok[1:-1] if c not in b" \r\n\t")
        if len(hexa) % 2:
            hexa += b"0"
        try:
            raw = binascii.unhexlify(hexa)
        except (binascii.Error, ValueError):
            return ""
        if raw.startswith(b"\xfe\xff"):
            return raw[2:].decode("utf-16-be", "replace")
        if len(raw) >= 4 and raw[0::2].count(0) >= len(raw) // 2 * 0.8:
            return raw.decode("utf-16-be", "replace")
        return raw.decode("latin-1")
    body = tok[1:-1]
    out: list[str] = []
    i = 0
    while i < len(body):
        c = body[i]
        if c == 0x5C and i + 1 < len(body):
            n = body[i + 1]
            if n in _PDF_ESC:
                out.append(_PDF_ESC[n])
                i += 2
            elif 0x30 <= n <= 0x37:
                j = i + 1
                digits = b""
                while j < len(body) and len(digits) < 3 and 0x30 <= body[j] <= 0x37:
                    digits += body[j:j + 1]
                    j += 1
                out.append(chr(int(digits, 8) & 0xFF))
                i = j
            elif n in (0x0A, 0x0D):
                i += 2
            else:
                out.append(chr(n))
                i += 2
        else:
            out.append(chr(c))
            i += 1
    return "".join(out)


def _readable(text: str) -> bool:
    text = text.strip()
    if len(text) < 2:
        return False
    good = sum(c.isalnum() or c in " .,;:!?'\"-_/()@#$%&*+=~<>[]{}|\\\n" for c in text)
    return good >= 0.85 * len(text)


def _pdf_content(stream: bytes, page: tuple[float, float], rep: PdfReport) -> None:
    """Walk one content stream, tracking the state that decides whether shown text is visible."""
    operands: list[bytes] = []
    size, mode, white, dark_bg = 12.0, 0, False, False
    fill_dark = False
    scale = 1.0          # vertical scale of the text matrix times the current transformation matrix
    cm_scale, tm_scale = 1.0, 1.0
    x = y = 0.0
    visible: list[str] = []
    hidden: dict[str, list[str]] = {}

    def num(tok: bytes) -> float:
        try:
            return float(tok)
        except ValueError:
            return 0.0

    def show(strings: list[str]) -> None:
        text = "".join(strings)
        if not _readable(text):
            return
        why = ""
        if mode in (3, 7):
            why = "invisible render mode"
        elif abs(size * scale) < 1.5:
            why = f"font size {abs(size * scale):.2g}"
        elif white and not dark_bg:
            why = "white text"
        elif x < -50 or y < -50 or x > page[0] + 50 or y > page[1] + 50:
            why = "placed off the page"
        if why:
            hidden.setdefault(why, []).append(text)
        else:
            visible.append(text)

    for m in _PDF_TOKEN.finditer(stream):
        tok = m.group(0)
        c = tok[:1]
        if c == b"%":
            continue
        if c in b"(</[]" or c in b"+-.0123456789" or tok in (b"<<", b">>"):
            operands.append(tok)
            if len(operands) > 4096:
                del operands[:2048]
            continue
        op = tok
        nums = [num(t) for t in operands if t[:1] in b"+-.0123456789"]
        if op == b"Tf" and nums:
            size = nums[-1]
        elif op == b"Tr" and nums:
            mode = int(nums[-1])
        elif op in (b"rg", b"sc", b"scn") and len(nums) >= 3:
            white = all(v >= 0.98 for v in nums[-3:])
            fill_dark = sum(nums[-3:]) / 3 <= 0.35
        elif op in (b"g",) and nums:
            white, fill_dark = nums[-1] >= 0.98, nums[-1] <= 0.35
        elif op == b"k" and len(nums) >= 4:
            white = all(v <= 0.02 for v in nums[-4:])
            fill_dark = nums[-1] >= 0.65 or sum(nums[-4:-1]) / 3 >= 0.65
        elif op in (b"f", b"F", b"f*", b"B", b"B*", b"b", b"b*"):
            dark_bg = dark_bg or fill_dark
        elif op == b"cm" and len(nums) >= 6:
            cm_scale *= abs(nums[-3]) or 1.0
            scale = cm_scale * tm_scale
        elif op == b"Tm" and len(nums) >= 6:
            tm_scale = abs(nums[-3]) or 1.0
            scale = cm_scale * tm_scale
            x, y = nums[-2], nums[-1]
        elif op in (b"Td", b"TD") and len(nums) >= 2:
            x, y = x + nums[-2], y + nums[-1]
        elif op == b"BT":
            x = y = 0.0
            tm_scale = 1.0
            scale = cm_scale
        elif op in (b"Tj", b"'", b'"'):
            strings = [_pdf_string(t) for t in operands if t[:1] in b"(<" and t not in (b"<<",)]
            show(strings[-1:])
        elif op == b"TJ":
            show([_pdf_string(t) for t in operands if t[:1] in b"(<" and t not in (b"<<",)])
        operands.clear()
    if visible:
        rep.text.append(" ".join(visible))
    for why, parts in hidden.items():
        rep.hidden.append((why, " ".join(parts)))


def _ascii85(data: bytes) -> bytes | None:
    import base64

    data = data.strip()
    if data.startswith(b"<~"):
        data = data[2:]
    end = data.find(b"~>")
    if end >= 0:
        data = data[:end]
    try:
        return base64.a85decode(data, adobe=False)
    except ValueError:
        return None


def pdf_scan(data: bytes) -> PdfReport:
    rep = PdfReport()
    if not data.startswith(b"%PDF-") and b"%PDF-" not in data[:1024]:
        return rep
    rep.parsed = True
    plain = _PDF_NAME_ESC.sub(lambda m: bytes([int(m.group(1), 16)]), data)
    rep.encrypted = b"/Encrypt" in plain
    mb = _PDF_MEDIABOX.search(plain)
    page = (float(mb.group(3)) - float(mb.group(1)), float(mb.group(4)) - float(mb.group(2))) if mb else (612.0, 792.0)
    decoded: list[bytes] = []
    for m in _PDF_STREAM.finditer(data):
        if rep.streams >= MAX_STREAMS:
            break
        rep.streams += 1
        end = data.find(b"endstream", m.end())
        if end < 0:
            rep.unread_streams += 1
            break
        dict_start = data.rfind(b"obj", max(0, m.start() - 4096), m.start())
        head = _PDF_NAME_ESC.sub(lambda mm: bytes([int(mm.group(1), 16)]), data[max(dict_start, 0):m.start()])
        body: bytes | None = data[m.end():end].rstrip(b"\r\n")
        if rep.encrypted:
            rep.unread_streams += 1
            continue
        fm = regex.search(rb"/Filter\s*(\[[^\]]*\]|/\w+)", head)
        filters = regex.findall(rb"/(\w+)", fm.group(1)) if fm else []
        for f in filters:
            if body is None:
                break
            if f in (b"FlateDecode", b"Fl"):
                body = _inflate(body)
            elif f in (b"ASCIIHexDecode", b"AHx"):
                hexa = bytes(c for c in body if c in b"0123456789abcdefABCDEF")
                body = binascii.unhexlify(hexa[: len(hexa) // 2 * 2])
            elif f in (b"ASCII85Decode", b"A85"):
                body = _ascii85(body)
            elif f in (b"DCTDecode", b"DCT", b"JPXDecode", b"CCITTFaxDecode", b"CCF", b"JBIG2Decode"):
                body = b""                        # image data: nothing to read as text
            else:
                body = None
        if body is None:
            rep.unread_streams += 1
            continue
        if body:
            decoded.append(body)
    haystack = plain + b"\n" + b"\n".join(_PDF_NAME_ESC.sub(lambda m: bytes([int(m.group(1), 16)]), d) for d in decoded
                                           if b"/" in d and (b"obj" in d or b"<<" in d))
    for name, label in _PDF_ACTIVE:
        if regex.search(regex.escape(name) + rb"(?![A-Za-z0-9])", haystack) and label not in rep.active:
            rep.active.append(label)
    rep.automatic = any(regex.search(regex.escape(n) + rb"(?![A-Za-z0-9])", haystack) for n in _PDF_AUTO)
    for body in decoded:
        if b"BT" in body and (b"Tj" in body or b"TJ" in body or b"'" in body):
            try:
                _pdf_content(body, page, rep)
            except (ValueError, IndexError, RecursionError):
                rep.unread_streams += 1
    return rep


# ---------------------------------------------------------------------------------------------------------------
# Office documents
# ---------------------------------------------------------------------------------------------------------------
_MACRO_MEMBER = regex.compile(r"(?:^|/)(?:vbaProject\.bin|vbaData\.xml|[^/]*\.vba)$|(?:^|/)macrosheets/", regex.I)
_OLE_MEMBER = regex.compile(r"(?:^|/)(?:embeddings/[^/]+|oleObject\d*\.bin|activeX/[^/]+\.bin)$", regex.I)
_OLE_MACRO_MARKS = (b"_\x00V\x00B\x00A\x00_\x00P\x00R\x00O\x00J\x00E\x00C\x00T", b"M\x00a\x00c\x00r\x00o\x00s\x00", b"V\x00B\x00A\x00\x00\x00")
_OLE_OBJECT_MARKS = (b"\x01\x00O\x00l\x00e\x001\x000\x00N\x00a\x00t\x00i\x00v\x00e", b"O\x00b\x00j\x00e\x00c\x00t\x00P\x00o\x00o\x00l")


def office_members(names: list[str]) -> tuple[list[str], list[str]]:
    """(macro members, embedded object members) among the member names of an OOXML or OpenDocument package."""
    return [n for n in names if _MACRO_MEMBER.search(n)], [n for n in names if _OLE_MEMBER.search(n)]


def zip_names(data: bytes) -> list[str]:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            return z.namelist()[:5000]
    except (zipfile.BadZipFile, ValueError, OSError, NotImplementedError):
        return []


def ole_scan(data: bytes) -> tuple[bool, bool]:
    """(has macros, has embedded objects) for a legacy OLE2 document (.doc, .xls, .ppt)."""
    if not data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return False, False
    return any(m in data for m in _OLE_MACRO_MARKS), any(m in data for m in _OLE_OBJECT_MARKS)


# ---------------------------------------------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------------------------------------------
_HTML_HIDDEN = regex.compile(
    r"""<\s*(?P<tag>[a-z][a-z0-9]*)\b(?P<attrs>[^>]*?(?:
        style\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\.0+)?(?![\d.])|font-size\s*:\s*0(?![\d.])
            |(?:left|top|text-indent|margin-left)\s*:\s*-\d{3,}|color\s*:\s*(?:\#fff(?:fff)?\b|white\b)|(?:height|width)\s*:\s*0(?:px)?\s*[;"'])
        |\shidden(?=[\s>=])
    )[^>]*)>(?P<body>.*?)<\s*/\s*(?P=tag)\s*>""", regex.I | regex.S | regex.X)
_HTML_SCRIPT = regex.compile(r"<\s*script\b(?P<attrs>[^>]*)>(?P<body>.*?)<\s*/\s*script\s*>", regex.I | regex.S)
_HTML_SCRIPT_RISK = regex.compile(
    r"\bfetch\s*\(|XMLHttpRequest|navigator\.sendBeacon|WebSocket\s*\(|\beval\s*\(|new\s+Function\s*\(|document\.cookie|atob\s*\(|"
    r"localStorage|importScripts|\.src\s*=", regex.I)
_HTML_SRC = regex.compile(r"""\bsrc\s*=\s*["']?\s*((?:https?:)?//[^"'\s>]+)""", regex.I)


def html_scan(text: str) -> tuple[list[tuple[int, str]], list[tuple[int, str]]]:
    """(hidden text, risky scripts) of an HTML file, each as (offset, text)."""
    hidden: list[tuple[int, str]] = []
    scripts: list[tuple[int, str]] = []
    try:
        for m in _HTML_HIDDEN.finditer(text, timeout=2):
            if m.group("tag").lower() in ("script", "style", "template", "option", "input"):
                continue
            body = strip_tags(m.group("body"))
            if len(body) >= 12:
                hidden.append((m.start(), body))
            if len(hidden) >= 20:
                break
        for m in _HTML_SCRIPT.finditer(text, timeout=2):
            src = _HTML_SRC.search(m.group("attrs"))
            risk = _HTML_SCRIPT_RISK.search(m.group("body"))
            if src:
                scripts.append((m.start(), f"script loaded from {src.group(1)[:120]}"))
            elif risk:
                scripts.append((m.start(), f"inline script that uses `{risk.group(0).strip()}`"))
            if len(scripts) >= 20:
                break
    except TimeoutError:
        pass
    return hidden, scripts


# ---------------------------------------------------------------------------------------------------------------
# Notebooks
# ---------------------------------------------------------------------------------------------------------------
@dataclass
class NotebookCell:
    index: int
    kind: str                      # code | markdown | raw
    source: str
    hidden: bool
    outputs: list[str] = field(default_factory=list)


def _joined(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "".join(v for v in value if isinstance(v, str))
    return ""


def notebook_cells(doc: object) -> list[NotebookCell]:
    cells = doc.get("cells") if isinstance(doc, dict) else None
    out: list[NotebookCell] = []
    for i, cell in enumerate(cells if isinstance(cells, list) else []):
        if not isinstance(cell, dict):
            continue
        meta = cell.get("metadata") if isinstance(cell.get("metadata"), dict) else {}
        jup = meta.get("jupyter") if isinstance(meta.get("jupyter"), dict) else {}
        tags = [str(t) for t in meta.get("tags")] if isinstance(meta.get("tags"), list) else []
        hidden = bool(jup.get("source_hidden") or meta.get("hide_input") or meta.get("collapsed") is True and cell.get("cell_type") == "code"
                      or any(t in ("hide-input", "remove-input", "hide-cell", "remove-cell", "hide_input") for t in tags))
        nc = NotebookCell(i, str(cell.get("cell_type") or "code"), _joined(cell.get("source")), hidden)
        for o in cell.get("outputs") if isinstance(cell.get("outputs"), list) else []:
            if not isinstance(o, dict):
                continue
            if "text" in o:
                nc.outputs.append(_joined(o.get("text")))
            data = o.get("data") if isinstance(o.get("data"), dict) else {}
            for mime in ("text/plain", "text/markdown", "text/html", "application/javascript"):
                if mime in data:
                    nc.outputs.append(_joined(data[mime]))
        out.append(nc)
    return out


__all__ = ["ImageInfo", "NotebookCell", "PdfReport", "SvgReport", "html_scan", "image_info", "notebook_cells", "office_members",
           "ole_scan", "pdf_scan", "png_chunks", "png_lsb_anomaly", "printable_runs", "strip_tags", "svg_scan", "zip_names"]
