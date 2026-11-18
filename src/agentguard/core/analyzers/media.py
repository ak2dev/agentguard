"""Media and documents as instruction carriers (engine G; the MM family).

What a file's container can be made to say is read here, statically: image metadata, SVG markup, PDF content
streams and actions, Office macros, notebook cells and outputs, hidden HTML. Text recovered from a file is added to
the units the pattern rules read (scope ``decoded``, with the technique in the derivation), so an instruction in a
PNG text chunk or an invisible PDF line is judged like one written in the skill itself.

What needs pixels or a renderer arrives as recorded facts, gathered on the host when an OCR engine is installed:

* ``ScanOptions.media_text[path]``: ``(label, text)`` pairs; labels ``ocr`` (text in the picture), ``ocr:small`` and
  ``ocr:low-contrast`` (text a person would not notice), ``rendered`` (OCR of a rendered PDF page), ``qr``.
* ``ScanOptions.facts["media"][path]``: ``{"qr": [...], "low_contrast_text": [...], "small_text": [...], "stego": "..."}``.

A file whose container was read is registered in ``ctx.data["analysed_paths"]`` so coverage stays truthful: an
encrypted PDF, a legacy Office file or an audio file is not, and is listed as unanalysed.
"""

from __future__ import annotations

import json
import posixpath
from typing import Any, ClassVar

import regex

from .. import mediaparse as mp
from ..artifacts import ArtifactText, TextUnit, binary_kind
from ..models import Span
from ..models.enums import ArtifactRole, EvidenceKind, Severity
from ..normalize.unicode import normalize
from ..parsers import parse_json
from ..textutil import TIMEOUT
from .base import Context
from .connectors import DIRECTIVE
from .instructions import CORE

_F = regex.IGNORECASE
_IMAGE_KINDS = ("png", "jpeg", "gif", "webp", "tiff")
_OFFICE_EXT = (".docx", ".docm", ".dotm", ".dotx", ".xlsx", ".xlsm", ".xlsb", ".xltm", ".pptx", ".pptm", ".potm", ".ppsm", ".odt", ".ods",
               ".odp")
_PROSE = (ArtifactRole.skill_md, ArtifactRole.instruction_md, ArtifactRole.command_md, ArtifactRole.reference)
_URL = regex.compile(r"https?://[^\s\"'<>)\]]{4,}", _F)
_NAMESPACE_HOST = regex.compile(
    r"^https?://(?:ns\.adobe\.com|purl\.org|www\.w3\.org|w3\.org|iptc\.org|www\.iptc\.org|ns\.useplus\.org|schema\.org|cipa\.jp|"
    r"ns\.google\.com|www\.aiim\.org|www\.npes\.org|creativecommons\.org|www\.inkscape\.org|inkscape\.org|sodipodi\.sourceforge\.net|"
    r"xmlns\.com|www\.color\.org|ns\.microsoft\.com|www\.adobe\.com|www\.gimp\.org|ns\.apple\.com)\b", _F)
_CODE = regex.compile(
    r"\b(?:curl|wget|bash|sh|powershell|pwsh|python3?|node|eval|exec|base64|nc|ncat)\b[^\n]{0,60}(?:https?://|\|\s*(?:ba)?sh\b|\s-c\s|\s-e\s|\s-d\b|\()"
    r"|<\s*script\b|\$\([^)]{3,}\)|\brm\s+-rf\b|\bchmod\s+\+x\b|\bInvoke-(?:Expression|WebRequest)\b", _F)
_AGENT_WORDS = regex.compile(
    r"\b(?:ignore|instructions?|assistant|agent|system\s+prompt|execute|run\s+the|curl|wget|send|upload|password|token|secret|credentials?|"
    r"api\s+key|ssh|do\s+not\s+tell|without\s+(?:asking|telling))\b", _F)
_IMG_REF = r"(?:image|picture|screenshot|figure|diagram|photo|`?[\w./\-]+\.(?:png|jpe?g|gif|webp|bmp|svg)`?)"
_SPLIT = regex.compile(
    r"\b(?:replace|fill\s+in|substitute|complete)\s+(?:the\s+)?(?:blank|blanks|placeholder|gap|missing\s+\w+|_{3,}|<[^>\n]{0,30}>|"
    r"\[[^\]\n]{0,30}\]|X{4,})\s+(?:with|using|from)\s+(?:the\s+)?(?:[\w-]+\s+){0,4}(?:in|from|on|of)\s+(?:the\s+)?(?:attached\s+)?" + _IMG_REF
    + r"|\b(?:the\s+)?(?:url|address|host|domain|endpoint|command|token|key|password|code|value|recipient|destination|server)\s+(?:to\s+use\s+)?"
    r"(?:is|are)\s+(?:only\s+)?(?:shown|given|written|found|printed|displayed)\s+(?:only\s+)?in\s+(?:the\s+)?(?:attached\s+)?" + _IMG_REF
    + r"|\b(?:_{4,}|\[\s*(?:see|from)\s+(?:the\s+)?image\s*\]|<\s*(?:see|from)\s+(?:the\s+)?image\s*>)[^\n]{0,120}\b" + _IMG_REF, _F)
_IMG_FILE = regex.compile(r"[\w./\-]+\.(?:png|jpe?g|gif|webp|bmp|svg)", _F)
_NB_RISK = regex.compile(
    r"^\s*[!%]{1,2}\s*(?:curl|wget|bash|sh|pip\s+install\s+(?:-\S+\s+)*(?:git\+|https?://))|\bsubprocess\.|\bos\.system\s*\(|"
    r"\brequests\.post\s*\(|\beval\s*\(|\bexec\s*\(|\bbase64\.b64decode\s*\(|__import__\s*\(", _F | regex.MULTILINE)


def _search(rx: regex.Pattern[str], text: str) -> regex.Match[str] | None:
    try:
        return rx.search(text, timeout=TIMEOUT)
    except TimeoutError:
        return None


def carries(text: str) -> tuple[str, str]:
    """What recovered text carries: ("instructions" | "code" | "a URL", the matched part), or ("", "")."""
    m = _search(DIRECTIVE, text) or _search(CORE, text)
    if m:
        return "instructions", m.group(0)
    m = _search(_CODE, text)
    if m:
        return "code", m.group(0)
    try:
        for u in _URL.finditer(text, timeout=TIMEOUT):
            if not _search(_NAMESPACE_HOST, u.group(0)):
                return "a URL", u.group(0)
    except TimeoutError:
        pass
    return "", ""


def _letters(text: str) -> int:
    return sum(c.isalpha() for c in text)


class MediaAnalyzer:
    id: ClassVar[str] = "media"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = ("AG-MM-001", "AG-MM-003", "AG-MM-004", "AG-MM-005", "AG-MM-006", "AG-MM-007", "AG-MM-008",
                                        "AG-MM-009", "AG-MM-010", "AG-MM-011", "AG-MM-012", "AG-MM-014", "AG-MM-015")

    def run(self, ctx: Context) -> None:
        self.ctx = ctx
        self.inv = ctx.inventory
        tree = self.inv.tree
        if tree is None:
            return
        self.analysed: set[str] = ctx.data.setdefault("analysed_paths", set())  # type: ignore[assignment]
        self.units: list[TextUnit] = ctx.data.setdefault("extra_units", [])  # type: ignore[assignment]
        self.media_text = ctx.options.media_text or {}
        facts = ctx.options.facts if isinstance(ctx.options.facts, dict) else {}
        self.facts: dict[str, Any] = facts.get("media") if isinstance(facts.get("media"), dict) else {}
        office: dict[str, list[str]] = {}
        for path in tree.files:
            if "!/" in path:
                outer, _, inner = path.partition("!/")
                if outer.lower().endswith(_OFFICE_EXT):
                    office.setdefault(outer, []).append(inner)
        for path in sorted(tree.files):
            data = tree.files[path].data
            if not data:
                continue
            lower = path.lower()
            kind = binary_kind(data)
            if kind in _IMAGE_KINDS:
                self._image(path, data, kind)
            elif kind == "pdf":
                self._pdf(path, data)
            elif kind == "ole":
                self._ole(path, data)
            elif kind == "zip" and lower.endswith(_OFFICE_EXT):
                self._office(path, office.get(path) or mp.zip_names(data))
            elif kind is None and (lower.endswith(".svg") or (b"<svg" in data[:2048] and lower.endswith((".xml", ".svgz")))):
                self._svg(path, data)
            elif kind is None and lower.endswith(".ipynb"):
                self._notebook(path, data)
            elif kind is None and lower.endswith((".html", ".htm", ".xhtml")):
                self._html(path, data)
            self._recorded(path)
        self._split_instructions()

    # -- helpers ------------------------------------------------------------------------------------------------
    def _cid(self, path: str) -> list[str]:
        art = self.inv.artifacts.get(path)
        return [art.component_id] if art is not None else []

    def _unit(self, path: str, text: str, technique: str, label: str = "") -> None:
        """Hand recovered text to the pattern rules, pointing back at the file it came from."""
        cid = self._cid(path)
        text = text.strip()
        if not cid or len(text) < 12 or len(text) > 200_000:
            return
        self.units.append(TextUnit(path=path, component_id=cid[0], role="reference", scope="decoded", text=text, norm=normalize(text),
                                   base=None, anchor_span=Span(path=path), label=label or technique, decode_path=(technique,)))

    def _line(self, path: str, text: str, offset: int) -> Span:
        at: ArtifactText | None = self.inv.texts.get(path)
        if at is not None and at.text == text:
            return at.span(offset, offset + 1)
        return Span(path=path, start_line=text.count("\n", 0, offset) + 1)

    # -- images: AG-MM-005, AG-MM-015 ---------------------------------------------------------------------------
    def _image(self, path: str, data: bytes, kind: str) -> None:
        info = mp.image_info(data, kind)
        if not info.parsed:
            return
        self.analysed.add(path)
        cid = self._cid(path)
        best: tuple[int, str, str, str, str] | None = None
        for where, text in info.metadata:
            what, part = carries(text)
            if what:
                rank = {"instructions": 0, "code": 1, "a URL": 2}[what]
                if best is None or rank < best[0]:
                    best = (rank, what, part, where, text)
            if len(text.strip()) >= 12 and _letters(text) >= 8:
                self._unit(path, mp.strip_tags(text) if "<" in text else text, f"{kind}-metadata", f"{where}")
        if best is not None:
            _, what, part, where, text = best
            self.ctx.emit("AG-MM-005", component_ids=cid, span=Span(path=path), snippet=f"{where}: {text.strip()[:200]}",
                          match=f"meta:{path}:{where}:{part[:80]}", kind=EvidenceKind.metadata, decoded=text.strip()[:400],
                          decode_path=(f"{kind}-metadata",), detail=where, severity=Severity.medium if what == "a URL" else None,
                          message=f"The {where} metadata of `{path}` carries {what} (\"{part.strip()[:80]}\"). Metadata is not shown when "
                                  "the image is viewed, and a tool that describes or converts the image hands it to the model.")
        why = info.lsb
        if not why and info.private_chunks and sum(n for _, n in info.private_chunks) >= 1024:
            names = ", ".join(f"`{n}` ({size} bytes)" for n, size in info.private_chunks[:3])
            why = f"it carries private chunks no viewer displays: {names}"
        if why:
            self.ctx.emit("AG-MM-015", component_ids=cid, span=Span(path=path), snippet=posixpath.basename(path), match=f"stego:{path}",
                          kind=EvidenceKind.metadata,
                          message=f"`{path}` shows a statistical trace of hidden data: {why}. This is an indicator, not proof; "
                                  "check where the image came from and whether anything reads its bytes.")

    # -- SVG: AG-MM-006, AG-MM-004 ------------------------------------------------------------------------------
    def _svg(self, path: str, data: bytes) -> None:
        text = data.decode("utf-8", "replace")
        rep = mp.svg_scan(text)
        self.analysed.add(path)
        cid = self._cid(path)
        seen: set[str] = set()
        for what, offset, matched in rep.active:
            if what in seen:
                continue
            seen.add(what)
            self.ctx.emit("AG-MM-006", component_ids=cid, span=self._line(path, text, offset), snippet=matched, match=f"svg:{path}:{what}",
                          kind=EvidenceKind.metadata, detail=what,
                          message=f"`{path}` is an SVG image with {'an' if what[0] in 'aeiou' else 'a'} {what} (`{matched[:80]}`). An SVG "
                                  "is a document that can run script and load other resources wherever it is rendered.")
        if rep.hidden:
            why, offset, hidden = rep.hidden[0]
            joined = " ".join(h for _, _, h in rep.hidden)
            if len(joined) >= 12:
                self.ctx.emit("AG-MM-004", component_ids=cid, span=self._line(path, text, offset), snippet=hidden[:200],
                              match=f"svg-hidden:{path}:{joined[:80]}", kind=EvidenceKind.metadata, hidden=True, hidden_kind="svg-hidden-text",
                              decoded=joined[:400], detail=why,
                              message=f"`{path}` contains text nobody sees when the image is displayed ({why}): \"{joined[:120]}\". A model "
                                      "given the image, or its source, reads it.")
                self._unit(path, joined, "svg-hidden-text")
        visible = " ".join(t for _, t in rep.text)
        if visible:
            self._unit(path, visible, "svg-text")

    # -- PDF: AG-MM-007, AG-MM-008, AG-MM-009 -------------------------------------------------------------------
    def _pdf(self, path: str, data: bytes) -> None:
        rep = mp.pdf_scan(data)
        if not rep.parsed:
            return
        cid = self._cid(path)
        if not rep.encrypted and rep.unread_streams == 0:
            self.analysed.add(path)
        if rep.active:
            auto = " It also defines an automatic action, so this runs when the document is opened." if rep.automatic else ""
            self.ctx.emit("AG-MM-009", component_ids=cid, span=Span(path=path), snippet=", ".join(rep.active), match=f"pdf-active:{path}:{rep.active}",
                          kind=EvidenceKind.metadata,
                          message=f"`{path}` contains active content: {', '.join(rep.active)}.{auto} A reference document has no need "
                                  "for it, and a viewer or converter that honours it acts on the reader's machine.")
        for why, text in rep.hidden[:3]:
            if _letters(text) < 8:
                continue
            self.ctx.emit("AG-MM-007", component_ids=cid, span=Span(path=path), snippet=text[:200], match=f"pdf-hidden:{path}:{why}:{text[:80]}",
                          kind=EvidenceKind.metadata, hidden=True, hidden_kind="pdf-hidden-text", decoded=text[:400], detail=why,
                          message=f"`{path}` contains text that is not visible on the page ({why}): \"{text[:120]}\". A person reading "
                                  "the document does not see it; text extraction, which is how an agent reads a PDF, returns it.")
            self._unit(path, text, "pdf-hidden-text", why)
        extracted = " ".join(rep.text)
        if extracted:
            self._unit(path, extracted, "pdf-text")
        rendered = " ".join(t for label, t in self.media_text.get(path, []) if label == "rendered")
        if rendered and extracted:
            seen = set(regex.findall(r"[a-z0-9]{3,}", rendered.lower()))
            words = regex.findall(r"[A-Za-z0-9]{3,}", extracted + " " + " ".join(t for _, t in rep.hidden))
            missing = [w for w in words if w.lower() not in seen]
            if len(missing) >= 6 and len(missing) >= 0.3 * max(len(words), 1):
                gone = " ".join(missing)[:300]
                self.ctx.emit("AG-MM-008", component_ids=cid, span=Span(path=path), snippet=gone[:200], match=f"pdf-diff:{path}:{gone[:80]}",
                              kind=EvidenceKind.metadata, decoded=gone, hidden=True, hidden_kind="pdf-unrendered-text",
                              message=f"Text extraction of `{path}` returns {len(missing)} words that do not appear on the rendered "
                                      f"pages (\"{gone[:100]}\"). What an agent reads from this file is not what a person sees.")

    # -- Office: AG-MM-010 --------------------------------------------------------------------------------------
    def _office(self, path: str, names: list[str]) -> None:
        macros, objects = mp.office_members(names)
        self._office_finding(path, macros, objects)

    def _ole(self, path: str, data: bytes) -> None:
        macros, objects = mp.ole_scan(data)
        self._office_finding(path, ["a VBA project"] if macros else [], ["an embedded object"] if objects else [])

    def _office_finding(self, path: str, macros: list[str], objects: list[str]) -> None:
        if not macros and not objects:
            return
        bits = []
        if macros:
            bits.append(f"macros ({', '.join(macros[:3])})")
        if objects:
            bits.append(f"embedded objects ({', '.join(objects[:3])})")
        self.ctx.emit("AG-MM-010", component_ids=self._cid(path), span=Span(path=path), snippet=", ".join((macros + objects)[:6]),
                      match=f"office:{path}:{sorted(macros + objects)}", kind=EvidenceKind.metadata,
                      message=f"`{path}` is an Office document with {' and '.join(bits)}. Macros are code that runs when the document "
                              "is opened with them enabled, and an embedded object can be any file, including an executable.")

    # -- notebooks: AG-MM-011 -----------------------------------------------------------------------------------
    def _notebook(self, path: str, data: bytes) -> None:
        text = data.decode("utf-8", "replace")
        parsed = parse_json(text)
        cells = mp.notebook_cells(parsed.value)
        if not cells:
            return
        cid = self._cid(path)
        done = 0

        def where(snippet: str) -> Span:
            first = next((ln for ln in snippet.split("\n") if ln.strip()), "")
            needle = json.dumps(first[:40])[1:-1]
            off = text.find(needle) if needle else -1
            return self._line(path, text, off) if off >= 0 else Span(path=path, start_line=1)

        for cell in cells:
            if done >= 5:
                break
            for out in cell.outputs:
                body = mp.strip_tags(out) if "<" in out else out
                what, part = carries(body)
                script = "<script" in out.lower()
                if what == "instructions" or script:
                    done += 1
                    self.ctx.emit("AG-MM-011", component_ids=cid, span=where(out), snippet=body[:200],
                                  match=f"nb-output:{path}:{cell.index}:{(part or 'script')[:80]}", kind=EvidenceKind.metadata,
                                  decoded=body[:400], decode_path=("notebook-output",),
                                  message=f"A stored output of cell {cell.index + 1} in `{path}` contains "
                                          + (f"instructions (\"{part[:80]}\")" if what == "instructions" else "a script element")
                                          + ". Stored outputs are not produced by running the notebook: they are whatever the "
                                            "file says they are, and an agent reading the notebook reads them as results.")
                    break
                if len(body) >= 12:
                    self._unit(path, body, "notebook-output", f"cell {cell.index + 1} output")
            if cell.kind in ("markdown", "raw"):
                what, part = carries(cell.source)
                if what == "instructions":
                    done += 1
                    self.ctx.emit("AG-MM-011", component_ids=cid, span=where(cell.source), snippet=cell.source[:200],
                                  match=f"nb-cell:{path}:{cell.index}:{part[:80]}", kind=EvidenceKind.metadata,
                                  message=f"The {cell.kind} cell {cell.index + 1} of `{path}` contains instructions (\"{part[:80]}\").")
                self._unit(path, cell.source, "notebook-cell", f"cell {cell.index + 1}")
            elif cell.hidden:
                risk = _search(_NB_RISK, cell.source)
                if risk:
                    done += 1
                    self.ctx.emit("AG-MM-011", component_ids=cid, span=where(cell.source), snippet=cell.source[:200],
                                  match=f"nb-hidden:{path}:{cell.index}:{risk.group(0)[:60]}", kind=EvidenceKind.metadata, hidden=True,
                                  hidden_kind="notebook-hidden-cell",
                                  message=f"Code cell {cell.index + 1} of `{path}` is marked hidden in the notebook interface and "
                                          f"contains `{risk.group(0).strip()[:60]}`. Whoever opens the notebook does not see the "
                                          "cell; running all cells runs it.")

    # -- HTML: AG-MM-012 ----------------------------------------------------------------------------------------
    def _html(self, path: str, data: bytes) -> None:
        art = self.inv.artifacts.get(path)
        if art is not None and art.role == ArtifactRole.ui_resource:
            return                                   # MCP app resources have their own rules
        text = data.decode("utf-8", "replace")
        hidden, scripts = mp.html_scan(text)
        cid = self._cid(path)
        for offset, body in hidden:
            if not _search(_AGENT_WORDS, body):
                continue
            self.ctx.emit("AG-MM-012", component_ids=cid, span=self._line(path, text, offset), snippet=body[:200],
                          match=f"html-hidden:{path}:{body[:80]}", kind=EvidenceKind.metadata, hidden=True, hidden_kind="html-hidden-element",
                          decoded=body[:400],
                          message=f"`{path}` has an element that is not displayed and contains \"{body[:120]}\". A browser hides it; "
                                  "an agent that reads the file's text does not.")
            self._unit(path, body, "html-hidden-element")
            break
        if scripts:
            offset, what = scripts[0]
            self.ctx.emit("AG-MM-012", component_ids=cid, span=self._line(path, text, offset), snippet=what, match=f"html-script:{path}:{what[:80]}",
                          kind=EvidenceKind.metadata, severity=Severity.low,
                          message=f"`{path}` contains a {what}. An HTML file shipped as an asset runs this wherever it is opened or "
                                  "rendered.")

    # -- recorded facts: AG-MM-001, AG-MM-004, AG-MM-014, AG-MM-015 -----------------------------------------------
    def _recorded(self, path: str) -> None:
        texts = self.media_text.get(path) or []
        fact = self.facts.get(path) if isinstance(self.facts.get(path), dict) else {}
        if not texts and not fact:
            return
        cid = self._cid(path)
        ocr = " ".join(t for label, t in texts if label == "ocr" or label.startswith("ocr:"))
        if ocr:
            self._unit(path, ocr, "ocr")
            what, part = carries(ocr)
            if what in ("instructions", "code"):
                self.ctx.emit("AG-MM-001", component_ids=cid, span=Span(path=path), snippet=ocr[:200], match=f"ocr:{path}:{part[:80]}",
                              kind=EvidenceKind.metadata, decoded=ocr[:400], decode_path=("ocr",),
                              message=f"The picture in `{path}` contains {what} (\"{part.strip()[:80]}\"). A text scanner sees an image "
                                      "file; a model that looks at the image reads the text.")
        faint = [t for label, t in texts if label in ("ocr:low-contrast", "ocr:small")]
        faint += [str(t) for key in ("low_contrast_text", "small_text") for t in (fact.get(key) or []) if isinstance(t, str)]
        faint_text = " ".join(faint).strip()
        if len(faint_text) >= 8:
            self.ctx.emit("AG-MM-004", component_ids=cid, span=Span(path=path), snippet=faint_text[:200], match=f"faint:{path}:{faint_text[:80]}",
                          kind=EvidenceKind.metadata, hidden=True, hidden_kind="low-contrast-text", decoded=faint_text[:400],
                          decode_path=("ocr",),
                          message=f"`{path}` contains text too faint or too small for a person to notice: \"{faint_text[:120]}\". "
                                  "A vision model reads it without difficulty.")
            self._unit(path, faint_text, "ocr")
        codes = [t for label, t in texts if label == "qr"] + [str(t) for t in (fact.get("qr") or []) if isinstance(t, str)]
        for code in codes[:3]:
            what, part = carries(code)
            if what:
                self.ctx.emit("AG-MM-014", component_ids=cid, span=Span(path=path), snippet=code[:200], match=f"qr:{path}:{code[:80]}",
                              kind=EvidenceKind.metadata, decoded=code[:400], decode_path=("qr",),
                              message=f"A QR code or barcode in `{path}` decodes to {what}: `{code.strip()[:120]}`. Nobody can read a "
                                      "code by eye, and an agent told to scan it follows where it points.")
                self._unit(path, code, "qr")
                break
        if isinstance(fact.get("stego"), str) and fact["stego"].strip():
            self.ctx.emit("AG-MM-015", component_ids=cid, span=Span(path=path), snippet=posixpath.basename(path), match=f"stego:{path}",
                          kind=EvidenceKind.metadata,
                          message=f"`{path}` shows a statistical trace of hidden data: {fact['stego'].strip()[:200]}. This is an "
                                  "indicator, not proof.")

    # -- AG-MM-003 ------------------------------------------------------------------------------------------------
    def _split_instructions(self) -> None:
        for at in self.ctx.texts():
            if at.artifact.role not in _PROSE:
                continue
            m = _search(_SPLIT, at.text)
            if not m:
                continue
            line = at.line_text(m.start())
            ref = _search(_IMG_FILE, m.group(0)) or _search(_IMG_FILE, line)
            found = ""
            if ref:
                name = ref.group(0).strip("`")
                target = next((p for p in sorted(self.media_text) if p == name or p.endswith("/" + name.lstrip("./"))), None)
                found = " ".join(t for label, t in self.media_text.get(target or "", []) if label.startswith("ocr"))
            extra = f" The image reads: \"{found[:120]}\"." if found else ""
            self.ctx.emit("AG-MM-003", component_ids=at.artifact.component_id, span=at.span(m.start(), m.end()), snippet=line.strip()[:240],
                          match=f"split:{at.path}:{m.group(0).lower()[:120]}", kind=EvidenceKind.regex, decoded=found[:400],
                          message="The instruction is incomplete in the text and says the missing part is in an image "
                                  f"(\"{m.group(0).strip()[:100]}\").{extra} Neither half is an attack on its own, and a scanner that "
                                  "reads only text never sees the whole.")


__all__ = ["MediaAnalyzer", "carries"]
