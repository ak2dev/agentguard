"""Host side of engine G: the text inside pictures and rendered pages (PLAN §5.4 G).

The pure media analyzer (``core/analyzers/media.py``) reads containers. What needs pixels is gathered here, before
the scan, and handed to it as recorded facts (``ScanOptions.media_text`` and ``ScanOptions.facts["media"]``):

* OCR of images, with an optional ONNX engine (``pip install 'agentguard-v1[ocr]'``). Every line is labelled ``ocr``;
  a line a person would not notice is labelled ``ocr:small`` (too small at the image's size) or ``ocr:low-contrast``
  (it barely differs from its background; this needs Pillow, ``[media]``), which AG-MM-004 reports;
* OCR of rendered PDF pages (``rendered``; needs pypdfium2, ``[ocr]``), which AG-MM-008 compares with what a PDF
  text extractor returns;
* QR codes and barcodes (``qr``; needs zxing-cpp, ``[ocr]``), for AG-MM-014.

When no OCR engine is installed and a model is configured, the model stage asks a vision model to transcribe the
images instead (``judge/vision.py``); the analyzer treats that text the same way.

Nothing here executes the target: images and PDFs are decoded as data by the libraries above, with size limits.
``collect_media`` takes the engines as arguments, so it is tested with fakes and works with any engine that has the
same small interface.
"""

from __future__ import annotations

import io
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from .core.artifacts import binary_kind
from .core.mediaparse import image_info
from .core.tree import ArtifactTree

IMAGE_KINDS = ("png", "jpeg", "gif", "webp", "tiff")
MAX_IMAGE_BYTES = 20_000_000
MAX_IMAGES = 200
MAX_PDF_PAGES = 20
# A line is "small" when it is under 7 pixels tall, or under 0.8% of the image height (it would be a few pixels on
# screen when the picture is shown whole); "low contrast" when text and background differ by under 15% of full range.
SMALL_PX = 7.0
SMALL_FRACTION = 0.008
LOW_CONTRAST = 0.15

Box = tuple[float, float, float, float]          # x0, y0, x1, y1 in pixels


class OcrEngine(Protocol):
    name: str

    def read(self, data: bytes) -> list[tuple[str, Box, float]]: ...


class PageRenderer(Protocol):
    def render(self, data: bytes, max_pages: int) -> list[bytes]: ...


class CodeReader(Protocol):
    def decode(self, data: bytes) -> list[str]: ...


@dataclass
class MediaResult:
    media_text: dict[str, list[tuple[str, str]]] = field(default_factory=dict)
    facts: dict[str, dict[str, Any]] = field(default_factory=dict)
    read: list[str] = field(default_factory=list)          # paths whose pixels were read
    unread: list[str] = field(default_factory=list)        # images nobody read the pixels of
    notes: list[str] = field(default_factory=list)


# ------------------------------------------------------------------ engines --
def _box(points: Any) -> Box | None:
    """A box from either four corner points or (x0, y0, x1, y1)."""
    try:
        if len(points) == 4 and all(isinstance(p, (int, float)) for p in points):
            x0, y0, x1, y1 = (float(v) for v in points)
            return (min(x0, x1), min(y0, y1), max(x0, x1), max(y0, y1))
        xs = [float(p[0]) for p in points]
        ys = [float(p[1]) for p in points]
        return (min(xs), min(ys), max(xs), max(ys))
    except (TypeError, ValueError, IndexError):
        return None


class RapidOcr:
    """The ``rapidocr`` / ``rapidocr_onnxruntime`` package (Apache-2.0; ONNX models, runs locally)."""

    name = "rapidocr"

    def __init__(self) -> None:
        try:
            from rapidocr_onnxruntime import RapidOCR  # type: ignore[import-not-found]
        except ImportError:
            from rapidocr import RapidOCR  # type: ignore[import-not-found,no-redef]
        self._engine = RapidOCR()

    def read(self, data: bytes) -> list[tuple[str, Box, float]]:
        out = self._engine(data)
        lines: list[tuple[str, Box, float]] = []
        # rapidocr_onnxruntime returns (result, elapsed) with result = [[points, text, score], ...] or None;
        # rapidocr 2 and later return an object with boxes, txts and scores.
        if isinstance(out, tuple):
            for entry in out[0] or []:
                box = _box(entry[0])
                if box is not None and str(entry[1]).strip():
                    lines.append((str(entry[1]), box, float(entry[2])))
            return lines
        boxes, txts, scores = getattr(out, "boxes", None), getattr(out, "txts", None), getattr(out, "scores", None)
        for points, text, score in zip(boxes if boxes is not None else [], txts or [], scores or []):
            box = _box(points)
            if box is not None and str(text).strip():
                lines.append((str(text), box, float(score)))
        return lines


class PdfiumRenderer:
    """``pypdfium2`` (Apache-2.0 / BSD-3-Clause) renders PDF pages to PNG, with Pillow."""

    def render(self, data: bytes, max_pages: int) -> list[bytes]:
        import pypdfium2 as pdfium  # type: ignore[import-not-found]

        pages: list[bytes] = []
        pdf = pdfium.PdfDocument(data)
        try:
            for i in range(min(len(pdf), max_pages)):
                bitmap = pdf[i].render(scale=2)
                buf = io.BytesIO()
                bitmap.to_pil().save(buf, format="PNG")
                pages.append(buf.getvalue())
        finally:
            pdf.close()
        return pages


class ZxingReader:
    """``zxing-cpp`` (Apache-2.0) reads QR codes and barcodes, with Pillow."""

    def decode(self, data: bytes) -> list[str]:
        import zxingcpp  # type: ignore[import-not-found]
        from PIL import Image  # type: ignore[import-not-found]

        with Image.open(io.BytesIO(data)) as img:
            return [r.text for r in zxingcpp.read_barcodes(img) if getattr(r, "text", "")]


def _try(make: Callable[[], Any]) -> Any:
    try:
        return make()
    except Exception:  # noqa: BLE001 - an optional engine that is missing or broken is simply not used
        return None


def available_engines() -> dict[str, Any]:
    """The optional engines installed here: ``ocr``, ``renderer``, ``codes``, ``pixels`` (bool)."""
    ocr = _try(RapidOcr)
    renderer = PdfiumRenderer() if _importable("pypdfium2") and _importable("PIL") else None
    codes = ZxingReader() if _importable("zxingcpp") and _importable("PIL") else None
    return {"ocr": ocr, "renderer": renderer, "codes": codes, "pixels": _importable("PIL")}


def _importable(name: str) -> bool:
    import importlib.util

    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


# ------------------------------------------------------------------ pixels --
def _contrast(data: bytes, box: Box) -> float | None:
    """How far text and background differ inside ``box`` (0..1), by Otsu's split of the grey levels. None without Pillow."""
    try:
        from PIL import Image  # type: ignore[import-not-found]
    except ImportError:
        return None
    try:
        with Image.open(io.BytesIO(data)) as img:
            grey = img.convert("L")
            x0, y0, x1, y1 = (int(round(v)) for v in box)
            region = grey.crop((max(0, x0), max(0, y0), max(x0 + 1, x1), max(y0 + 1, y1)))
            hist = region.histogram()
    except Exception:  # noqa: BLE001 - an image Pillow cannot read has no contrast figure
        return None
    total = sum(hist)
    if total < 4:
        return None
    sum_all = sum(i * n for i, n in enumerate(hist))
    best, w0, s0 = (-1.0, 0.0, 0.0), 0, 0.0
    for t in range(256):
        w0 += hist[t]
        if w0 == 0 or w0 == total:
            continue
        s0 += t * hist[t]
        m0, m1 = s0 / w0, (sum_all - s0) / (total - w0)
        between = w0 * (total - w0) * (m0 - m1) ** 2
        if between > best[0]:
            best = (between, m0, m1)
    if best[0] < 0:
        return 0.0
    return abs(best[2] - best[1]) / 255.0


def _labels(data: bytes, lines: Sequence[tuple[str, Box, float]], height: int, pixels: bool) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    text = " ".join(t.strip() for t, _, _ in lines if t.strip())
    if text:
        out.append(("ocr", text))
    small: list[str] = []
    faint: list[str] = []
    for t, box, _score in lines:
        h = box[3] - box[1]
        if h > 0 and (h < SMALL_PX or (height and h < SMALL_FRACTION * height)):
            small.append(t.strip())
            continue
        if pixels:
            c = _contrast(data, box)
            if c is not None and c < LOW_CONTRAST:
                faint.append(t.strip())
    if small:
        out.append(("ocr:small", " ".join(small)))
    if faint:
        out.append(("ocr:low-contrast", " ".join(faint)))
    return out


# ----------------------------------------------------------------- collect --
def images_in(tree: ArtifactTree) -> list[tuple[str, bytes, str]]:
    """(path, bytes, kind) of every raster image in the tree, in path order."""
    out = []
    for path in sorted(tree.files):
        data = tree.files[path].data
        kind = binary_kind(data) if data else None
        if kind in IMAGE_KINDS and len(data) <= MAX_IMAGE_BYTES:
            out.append((path, data, kind))
    return out


def collect_media(tree: ArtifactTree, *, ocr: OcrEngine | None = None, renderer: PageRenderer | None = None,
                  codes: CodeReader | None = None, pixels: bool = False,
                  only: Iterable[str] | None = None) -> MediaResult:
    """Read the pixels of the tree's images and PDF pages with whichever engines are given."""
    res = MediaResult()
    wanted = set(only) if only is not None else None
    images = [i for i in images_in(tree) if wanted is None or i[0] in wanted]
    for path, data, kind in images[:MAX_IMAGES]:
        got: list[tuple[str, str]] = []
        if ocr is not None:
            try:
                lines = ocr.read(data)
            except Exception as exc:  # noqa: BLE001 - one unreadable image must not stop the scan
                res.notes.append(f"OCR could not read {path}: {type(exc).__name__}")
                lines = None
            if lines is not None:
                got += _labels(data, lines, image_info(data, kind).height, pixels)
                res.read.append(path)
        if codes is not None:
            try:
                got += [("qr", c) for c in codes.decode(data)[:5]]
            except Exception:  # noqa: BLE001
                pass
        if got:
            res.media_text[path] = got
        if path not in res.read:
            res.unread.append(path)
    res.unread += [p for p, _, _ in images[MAX_IMAGES:]]
    if ocr is not None and renderer is not None:
        for path in sorted(tree.files):
            data = tree.files[path].data
            if (wanted is not None and path not in wanted) or not data.startswith(b"%PDF-") or len(data) > MAX_IMAGE_BYTES:
                continue
            try:
                pages = renderer.render(data, MAX_PDF_PAGES)
                text = " ".join(t.strip() for page in pages for t, _, _ in ocr.read(page) if t.strip())
            except Exception as exc:  # noqa: BLE001 - an encrypted or broken PDF is reported by the analyzer itself
                res.notes.append(f"could not render {path}: {type(exc).__name__}")
                continue
            res.media_text.setdefault(path, []).append(("rendered", text))
            res.read.append(path)
    for path in res.read:
        res.facts.setdefault(path, {})["read_by"] = getattr(ocr, "name", "ocr")
    return res


def apply(options: Any, res: MediaResult) -> None:
    """Merge a result into ``ScanOptions`` (recorded text wins over nothing; earlier entries are kept)."""
    merged = {k: list(v) for k, v in (options.media_text or {}).items()}
    for path, items in res.media_text.items():
        merged.setdefault(path, [])
        merged[path] += [i for i in items if i not in merged[path]]
    options.media_text = merged
    facts = dict(options.facts or {})
    ocr_facts = dict(facts.get("ocr") or {})
    for path in res.read:
        ocr_facts[path] = True
    if ocr_facts:
        facts["ocr"] = ocr_facts
    options.facts = facts


def has_media(tree: ArtifactTree) -> bool:
    return any(binary_kind(b.data[:16]) in IMAGE_KINDS or b.data.startswith(b"%PDF-") for b in tree.files.values() if b.data)


def gather(tree: ArtifactTree, options: Any, notes: list[str], engines: dict[str, Any] | None = None) -> MediaResult:
    """What ``run_scan`` calls: OCR with the installed engines, merged into ``options``. Engines are only loaded
    when the tree holds an image or a PDF."""
    if not has_media(tree):
        return MediaResult()
    engines = engines if engines is not None else available_engines()
    res = collect_media(tree, ocr=engines.get("ocr"), renderer=engines.get("renderer"), codes=engines.get("codes"),
                        pixels=bool(engines.get("pixels")))
    apply(options, res)
    notes += res.notes
    return res


def unread_note(tree: ArtifactTree, options: Any) -> str:
    """A note saying how many images nobody read the text of (no OCR engine, no model), or ''."""
    read = (options.facts or {}).get("ocr") or {}
    unread = [p for p, _, _ in images_in(tree) if p not in read]
    if not unread:
        return ""
    return (f"{len(unread)} image(s) were not read for text: install the OCR engine (pip install 'agentguard-v1[ocr]'), "
            "or scan in the standard profile with a model, so that instructions drawn into a picture are seen")


__all__ = ["MediaResult", "OcrEngine", "PageRenderer", "CodeReader", "RapidOcr", "PdfiumRenderer", "ZxingReader",
           "available_engines", "collect_media", "apply", "gather", "has_media", "images_in", "unread_note"]
