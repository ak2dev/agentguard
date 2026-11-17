"""Coverage accounting: every byte is accounted for.

A file counts as analysed when an engine read its content: its text was
prepared and scanned, or an engine that understands its format (archive,
media, document, bytecode) registered it in ``ctx.data["analysed_paths"]``.
Everything else is listed with the reason, and the loader's limit events
(too large, unreadable, not fetched …) count as content that was not analysed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .artifacts import ARCHIVE_KINDS, binary_kind
from .models import Coverage, UnanalysedItem

if TYPE_CHECKING:
    from .analyzers.base import Context
    from .inventory import Inventory
    from .tree import ArtifactTree

# Limit events that mean "this content exists and was not read".
SKIPPED_KINDS = {
    "too_large", "too_many_files", "too_deep", "total_bytes_exceeded", "encrypted_member", "special_file",
    "unreadable", "archive_error", "archive_bomb", "submodule", "lfs_pointer", "listing_truncated", "not_fetched",
    "decode_limit",
}
MAX_LISTED = 200


def _reason(path: str, data: bytes) -> str:
    kind = binary_kind(data)
    if kind in ARCHIVE_KINDS:
        return f"{kind} archive not unpacked"
    if kind:
        return f"opaque binary ({kind})"
    return "not decodable as text"


def compute_coverage(tree: ArtifactTree, inv: Inventory, ctx: Context) -> Coverage:
    analysed: set[str] = set(inv.texts) | set(ctx.data.get("analysed_paths", ())) | set(inv.unpacked)  # type: ignore[arg-type]
    files_total = len(tree.files)
    bytes_total = tree.total_bytes
    files_analysed = bytes_analysed = 0
    missing: list[UnanalysedItem] = []
    for path in sorted(tree.files):
        blob = tree.files[path]
        if path in analysed or blob.size == 0:
            files_analysed += 1
            bytes_analysed += blob.size
        else:
            missing.append(UnanalysedItem(path=path, reason=_reason(path, blob.data), bytes=blob.size))
    events = ctx.data.get("limit_events", [])
    for ev in sorted(events, key=lambda e: (e.kind, e.path)):  # type: ignore[union-attr]
        if ev.kind in SKIPPED_KINDS:
            files_total += 1
            bytes_total += ev.bytes
            missing.append(UnanalysedItem(path=ev.path, reason=ev.kind.replace("_", " "), bytes=ev.bytes))
    if bytes_total > 0:
        ratio = bytes_analysed / bytes_total
    else:
        ratio = 1.0 if files_analysed >= files_total else files_analysed / max(files_total, 1)
    if missing and ratio >= 1.0:
        ratio = min(ratio, files_analysed / max(files_total, 1))
    excluded = sorted({ev.path for ev in events if ev.kind == "excluded_dir"})  # type: ignore[union-attr]
    return Coverage(
        files_total=files_total, files_analysed=files_analysed, bytes_total=bytes_total, bytes_analysed=bytes_analysed,
        analyzability=round(ratio, 4), unanalysed=missing[:MAX_LISTED], excluded=excluded[:MAX_LISTED],
    )
