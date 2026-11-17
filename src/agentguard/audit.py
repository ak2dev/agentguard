"""The audit log (PLAN §11 Phase 6; OWASP AST09 governance): what was approved, installed, fixed or updated.

One JSON object per line in ``<data home>/audit.jsonl`` (``AGENTGUARD_HOME`` moves it). Every entry carries the
SHA-256 of the line before it, so editing or deleting an entry breaks the chain; ``verify`` finds the first break and
``agentguard doctor`` reports it.

Written by ``install`` (installed, or refused and why), ``baseline create`` and ``baseline update`` (what was
approved), ``fix --apply`` (which files changed, which findings were fixed), ``update`` (which signed bundle was
installed) and ``rules import``. Entries hold rule ids, component ids, paths, verdicts and hashes; never scanned text.
``actor`` is what the user passed as ``--approved-by``; nothing is taken from the environment.

Writing the log never fails a command: when it cannot be written the command says so and carries on.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
from typing import Any

from .io.intel_store import data_home

LOG_NAME = "audit.jsonl"
FORMAT = 1


def log_path() -> Path:
    return data_home() / LOG_NAME


def _sha(line: str) -> str:
    return hashlib.sha256(line.encode("utf-8")).hexdigest()


def _last_line(path: Path) -> str:
    try:
        with path.open("rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            fh.seek(max(0, size - 65536))
            tail = fh.read().decode("utf-8", "replace")
    except OSError:
        return ""
    lines = [ln for ln in tail.split("\n") if ln.strip()]
    return lines[-1] if lines else ""


def record(action: str, *, actor: str = "", target: str = "", details: dict[str, Any] | None = None,
           path: Path | None = None, now: dt.datetime | None = None) -> dict[str, Any] | None:
    """Append one entry; returns it, or None when the log could not be written."""
    p = path or log_path()
    prev = _last_line(p)
    entry = {
        "v": FORMAT,
        "at": (now or dt.datetime.now(dt.UTC)).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "action": action, "actor": actor[:200], "target": target[:500], "details": details or {},
        "prev": _sha(prev) if prev else "",
    }
    line = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a", encoding="utf-8", newline="\n") as fh:
            fh.write(line + "\n")
    except OSError:
        return None
    return entry


def read_log(path: Path | None = None) -> list[dict[str, Any]]:
    p = path or log_path()
    try:
        text = p.read_text(encoding="utf-8")
    except OSError:
        return []
    out = []
    for ln in text.split("\n"):
        if ln.strip():
            try:
                out.append(json.loads(ln))
            except ValueError:
                out.append({"unreadable": ln[:80]})
    return out


def verify(path: Path | None = None) -> tuple[int, str]:
    """(number of entries, '' when the chain is intact, else the first problem)."""
    p = path or log_path()
    try:
        lines = [ln for ln in p.read_text(encoding="utf-8").split("\n") if ln.strip()]
    except FileNotFoundError:
        return 0, ""
    except OSError as exc:
        return 0, f"cannot read the audit log: {exc.strerror or exc}"
    prev = ""
    for n, ln in enumerate(lines, 1):
        try:
            entry = json.loads(ln)
        except ValueError:
            return len(lines), f"entry {n} is not valid JSON"
        if entry.get("prev", None) != (_sha(prev) if prev else ""):
            return len(lines), f"entry {n} does not follow entry {n - 1}: an entry was changed, removed or inserted"
        prev = ln
    return len(lines), ""


def note_failure(entry: dict[str, Any] | None) -> str:
    return "" if entry is not None else f"could not write the audit log ({log_path()})"


__all__ = ["LOG_NAME", "log_path", "note_failure", "read_log", "record", "verify"]
