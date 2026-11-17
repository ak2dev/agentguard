"""`agentguard doctor`: what this machine can run, tier by tier."""

from __future__ import annotations

import importlib.util
import os
import shutil
import sys
from typing import Any

from .core.engine import ENGINE_VERSION
from .core.rules.pack import RulePack


def _has(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


def _platform() -> str:
    """Operating system and release. Not `platform.uname()`: on Windows it starts `cmd /c ver`,
    which the no-execution guard refuses."""
    if sys.platform == "win32":
        v = sys.getwindowsversion()
        return f"Windows {v.major}.{v.minor}.{v.build}"
    try:
        u = os.uname()
    except AttributeError:
        return sys.platform
    return f"{u.sysname} {u.release}"


def _check(name: str, ok: bool, used_by: str, detail_ok: str, detail_missing: str) -> dict[str, str]:
    return {"name": name, "status": "ok" if ok else "missing", "used_by": used_by, "detail": detail_ok if ok else detail_missing}


def diagnose(env: dict[str, str] | None = None) -> dict[str, Any]:
    env = dict(os.environ) if env is None else env
    pack = RulePack.default()
    core = [r for r in pack.rules.values() if not r.extension]
    checks: list[dict[str, str]] = []
    checks.append(_check("Deterministic static analysis", True, "quick, standard, deep",
                         f"{len(pack.detectors)} detectors; nothing is sent anywhere", ""))
    ts = all(_has(m) for m in ("tree_sitter", "tree_sitter_python", "tree_sitter_javascript"))
    checks.append(_check("tree-sitter taint analysis", ts, "quick, standard, deep", "installed",
                         "optional: pip install 'agentguard-v1[code]' (pattern and Python AST analysis still run)"))
    checks.append(_check("YARA signatures", _has("yara"), "quick, standard, deep", "installed",
                         "optional: pip install 'agentguard-v1[yara]'"))
    checks.append(_check("Low-contrast text in images", _has("PIL"), "quick, standard, deep", "Pillow installed",
                         "optional: pip install 'agentguard-v1[media]' (image metadata and structure are read without it)"))
    ocr = _has("rapidocr_onnxruntime") or _has("rapidocr")
    extras = [n for m, n in (("pypdfium2", "rendered PDF pages"), ("zxingcpp", "QR codes")) if _has(m) and _has("PIL")]
    checks.append(_check("OCR of images", ocr, "quick, standard, deep",
                         "an ONNX OCR engine is installed" + (f"; also {' and '.join(extras)}" if extras else ""),
                         "optional: pip install 'agentguard-v1[ocr]'. Without it, in the standard profile with a model, "
                         "the model transcribes the images instead"))
    from .io.intel_store import load_active_feed

    feed, note = load_active_feed()
    checks.append(_check("Indicator feed", feed is not None, "quick, standard, deep", note, note))
    from .packs import installed_packs

    extra = [p for p in installed_packs() if p["enabled"]]
    checks.append(_check("Extra rule packs", True, "quick, standard, deep",
                         ", ".join(f"{p['name']} {p.get('version') or ''}".strip() for p in extra) or "none installed", ""))
    sdk = _has("anthropic")
    creds = bool(env.get("ANTHROPIC_API_KEY") or env.get("ANTHROPIC_AUTH_TOKEN"))
    checks.append(_check("Model adjudicator (Anthropic)", sdk and creds, "standard, deep", "SDK installed and credentials found",
                         ("credentials not found (set ANTHROPIC_API_KEY or run `ant auth login`)" if sdk
                          else "optional: pip install 'agentguard-v1[judge]'")
                         + "; an OpenAI-compatible or local endpoint can be configured instead (llm.provider)"))
    from .core.triage import load_model

    tm = load_model(pack.data.get("triage-model"))
    held = (tm.info.get("heldout") or {}) if tm else {}
    checks.append(_check("Triage model", tm is not None, "standard, deep",
                         (f"version {tm.version}, runs locally, no network; held-out AUC {held.get('auc')} on "
                          f"{held.get('components')} components of the internal corpus" if tm else ""),
                         "the rule pack carries no triage model (rules/data/triage-model.json); standard runs without it"))
    docker = sandbox_status()
    checks.append({"name": "Sandbox (Docker)", "status": "ok" if docker["available"] else "missing", "used_by": "deep",
                   "detail": docker["detail"]})
    checks.append({"name": "Sandbox level", "status": "ok" if docker["available"] else "missing", "used_by": "deep",
                   "detail": docker["level_detail"]})
    from .audit import log_path, verify

    entries, broken = verify()
    checks.append({"name": "Audit log", "status": "ok" if not broken else "error", "used_by": "install, baseline, fix, update",
                   "detail": (f"{entries} entr{'y' if entries == 1 else 'ies'} in {log_path()}; chain intact" if not broken
                              else f"{log_path()}: {broken}")})
    token = next((v for v in ("AGENTGUARD_GITHUB_TOKEN", "GITHUB_TOKEN") if env.get(v)), None)
    checks.append(_check("GitHub token", token is not None, "GitHub targets, --check-hijackable",
                         f"${token} is set (sent to api.github.com only)",
                         "not set: public repositories still work, at the unauthenticated rate limit"))
    profiles = {
        "quick": "ready. Deterministic static analysis; sends nothing anywhere.",
        "standard": ("ready with the model adjudicator." if sdk and creds
                     else "ready without a model: the triage model runs locally, the adjudicator is skipped until a model is configured."
                     if tm is not None else "ready without a model: the adjudicator is skipped until a model is configured."),
        "deep": ("ready: dynamic analysis runs at the " + docker["level"] + " level." if docker["available"]
                 else "not available: dynamic analysis needs Docker and refuses to run without its sandbox."),
    }
    return {
        "engine": ENGINE_VERSION, "python": sys.version.split()[0], "platform": _platform(),
        "rule_pack": {"version": pack.version, "digest": pack.digest, "rules": len(core),
                      "implemented": sum(1 for r in core if r.implemented), "detectors": len(pack.detectors)},
        "checks": checks, "profiles": profiles,
    }


def sandbox_status() -> dict[str, Any]:
    """Whether the dynamic tier can run here, and at which level (spec/sandbox.md §2)."""
    try:
        from .sandbox.runtime import docker_status

        return docker_status()
    except ImportError:
        found = shutil.which("docker")
        return {"available": False, "level": "none",
                "detail": f"docker found at {found}; the sandbox runtime is not installed" if found else "docker not found on PATH",
                "level_detail": "baseline needs Docker; enhanced needs a Linux host that allows privileged containers"}
