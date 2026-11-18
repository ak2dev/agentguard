"""`agentguard bench malskillbench` and `agentguard bench skilltrustbench`: the two public benchmarks (PLAN §12).

Neither benchmark is shipped, fetched or copied by Agent Guard. Both restrict use (MalSkillBench: academic
research only; SkillTrustBench: CC BY-NC-SA 4.0) and both contain live malware. You download a copy yourself
and pass its directory with ``--data``. Every case is read into memory and scanned there: nothing from a case
is executed, installed, imported or written anywhere, and the scorecard holds only case ids, labels, verdicts
and rule ids (no sample content).

Layouts read (as the publishers document them; checked against both repositories on 2026-11-16):

MalSkillBench (github.com/lxyeternal/MalSkillBench)
    ``Dataset/Skills/malware/<sample>/`` and ``Dataset/Skills/benign/<sample>/``, one skill package per
    directory. A generated sample is named ``<skill>__<VECTOR>_<Bn>`` (vector CI, PI or MIXED; behaviour
    B1-B15); a sample without that suffix came from the wild or from a tool's test suite. ``--data`` may be
    the repository, its ``Dataset`` directory or ``Dataset/Skills``.

SkillTrustBench (huggingface.co/datasets/cuhk-zhuque/SkillTrustBench)
    A ground-truth index (``ground_truth.json`` with ``test_cases``, or ``ground_truth.jsonl``) whose rows
    carry ``id``, ``judgment`` (normal | suspicious | malicious) and ``risk_labels`` (T01-T09), and one
    directory per case, either unpacked or still inside the published zip. ``--data`` may be the dataset
    repository, an unpacked ``benchmark_full_v1.0`` tree or an unpacked ``skilltrustbench_556_v1_1`` subset.
    ``--split subset`` scores the fixed 556-case subset (the default when it is present), ``--split full``
    the whole corpus.

Scoring. ALLOW = normal, REVIEW = suspicious, BLOCK = malicious (spec/interfaces.md §4). For SkillTrustBench
the publisher's metric names are kept with the publisher's definitions (``malicious_recall`` is the recall of
the malicious class, so a malicious skill that only reached REVIEW counts as missed), and
``malicious_not_allowed`` is reported beside it: the share of malicious skills that were not allowed.

Profiles. ``quick`` is the deterministic static scan. ``standard`` adds the model stage when a model is
configured, which sends excerpts of the samples to that model's provider: check that the benchmark's terms
and your own allow it. ``deep`` also detonates each case in the sandbox and refuses to run without it.
"""

from __future__ import annotations

import json
import os
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from ..core.engine import scan
from ..core.models import LimitEvent, Report, ScanOptions
from ..core.rules.pack import RulePack
from ..core.tree import ArtifactTree
from ..io.fs_loader import load_path
from .metrics import ratio, verdict_metrics

# PLAN §12.2. The false-positive ceilings are the plan's counts over the benchmark's benign set, as rates.
MALSKILL_TARGETS = {"quick": {"recall": 0.60, "false_positive_rate": 80 / 4000},
                    "standard": {"recall": 0.95, "false_positive_rate": 120 / 4000},
                    "deep": {"recall": 0.95, "false_positive_rate": 120 / 4000}}
TRUST_TARGETS = {"malicious_not_allowed": 0.95, "normal_flagged": 0.05, "macro_f1": 0.85}
_SAMPLE_NAME = re.compile(r"^(?P<skill>.+)__(?P<vector>CI|PI|MIXED)_(?P<behaviour>B\d{1,2})$")
_LABEL_OF = {"ALLOW": "normal", "REVIEW": "suspicious", "BLOCK": "malicious"}
_JUDGMENTS = ("normal", "suspicious", "malicious")


@dataclass
class Case:
    id: str
    label: str                                  # malicious | benign (MalSkillBench); normal | suspicious | malicious
    path: Path | None = None                    # an unpacked case directory
    archive: Path | None = None                 # or the zip that holds it
    prefix: str = ""                            # and the member prefix of the case inside that zip
    tags: dict[str, Any] = field(default_factory=dict)


# ------------------------------------------------------------------ reading --
class _Zips:
    """Open zip files and their member lists, kept for the length of one run."""

    def __init__(self) -> None:
        self._open: dict[Path, zipfile.ZipFile] = {}
        self._members: dict[Path, dict[str, list[zipfile.ZipInfo]]] = {}

    def cases(self, archive: Path) -> dict[str, list[zipfile.ZipInfo]]:
        """Members grouped by case directory: `<anything>/case_NNNNN/` -> its files."""
        if archive not in self._members:
            zf = self._open[archive] = zipfile.ZipFile(archive)
            groups: dict[str, list[zipfile.ZipInfo]] = {}
            for info in zf.infolist():
                if info.is_dir():
                    continue
                parts = PurePosixPath(info.filename).parts
                at = next((i for i, part in enumerate(parts[:-1]) if part.startswith("case_")), None)
                if at is not None:
                    groups.setdefault("/".join(parts[: at + 1]) + "/", []).append(info)
            self._members[archive] = groups
        return self._members[archive]

    def tree(self, archive: Path, prefix: str, options: ScanOptions) -> ArtifactTree:
        tree = ArtifactTree()
        members = self.cases(archive).get(prefix, [])       # opens the archive on first use
        zf = self._open[archive]
        for info in sorted(members, key=lambda i: i.filename):
            rel = info.filename[len(prefix):]
            if not rel or rel.startswith("/") or ".." in PurePosixPath(rel).parts:
                tree.limit_events.append(LimitEvent(kind="path_escape", path=info.filename))
                continue
            if info.file_size > options.limits.max_file_bytes:      # checked before reading: the size is declared in the index
                tree.limit_events.append(LimitEvent(kind="too_large", path=rel, detail=f"{info.file_size} bytes"))
                continue
            if info.flag_bits & 0x1:
                tree.limit_events.append(LimitEvent(kind="encrypted", path=rel))
                continue
            with zf.open(info) as fh:
                data = fh.read(options.limits.max_file_bytes + 1)
            tree.add(rel, data, options.limits)
        return tree

    def close(self) -> None:
        for zf in self._open.values():
            zf.close()


def _evenly(cases: list[Case], limit: int | None) -> list[Case]:
    """At most `limit` cases, keeping the label mix: evenly spaced within each label."""
    if not limit or limit >= len(cases):
        return cases
    by_label: dict[str, list[Case]] = {}
    for c in cases:
        by_label.setdefault(c.label, []).append(c)
    out: list[Case] = []
    for label in sorted(by_label):
        group = by_label[label]
        want = max(1, round(limit * len(group) / len(cases)))
        step = len(group) / want
        out += [group[int(i * step)] for i in range(min(want, len(group)))]
    return sorted(out, key=lambda c: c.id)[:limit]


def _scan_case(case: Case, zips: _Zips, pack: RulePack, profile: str, runtime: Any, model: dict[str, Any]) -> Report:
    options = ScanOptions(profile=profile)
    tree = load_path(case.path, options.limits) if case.path is not None else zips.tree(case.archive, case.prefix, options)  # type: ignore[arg-type]
    if profile != "quick":
        from ..judge.stage import ModelBudget, run_model_stage

        notes: list[str] = []
        used = run_model_stage(tree, options, pack, mode="auto", budget=ModelBudget.from_config(None), env=dict(os.environ), notes=notes)
        model["calls"] += int((used or {}).get("calls", 0))
        model["cost_usd"] += float((used or {}).get("cost_usd", 0.0))
        if any(n.startswith("model analysis not run") for n in notes):
            model["unavailable"] = notes[-1]
    if profile == "deep":
        from ..sandbox import detonate_into

        detonate_into(tree, options, runtime=runtime, timeout=120, pack=pack)
    return scan(tree, options, pack)


def _run(cases: list[Case], pack: RulePack, profile: str, runtime: Any) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    from ..runner import PROFILES, UsageError

    if profile not in PROFILES:
        raise UsageError(f"--profile: {profile!r} is not one of {', '.join(PROFILES)}")
    if profile == "deep":
        from ..sandbox import SandboxUnavailable
        from ..sandbox.runtime import default_runtime

        try:
            runtime = runtime or default_runtime()
        except SandboxUnavailable as exc:
            raise UsageError(f"the deep profile detonates every case in the sandbox and will not run without it: {exc}") from exc
    zips, rows, model = _Zips(), [], {"calls": 0, "cost_usd": 0.0}
    try:
        for case in cases:
            row: dict[str, Any] = {"id": case.id, "label": case.label, **case.tags}
            try:
                report = _scan_case(case, zips, pack, profile, runtime, model)
            except Exception as exc:  # noqa: BLE001 - one unreadable case must not end a run of thousands
                row.update(verdict=None, error=f"{type(exc).__name__}: {exc}"[:200])
            else:
                row.update(verdict=report.verdict.value, score=report.score,
                           rules=sorted({f.key for f in report.findings if "coverage" not in f.tags}))
            rows.append(row)
    finally:
        zips.close()
    return rows, model


def _by(rows: list[dict[str, Any]], key: str, caught: Any) -> dict[str, dict[str, Any]]:
    """Per value of `key` (a string or a list of strings on each row): cases, and the share `caught` holds for."""
    groups: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        values = r.get(key)
        for v in (values if isinstance(values, list) else [values]):
            if v:
                groups.setdefault(str(v), []).append(r)
    return {k: {"cases": len(g), "caught": ratio(sum(1 for r in g if caught(r)), len(g)),
                "blocked": ratio(sum(1 for r in g if r["verdict"] == "BLOCK"), len(g))}
            for k, g in sorted(groups.items(), key=lambda kv: (len(kv[0]), kv[0]))}


def _target(actual: float | None, target: float, *, at_most: bool = False) -> dict[str, Any]:
    met = actual is not None and (actual <= target if at_most else actual >= target)
    return {"target": round(target, 4), "actual": actual, "met": bool(met), "direction": "at most" if at_most else "at least"}


def _common(suite: str, data: Path, profile: str, pack: RulePack, rows: list[dict[str, Any]], model: dict[str, Any],
            total: int) -> tuple[dict[str, Any], list[dict[str, Any]], list[str]]:
    scored = [r for r in rows if r["verdict"] is not None]
    errors = [r for r in rows if r["verdict"] is None]
    result = {"suite": suite, "schema": f"agentguard-bench-{suite}/1", "profile": profile,
              "rule_pack": {"version": pack.version, "digest": pack.digest}, "data": str(data),
              "cases_available": total, "cases": len(rows), "scored": len(scored), "coverage": ratio(len(scored), len(rows)),
              "errors": [{"id": r["id"], "error": r["error"]} for r in errors[:50]], "model": model, "items": rows}
    lines = []
    if len(rows) < total:
        lines.append(f"A sample of {len(rows)} of {total} cases was scanned (--limit); the figures are for the sample, not the benchmark.")
    if profile == "quick":
        lines.append("Profile quick: deterministic static analysis only; no model and no sandbox.")
    elif model.get("unavailable"):
        lines.append(f"Profile {profile}: {model['unavailable']}; the figures are for static analysis alone.")
    else:
        lines.append(f"Profile {profile}: model stage used ({model['calls']} call(s), ${model['cost_usd']:.2f}).")
    if errors:
        lines.append(f"{len(errors)} case(s) could not be scanned and are not in the figures: " + ", ".join(r["id"] for r in errors[:5]))
    return result, scored, lines


# ----------------------------------------------------------- MalSkillBench --
def _malskill_cases(data: Path) -> list[Case]:
    from ..runner import UsageError

    root = next((d for d in (data, data / "Skills", data / "Dataset" / "Skills") if (d / "malware").is_dir() and (d / "benign").is_dir()), None)
    if root is None:
        raise UsageError(f"{data} is not a MalSkillBench copy: expected Dataset/Skills/malware and Dataset/Skills/benign "
                         "(clone github.com/lxyeternal/MalSkillBench yourself; it is never downloaded for you)")
    cases = []
    for label, sub in (("malicious", "malware"), ("benign", "benign")):
        for entry in sorted(os.scandir(root / sub), key=lambda e: e.name):
            if not entry.is_dir(follow_symlinks=False):
                continue
            m = _SAMPLE_NAME.match(entry.name) if label == "malicious" else None
            tags = {"vector": m["vector"], "behaviour": m["behaviour"], "origin": "generated"} if m else \
                   ({"origin": "wild or tool test"} if label == "malicious" else {})
            cases.append(Case(id=f"{sub}/{entry.name}", label=label, path=Path(entry.path), tags=tags))
    return cases


def run_malskillbench(*, data: Path | None = None, profile: str = "quick", limit: int | None = None, pack: RulePack | None = None,
                      runtime: Any = None, **_: Any) -> dict[str, Any]:
    from ..runner import UsageError

    if data is None:
        raise UsageError("bench malskillbench needs --data <your local copy>; the benchmark is not shipped or downloaded")
    pack = pack or RulePack.default()
    available = _malskill_cases(data)
    rows, model = _run(_evenly(available, limit), pack, profile, runtime)
    result, scored, lines = _common("malskillbench", data, profile, pack, rows, model, len(available))
    v = verdict_metrics(scored)
    bad = [r for r in scored if r["label"] == "malicious"]
    want = MALSKILL_TARGETS[profile]
    targets = {"recall": _target(v["malicious_recall"], want["recall"]),
               "false_positive_rate": _target(v["benign_flagged"], want["false_positive_rate"], at_most=True)}
    caught = lambda r: r["verdict"] != "ALLOW"  # noqa: E731
    result.update({"verdicts": v, "targets": targets, "by_vector": _by(bad, "vector", caught), "by_behaviour": _by(bad, "behaviour", caught),
                   "by_origin": _by(bad, "origin", caught)})
    lines.insert(0, f"MalSkillBench: {len(bad)} malicious and {len(scored) - len(bad)} benign skill(s) scored.")
    lines.append(f"recall (malicious not allowed) {v['malicious_recall']} · blocked outright {v['malicious_blocked']} · "
                 f"benign flagged {v['false_positives']} ({v['benign_flagged']})")
    for name, t in targets.items():
        lines.append(f"{name}: {t['actual']} (target {t['direction']} {t['target']}): {'met' if t['met'] else 'NOT met'}")
    result["lines"] = lines
    result["table"] = {"title": "Malicious skills by behaviour and by vector (caught = REVIEW or BLOCK)",
                       "columns": ["Group", "Cases", "Caught", "Blocked"],
                       "rows": [[k, g["cases"], g["caught"], g["blocked"]]
                                for part in ("by_vector", "by_behaviour", "by_origin") for k, g in result[part].items()]}
    result["ok"] = bool(scored) and not result["errors"] and all(t["met"] for t in targets.values())
    return result


# --------------------------------------------------------- SkillTrustBench --
def _records(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".jsonl":
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    doc = json.loads(text)
    return list(doc.get("test_cases", [])) if isinstance(doc, dict) else list(doc)


def _trust_sources(data: Path) -> dict[str, tuple[Path, Path | None, Path | None]]:
    """split -> (ground truth, directory holding the case directories, zip holding them)."""
    def first(*paths: Path) -> Path | None:
        return next((p for p in paths if p.exists()), None)

    out: dict[str, tuple[Path, Path | None, Path | None]] = {}
    sub = data / "subsets" / "skilltrustbench_556_v1_1"
    truth = first(sub / "ground_truth.json", sub / "ground_truth.jsonl", data / "data" / "evaluation_subset_556_v1_1.jsonl")
    if truth is not None:
        out["subset"] = (truth, first(sub / "cases", data / "skilltrustbench_556_v1_1" / "cases"), first(data / "skilltrustbench_556_v1_1.zip"))
    full = data / "benchmark_full_v1.0"
    truth = first(full / "ground_truth.json", data / "data" / "test_cases.jsonl")
    if truth is not None:
        out["full"] = (truth, full if any(full.glob("case_*")) else None, first(data / "benchmark_full_v1.0.zip"))
    # `--data` is itself an unpacked tree: the full benchmark (case_*/ beside the index) or the subset (cases/).
    truth = first(data / "ground_truth.json", data / "ground_truth.jsonl")
    if truth is not None and not out:
        if (data / "cases").is_dir():
            out["subset"] = (truth, data / "cases", None)
        elif any(data.glob("case_*")):
            out["full"] = (truth, data, None)
    return out


def _trust_cases(data: Path, split: str) -> tuple[list[Case], str]:
    from ..runner import UsageError

    sources = _trust_sources(data)
    if not sources:
        raise UsageError(f"{data} is not a SkillTrustBench copy: expected ground_truth.json with its case directories, or the dataset "
                         "repository (download huggingface.co/datasets/cuhk-zhuque/SkillTrustBench yourself; it is never downloaded for you)")
    wanted = {"all": None, "subset": "subset", "556": "subset", "full": "full"}.get(split, "?")
    if wanted == "?":
        raise UsageError("--split for skilltrustbench is subset (the fixed 556 cases) or full")
    chosen = wanted or ("subset" if "subset" in sources else "full")
    if chosen not in sources:
        raise UsageError(f"the {chosen} split is not in {data} (found: {', '.join(sorted(sources))})")
    truth, directory, archive = sources[chosen]
    zips = _Zips()
    try:
        packed = zips.cases(archive) if archive is not None else {}
    finally:
        zips.close()
    by_id = {PurePosixPath(prefix.rstrip("/")).name: prefix for prefix in packed}
    cases, missing = [], 0
    for rec in sorted(_records(truth), key=lambda r: str(r.get("id", ""))):
        cid, label = str(rec.get("id", "")), str(rec.get("judgment", "")).lower()
        if not cid or label not in _JUDGMENTS:
            continue
        tags = {"risk_labels": [str(x) for x in rec.get("risk_labels") or []], "source": rec.get("source") or "",
                "category": rec.get("base_category") or ""}
        if directory is not None and (directory / cid).is_dir():
            cases.append(Case(id=cid, label=label, path=directory / cid, tags=tags))
        elif cid in by_id:
            cases.append(Case(id=cid, label=label, archive=archive, prefix=by_id[cid], tags=tags))
        else:
            missing += 1
    if not cases:
        raise UsageError(f"{truth} lists cases but none of their directories were found (unpack the archive next to it, or keep the zip there)")
    return cases, f"{chosen} split, {truth.name}" + (f", {missing} listed case(s) without files" if missing else "")


def _three_class(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """The publisher's metrics (tools/scanner_benchmark/evaluate_predictions.py), from verdicts mapped to labels."""
    pred = [(_LABEL_OF[r["verdict"]], r["label"]) for r in rows]
    confusion = {t: {p: sum(1 for pp, tt in pred if tt == t and pp == p) for p in _JUDGMENTS} for t in _JUDGMENTS}
    per_label: dict[str, Any] = {}
    f1s = []
    for label in _JUDGMENTS:
        tp = confusion[label][label]
        support = sum(confusion[label].values())
        predicted = sum(confusion[t][label] for t in _JUDGMENTS)
        p, rc = (tp / predicted if predicted else 0.0), (tp / support if support else 0.0)
        f1 = 2 * p * rc / (p + rc) if p + rc else 0.0
        per_label[label] = {"precision": round(p, 4), "recall": round(rc, 4), "f1": round(f1, 4), "support": support}
        if support:
            f1s.append(f1)
    bad = sum(confusion["malicious"].values())
    non_normal = [r for r in rows if r["label"] != "normal"]
    normal = [r for r in rows if r["label"] == "normal"]
    return {"accuracy": ratio(sum(1 for p, t in pred if p == t), len(pred)),
            "macro_f1": round(sum(f1s) / len(f1s), 4) if f1s else None,
            "malicious_recall": ratio(confusion["malicious"]["malicious"], bad),
            "malicious_false_negative_rate": ratio(bad - confusion["malicious"]["malicious"], bad),
            "malicious_not_allowed": ratio(bad - confusion["malicious"]["normal"], bad),
            "non_normal_recall": ratio(sum(1 for r in non_normal if r["verdict"] != "ALLOW"), len(non_normal)),
            "normal_flagged": ratio(sum(1 for r in normal if r["verdict"] != "ALLOW"), len(normal)),
            "per_label": per_label, "confusion": confusion}


def run_skilltrustbench(*, data: Path | None = None, profile: str = "quick", limit: int | None = None, split: str = "all",
                        pack: RulePack | None = None, runtime: Any = None, **_: Any) -> dict[str, Any]:
    from ..runner import UsageError

    if data is None:
        raise UsageError("bench skilltrustbench needs --data <your local copy>; the benchmark is not shipped or downloaded")
    pack = pack or RulePack.default()
    available, which = _trust_cases(data, split)
    rows, model = _run(_evenly(available, limit), pack, profile, runtime)
    result, scored, lines = _common("skilltrustbench", data, profile, pack, rows, model, len(available))
    m = _three_class(scored)
    targets = {"malicious_not_allowed": _target(m["malicious_not_allowed"], TRUST_TARGETS["malicious_not_allowed"]),
               "normal_flagged": _target(m["normal_flagged"], TRUST_TARGETS["normal_flagged"], at_most=True),
               "macro_f1": _target(m["macro_f1"], TRUST_TARGETS["macro_f1"])}
    risky = [r for r in scored if r["label"] != "normal"]
    result.update({"split": which, "three_class": m, "targets": targets,
                   "by_risk_label": _by(risky, "risk_labels", lambda r: r["verdict"] != "ALLOW"),
                   "by_source": _by(scored, "source", lambda r: _LABEL_OF[r["verdict"]] == r["label"])})
    counts = {label: m["per_label"][label]["support"] for label in _JUDGMENTS}
    lines.insert(0, f"SkillTrustBench ({which}): {counts['malicious']} malicious, {counts['suspicious']} suspicious and "
                    f"{counts['normal']} normal skill(s) scored. ALLOW = normal, REVIEW = suspicious, BLOCK = malicious.")
    lines.append(f"accuracy {m['accuracy']} · macro-F1 {m['macro_f1']} · malicious recall (BLOCK) {m['malicious_recall']} · "
                 f"malicious not allowed {m['malicious_not_allowed']} · non-normal recall {m['non_normal_recall']} · "
                 f"normal flagged {m['normal_flagged']}")
    for name, t in targets.items():
        lines.append(f"{name}: {t['actual']} (target {t['direction']} {t['target']}): {'met' if t['met'] else 'NOT met'}")
    result["lines"] = lines
    result["table"] = {"title": "Confusion (rows: ground truth, columns: verdict) and non-normal cases by risk label",
                       "columns": ["Row", "ALLOW / cases", "REVIEW / caught", "BLOCK / blocked"],
                       "rows": [[t, *(m["confusion"][t][p] for p in _JUDGMENTS)] for t in _JUDGMENTS]
                               + [[k, g["cases"], g["caught"], g["blocked"]] for k, g in result["by_risk_label"].items()]}
    result["ok"] = bool(scored) and not result["errors"] and all(t["met"] for t in targets.values())
    return result


__all__ = ["MALSKILL_TARGETS", "TRUST_TARGETS", "run_malskillbench", "run_skilltrustbench"]
