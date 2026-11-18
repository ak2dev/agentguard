"""Write the rule fixtures defined in scripts/fixtures_catalog/ to fixtures/rules/.

    python scripts/bootstrap_fixtures_catalog.py            # write every case
    python scripts/bootstrap_fixtures_catalog.py --check    # fail if a file on disk differs
    python scripts/bootstrap_fixtures_catalog.py AG-INJ     # only keys with this prefix

A case directory this script owns is rewritten in full (stale files are
removed); case directories it does not define are left alone.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))

from fixtures_catalog import Case, load_all  # noqa: E402

FIXTURES = ROOT / "fixtures" / "rules"


def case_dir(key: str, case: Case) -> Path:
    rule_id, _, variant = key.partition("/")
    base = FIXTURES / rule_id / "variants" / variant if variant else FIXTURES / rule_id
    return base / case.side / case.name


def render(case: Case) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for rel, content in case.files.items():
        out[rel] = content if isinstance(content, bytes) else content.encode("utf-8")
    if case.config:
        out["_case.yaml"] = (json.dumps(case.config, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    return out


def main(argv: list[str]) -> int:
    check = "--check" in argv
    prefixes = [a for a in argv if not a.startswith("-")]
    registry = load_all()
    from agentguard.core.rules.pack import RulePack

    pack = RulePack.default()
    unknown = sorted(k for k in registry if k not in pack.detectors)
    if unknown:
        print("fixtures defined for keys with no detector: " + ", ".join(unknown))
        return 1
    stale = written = 0
    for key in sorted(registry):
        if prefixes and not any(key.startswith(p) for p in prefixes):
            continue
        for case in registry[key]:
            d = case_dir(key, case)
            files = render(case)
            current = {p.relative_to(d).as_posix(): p.read_bytes() for p in d.rglob("*") if p.is_file()} if d.is_dir() else {}
            if current == files:
                continue
            stale += 1
            if check:
                print(f"stale: {d.relative_to(ROOT).as_posix()}")
                continue
            if d.is_dir():
                shutil.rmtree(d)       # a case this script defines is rewritten in full
            for rel, data in files.items():
                p = d / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(data)
            written += 1
    n_cases = sum(len(v) for v in registry.values())
    if check:
        print(f"{n_cases} cases for {len(registry)} detectors checked; {stale} stale")
        return 1 if stale else 0
    print(f"{n_cases} cases for {len(registry)} detectors; {written} written")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
