"""Train the triage model (engine K) on the internal corpus and write rules/data/triage-model.json.

    python scripts/train_triage.py [--corpus bench] [--version 2026.11.17] [--check]

Fits on the corpus's dev split and records held-out figures in the model file (see agentguard/bench/triage.py).
``--check`` retrains and fails when the result differs from the committed file, so a rule change that moves the
features cannot leave a stale model behind unnoticed.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from agentguard.bench.triage import collect, model_document, train  # noqa: E402
from agentguard.core.rules.pack import RulePack  # noqa: E402

OUT = ROOT / "rules" / "data" / "triage-model.json"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--corpus", type=Path, default=ROOT / "bench")
    ap.add_argument("--version", default=None, help="Model version recorded in the file (default: the one there now).")
    ap.add_argument("--rounds", type=int, default=60)
    ap.add_argument("--check", action="store_true", help="Fail if retraining changes the committed model.")
    args = ap.parse_args()

    current = json.loads(OUT.read_text(encoding="utf-8")) if OUT.is_file() else {}
    version = args.version or current.get("version") or "1"
    # Features come from the deterministic engines only, so the model in the pack does not change them.
    pack = RulePack.default()
    done = [0]

    def progress(item, n):  # noqa: ANN001
        done[0] += 1
        if done[0] % 25 == 0:
            print(f"  {done[0]} items scanned", file=sys.stderr)

    rows, skipped = collect(args.corpus, pack, on_item=progress)
    model = train(rows, version=version, rounds=args.rounds)
    doc = model_document(model, skipped)
    text = json.dumps(doc, indent=1, sort_keys=False) + "\n"
    if args.check:
        if not OUT.is_file() or OUT.read_text(encoding="utf-8") != text:
            print("triage model is stale: run python scripts/train_triage.py", file=sys.stderr)
            return 1
        print("triage model is current")
        return 0
    OUT.write_text(text, encoding="utf-8", newline="\n")
    held = doc["heldout"]
    print(f"wrote {OUT.relative_to(ROOT)}: {len(model.trees)} trees over {len(model.features)} features")
    print(f"dev: {doc['trained']['components']} components ({doc['trained']['positives']} positive) from "
          f"{doc['trained']['items']} items; out-of-fold AUC {doc['trained']['out_of_fold']['auc']}")
    print(f"heldout: {held.get('components')} components, AUC {held.get('auc')}, Brier {held.get('brier')}, "
          f"at {model.agrees}: {held.get('at_agrees')}")
    if skipped:
        print(f"{len(skipped)} malicious item(s) with a label note: {', '.join(sorted(skipped))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
