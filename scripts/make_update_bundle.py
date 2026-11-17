"""Build a signed update bundle for `agentguard update --from <file>` (spec/interfaces.md §15).

    python scripts/make_update_bundle.py --serial 7 --key-id release-2026 --secret-file release.key \
        --out agentguard-update-7.agbundle [--feed feed.json] [--no-rules] [--expires 2027-11-01]

The secret is the 32-byte Ed25519 seed of the release key, read from a file (raw bytes or base64) and
never taken from the command line. The matching public key must be in `intel/keys/` of the Agent Guard
that will install the bundle, or in the user's `<config dir>/keys/`.

`--new-key <id>` makes a key pair instead: it writes `<id>.key` (keep it offline) and `<id>.pub.json`.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from agentguard.core.intel import ed25519  # noqa: E402
from agentguard.core.intel.feed import sign_feed  # noqa: E402
from agentguard.update import build_bundle, read_bundle  # noqa: E402


def read_secret(path: Path) -> bytes:
    raw = path.read_bytes().strip()
    if len(raw) != 32:
        raw = base64.b64decode(raw)
    if len(raw) != 32:
        raise SystemExit("the secret file must hold a 32-byte Ed25519 seed (raw or base64)")
    return raw


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--new-key", metavar="ID", help="make a key pair named ID in the current directory and exit")
    ap.add_argument("--serial", type=int)
    ap.add_argument("--key-id")
    ap.add_argument("--secret-file", type=Path)
    ap.add_argument("--out", type=Path)
    ap.add_argument("--rules", type=Path, default=ROOT / "rules")
    ap.add_argument("--mappings", type=Path, default=ROOT / "mappings")
    ap.add_argument("--no-rules", action="store_true", help="an intelligence-only bundle")
    ap.add_argument("--feed", type=Path, help="feed.json to include (signed here with the same key)")
    ap.add_argument("--issued", type=dt.date.fromisoformat, default=dt.date.today())
    ap.add_argument("--expires", type=dt.date.fromisoformat)
    ap.add_argument("--min-engine")
    args = ap.parse_args()

    if args.new_key:
        secret = os.urandom(32)
        key, pub = Path(f"{args.new_key}.key"), Path(f"{args.new_key}.pub.json")
        if key.exists() or pub.exists():
            raise SystemExit(f"{key} or {pub} already exists")
        key.write_bytes(base64.b64encode(secret) + b"\n")
        pub.write_text(json.dumps({"key_id": args.new_key, "public": base64.b64encode(ed25519.public_key(secret)).decode()}, indent=2) + "\n",
                       encoding="utf-8")
        print(f"wrote {key} (keep it offline) and {pub}")
        return
    if not (args.serial and args.key_id and args.secret_file and args.out):
        ap.error("--serial, --key-id, --secret-file and --out are required")
    secret = read_secret(args.secret_file)
    feed = feed_sig = None
    if args.feed:
        feed = args.feed.read_bytes()
        feed_sig = sign_feed(feed, secret, args.key_id)
    data = build_bundle(serial=args.serial, issued=args.issued, secret=secret, key_id=args.key_id,
                        rules_dir=None if args.no_rules else args.rules, mappings_dir=None if args.no_rules else args.mappings,
                        feed=feed, feed_sig=feed_sig, expires=args.expires, min_engine=args.min_engine)
    bundle = read_bundle(data, keys={args.key_id: ed25519.public_key(secret)}, today=args.issued)   # it must verify before it is written
    args.out.write_bytes(data)
    print(f"wrote {args.out}: serial {bundle.serial}, {len(bundle.files)} files, signed by {args.key_id}")


if __name__ == "__main__":
    main()
