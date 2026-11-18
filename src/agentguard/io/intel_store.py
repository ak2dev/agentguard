"""Host-side IOC feed store with rollback protection.

The active feed lives in the user data directory. ``intel update`` only
accepts a feed that verifies against a bundled trusted key *and* has a
version greater than or equal to the last accepted one; otherwise the bundled
sample feed is used. Nothing here touches the network unless the caller
passes a URL and has opted in.
"""

from __future__ import annotations

import datetime as dt
import os
import sys
from pathlib import Path

from ..core.intel.feed import FeedError, IntelFeed, load_trusted_keys, verify_feed
from ..core.rules.pack import bundled_dirs


def data_home() -> Path:
    override = os.environ.get("AGENTGUARD_HOME")
    if override:
        return Path(override)
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
        return base / "agentguard"
    base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return base / "agentguard"


def bundled_intel_dir() -> Path:
    rules_dir, _ = bundled_dirs()
    return rules_dir.parent / "intel"


def user_keys_dir() -> Path:
    """Where the user may add release keys of their own (an organisation's mirror, for example). It is in
    the user's configuration directory, never in a scanned target."""
    override = os.environ.get("AGENTGUARD_CONFIG_HOME")
    if override:
        return Path(override) / "keys"
    if sys.platform == "win32":
        return Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming") / "agentguard" / "keys"
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "agentguard" / "keys"


def trusted_keys(strict: bool = False) -> dict[str, bytes]:
    """Keys a feed or an update bundle may be signed with: the ones shipped with Agent Guard, then the
    user's own. A user key never replaces a shipped key of the same name. A malformed user key file is
    ignored unless `strict`."""
    kdir = bundled_intel_dir() / "keys"
    files = {p.name: p.read_bytes() for p in sorted(kdir.glob("*.pub.json"), key=lambda p: p.name)} if kdir.is_dir() else {}
    keys = load_trusted_keys(files)
    udir = user_keys_dir()
    if udir.is_dir():
        for p in sorted(udir.glob("*.pub.json"), key=lambda p: p.name):
            try:
                extra = load_trusted_keys({p.name: p.read_bytes()})
            except (FeedError, OSError):
                if strict:
                    raise FeedError(f"{p} is not a valid public key file") from None
                continue
            for key_id, pub in extra.items():
                keys.setdefault(key_id, pub)
    return keys


def _state_file() -> Path:
    return data_home() / "intel" / "accepted_version"


def load_active_feed(today: dt.date | None = None) -> tuple[IntelFeed | None, str]:
    """Return (feed, note). Prefers the user's updated feed, else the bundled sample."""
    keys = trusted_keys()
    user = data_home() / "intel"
    for base, label in ((user, "installed"), (bundled_intel_dir(), "bundled")):
        feed_p, sig_p = base / "feed.json", base / "feed.json.sig"
        if not feed_p.is_file():
            feed_p, sig_p = base / "sample-feed.json", base / "sample-feed.json.sig"
        if feed_p.is_file() and sig_p.is_file():
            try:
                feed = verify_feed(feed_p.read_bytes(), sig_p.read_bytes(), keys, today=today)
                return feed, f"{label} {feed.describe()}"
            except FeedError as exc:
                if label == "installed":
                    continue
                return None, f"bundled feed rejected: {exc}"
    return None, "no intel feed available"


def install_feed(feed_bytes: bytes, sig_bytes: bytes, today: dt.date | None = None) -> IntelFeed:
    feed = verify_feed(feed_bytes, sig_bytes, trusted_keys(), today=today or dt.date.today())
    state = _state_file()
    last = int(state.read_text(encoding="utf-8").strip()) if state.is_file() else 0
    if feed.version < last:
        raise FeedError(f"refusing feed v{feed.version}: older than accepted v{last} (rollback protection)")
    target = data_home() / "intel"
    target.mkdir(parents=True, exist_ok=True)
    (target / "feed.json").write_bytes(feed_bytes)
    (target / "feed.json.sig").write_bytes(sig_bytes)
    state.write_text(str(feed.version), encoding="utf-8")
    return feed
