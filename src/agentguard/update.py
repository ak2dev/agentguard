"""`agentguard update`: signed rule-pack and intelligence updates (spec/interfaces.md §15).

The engine, the rule pack and the intelligence feed are versioned separately. An **update bundle** is one
file that carries a rule pack, an indicator feed, or both::

    manifest.json    what the bundle holds: serial, dates, versions, and the SHA-256 of every file
    manifest.sig     detached Ed25519 signature over the exact bytes of manifest.json
    rules/…          the rule pack (pack.yaml, the catalogue, detection entries, data lists, YARA sources)
    mappings/…       the standards catalogues and the crosswalk
    intel/feed.json, intel/feed.json.sig     the indicator feed, signed in its own right

Nothing in a bundle is used until:

1. the signature over the manifest verifies against a **trusted release key** (the keys shipped with
   Agent Guard, plus any the user placed in their own configuration directory);
2. every file is listed in the manifest and matches its hash, and the bundle holds nothing else;
3. the bundle is not older than the one already installed (rollback protection) and has not expired;
4. the rule pack loads with the hardened loader and this engine is new enough for it.

`agentguard update --from <file>` does the same from a local file, for machines with no network.
An installed rule pack is verified again every time it is loaded; if it no longer verifies, the bundled
pack is used and the run says so. Hosting a public feed is a publishing task and is not part of this build.

The signature scheme is Ed25519 with pinned keys, verified in pure Python so it works offline and needs
no extra dependency. It is not Sigstore: there is no transparency log and no identity binding beyond
holding the release key.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import io
import json
import os
import re
import shutil
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .core.engine import ENGINE_VERSION
from .core.intel import ed25519
from .core.intel.feed import FeedError, IntelFeed, verify_feed
from .core.rules import pack as pack_mod
from .core.rules.pack import RulePackError, strict_pack_check
from .core.tree import UnsafePath, normalize_member_path
from .io.intel_store import data_home, install_feed, trusted_keys, user_keys_dir

FORMAT = "agentguard-update/1"
MAX_BUNDLE = 64 * 1024 * 1024
MAX_MEMBERS = 2000
MAX_MEMBER = 16 * 1024 * 1024
MAX_TOTAL = 128 * 1024 * 1024
_PREFIXES = ("rules/", "mappings/", "intel/")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_ZIP_TIME = (2020, 1, 1, 0, 0, 0)


class UpdateError(ValueError):
    """The update was refused. Nothing was installed."""


@dataclass
class Bundle:
    manifest: dict[str, Any]
    manifest_bytes: bytes
    sig_bytes: bytes
    files: dict[str, bytes]
    key_id: str

    @property
    def serial(self) -> int:
        return int(self.manifest["serial"])

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.manifest_bytes).hexdigest()

    def part(self, prefix: str) -> dict[str, bytes]:
        return {k: v for k, v in self.files.items() if k.startswith(prefix)}


@dataclass
class UpdateResult:
    lines: list[str] = field(default_factory=list)
    installed: bool = False
    serial: int | None = None
    rule_pack: str | None = None
    intel: int | None = None
    key_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"installed": self.installed, "serial": self.serial, "rule_pack": self.rule_pack, "intel": self.intel,
                "key_id": self.key_id, "lines": list(self.lines)}


# ------------------------------------------------------------------ keys --
def release_keys(strict: bool = False) -> dict[str, bytes]:
    """Keys an update may be signed with: the ones shipped with Agent Guard, and the ones the user added
    to `<config dir>/keys/*.pub.json` (an organisation's own mirror, for example). Never anything from a
    scanned target or from the bundle itself, and a user key never replaces a shipped key of the same name."""
    try:
        return trusted_keys(strict=strict)
    except FeedError as exc:
        raise UpdateError(str(exc)) from exc


# ---------------------------------------------------------------- bundle --
def _version_tuple(text: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", text.split("+")[0].split(".dev")[0])[:4])


def build_bundle(*, serial: int, issued: dt.date, secret: bytes, key_id: str, rules_dir: Path | None = None,
                 mappings_dir: Path | None = None, feed: bytes | None = None, feed_sig: bytes | None = None,
                 expires: dt.date | None = None, min_engine: str | None = None) -> bytes:
    """Make a signed bundle (for maintainers and for tests). Byte-for-byte reproducible for the same input."""
    files: dict[str, bytes] = {}
    for base, prefix in ((rules_dir, "rules"), (mappings_dir, "mappings")):
        if base is None:
            continue
        for p in sorted(Path(base).rglob("*")):
            if p.is_file() and not p.name.startswith("."):
                files[f"{prefix}/{p.relative_to(base).as_posix()}"] = p.read_bytes()
    if (rules_dir is None) != (mappings_dir is None):
        raise UpdateError("a rule pack needs both its rules and its mappings directory")
    if feed is not None:
        if feed_sig is None:
            raise UpdateError("an indicator feed needs its signature file")
        files["intel/feed.json"], files["intel/feed.json.sig"] = feed, feed_sig
    if not files:
        raise UpdateError("a bundle needs a rule pack, an indicator feed, or both")
    rule_pack = None
    if rules_dir is not None:
        meta = re.search(r'(?m)^version:\s*["\']?([^"\'\s#]+)', files.get("rules/pack.yaml", b"").decode("utf-8", "replace"))
        rule_pack = {"version": meta.group(1) if meta else "0"}
    intel = {"version": int(json.loads(feed)["version"])} if feed is not None else None
    manifest = {"format": FORMAT, "serial": int(serial), "issued": issued.isoformat(), "expires": expires.isoformat() if expires else None,
                "key_id": key_id, "min_engine": min_engine, "rule_pack": rule_pack, "intel": intel,
                "files": {name: hashlib.sha256(data).hexdigest() for name, data in sorted(files.items())}}
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    sig = {"key_id": key_id, "alg": "ed25519", "sig": base64.b64encode(ed25519.sign(secret, manifest_bytes)).decode("ascii")}
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in [("manifest.json", manifest_bytes), ("manifest.sig", (json.dumps(sig, indent=2) + "\n").encode()),
                           *sorted(files.items())]:
            info = zipfile.ZipInfo(name, date_time=_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, data)
    return out.getvalue()


def _verify_manifest(manifest_bytes: bytes, sig_bytes: bytes, keys: dict[str, bytes]) -> str:
    try:
        sig_doc = json.loads(sig_bytes)
        key_id, alg, sig = str(sig_doc["key_id"]), sig_doc.get("alg", "ed25519"), base64.b64decode(sig_doc["sig"], validate=True)
    except (ValueError, KeyError, TypeError) as exc:
        raise UpdateError("the bundle's signature file is malformed") from exc
    if alg != "ed25519":
        raise UpdateError(f"the bundle is signed with an unsupported algorithm ({str(alg)[:20]!r})")
    pub = keys.get(key_id)
    if pub is None:
        raise UpdateError(f"the bundle is signed by '{key_id[:60]}', which is not a trusted release key")
    if not ed25519.verify(pub, manifest_bytes, sig):
        raise UpdateError("the bundle's signature does not verify: it was not made by the key it names, or it was changed afterwards")
    return key_id


def read_bundle(data: bytes, keys: dict[str, bytes] | None = None, today: dt.date | None = None) -> Bundle:
    """Verify a bundle and return its content. Raises UpdateError; nothing is written anywhere."""
    if len(data) > MAX_BUNDLE:
        raise UpdateError(f"the bundle is larger than {MAX_BUNDLE // (1024 * 1024)} MB")
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        infos = zf.infolist()
    except (zipfile.BadZipFile, OSError, ValueError) as exc:
        raise UpdateError("the file is not an update bundle (it is not a zip archive)") from exc
    if len(infos) > MAX_MEMBERS:
        raise UpdateError(f"the bundle holds more than {MAX_MEMBERS} files")
    members: dict[str, zipfile.ZipInfo] = {}
    total = 0
    for info in infos:
        if info.is_dir():
            continue
        try:
            name = normalize_member_path(info.filename)
        except UnsafePath as exc:
            raise UpdateError(f"the bundle holds a file with an unsafe path ({exc})") from exc
        if name in members:
            raise UpdateError(f"the bundle holds '{name[:80]}' twice")
        if info.file_size > MAX_MEMBER:
            raise UpdateError(f"'{name[:80]}' in the bundle is larger than {MAX_MEMBER // (1024 * 1024)} MB")
        total += info.file_size
        members[name] = info
    if total > MAX_TOTAL:
        raise UpdateError("the bundle unpacks to more than the size limit")

    def read(name: str) -> bytes:
        info = members[name]
        with zf.open(info) as fh:
            raw = fh.read(MAX_MEMBER + 1)
        if len(raw) != info.file_size or len(raw) > MAX_MEMBER:
            raise UpdateError(f"'{name[:80]}' in the bundle does not have the size its header states")
        return raw

    if "manifest.json" not in members or "manifest.sig" not in members:
        raise UpdateError("the file is not an update bundle (it has no signed manifest)")
    try:
        manifest_bytes, sig_bytes = read("manifest.json"), read("manifest.sig")
    except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
        raise UpdateError("the bundle's manifest could not be read") from exc
    # The signature is checked before anything in the manifest is believed.
    key_id = _verify_manifest(manifest_bytes, sig_bytes, release_keys(strict=True) if keys is None else keys)
    try:
        manifest = json.loads(manifest_bytes)
        files = manifest["files"]
        serial = manifest["serial"]
        issued = dt.date.fromisoformat(str(manifest["issued"]))
        expires = dt.date.fromisoformat(str(manifest["expires"])) if manifest.get("expires") else None
    except (ValueError, KeyError, TypeError) as exc:
        raise UpdateError("the bundle's manifest is malformed") from exc
    if manifest.get("format") != FORMAT:
        raise UpdateError(f"the bundle's format ({str(manifest.get('format'))[:40]!r}) is not one this engine reads")
    if not isinstance(serial, int) or isinstance(serial, bool) or serial < 1 or not isinstance(files, dict) or not files:
        raise UpdateError("the bundle's manifest is malformed")
    if manifest.get("key_id") and manifest["key_id"] != key_id:
        raise UpdateError("the manifest names a different key than the one that signed it")
    today = today or dt.date.today()
    if expires is not None and expires < today:
        raise UpdateError(f"the bundle expired on {expires}")
    if issued > today + dt.timedelta(days=2):
        raise UpdateError(f"the bundle is dated in the future ({issued})")
    listed = set(files)
    extra = sorted(set(members) - listed - {"manifest.json", "manifest.sig"})
    if extra:
        raise UpdateError(f"the bundle holds files its manifest does not list ({', '.join(extra[:3])[:160]})")
    out: dict[str, bytes] = {}
    for name in sorted(listed):
        digest = files[name]
        if not isinstance(name, str) or not name.startswith(_PREFIXES) or not isinstance(digest, str) or not _SHA.match(digest):
            raise UpdateError("the bundle's manifest lists a file outside rules/, mappings/ and intel/, or without a hash")
        try:
            if normalize_member_path(name) != name:
                raise UnsafePath("not normalised")
        except UnsafePath as exc:
            raise UpdateError("the bundle's manifest lists a file with an unsafe path") from exc
        if name not in members:
            raise UpdateError(f"the bundle is missing '{name[:80]}', which its manifest lists")
        try:
            raw = read(name)
        except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
            raise UpdateError(f"'{name[:80]}' in the bundle could not be read") from exc
        if hashlib.sha256(raw).hexdigest() != digest:
            raise UpdateError(f"'{name[:80]}' does not match the hash in the signed manifest")
        out[name] = raw
    need = manifest.get("min_engine")
    if need and _version_tuple(str(need)) > _version_tuple(ENGINE_VERSION):
        raise UpdateError(f"the bundle needs engine {need} or later; this is {ENGINE_VERSION}")
    return Bundle(manifest=manifest, manifest_bytes=manifest_bytes, sig_bytes=sig_bytes, files=out, key_id=key_id)


# ----------------------------------------------------------- installing --
def update_home() -> Path:
    return data_home() / "update"


def _accepted() -> tuple[int, str]:
    state = update_home() / "accepted.json"
    try:
        doc = json.loads(state.read_text(encoding="utf-8"))
        return int(doc.get("serial", 0)), str(doc.get("digest", ""))
    except (OSError, ValueError, TypeError):
        return 0, ""


def _write_tree(root: Path, files: dict[str, bytes]) -> None:
    for name, data in sorted(files.items()):
        dest = root / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)


def _check_pack(bundle: Bundle, staging: Path) -> pack_mod.RulePack:
    """The bundle's rule pack, loaded with the hardened loader from a staging directory."""
    _write_tree(staging, {**bundle.part("rules/"), **bundle.part("mappings/")})
    if not (staging / "rules" / "pack.yaml").is_file() or not (staging / "mappings").is_dir():
        raise UpdateError("the bundle's rule pack is incomplete (no rules/pack.yaml or no mappings/)")
    try:
        pack = strict_pack_check(staging / "rules", staging / "mappings")
    except RulePackError as exc:
        raise UpdateError("the bundle's rule pack does not load: " + " ".join(str(exc).split())[:300]) from exc
    if _version_tuple(pack.min_engine) > _version_tuple(ENGINE_VERSION):
        raise UpdateError(f"the bundle's rule pack needs engine {pack.min_engine} or later; this is {ENGINE_VERSION}")
    return pack


def _fetch(source: str, http: Any = None) -> bytes:
    if source.lower().startswith("https://"):
        from .net.safe_http import BlockedRequest, FetchError, SafeHttpClient

        client = http or SafeHttpClient(max_bytes=MAX_BUNDLE, timeout=30.0, deadline_s=300.0)
        try:
            resp = client.get(source)
        except (BlockedRequest, FetchError) as exc:
            raise UpdateError(f"the update could not be downloaded from {source[:120]}: {str(exc)[:160]}") from exc
        if resp.status != 200:
            raise UpdateError(f"the update source answered HTTP {resp.status}")
        return resp.body
    if re.match(r"^[a-z][a-z0-9+.-]*://", source, re.I):
        raise UpdateError("an update is fetched over https:// or read from a local file; other schemes are refused")
    path = Path(source)
    try:
        if path.stat().st_size > MAX_BUNDLE:
            raise UpdateError(f"the bundle is larger than {MAX_BUNDLE // (1024 * 1024)} MB")
        return path.read_bytes()
    except OSError as exc:
        raise UpdateError(f"the bundle {source} could not be read ({type(exc).__name__})") from exc


def run_update(source: str | None, check_only: bool = False, cwd: Path | None = None, *, http: Any = None,
               today: dt.date | None = None) -> UpdateResult:
    """Fetch, verify and (unless `check_only`) install an update bundle."""
    if not source:
        from .cli.config import ConfigError, load_user_config

        try:
            conf, _path = load_user_config(cwd or Path.cwd())
        except ConfigError as exc:
            raise UpdateError(str(exc)) from exc
        source = conf.intel.update_source if conf is not None else None
        if not source:
            raise UpdateError("no update source is configured. Pass --from <bundle file or https:// URL>, or set intel.update_source "
                              "in your configuration. (A public update feed is not hosted yet.)")
    if os.environ.get("AGENTGUARD_OFFLINE") == "1" and source.lower().startswith("https://"):
        raise UpdateError("offline mode forbids network use; pass --from <local bundle file>")
    today = today or dt.date.today()
    bundle = read_bundle(_fetch(source, http), today=today)
    res = UpdateResult(serial=bundle.serial, key_id=bundle.key_id)
    m = bundle.manifest
    res.lines.append(f"Bundle serial {bundle.serial}, issued {m['issued']}"
                     + (f", expires {m['expires']}" if m.get("expires") else "") + f", signed by '{bundle.key_id}': signature verified, "
                     f"{len(bundle.files)} file(s) match the signed manifest.")
    accepted, accepted_digest = _accepted()
    if bundle.serial < accepted:
        raise UpdateError(f"refusing bundle serial {bundle.serial}: serial {accepted} is already installed (rollback protection)")
    if bundle.serial == accepted and accepted_digest and bundle.digest != accepted_digest:
        raise UpdateError(f"refusing bundle serial {bundle.serial}: a different bundle with the same serial is already installed")

    home = update_home()
    staging = home / f"staging-{bundle.serial}-{os.getpid()}"
    has_pack = bool(bundle.part("rules/"))
    feed: IntelFeed | None = None
    try:
        if has_pack:
            if staging.exists():
                shutil.rmtree(staging)
            new_pack = _check_pack(bundle, staging)
            current = pack_mod.RulePack.default()
            res.rule_pack = new_pack.version
            res.lines.append(f"Rule pack {new_pack.version}: {len([r for r in new_pack.rules.values() if not r.extension])} rules, "
                             f"{len(new_pack.detectors)} detectors (in use now: {current.version}, {len(current.detectors)} detectors).")
        if "intel/feed.json" in bundle.files:
            if "intel/feed.json.sig" not in bundle.files:
                raise UpdateError("the bundle's indicator feed has no signature file")
            try:
                feed = verify_feed(bundle.files["intel/feed.json"], bundle.files["intel/feed.json.sig"], trusted_keys(), today=today)
            except FeedError as exc:
                raise UpdateError(f"the bundle's indicator feed was refused: {exc}") from exc
            e = feed.entries
            res.intel = feed.version
            res.lines.append(f"Indicator feed v{feed.version} ({feed.issued}): {len(e.hashes)} hashes, {len(e.domains)} domains, "
                             f"{len(e.ips)} addresses, {len(e.publishers)} publishers.")
        if not has_pack and feed is None:
            raise UpdateError("the bundle holds neither a rule pack nor an indicator feed")
        if check_only:
            res.lines.append("Nothing was installed (--check).")
            return res
        if bundle.serial == accepted and bundle.digest == accepted_digest:
            res.lines.append("This bundle is already installed; nothing changed.")
            return res
        if feed is not None:
            try:
                install_feed(bundle.files["intel/feed.json"], bundle.files["intel/feed.json.sig"], today=today)
            except FeedError as exc:
                raise UpdateError(f"the bundle's indicator feed was refused: {exc}") from exc
        if has_pack:
            dest = home / "packs" / str(bundle.serial)
            if dest.exists():
                shutil.rmtree(dest)
            dest.parent.mkdir(parents=True, exist_ok=True)
            (staging / "manifest.json").write_bytes(bundle.manifest_bytes)
            (staging / "manifest.sig").write_bytes(bundle.sig_bytes)
            staging.replace(dest)
            (home / "current").write_text(f"{bundle.serial}\n", encoding="utf-8")
            for old in sorted((home / "packs").iterdir()):
                if old.is_dir() and old.name != str(bundle.serial) and old.name.isdigit():
                    shutil.rmtree(old, ignore_errors=True)
        home.mkdir(parents=True, exist_ok=True)
        (home / "accepted.json").write_text(json.dumps({"serial": bundle.serial, "digest": bundle.digest, "key_id": bundle.key_id,
                                                         "installed": today.isoformat()}, indent=2) + "\n", encoding="utf-8")
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
    res.installed = True
    res.lines.append("Installed" + (f" rule pack {res.rule_pack}" if has_pack else "")
                     + (" and" if has_pack and feed is not None else "") + (f" indicator feed v{feed.version}" if feed is not None else "") + ".")
    activate()
    return res


# ----------------------------------------------------------- activation --
_CACHE: dict[str, Any] = {"key": None, "dirs": None, "note": ""}


def installed_pack() -> tuple[tuple[Path, Path] | None, str]:
    """(rules dir, mappings dir) of the rule pack an update installed, verified again now, and a note when
    it was refused. `(None, "")` when no update is installed."""
    home = update_home()
    pointer = home / "current"
    try:
        serial = pointer.read_text(encoding="utf-8").strip()
        stamp = pointer.stat().st_mtime_ns
    except OSError:
        return None, ""
    key = (str(home), serial, stamp)
    if _CACHE["key"] == key:
        return _CACHE["dirs"], _CACHE["note"]
    dirs, note = None, ""
    root = home / "packs" / serial
    try:
        if not serial.isdigit():
            raise UpdateError("the pointer to the installed pack is malformed")
        manifest_bytes, sig_bytes = (root / "manifest.json").read_bytes(), (root / "manifest.sig").read_bytes()
        _verify_manifest(manifest_bytes, sig_bytes, release_keys())
        listed = {n: h for n, h in json.loads(manifest_bytes)["files"].items() if n.startswith(("rules/", "mappings/"))}
        on_disk = {p.relative_to(root).as_posix() for sub in ("rules", "mappings") for p in (root / sub).rglob("*") if p.is_file()}
        if on_disk != set(listed):
            raise UpdateError("its files are not the ones its signed manifest lists")
        for name, digest in listed.items():
            if hashlib.sha256((root / name).read_bytes()).hexdigest() != digest:
                raise UpdateError(f"'{name[:80]}' was changed after it was installed")
        dirs = (root / "rules", root / "mappings")
    except (UpdateError, OSError, ValueError, KeyError, TypeError) as exc:
        note = (f"the rule pack installed by `agentguard update` (serial {serial[:20]}) no longer verifies ({str(exc)[:160]}); "
                "the rule pack shipped with Agent Guard is used instead")
    _CACHE.update(key=key, dirs=dirs, note=note)
    return dirs, note


def activate() -> str:
    """Point the default rule pack at a verified installed update, or back at the bundled pack. Returns a
    note for the user when an installed pack was refused. Cheap when nothing is installed."""
    dirs, note = installed_pack()
    if dirs is None:
        pack_mod.use_dirs(None)
    else:
        pack_mod.use_dirs(*dirs)
    return note


def status() -> dict[str, Any]:
    """What is installed (for `agentguard doctor`)."""
    serial, digest = _accepted()
    dirs, note = installed_pack()
    return {"serial": serial or None, "digest": digest or None, "rule_pack_active": dirs is not None, "note": note,
            "user_keys": sorted(p.name for p in user_keys_dir().glob("*.pub.json")) if user_keys_dir().is_dir() else []}


__all__ = ["Bundle", "UpdateError", "UpdateResult", "activate", "build_bundle", "installed_pack", "read_bundle", "release_keys",
           "run_update", "status"]
