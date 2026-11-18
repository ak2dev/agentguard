"""Network lookups a pinning fix needs (`agentguard fix --network`): the commit a
git ref points at, the current version of a package, the SHA-256 of a download.

Read-only GET requests through the SSRF-hardened client. Nothing fetched is
executed; a download is only hashed.
"""

from __future__ import annotations

import hashlib
import re
import urllib.parse
from typing import Any

_REPO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$")
_SHA = re.compile(r"^[0-9a-f]{40}$")
_VERSION = re.compile(r"^\d[A-Za-z0-9.+_!-]{0,63}$")


class Resolver:
    """``resolver(kind, subject)`` → value or None. Kinds: ``commit`` (``owner/repo@ref``),
    ``version`` (``npm/<name>`` or ``pypi/<name>``), ``sha256`` (a URL)."""

    def __init__(self, http: Any = None, github_token: str | None = None) -> None:
        if http is None:
            from ..net.safe_http import SafeHttpClient

            http = SafeHttpClient(max_bytes=64 * 1024 * 1024, deadline_s=60)
        self.http = http
        self.token = github_token
        self.cache: dict[tuple[str, str], str | None] = {}

    def __call__(self, kind: str, subject: str) -> str | None:
        key = (kind, subject)
        if key not in self.cache:
            try:
                self.cache[key] = getattr(self, f"_{kind}")(subject)
            except Exception:  # noqa: BLE001 - a failed lookup is "unknown", and the fix is skipped
                self.cache[key] = None
        return self.cache[key]

    def _commit(self, subject: str) -> str | None:
        repo, _, ref = subject.partition("@")
        if not _REPO.match(repo):
            return None
        headers = {"Accept": "application/vnd.github+json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        ref = ref or "HEAD"
        url = f"https://api.github.com/repos/{repo}/commits/{urllib.parse.quote(ref, safe='')}"
        resp = self.http.get(url, headers=headers)
        if resp.status != 200:
            return None
        sha = str(resp.json().get("sha", ""))
        return sha if _SHA.match(sha) else None

    def _version(self, subject: str) -> str | None:
        eco, _, name = subject.partition("/")
        if eco == "npm":
            resp = self.http.get(f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}/latest")
            version = str(resp.json().get("version", "")) if resp.status == 200 else ""
        elif eco == "pypi":
            resp = self.http.get(f"https://pypi.org/pypi/{urllib.parse.quote(name, safe='')}/json")
            version = str((resp.json().get("info") or {}).get("version", "")) if resp.status == 200 else ""
        else:
            return None
        return version if _VERSION.match(version) else None

    def _sha256(self, url: str) -> str | None:
        resp = self.http.get(url)
        if resp.status != 200:
            return None
        return hashlib.sha256(resp.body).hexdigest()
