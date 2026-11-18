"""Static supply-chain analysis of dependency manifests and lockfiles (engine E),
and package hygiene.

``DependencyAnalyzer`` reads `package.json`, npm / yarn / pnpm lockfiles,
`requirements*.txt`, `pyproject.toml`, `uv.lock` / `poetry.lock`,
`.gitmodules` and marketplace audit records. Nothing is installed and no
lifecycle script runs. Rules that need a registry or a repository host take
recorded facts (``options.package_facts``, ``options.facts``).

``HygieneAnalyzer`` reports what makes a package hard to review or reproduce.
"""

from __future__ import annotations

import datetime as dt
import posixpath
import urllib.parse
from typing import Any, ClassVar

import regex

from ..artifacts import EXECUTABLE_KINDS, binary_kind
from ..models import Component, Span
from ..models.enums import ArtifactRole, CapLabel, ComponentKind, EvidenceKind, Severity
from ..parsers import parse_json, parse_toml
from ..textutil import TIMEOUT
from .base import Context
from .system import submodules

_F = regex.IGNORECASE
PACKAGE_KINDS = (ComponentKind.skill, ComponentKind.plugin, ComponentKind.bundle, ComponentKind.mcp_server, ComponentKind.package)
_NPM_LOCKS = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb")
_PY_LOCKS = ("uv.lock", "poetry.lock", "pipfile.lock", "pdm.lock", "requirements.lock", "pylock.toml")
_EXACT = regex.compile(r"^[=v]?\d+(?:\.\d+){0,3}(?:[-+][0-9A-Za-z.\-]+)?$")
_NPM_REMOTE = regex.compile(r"^(?:git\+|git://|git@|https?://|ssh://|github:|gitlab:|bitbucket:|gist:)|^[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+(?:#.*)?$")
_NPM_LOCAL = regex.compile(r"^(?:file:|link:|workspace:|portal:|catalog:|npm:|\.{1,2}/|/)")
_COMMIT = regex.compile(r"(?:#|@|/commit/|/archive/|rev=|/)([0-9a-f]{40})\b", _F)
_REQ = regex.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(\[[^\]]*\])?\s*(.*)$")
_HASHED = regex.compile(r"--hash[=\s]|#(?:sha256|sha512|md5)=", _F)
_NPM_REGISTRIES = ("registry.npmjs.org", "registry.yarnpkg.com")
_PY_REGISTRIES = ("pypi.org", "files.pythonhosted.org", "pypi.python.org")
_SOURCE_EXT = (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".go", ".rs", ".zig", ".swift", ".java", ".kt", ".cs", ".m", ".mm", ".nim",
               ".asm", ".s")
_AUDIT_STATUS = regex.compile(r"^(?:pass|passed|review|warn|warning|malicious|pending|error|unscanned|unknown|failed|not[-_ ]scanned)$", _F)
_AUDIT_KEY = regex.compile(r"audit|scan|security|verdict|status|trust", _F)
_DOC_URL = regex.compile(
    r"\b(?:see|read|refer\s+to|consult|follow|load|open|fetch|check|use|according\s+to|documented\s+(?:at|in)|described\s+(?:at|in)|"
    r"details?\s+(?:at|in)|instructions?\s+(?:at|in|from)|guide\s+(?:at|in))\b[^\n]{0,80}?(https?://[^\s\"'`<>)\]]+)", _F)
_MUTABLE = regex.compile(r"/(?:main|master|HEAD|latest|develop|trunk|stable)/|raw\.githubusercontent\.com|gist\.githubusercontent\.com"
                         r"|/blob/|/raw/|\.(?:md|txt|rst|html?|json|ya?ml|pdf)(?:[?#]|$)", _F)
_INSECURE_GIT = regex.compile(r"^(?:http://|git://|ftp://)|://[^/@\s]+:[^/@\s]+@", _F)
_REMOVAL_WORDS = regex.compile(r"\b(?:uninstall|remov(?:e|al|ing)|clean(?:[- ]?up|ing up)|revert|undo|roll(?:ing)?[- ]?back|delete\s+the|tear[- ]?down|disable)\b", _F)
_SCRIPT_SUFFIXES = (".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts", ".ps1", ".bat", ".cmd", ".rb", ".pl", ".php", ".lua")
_FOLLOW_FILE = regex.compile(r"\b(?:follow|obey|apply|carry\s+out|continue\s+with|proceed\s+with|do\s+what|execute|as\s+described\s+in"
                             r"|according\s+to|steps?\s+in|instructions?\s+in)\b", _F)
_RUN_VERB = regex.compile(r"\b(?:run|execute|invoke|launch|start|call|source|python3?|node|bash|sh|zsh|pwsh|powershell|deno|bun|ruby|perl|chmod)\b|^\s*[!$>]", _F)
_MD_LINK = regex.compile(r"(?<!!)\[[^\]\n]{1,200}\]\(\s*<?([^)\s>#?]+)[^)]*\)")
_UNVERSIONED = regex.compile(
    r"releases/latest(?:/download)?|@latest\b|:latest\b|\bgit\s+clone\s+(?!.*(?:--branch|-b)\s+v?\d)[^\n]*$"
    r"|\b(?:pip3?|uv\s+pip)\s+install\s+(?!-r\b|-e\b|\.|--)[A-Za-z0-9_.\-]+(?:\s|$)(?![^\n]*==)"
    r"|\bnpm\s+(?:i|install)\s+(?:-g\s+|--global\s+)?(?!-)[@A-Za-z0-9_./\-]+(?<!@\d[\d.]*)(?:\s|$)(?![^\n]*@\d)"
    r"|\bbrew\s+install\b|\bapt(?:-get)?\s+install\b(?![^\n]*=\d)|\bcurl\b[^\n]*/(?:main|master)/", _F | regex.MULTILINE)
_MAX_LISTED = 5


def _host(url: str) -> str:
    try:
        return (urllib.parse.urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _is_ip(host: str) -> bool:
    return bool(regex.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-f:]+\]", host, _F))


def _line_of(text: str, needle: str, start: int = 0) -> int:
    pos = text.find(needle, start)
    return text.count("\n", 0, pos) + 1 if pos >= 0 else 1


class DependencyAnalyzer:
    id: ClassVar[str] = "supply.deps"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = (
        "AG-SUPPLY-002", "AG-SUPPLY-005", "AG-SUPPLY-006", "AG-SUPPLY-008", "AG-SUPPLY-010", "AG-SUPPLY-016", "AG-SUPPLY-018",
        "AG-SUPPLY-020", "AG-SUPPLY-021", "AG-SUPPLY-023", "AG-SUPPLY-024", "AG-SUPPLY-025",
    )

    def run(self, ctx: Context) -> None:
        self.ctx = ctx
        inv = ctx.inventory
        tree = inv.tree
        if tree is None:
            return
        self.tree = tree
        self.malicious = _malicious_index(ctx.pack.list_data("malicious-packages"))
        self.allowed_registries = [r.lower().split("://")[-1].strip("/") for r in ctx.options.effective_policy.allow.registries]
        by_dir: dict[str, set[str]] = {}
        for p in tree.files:
            by_dir.setdefault(posixpath.dirname(p), set()).add(posixpath.basename(p).lower())
        for path in sorted(tree.files):
            art = inv.artifacts.get(path)
            comp = inv.components.get(art.component_id) if art else None
            if comp is None:
                continue
            base = posixpath.basename(path).lower()
            siblings = by_dir.get(posixpath.dirname(path), set())
            scoped = comp.kind in PACKAGE_KINDS            # manifests of the catch-all repository are not an agent's
            text = None
            if base == "package.json" and scoped:
                text = self._text(path)
                self._package_json(path, comp, text, siblings)
            elif (base == "package-lock.json" or base == "npm-shrinkwrap.json") and scoped:
                self._package_lock(path, comp, self._text(path), siblings)
            elif base == "yarn.lock" and scoped:
                self._text_lock(path, comp, self._text(path), r'(?m)^\s*resolved\s+"?(https?://[^"\s#]+)', _NPM_REGISTRIES, "npm")
            elif base == "pnpm-lock.yaml" and scoped:
                self._text_lock(path, comp, self._text(path), r"(?m)\btarball:\s*['\"]?(https?://[^'\"\s}]+)", _NPM_REGISTRIES, "npm")
            elif base in ("uv.lock", "poetry.lock", "pdm.lock") and scoped:
                self._text_lock(path, comp, self._text(path), r'(?m)\b(?:url|registry)\s*=\s*"(https?://[^"]+)"', _PY_REGISTRIES, "pypi")
            elif regex.fullmatch(r"requirements[^/]*\.(?:txt|in)", base) and scoped:
                self._requirements(path, comp, self._text(path), siblings)
            elif base == "pyproject.toml" and scoped:
                self._pyproject(path, comp, self._text(path), siblings)
            elif base == ".gitmodules":
                self._gitmodules(path, comp, self._text(path))
            elif regex.search(r"(?:^|/)\.clawhub/(?:origin|lock)\.json$", path):
                self._clawhub(path, comp, self._text(path))
        for comp in sorted(inv.of_kind(ComponentKind.skill, ComponentKind.plugin, ComponentKind.bundle), key=lambda c: c.id):
            self._binaries(comp)
        self._documents()
        self._facts()

    def _text(self, path: str) -> str:
        return self.tree.files[path].data.decode("utf-8", "replace")

    def _emit(self, rule: str, comp: Component, path: str, line: int, snippet: str, message: str, *, key: str = "",
              severity: Severity | None = None) -> None:
        self.ctx.emit(rule, component_ids=comp.id, span=Span(path=path, start_line=max(1, line)), snippet=snippet[:300],
                      kind=EvidenceKind.metadata, match=f"{path}:{key or snippet[:80]}", message=message, severity=severity)

    def _known_bad(self, comp: Component, path: str, text: str, eco: str, name: str, version: str) -> None:
        versions = self.malicious.get((eco, name.lower()))
        if versions is None:
            return
        v = version.lstrip("=v^~ ")
        if versions and v not in versions:
            return
        self._emit("AG-SUPPLY-002", comp, path, _line_of(text, name), f"{name}@{version or '*'}",
                   f"The {eco} package `{name}`{' ' + v if versions else ''} is on the list of packages published as malware or "
                   "taken over and republished with a payload.", key=f"malicious:{eco}:{name}")

    # -- npm --------------------------------------------------------------------------------------------
    def _package_json(self, path: str, comp: Component, text: str, siblings: set[str]) -> None:
        pkg = parse_json(text).value
        if not isinstance(pkg, dict):
            return
        locked = any(n in siblings for n in _NPM_LOCKS)
        ranges: list[str] = []
        for section in ("dependencies", "optionalDependencies", "peerDependencies", "devDependencies"):
            deps = pkg.get(section)
            if not isinstance(deps, dict):
                continue
            for name, spec in deps.items():
                if not isinstance(spec, str):
                    continue
                s = spec.strip()
                self._known_bad(comp, path, text, "npm", str(name), s)
                if _NPM_LOCAL.match(s):
                    continue
                if _NPM_REMOTE.match(s):
                    if not _COMMIT.search(s) and not (locked and s.startswith(("http://", "https://")) and not s.startswith("http://")):
                        what = "a URL" if s.startswith(("http://", "https://")) else "a git source with no commit"
                        self._emit("AG-SUPPLY-006", comp, path, _line_of(text, f'"{name}"'), f'"{name}": "{s}"',
                                   f"The dependency `{name}` is installed from {what} (`{s[:80]}`), not from the registry at a "
                                   "version; what is fetched can change without the manifest changing.", key=f"{name}:{s}")
                    continue
                if section != "devDependencies" and not _EXACT.match(s):
                    ranges.append(f"{name}@{s}")
        if ranges and not locked:
            self._emit("AG-SUPPLY-005", comp, path, _line_of(text, '"dependencies"'), ", ".join(ranges[:_MAX_LISTED]),
                       f"{len(ranges)} dependenc{'y is' if len(ranges) == 1 else 'ies are'} given as a version range "
                       f"({', '.join(ranges[:_MAX_LISTED])}) and there is no lockfile: each install may resolve to different code.",
                       key="ranges")
        lic = pkg.get("license")
        if (not lic or (isinstance(lic, str) and regex.match(r"(?i)unlicensed|see license", lic))) and not _has_licence(siblings) \
                and pkg.get("private") is not True:
            self._emit("AG-SUPPLY-021", comp, path, _line_of(text, '"name"'), f"{pkg.get('name', '')}: license {lic!r}",
                       "The package declares no licence and ships no licence file; the terms under which its code may be used are unknown.",
                       key="licence")

    def _package_lock(self, path: str, comp: Component, text: str, siblings: set[str]) -> None:
        lock = parse_json(text).value
        packages = lock.get("packages") if isinstance(lock, dict) and isinstance(lock.get("packages"), dict) else {}
        if not packages and isinstance(lock, dict) and isinstance(lock.get("dependencies"), dict):
            packages = {f"node_modules/{k}": v for k, v in lock["dependencies"].items()}
        entries: list[tuple[str, str, str]] = []
        scripts: list[str] = []
        missing: list[str] = []
        for key, entry in packages.items():
            if not isinstance(entry, dict) or not key:
                continue
            name = key.rsplit("node_modules/", 1)[-1]
            version = str(entry.get("version") or "")
            self._known_bad(comp, path, text, "npm", name, version)
            if entry.get("hasInstallScript") is True:
                scripts.append(f"{name}@{version}")
            resolved = entry.get("resolved")
            if isinstance(resolved, str) and resolved.startswith(("http://", "https://")):
                entries.append((name, resolved, version))
                if not entry.get("integrity") and not entry.get("link") and not entry.get("inBundle"):
                    missing.append(f"{name}@{version}")
        self._urls(path, comp, text, entries, _NPM_REGISTRIES, "npm")
        if missing:
            self._emit("AG-SUPPLY-024", comp, path, _line_of(text, f'"node_modules/{missing[0].rsplit("@", 1)[0]}"'),
                       ", ".join(missing[:_MAX_LISTED]), f"{len(missing)} lockfile entr{'y has' if len(missing) == 1 else 'ies have'} "
                       f"no `integrity` hash ({', '.join(missing[:_MAX_LISTED])}); the downloaded archive is not checked.",
                       key="no-integrity", severity=Severity.medium)
        if scripts:
            self._emit("AG-SUPPLY-008", comp, path, _line_of(text, '"hasInstallScript"'), ", ".join(scripts[:_MAX_LISTED]),
                       f"{len(scripts)} locked dependenc{'y runs' if len(scripts) == 1 else 'ies run'} an install script "
                       f"({', '.join(scripts[:_MAX_LISTED])}); installing with scripts enabled runs their code.", key="install-scripts")

    def _text_lock(self, path: str, comp: Component, text: str, pattern: str, registries: tuple[str, ...], eco: str) -> None:
        try:
            urls = [m.group(1) for m in regex.finditer(pattern, text, timeout=TIMEOUT)]
        except TimeoutError:
            return
        self._urls(path, comp, text, [("", u, "") for u in urls[:50_000]], registries, eco)

    def _urls(self, path: str, comp: Component, text: str, entries: list[tuple[str, str, str]], registries: tuple[str, ...],
              eco: str) -> None:
        """Lockfile injection: a few entries resolved from somewhere other than where the rest come from."""
        if not entries:
            return
        hosts: dict[str, int] = {}
        for _n, url, _v in entries:
            hosts[_host(url)] = hosts.get(_host(url), 0) + 1
        total = len(entries)
        reported = 0
        for name, url, _version in entries:
            host = _host(url)
            if reported >= _MAX_LISTED:
                break
            if any(host == r or host.endswith("." + r) for r in registries) or any(host == a.split("/")[0] for a in self.allowed_registries):
                if url.startswith("http://"):
                    pass
                else:
                    continue
            plain = url.startswith("http://")
            outlier = hosts[host] / total < 0.2 or total < 5
            if not (plain or _is_ip(host) or outlier):
                continue                              # a private registry serving most of the tree is not an injection
            why = "over plain HTTP" if plain else "from a raw IP address" if _is_ip(host) else \
                f"from `{host}` while the rest of the lockfile comes from elsewhere"
            reported += 1
            self._emit("AG-SUPPLY-024", comp, path, _line_of(text, url), url, f"The lockfile resolves "
                       f"{'`' + name + '`' if name else 'a package'} {why}. A lockfile entry pointing at an unexpected URL replaces "
                       f"that {eco} package with whatever the URL serves.", key=f"url:{url}")

    # -- Python -----------------------------------------------------------------------------------------
    def _requirements(self, path: str, comp: Component, text: str, siblings: set[str]) -> None:
        loose: list[str] = []
        hashed_file = bool(_HASHED.search(text))
        for i, raw in enumerate(text.splitlines(), 1):
            line = raw.split(" #", 1)[0].strip()
            if not line or line.startswith(("#", "-r", "-c", "--", "-i", "-f")):
                continue
            if regex.match(r"(?i)(?:-e\s+)?(?:git\+|https?://|[\w.\-]+\s*@\s*(?:git\+|https?://))", line):
                if not _COMMIT.search(line) and not _HASHED.search(raw):
                    self._emit("AG-SUPPLY-006", comp, path, i, line, f"`{line[:80]}` installs from a URL or git source with no "
                               "commit or hash; what is fetched can change without this file changing.", key=line)
                continue
            m = _REQ.match(line)
            if not m:
                continue
            name, spec = m.group(1), m.group(3).split(";", 1)[0].strip()
            pinned = spec.startswith(("==", "==="))
            self._known_bad(comp, path, text, "pypi", name, spec.lstrip("=").strip() if pinned else "")
            if not pinned and not hashed_file:
                loose.append(f"{name}{spec}")
        if loose and not any(n in siblings for n in _PY_LOCKS):
            self._emit("AG-SUPPLY-005", comp, path, 1, ", ".join(loose[:_MAX_LISTED]),
                       f"{len(loose)} requirement{' is' if len(loose) == 1 else 's are'} not pinned to a version "
                       f"({', '.join(loose[:_MAX_LISTED])}) and there is no lockfile: each install may resolve to different code.",
                       key="ranges")

    def _pyproject(self, path: str, comp: Component, text: str, siblings: set[str]) -> None:
        data = parse_toml(text).value
        if not isinstance(data, dict):
            return
        project = data.get("project") if isinstance(data.get("project"), dict) else {}
        deps = [d for d in project.get("dependencies") or [] if isinstance(d, str)]
        poetry = data.get("tool", {}).get("poetry", {}) if isinstance(data.get("tool"), dict) else {}
        loose: list[str] = []
        for dep in deps:
            line = dep.split(";", 1)[0].strip()
            if "@" in line and regex.search(r"@\s*(?:git\+|https?://)", line):
                if not _COMMIT.search(line):
                    self._emit("AG-SUPPLY-006", comp, path, _line_of(text, line[:30]), line, f"`{line[:80]}` installs from a URL or "
                               "git source with no commit; what is fetched can change without this file changing.", key=line)
                continue
            m = _REQ.match(line)
            if m:
                self._known_bad(comp, path, text, "pypi", m.group(1), m.group(3).lstrip("=").strip() if m.group(3).startswith("==") else "")
                if not m.group(3).strip().startswith("=="):
                    loose.append(line)
        if isinstance(poetry.get("dependencies"), dict):
            for name, spec in poetry["dependencies"].items():
                if name == "python":
                    continue
                if isinstance(spec, dict) and (spec.get("git") or spec.get("url")) and not spec.get("rev"):
                    self._emit("AG-SUPPLY-006", comp, path, _line_of(text, str(name)), f"{name} = {spec}", f"The dependency `{name}` "
                               "is installed from a git or URL source with no `rev`.", key=f"{name}:git")
                elif isinstance(spec, str) and not _EXACT.match(spec.strip()):
                    loose.append(f"{name}{spec}")
        if loose and not any(n in siblings for n in _PY_LOCKS):
            self._emit("AG-SUPPLY-005", comp, path, _line_of(text, "dependencies"), ", ".join(loose[:_MAX_LISTED]),
                       f"{len(loose)} dependenc{'y is' if len(loose) == 1 else 'ies are'} given as a range "
                       f"({', '.join(loose[:_MAX_LISTED])}) and there is no lockfile: each install may resolve to different code.",
                       key="ranges")
        has_licence = project.get("license") or poetry.get("license") or any(
            "License ::" in c for c in project.get("classifiers") or [] if isinstance(c, str))
        if (project or poetry) and not has_licence and not _has_licence(siblings):
            self._emit("AG-SUPPLY-021", comp, path, _line_of(text, "[project]"), f"{project.get('name') or poetry.get('name') or ''}: no license",
                       "The package declares no licence and ships no licence file; the terms under which its code may be used are unknown.",
                       key="licence")

    # -- git submodules (SUPPLY-020) -----------------------------------------------------------------------
    def _gitmodules(self, path: str, comp: Component, text: str) -> None:
        base = posixpath.dirname(path)
        for sub in submodules(text):
            url = sub.get("url", "")
            line = int(sub["line"])
            problems = []
            if _INSECURE_GIT.search(url):
                problems.append("its URL is not authenticated (plain `http://` or `git://`) or embeds credentials")
            if sub.get("branch"):
                problems.append(f"it tracks the branch `{sub['branch']}`, so `git submodule update --remote` follows whatever is pushed there")
            root = posixpath.normpath(posixpath.join(base, sub.get("path", "").strip("/"))) if sub.get("path") else ""
            if root and not any(p.startswith(root + "/") for p in self.tree.files):
                problems.append("its content is not in the scanned tree, so it was not analysed")
            if problems:
                self._emit("AG-SUPPLY-020", comp, path, line, f'[submodule "{sub["name"]}"] url = {url}',
                           f"Submodule '{sub['name']}': {'; '.join(problems)}.", key=f"submodule:{sub['name']}")

    # -- marketplace audit records (SUPPLY-025) --------------------------------------------------------------
    def _clawhub(self, path: str, comp: Component, text: str) -> None:
        data = parse_json(text).value
        found: list[tuple[str, str]] = []
        stack: list[tuple[str, Any]] = [("", data)]
        while stack and len(found) < 50:
            where, node = stack.pop()
            if isinstance(node, dict):
                for k, v in node.items():
                    if isinstance(v, str) and _AUDIT_KEY.search(str(k)) and _AUDIT_STATUS.match(v.strip()):
                        found.append((f"{where}.{k}".strip("."), v.strip()))
                    elif isinstance(v, (dict, list)):
                        stack.append((f"{where}.{k}".strip("."), v))
            elif isinstance(node, list):
                stack.extend((f"{where}[{i}]", v) for i, v in enumerate(node[:200]))
        for where, status in sorted(found):
            low = status.lower()
            if low in ("pass", "passed"):
                continue
            sev = Severity.high if low == "malicious" else None
            what = "as malicious" if low == "malicious" else f"with the audit status '{status}', not as passed"
            self._emit("AG-SUPPLY-025", comp, path, _line_of(text, f'"{status}"'), f"{where}: {status}",
                       f"The marketplace's own record marks this install {what}. It was installed without a clean audit.",
                       key=f"audit:{where}:{low}", severity=sev)

    # -- binaries with no source (SUPPLY-023) -----------------------------------------------------------------
    def _binaries(self, comp: Component) -> None:
        inv = self.ctx.inventory
        arts = [a for a in inv.artifacts.values() if a.component_id == comp.id]
        if any(a.path.lower().endswith(_SOURCE_EXT) for a in arts):
            return
        for a in sorted(arts, key=lambda x: x.path):
            if a.role != ArtifactRole.binary or a.path not in self.tree.files:
                continue
            kind = binary_kind(self.tree.files[a.path].data)
            if kind in EXECUTABLE_KINDS:
                self._emit("AG-SUPPLY-023", comp, a.path, 1, a.path, f"`{posixpath.basename(a.path)}` is a compiled {kind} binary "
                           f"and the {comp.kind.spec_type} contains no source it could have been built from.", key=f"binary:{a.path}")

    # -- external documents (SUPPLY-010) -----------------------------------------------------------------------
    def _documents(self) -> None:
        ctx = self.ctx
        lock = ctx.options.lock
        pinned = {u for e in (lock.artifacts if lock else []) for u in e.external_refs}
        for at in ctx.texts("skill_md", "instruction_md", "command_md"):
            done = 0
            for unit in at.units:
                if unit.scope != "body" or unit.base is None:
                    continue
                try:
                    hits = list(_DOC_URL.finditer(unit.norm.text, timeout=TIMEOUT))
                except TimeoutError:
                    continue
                for m in hits:
                    url = m.group(1).rstrip(".,;:")
                    if done >= 3 or url in pinned or _COMMIT.search(url) or not _MUTABLE.search(url):
                        continue
                    off = unit.base + unit.norm.orig(m.start(1))
                    if at.in_code(off):
                        continue
                    done += 1
                    ctx.emit("AG-SUPPLY-010", component_ids=at.artifact.component_id, span=at.span(off, off + len(url)),
                             snippet=at.line_text(off).strip()[:300], kind=EvidenceKind.regex, match=f"doc:{url}",
                             message=f"The instructions send the agent to `{url[:100]}` for guidance. The document is not part of "
                                     "the package and is not pinned, so what the agent reads there can change after review.")

    # -- recorded facts (SUPPLY-002, 016, 018) ---------------------------------------------------------------------
    def _facts(self) -> None:
        ctx, inv = self.ctx, self.ctx.inventory
        for f in ctx.options.package_facts:
            bad = [v for v in f.vulns if v.id.upper().startswith("MAL-")]
            if bad:
                comp = next((c for c in inv.components.values() if c.name.lower() == f.name.lower()), None)
                span = comp.server.config_span if comp and comp.server else Span(path=comp.root if comp and comp.root else f"{f.ecosystem}:{f.name}")
                ctx.emit("AG-SUPPLY-002", component_ids=comp.id if comp else [], span=span, snippet=f"{f.name}@{f.version}: {bad[0].id}",
                         kind=EvidenceKind.intel, match=f"malicious:{f.ecosystem}:{f.name}",
                         message=f"The {f.ecosystem} package `{f.name}`@{f.version} has a malicious-package record ({bad[0].id})"
                                 + (f": {bad[0].summary[:120]}" if bad[0].summary else "."))
        facts = ctx.options.facts if isinstance(ctx.options.facts, dict) else {}
        packages = facts.get("packages") if isinstance(facts.get("packages"), dict) else {}
        for ident, info in sorted(packages.items()):
            diff = info.get("source_diff") if isinstance(info, dict) else None
            if not isinstance(diff, dict):
                continue
            only = [str(x) for x in diff.get("only_in_package") or []]
            changed = [str(x) for x in diff.get("changed") or []]
            if not only and not changed:
                continue
            name = ident.split("/", 1)[-1]
            comp = next((c for c in inv.components.values() if c.name.lower() == name.lower()), None)
            first = (only + changed)[0]
            target = next((p for p in self.tree.files if p.endswith(first)), None)
            bits = []
            if only:
                bits.append(f"{len(only)} file(s) exist only in the published package ({', '.join(only[:3])})")
            if changed:
                bits.append(f"{len(changed)} file(s) differ from the source ({', '.join(changed[:3])})")
            ctx.emit("AG-SUPPLY-016", component_ids=comp.id if comp else [], span=Span(path=target or (comp.root if comp and comp.root else ident)),
                     snippet=", ".join((only + changed)[:6]), kind=EvidenceKind.intel, match=f"source-diff:{ident}",
                     message=f"The published package `{ident}` is not what its source repository holds at "
                             f"{diff.get('ref') or 'the tagged commit'}: {'; '.join(bits)}.")
        sources = facts.get("sources") if isinstance(facts.get("sources"), dict) else {}
        today = ctx.options.today
        for url, info in sorted(sources.items()):
            if not isinstance(info, dict):
                continue
            why = ""
            if info.get("archived") is True:
                why = "is archived by its owner"
            elif isinstance(info.get("pushed_at"), str) and today is not None:
                try:
                    last = dt.date.fromisoformat(info["pushed_at"][:10])
                    if (today - last).days > 730:
                        why = f"has had no commit since {last.isoformat()}"
                except ValueError:
                    pass
            if why:
                comp = next((c for c in inv.components.values() if c.metadata.get("repository") == url), None)
                ctx.emit("AG-SUPPLY-018", component_ids=comp.id if comp else [], span=Span(path=comp.root if comp and comp.root else url),
                         snippet=url, kind=EvidenceKind.intel, match=f"abandoned:{url}",
                         message=f"The source repository `{url}` {why}: problems found in it will not be fixed there.")


def _shipped_tail(ref: str, comp: Component, paths: set[str]) -> bool:
    """``ref`` names a file of the package through the place it is installed to
    (``.codex/skills/<name>/scripts/run.py``, ``$skill_dir/scripts/run.sh``): the
    path below the install location is in the package."""
    parts = [p for p in ref.replace("\\", "/").split("/") if p not in ("", ".")]
    for i in range(1, len(parts)):
        tail = "/".join(parts[i:])
        named = comp.name and comp.name in parts[:i]
        if (len(parts) - i >= 2 or named) and (posixpath.join(comp.root, tail) if comp.root else tail) in paths:
            return True
    return False


def _has_licence(siblings: set[str]) -> bool:
    return any(regex.match(r"(?i)(?:licen[cs]e|copying|unlicense)(?:[.\-_].*)?$", n) for n in siblings)


def _malicious_index(lines: list[str]) -> dict[tuple[str, str], set[str]]:
    """``npm:name@version`` / ``pypi:name`` lines → {(ecosystem, name): {versions}} (empty set: every version)."""
    out: dict[tuple[str, str], set[str]] = {}
    for line in lines:
        eco, _, rest = line.partition(":")
        name, _, version = rest.rpartition("@") if "@" in rest.lstrip("@") else (rest, "", "")
        if not name:
            name, version = rest, ""
        bucket = out.setdefault((eco.strip().lower(), name.strip().lower()), set())
        if version:
            bucket.add(version.strip())
    return out


class HygieneAnalyzer:
    id: ClassVar[str] = "hygiene"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = ("AG-HYG-001", "AG-HYG-002", "AG-HYG-003", "AG-HYG-004", "AG-HYG-006", "AG-HYG-007",
                                        "AG-HYG-009", "AG-HYG-010", "AG-EVADE-012", "AG-PERSIST-015")
    MAX_LINES = 500
    MAX_CHARS = 20_000          # about 5,000 tokens

    def run(self, ctx: Context) -> None:
        inv = ctx.inventory
        tree = inv.tree
        if tree is None:
            return
        paths = set(tree.files)
        # HYG-001: a directory where a skill is expected, with files and no SKILL.md.
        skill_dirs: dict[str, list[str]] = {}
        for p in sorted(paths):
            m = regex.match(r"^(.*?(?:^|/)(?:\.claude|\.agents|\.codex|\.cursor|\.gemini|\.github|\.openclaw)/skills/[^/]+)/(.+)$", p)
            if m:
                skill_dirs.setdefault(m.group(1), []).append(m.group(2))
        for root, files in sorted(skill_dirs.items()):
            if not any(f.lower() == "skill.md" for f in files) and posixpath.basename(root) != "synced":
                comp = inv.component_for(f"{root}/{files[0]}")
                ctx.emit("AG-HYG-001", component_ids=[comp.id] if comp else [], span=Span(path=f"{root}/{files[0]}"), snippet=root,
                         kind=EvidenceKind.metadata, match=f"noskill:{root}",
                         message=f"`{root}/` sits where agents load skills and has {len(files)} file(s) and no `SKILL.md`; the agent "
                                 "will not load it, and nothing says what it is.")
        for at in ctx.texts("skill_md"):
            comp = inv.components.get(at.artifact.component_id)
            if comp is None:
                continue
            fm = at.fm.data if at.fm is not None and isinstance(at.fm.data, dict) else {}
            root = comp.root
            names = {posixpath.basename(p).lower() for p in paths if posixpath.dirname(p) == root}
            body = at.fm.body if at.fm is not None else at.text
            if not fm.get("license") and not _has_licence(names):
                ctx.emit("AG-HYG-002", component_ids=comp.id, span=Span(path=at.path, start_line=1), snippet=f"name: {fm.get('name', '')}",
                         kind=EvidenceKind.metadata, match=f"licence:{at.path}",
                         message="The skill declares no licence in its frontmatter and ships no licence file.")
            n_lines = body.count("\n") + 1
            if n_lines > self.MAX_LINES or len(body) > self.MAX_CHARS:
                ctx.emit("AG-HYG-004", component_ids=comp.id, span=Span(path=at.path, start_line=1), kind=EvidenceKind.metadata,
                         snippet=f"{n_lines} lines, {len(body)} characters", match=f"size:{at.path}",
                         message=f"`SKILL.md` is {n_lines} lines and {len(body)} characters; the specification recommends under 500 "
                                 "lines (about 5,000 tokens), with detail moved to reference files.")
            desc = str(fm.get("description") or "").strip()
            if len(desc) < 20 or len(body.strip()) < 40:
                what = "no usable description" if len(desc) < 20 else "almost no instructions"
                ctx.emit("AG-HYG-006", component_ids=comp.id, span=Span(path=at.path, start_line=1), kind=EvidenceKind.metadata,
                         snippet=f"description: {desc[:80]}", match=f"desc:{at.path}",
                         message=f"The skill has {what}; neither the agent nor a reviewer can tell when it should be used.")
        # HYG-007: a package with a manifest and no version.
        for comp in sorted(inv.of_kind(ComponentKind.plugin, ComponentKind.bundle), key=lambda c: c.id):
            manifest = comp.metadata.get("manifest", "")
            if manifest and not comp.version and manifest in paths:
                names = {posixpath.basename(p).lower() for p in paths if posixpath.dirname(p) == comp.root}
                if not any(n.startswith("changelog") for n in names):
                    ctx.emit("AG-HYG-007", component_ids=comp.id, span=Span(path=manifest), snippet=comp.name, kind=EvidenceKind.metadata,
                             match=f"version:{manifest}", message=f"The {comp.kind.spec_type} '{comp.name}' has no version and no "
                                                                  "changelog; an update cannot be told from the version it replaces.")
        self._references(ctx, paths)
        self._install_steps(ctx)
        self._removal(ctx)

    def _references(self, ctx: Context, paths: set[str]) -> None:
        inv = ctx.inventory
        dirs = {posixpath.dirname(p) for p in paths}
        for d in list(dirs):
            while d:
                d = posixpath.dirname(d)
                dirs.add(d)
        # EVADE-012: instructions tell the agent to run a file the package does not contain.
        seen: set[tuple[str, str]] = set()
        # Lines of each instruction file that run a script which is in the package.
        runs_script: dict[str, set[int]] = {}
        for src, line, _ref, dst, kind in inv.references:
            if dst and kind in ("names", "runs") and dst.lower().endswith(_SCRIPT_SUFFIXES):
                runs_script.setdefault(src, set()).add(line)
        for src, line, ref, dst, kind in sorted(inv.references):
            if dst or kind != "document" or (src, ref) in seen or line < 1 or ref.startswith(("../", "/", "~", "$")):
                continue
            # "Run scripts/setup.py, then follow NEXT.md", where NEXT.md is not shipped: the script is expected to write it.
            art = inv.artifacts.get(src)
            comp = inv.components.get(art.component_id) if art else None
            at = inv.texts.get(src)
            if comp is None or at is None or comp.kind not in (ComponentKind.skill, ComponentKind.plugin, ComponentKind.bundle):
                continue
            if art.role not in (ArtifactRole.skill_md, ArtifactRole.instruction_md, ArtifactRole.command_md):
                continue
            if not any(abs(line - n) <= 2 for n in runs_script.get(src, ())):
                continue
            text_line = at.line_text(at.index.line_start(line))
            if not _FOLLOW_FILE.search(text_line) or regex.search(r"(?i)\b(?:create|write|save|generate|output|produce)s?\b", text_line):
                continue
            seen.add((src, ref))
            ctx.emit("AG-EVADE-012", component_ids=comp.id, span=Span(path=src, start_line=line), snippet=text_line.strip()[:300],
                     kind=EvidenceKind.metadata, match=f"missing:{src}:{ref}",
                     message=f"The instructions run a script and then tell the agent to follow `{ref}`, which is not in the package. "
                             "Instructions that only exist after a script writes them cannot be reviewed or scanned beforehand.")
        for src, line, ref, dst, kind in sorted(inv.references):
            if dst or kind != "names" or (src, ref) in seen:
                continue
            art = inv.artifacts.get(src)
            comp = inv.components.get(art.component_id) if art else None
            at = inv.texts.get(src)
            if comp is None or at is None or comp.kind not in (ComponentKind.skill, ComponentKind.plugin, ComponentKind.bundle):
                continue
            if art.role not in (ArtifactRole.skill_md, ArtifactRole.instruction_md, ArtifactRole.command_md):
                continue
            if ref.startswith(("../", "/", "~", "$")) or line < 1:
                continue
            if _shipped_tail(ref, comp, paths):
                continue
            text_line = at.line_text(at.index.line_start(line))
            if not _RUN_VERB.search(text_line) or regex.search(r"(?i)\b(?:create|write|save|generate|output|produce)s?\b", text_line):
                continue
            seen.add((src, ref))
            ctx.emit("AG-EVADE-012", component_ids=comp.id, span=Span(path=src, start_line=line), snippet=text_line.strip()[:300],
                     kind=EvidenceKind.metadata, match=f"missing:{src}:{ref}",
                     message=f"The instructions tell the agent to run `{ref}`, which is not in the package. A file that only exists "
                             "after something creates it at run time cannot be reviewed or scanned beforehand.")
        # HYG-003: a relative link to a file that is not there.
        for at in ctx.texts("skill_md", "instruction_md", "reference", "command_md"):
            comp = inv.components.get(at.artifact.component_id)
            if comp is None:
                continue
            base = posixpath.dirname(at.path)
            done = 0
            try:
                links = list(_MD_LINK.finditer(at.text, timeout=TIMEOUT))
            except TimeoutError:
                continue
            for m in links:
                target = m.group(1)
                if done >= 5 or regex.match(r"(?i)[a-z][a-z0-9+.\-]*:|//|#|\{|<|\$", target) or at.in_code(m.start()):
                    continue
                resolved = posixpath.normpath(posixpath.join(base, urllib.parse.unquote(target)))
                if resolved.startswith("..") or resolved in paths or resolved in dirs or resolved.rstrip("/") in dirs:
                    continue
                done += 1
                ctx.emit("AG-HYG-003", component_ids=comp.id, span=at.span(m.start(), m.end()), snippet=m.group(0)[:200],
                         kind=EvidenceKind.metadata, match=f"deadlink:{at.path}:{target}",
                         message=f"The link to `{target}` points at a file that is not in the package.")

    def _install_steps(self, ctx: Context) -> None:
        for at in ctx.texts("skill_md", "instruction_md", "command_md"):
            comp = ctx.inventory.components.get(at.artifact.component_id)
            if comp is None or comp.kind not in (ComponentKind.skill, ComponentKind.plugin, ComponentKind.command, ComponentKind.bundle):
                continue
            done = 0
            for f in at.fence_list:
                block = at.text[f.body_start:f.body_end]
                try:
                    hits = list(_UNVERSIONED.finditer(block, timeout=TIMEOUT))
                except TimeoutError:
                    continue
                for m in hits:
                    if done >= 3:
                        break
                    done += 1
                    off = f.body_start + m.start()
                    ctx.emit("AG-HYG-009", component_ids=comp.id, span=at.span(off, f.body_start + m.end()),
                             snippet=at.line_text(off).strip()[:300], kind=EvidenceKind.regex, match=f"unversioned:{m.group(0)[:80]}",
                             message="This install step fetches whatever is current (no version, tag or commit), so the same "
                                     "instructions install different software on different days.")

    def _removal(self, ctx: Context) -> None:
        inv = ctx.inventory
        for comp in sorted(inv.of_kind(ComponentKind.skill, ComponentKind.plugin, ComponentKind.bundle), key=lambda c: c.id):
            persists = next((c for c in comp.capabilities if c.label == CapLabel.persistence and c.observed), None)
            outside = next((c for c in comp.capabilities if c.label == CapLabel.fs_write_outside and c.observed), None)
            raw = next((r for r in ctx.raw if comp.id in r.component_ids and r.rid.startswith("AG-PERSIST-") and r.rid != "AG-PERSIST-015"), None)
            if persists is None and raw is None and outside is None:
                continue
            docs = "\n".join(t.text for t in inv.texts.values() if t.artifact.component_id == comp.id and t.artifact.role in (
                ArtifactRole.skill_md, ArtifactRole.instruction_md, ArtifactRole.reference, ArtifactRole.command_md))
            if _REMOVAL_WORDS.search(docs):
                continue
            ev = (persists or outside).evidence[0] if (persists or outside) and (persists or outside).evidence else None
            span = (ev.location if ev and ev.location else None) or (raw.primary if raw else None) or Span(path=comp.root or comp.name)
            what = "makes persistent changes" if (persists or raw) else "writes outside its own directory"
            if persists is not None or raw is not None:
                ctx.emit("AG-HYG-010", component_ids=comp.id, span=span, snippet=str(ev.snippet)[:200] if ev else comp.name,
                         kind=EvidenceKind.metadata, match=f"noremoval:{comp.id}",
                         message=f"The {comp.kind.spec_type} '{comp.name}' {what} and its documentation does not say how to remove them.")
            if outside is not None:
                ctx.emit("AG-PERSIST-015", component_ids=comp.id, span=span, snippet=str(ev.snippet)[:200] if ev else comp.name,
                         kind=EvidenceKind.metadata, match=f"nocleanup:{comp.id}",
                         message=f"The {comp.kind.spec_type} '{comp.name}' writes files outside its own directory and the workspace "
                                 "and documents no way to clean them up.")


__all__ = ["DependencyAnalyzer", "HygieneAnalyzer", "PACKAGE_KINDS"]
