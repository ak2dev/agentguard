"""What a package ships besides its instructions: secrets, executables, command templates and vendored code.

* AG-CRED-001: a hard-coded secret in any text file (provider key formats, private keys, high-entropy assignments).
* AG-CRED-010: an OAuth client secret stored as a literal in a configuration file.
* AG-CRED-014: a ``.env`` file whose values look live, shipped in the package.
* AG-EXEC-007: instructions, a configured command or a script run an executable that is shipped in the package.
* AG-EXEC-015: a Gemini CLI custom command whose template runs a risky shell block (``!{…}``) or injects a file from
  outside the project, or a file the arguments choose (``@{…}``).
* AG-SUPPLY-019: vendored third-party code that no longer matches its upstream: a Python ``.dist-info/RECORD`` whose
  hashes disagree with the files, or a recorded comparison in ``options.facts["vendored"]``.
"""

from __future__ import annotations

import base64
import hashlib
import posixpath
from typing import Any, ClassVar

import regex

from ..artifacts import EXECUTABLE_KINDS, ArtifactText, binary_kind
from ..inventory_surfaces import span_of
from ..models import Span
from ..models.enums import ArtifactRole, Confidence, EvidenceKind, Severity
from ..redact import redact_value
from ..secrets import find_secrets, is_placeholder, shannon_entropy
from ..textutil import TIMEOUT, sha256_hex
from .base import Context

_F = regex.IGNORECASE
MAX_PER_FILE = 5
_PROSE = (ArtifactRole.skill_md, ArtifactRole.instruction_md, ArtifactRole.command_md, ArtifactRole.reference)
_CODE = (ArtifactRole.script, ArtifactRole.source_code)
_SKIP_SECRET_ROLES = (ArtifactRole.client_config, ArtifactRole.env_file, ArtifactRole.lockfile)
_LOW_TRUST_PATH = regex.compile(r"(^|/)(?:tests?|__tests__|spec|fixtures?|testdata|examples?|samples?|docs?|mocks?)/|\.(?:test|spec)\.[a-z]+$", _F)
_CONFIG_EXT = (".json", ".jsonc", ".json5", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".properties")
_CLIENT_SECRET = regex.compile(
    r"""(?P<key>["']?(?:[a-z0-9]+[_.\-])*client[_\-]?secret["']?)\s*[:=]\s*["']?(?P<value>[^"'\s,}\]#]{8,})""", _F)
_ENV_REF = regex.compile(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|\{\{[^}]+\}\}|%[A-Za-z_][A-Za-z0-9_]*%|<[^>]+>|process\.env\.|os\.environ|env\(")
_ENV_LINE = regex.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")
_SECRET_NAME = regex.compile(r"(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|CREDENTIAL|PRIVATE|AUTH)", _F)
_EXEC_MARK = regex.compile(
    r"subprocess|os\.system|os\.exec|os\.spawn|os\.popen|Popen|child_process|execFile|spawn(?:Sync)?\(|exec(?:Sync)?\(|system\(|"
    r"Start-Process|Invoke-Expression|\bchmod\s+\+x\b|shell_exec|proc_open|\bexec\s", _F)
_COMMAND_POSITION = regex.compile(
    r"(?:^|&&|\|\||;|\||\$\(|`)\s*(?:[$>#]\s+)?(?:(?:sudo|exec|nohup|time|start|open|wine|env)\s+)*(?:[A-Za-z_][A-Za-z0-9_]*=\S+\s+)*"
    r"(?:chmod\s+\+x\s+\S+\s*(?:&&|;)\s*)?$")
_RUN_VERB = regex.compile(r"\b(?:run|runs|running|execute|executes|launch|launches|start|starts|invoke|invokes|call|calls)\b[^.\n`]{0,40}$", _F)
_INLINE_CODE = regex.compile(r"`([^`\n]{2,300})`")
_GEMINI_SHELL = regex.compile(r"!\{((?:[^{}]|\{\{[^{}]*\}\}|\{[^{}]*\})*)\}")
_GEMINI_FILE = regex.compile(r"@\{((?:[^{}]|\{\{[^{}]*\}\}|\{[^{}]*\})*)\}")
_ENV_FILE_NAME = regex.compile(r"^\.env(?:\.(?!example$|sample$|template$|dist$)[^/]+)?$", _F)
_RISKY_SHELL = regex.compile(
    r"\b(?:curl|wget|nc|ncat|scp|ssh|ftp|telnet)\b|\binvoke-webrequest\b|\biwr\b|\|\s*(?:ba|z|da)?sh\b|\beval\b|\bbase64\s+(?:-d|--decode)\b|"
    r"\brm\s+-[a-z]*[rf]|\bchmod\s+\+x\b|\bpython3?\s+-c\b|\bnode\s+-e\b|\bcrontab\b|>\s*~?/?\.(?:bashrc|zshrc|profile|ssh)|"
    r"(?:~|\$HOME)/\.(?:ssh|aws|gnupg|kube|docker|config/gcloud|netrc|npmrc|git-credentials)|\benv\b\s*(?:\||$)|\bprintenv\b", _F)
_SENSITIVE_FILE = regex.compile(
    r"^(?:~|\$HOME|/(?:etc|root|home|Users|var|proc)\b|[A-Za-z]:[\\/])|(?:^|/)\.\.(?:/|$)|"
    r"(?:^|/)\.(?:ssh|aws|gnupg|kube|docker|netrc|npmrc|git-credentials|env)(?:/|$|\.)|credentials|id_(?:rsa|ed25519)|\.pem$|\.key$", _F)
_ARGS = regex.compile(r"\{\{\s*args\s*\}\}", _F)


def _search(rx: regex.Pattern[str], text: str) -> regex.Match[str] | None:
    try:
        return rx.search(text, timeout=TIMEOUT)
    except TimeoutError:
        return None


# A name that contains "token", "secret" or "password" and holds something else: a tokenizer, a count or
# limit, a password policy, or the name, URL, path or template that points at where the secret is kept.
_NOT_SECRET_NAME = regex.compile(
    r"token(?:i[sz]er|i[sz]e|i[sz]ation)|"
    r"(?:tokens?|secrets?|passw(?:or)?ds?|pwd|credentials?|api[_\-]?keys?)[_\-]?"
    r"(?:count|limit|budget|len|length|usage|type|kind|name|names|url|uri|endpoint|file|path|dir|id|ids|header|prefix|suffix|"
    r"field|param|expir\w*|ttl|required\w*|min\w*|max\w*|policy|characters?|charset|strength|hint|input|prompt|regex|"
    r"pattern|rules?|reset|template|ref|arn|version|manager|env|var|label|placeholder|format|scope|source|location)\b|"
    r"(?:url|uri|template|path|file|name|header|label|env|var|placeholder|format)[\"']?$", _F)
_KEY_BEFORE = regex.compile(r"([A-Za-z0-9_\-.]+)[\"']?\s*[:=]\s*[\"']?$")
# A reference a build system or template fills in, or a plain URL or `owner/name` identifier.
_NOT_SECRET_VALUE = regex.compile(
    r"^(?:\$\(|\$\{\{|%\(|#\{|\{\{)|^https?://(?![^/\s@]+:[^/\s@]+@)[^\s]*$|^[A-Za-z0-9][\w.\-]*/[A-Za-z0-9][\w.\-]*$", _F)
_SECRET_QUERY = regex.compile(r"[?&](?:[a-z_\-]*(?:key|token|secret|sig|signature|password|auth)[a-z_\-]*)=[A-Za-z0-9._~%+/\-]{16,}", _F)
_DOC_COMMENT_LINE = regex.compile(r"^\s*\*\s")     # a line of a /** ... */ block


def not_a_secret(text: str, start: int, value: str) -> bool:
    """A name-based ("generic assignment") match that is not a credential: the name says it holds
    something else, or the value is a reference, a URL without credentials, or an identifier."""
    line_start = text.rfind("\n", 0, start) + 1
    if _DOC_COMMENT_LINE.match(text[line_start:start]):
        return True             # an example inside a documentation comment
    m = _search(_KEY_BEFORE, text[max(0, start - 200):start])
    if m and _search(_NOT_SECRET_NAME, m.group(1)):
        return True
    if _search(_NOT_SECRET_VALUE, value):
        return not _search(_SECRET_QUERY, value)
    return False


def live_looking(name: str, value: str) -> str:
    """Why the value of an environment-file line looks like a real secret, or ""."""
    value = value.strip().strip("\"'")
    if len(value) < 8 or is_placeholder(value) or _search(_ENV_REF, value):
        return ""
    found = [s for s in find_secrets(f"{name}={value}", include_placeholders=False) if s.kind != "generic_assignment"]
    if found:
        return found[0].kind.replace("_", " ")
    if _search(_SECRET_NAME, name) and len(value) >= 16 and shannon_entropy(value) >= 3.5 and not regex.fullmatch(r"[a-z]+(?:[-_ ][a-z]+)*", value):
        return "a high-entropy value under a secret-like name"
    return ""


class ShippedContentAnalyzer:
    id: ClassVar[str] = "shipped"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = ("AG-CRED-001", "AG-CRED-010", "AG-CRED-014", "AG-EXEC-007", "AG-EXEC-015", "AG-SUPPLY-019")

    def run(self, ctx: Context) -> None:
        self.ctx = ctx
        self.inv = ctx.inventory
        self.tree = ctx.inventory.tree
        self._claimed: set[tuple[str, str]] = set()        # (path, secret value) already reported by a narrower rule
        self._client_secrets()
        self._env_files()
        self._secrets()
        self._binaries()
        self._gemini_commands()
        self._vendored()

    def _cid(self, path: str) -> list[str]:
        art = self.inv.artifacts.get(path)
        return [art.component_id] if art is not None else []

    # -- AG-CRED-010 ----------------------------------------------------------------------------------------
    def _client_secrets(self) -> None:
        for at in self.ctx.texts():
            if not at.path.lower().endswith(_CONFIG_EXT) or at.artifact.role in _SKIP_SECRET_ROLES:
                continue
            done = 0
            try:
                matches = list(_CLIENT_SECRET.finditer(at.text, timeout=TIMEOUT))
            except TimeoutError:
                continue
            for m in matches:
                value = m.group("value")
                if is_placeholder(value) or _search(_ENV_REF, value) or shannon_entropy(value) < 2.5:
                    continue
                self._claimed.add((at.path, value))
                key = m.group("key").strip("\"'")
                self.ctx.emit("AG-CRED-010", component_ids=at.artifact.component_id, span=at.span(m.start("value"), m.end("value")),
                              snippet=f"{key}: {redact_value(value)}", match=f"{at.path}:{key}:{sha256_hex(value)[:12]}",
                              kind=EvidenceKind.regex, detail=f"key: {key}",
                              message=f"`{at.path}` stores an OAuth client secret as a literal under `{key}`. Everyone who receives the "
                                      "file can act as this client, and the secret cannot be rotated without shipping a new file.")
                done += 1
                if done >= MAX_PER_FILE:
                    break

    # -- AG-CRED-014 ----------------------------------------------------------------------------------------
    def _env_files(self) -> None:
        if self.tree is None:
            return
        for path, art in sorted(self.inv.artifacts.items()):
            if art.role != ArtifactRole.env_file and not _ENV_FILE_NAME.match(posixpath.basename(path)):
                continue
            blob = self.tree.files.get(path)
            if blob is None:
                continue
            text = blob.data.decode("utf-8", "replace")
            live: list[tuple[int, str, str]] = []
            for no, line in enumerate(text.split("\n"), start=1):
                if line.lstrip().startswith("#"):
                    continue
                m = _ENV_LINE.match(line)
                if not m:
                    continue
                why = live_looking(m.group(1), m.group(2))
                if why:
                    live.append((no, m.group(1), why))
                    self._claimed.add((path, m.group(2).strip().strip("\"'")))
            if not live:
                continue
            names = ", ".join(f"`{n}`" for _, n, _ in live[:5])
            self.ctx.emit("AG-CRED-014", component_ids=art.component_id, span=Span(path=path, start_line=live[0][0]),
                          snippet=", ".join(f"{n}=<redacted>" for _, n, _ in live[:5]), match=f"{path}:{[n for _, n, _ in live]}",
                          kind=EvidenceKind.regex, detail=f"key: {live[0][1]}",
                          message=f"`{path}` is shipped with {len(live)} value(s) that look live ({names}; the first is {live[0][2]}). "
                                  "An environment file belongs on the machine that uses it, not in a package: everyone who installs "
                                  "this gets the secret, and the agent loads it into its environment.")

    # -- AG-CRED-001 ----------------------------------------------------------------------------------------
    def _secrets(self) -> None:
        for at in self.ctx.texts():
            role = at.artifact.role
            if role in _SKIP_SECRET_ROLES or len(at.text) > 2_000_000 or _ENV_FILE_NAME.match(posixpath.basename(at.path)):
                continue
            found = find_secrets(at.text, include_placeholders=False)
            if not found:
                continue
            soft = bool(_search(_LOW_TRUST_PATH, at.path)) or role == ArtifactRole.repo_doc
            done = 0
            seen: set[str] = set()
            for s in found:
                if (at.path, s.value) in self._claimed or s.value in seen:
                    continue
                if s.kind == "generic_assignment" and (len(s.value) < 16 or shannon_entropy(s.value) < 3.6 or _search(_ENV_REF, s.value)
                                                       or not_a_secret(at.text, s.start, s.value)):
                    continue
                if s.kind in ("bearer_token", "url_credentials", "jwt") and (soft or shannon_entropy(s.value) < 3.6):
                    continue
                if at.in_code(s.start) and role in _PROSE and s.kind in ("generic_assignment", "bearer_token", "url_credentials"):
                    continue        # documentation examples in a fenced block; provider-format keys are still reported
                seen.add(s.value)
                kind = s.kind.replace("_", " ")
                self.ctx.emit("AG-CRED-001", component_ids=at.artifact.component_id, span=at.span(s.start, s.end),
                              snippet=at.line_text(s.start)[:240], match=f"{at.path}:{s.kind}:{sha256_hex(s.value)[:12]}",
                              kind=EvidenceKind.regex, detail=kind,
                              severity=Severity.medium if soft else None, confidence=Confidence.medium if soft else None,
                              message=f"`{at.path}` contains a hard-coded secret ({kind}: `{redact_value(s.value)}`). Anyone who can "
                                      "read the package can use it, and an agent that loads the file carries it into its context "
                                      "and its logs.")
                done += 1
                if done >= MAX_PER_FILE:
                    break

    # -- AG-EXEC-007 ----------------------------------------------------------------------------------------
    def _binaries(self) -> None:
        if self.tree is None:
            return
        exes: dict[str, str] = {}
        for path, art in self.inv.artifacts.items():
            if art.role != ArtifactRole.binary:
                continue
            blob = self.tree.files.get(path)
            kind = binary_kind(blob.data) if blob is not None else None
            if kind in EXECUTABLE_KINDS and len(posixpath.basename(path)) >= 3:
                exes[path] = kind or ""
        if not exes:
            return
        patterns = {p: regex.compile(r"(?<![\w.\-/])(?P<tok>(?:\.{1,2}/|[\w${}.\-]+/)*" + regex.escape(posixpath.basename(p)) + r")(?![\w\-])")
                    for p in exes}
        reported: set[str] = set()

        def fits(path: str, token: str) -> bool:
            token = token.lstrip("./")
            rel = regex.sub(r"^(?:\$\{?[A-Z_]+\}?/)+", "", token)
            return path == rel or path.endswith("/" + rel)

        def hit(path: str, where: str, span: Span, snippet: str, cids: list[str]) -> None:
            if path in reported:
                return
            reported.add(path)
            kind = {"elf": "an ELF", "pe": "a Windows", "macho": "a Mach-O", "wasm": "a WebAssembly"}.get(exes[path], "a compiled")
            self.ctx.emit("AG-EXEC-007", component_ids=cids or self._cid(path), span=span, snippet=snippet[:240],
                          match=f"binary:{path}:{span.path}", kind=EvidenceKind.regex, related=[Span(path=path)],
                          message=f"{where} runs `{path}`, {kind} executable shipped in the package. A compiled file cannot be "
                                  "reviewed the way a script can: the scanner sees what starts it, not what it does.")

        for at in self.ctx.texts():
            role = at.artifact.role
            if role in _PROSE:
                self._binary_in_prose(at, patterns, fits, hit)
            elif role in _CODE:
                offset = 0
                for line in at.text.split("\n"):
                    start = offset
                    offset += len(line) + 1
                    if len(line) > 2000:
                        continue
                    for path, rx in patterns.items():
                        m = _search(rx, line)
                        if m and fits(path, m.group("tok")) and (_search(_EXEC_MARK, line) or _search(_COMMAND_POSITION, line[:m.start()])):
                            hit(path, f"`{at.path}`", at.span(start + m.start(), start + m.end()), line.strip(), [at.artifact.component_id])
        for cmd in self.ctx.data.get("config_commands", []):  # type: ignore[union-attr]
            for path, rx in patterns.items():
                m = _search(rx, cmd.text)
                if m and fits(path, m.group("tok")) and _search(_COMMAND_POSITION, cmd.text[:m.start()]):
                    hit(path, f"The command at `{'.'.join(cmd.keypath)}` in `{cmd.path}`", cmd.span, cmd.text, [cmd.component_id])

    def _binary_in_prose(self, at: ArtifactText, patterns: dict[str, regex.Pattern[str]], fits: Any, hit: Any) -> None:
        cid = [at.artifact.component_id]
        for f in at.fence_list:
            pos = f.body_start
            for line in at.text[f.body_start:f.body_end].split("\n"):
                for path, rx in patterns.items():
                    m = _search(rx, line)
                    if m and fits(path, m.group("tok")) and _search(_COMMAND_POSITION, line[:m.start()]):
                        hit(path, f"A command in `{at.path}`", at.span(pos + m.start(), pos + m.end()), line.strip(), cid)
                pos += len(line) + 1
        try:
            spans = list(_INLINE_CODE.finditer(at.text, timeout=TIMEOUT))
        except TimeoutError:
            return
        for cm in spans:
            if at.in_code(cm.start()):
                continue
            code = cm.group(1)
            for path, rx in patterns.items():
                m = _search(rx, code)
                if not m or not fits(path, m.group("tok")) or not _search(_COMMAND_POSITION, code[:m.start()]):
                    continue
                line_start = at.text.rfind("\n", 0, cm.start()) + 1
                has_arguments = bool(code[m.end():].strip())
                if has_arguments or _search(_RUN_VERB, at.text[line_start:cm.start()]):
                    hit(path, f"`{at.path}`", at.span(cm.start(1) + m.start(), cm.start(1) + m.end()), at.line_text(cm.start()).strip(), cid)

    # -- AG-EXEC-015 ----------------------------------------------------------------------------------------
    def _gemini_commands(self) -> None:
        for doc in self.inv.of_surface("gemini.command"):
            prompt = doc.data.get("prompt")
            if not isinstance(prompt, str):
                continue
            cid = self._cid(doc.path)
            for m in _GEMINI_SHELL.finditer(prompt):
                body = m.group(1).strip()
                risky = _search(_RISKY_SHELL, body)
                if risky:
                    self.ctx.emit("AG-EXEC-015", component_ids=cid, span=span_of(doc.text, "prompt", body[:40], path=doc.path),
                                  snippet=m.group(0)[:240], match=f"shell:{doc.path}:{body[:120]}", kind=EvidenceKind.regex,
                                  detail="key: prompt",
                                  message=f"The custom command in `{doc.path}` runs `{body[:100]}` through `!{{…}}` every time it is "
                                          f"used, and the block contains `{risky.group(0).strip()}`. The command's output is placed "
                                          "in the prompt, so this both runs code and feeds the result to the model.")
            for m in _GEMINI_FILE.finditer(prompt):
                target = m.group(1).strip()
                sensitive = _search(_SENSITIVE_FILE, target)
                chosen = _search(_ARGS, target)
                if not sensitive and not chosen:
                    continue
                why = (f"reads `{target[:100]}`, a path outside the project or a credential file" if sensitive
                       else f"reads the file its arguments name (`{target[:100]}`), so any file the user can read can be pulled into the prompt")
                self.ctx.emit("AG-EXEC-015", component_ids=cid, span=span_of(doc.text, "prompt", target[:40], path=doc.path),
                              snippet=m.group(0)[:240], match=f"file:{doc.path}:{target[:120]}", kind=EvidenceKind.regex,
                              detail="key: prompt", severity=None if sensitive else Severity.medium,
                              message=f"The custom command in `{doc.path}` uses `@{{…}}` file injection and {why}.")

    # -- AG-SUPPLY-019 --------------------------------------------------------------------------------------
    def _vendored(self) -> None:
        tree = self.tree
        if tree is None:
            return
        for record in sorted(p for p in tree.files if p.endswith(".dist-info/RECORD")):
            base = posixpath.dirname(posixpath.dirname(record))
            changed: list[str] = []
            text = tree.files[record].data.decode("utf-8", "replace")
            for line in text.splitlines()[:20000]:
                parts = line.rsplit(",", 2)
                if len(parts) != 3 or not parts[1].startswith("sha256="):
                    continue
                target = posixpath.normpath(posixpath.join(base, parts[0])) if base else posixpath.normpath(parts[0])
                blob = tree.files.get(target)
                if blob is None:
                    continue
                digest = base64.urlsafe_b64encode(hashlib.sha256(blob.data).digest()).rstrip(b"=").decode("ascii")
                if digest != parts[1][len("sha256="):].rstrip("="):
                    changed.append(target)
            if changed:
                package = posixpath.basename(posixpath.dirname(record))[: -len(".dist-info")]
                self._vendored_finding(package, changed, [], record)
        facts = self.ctx.options.facts if isinstance(self.ctx.options.facts, dict) else {}
        vendored = facts.get("vendored") if isinstance(facts.get("vendored"), dict) else {}
        for root, info in sorted(vendored.items()):
            if not isinstance(info, dict):
                continue
            changed = [posixpath.join(root, str(x)) for x in info.get("changed") or []]
            added = [posixpath.join(root, str(x)) for x in info.get("only_local") or []]
            if changed or added:
                self._vendored_finding(str(info.get("upstream") or root), changed, added, root)

    def _vendored_finding(self, package: str, changed: list[str], added: list[str], origin: str) -> None:
        first = (changed + added)[0]
        tree = self.tree
        path = first if tree is not None and first in tree.files else origin
        bits = []
        if changed:
            bits.append(f"{len(changed)} file(s) differ from the published copy ({', '.join('`' + c + '`' for c in changed[:3])})")
        if added:
            bits.append(f"{len(added)} file(s) are not in the published copy ({', '.join('`' + a + '`' for a in added[:3])})")
        self.ctx.emit("AG-SUPPLY-019", component_ids=self._cid(path), span=Span(path=path, start_line=1),
                      snippet=", ".join((changed + added)[:6]), match=f"vendored:{package}:{sorted(changed + added)}",
                      kind=EvidenceKind.metadata, related=[Span(path=origin)] if origin != path else [],
                      message=f"The vendored copy of `{package}` is not the code its publisher released: {'; '.join(bits)}. A reviewer "
                              "who recognises the library name will not read it, which makes a vendored dependency a place to hide a change.")


__all__ = ["ShippedContentAnalyzer", "live_looking"]
