"""Second half of the inventory: everything that is not a skill, an MCP client
configuration or an MCP source package.

* plugins, extensions and bundles own their directory;
* every other agent-facing file becomes a component of its own (settings, hook
  files, subagents, commands, instruction files, CI workflows, workspace
  auto-execution files, containers, connector descriptors);
* what is left belongs to one catch-all ``repository`` component, so every
  file of the tree is accounted for;
* files an agent-facing file imports, runs or names are promoted out of the
  catch-all into the component that references them.

Parsed documents are kept in ``inv.docs`` for the configuration analyzers.
Pure: no filesystem, no network.
"""

from __future__ import annotations

import posixpath
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import regex

from .artifacts import binary_kind, is_markdown, language_for
from .discover import Surface, generic_role, is_agentic_ci, surface_for
from .models import Artifact, Component, LoadLimits, Span
from .models.enums import ArtifactRole, ComponentKind
from .parsers import parse_json, parse_toml, safe_load
from .parsers.json5 import parse_json5
from .scriptshape import RUN_AS_SCRIPT, is_script, language_of_run
from .textutil import TIMEOUT
from .tree import ArtifactTree

if TYPE_CHECKING:
    from .inventory import Inventory

K, R = ComponentKind, ArtifactRole


@dataclass
class Doc:
    """A parsed structured file of a known surface."""

    path: str
    surface: Surface
    value: Any = None
    error: str | None = None
    fmt: str = ""
    text: str = ""

    @property
    def data(self) -> dict[str, Any]:
        return self.value if isinstance(self.value, dict) else {}


# (manifest path pattern, directory levels from the manifest up to the plugin root, agent)
PLUGIN_MANIFESTS = (
    (r"(^|/)\.claude-plugin/plugin\.json$", 2, "claude-code"),
    (r"(^|/)\.codex-plugin/plugin\.json$", 2, "codex"),
    (r"(^|/)\.cursor-plugin/plugin\.json$", 2, "cursor"),
    (r"(^|/)gemini-extension\.json$", 1, "gemini"),
    (r"(^|/)openclaw\.plugin\.json$", 1, "openclaw"),
)
# Surfaces of files inside a plugin, by their path relative to the plugin root.
_PLUGIN_REL: tuple[tuple[str, str, ArtifactRole, str], ...] = (
    (r"^agents/.+\.md$", "plugin.agent", R.instruction_md, "md"),
    (r"^commands/.+\.md$", "plugin.command", R.command_md, "md"),
    (r"^commands/.+\.toml$", "gemini.command", R.command_md, "toml"),
    (r"^hooks/hooks\.json$", "plugin.hooks", R.hook_config, "json"),
    (r"^hooks/[^/]+/HOOK\.md$", "openclaw.hook", R.hook_config, "md"),
    (r"^settings\.json$", "plugin.settings", R.settings, "json"),
    (r"^policies/.+\.toml$", "gemini.policy", R.settings, "toml"),
    (r"^\.lsp\.json$", "claude.lsp", R.plugin_manifest, "json"),
    (r"^monitors/monitors\.json$", "claude.monitors", R.plugin_manifest, "json"),
    (r"^workflows/.+\.(js|mjs|cjs|ts)$", "plugin.workflow", R.script, ""),
    (r"^mods?/.+\.(js|mjs|cjs|ts)$", "plugin.mod", R.script, ""),
    (r"^bin/[^/]+$", "plugin.bin", R.script, ""),
    (r"^(output-styles|themes)/.+\.(md|json)$", "plugin.style", R.reference, ""),
)
_PLUGIN_REL_RX = tuple((regex.compile(p, regex.IGNORECASE), sid, role, fmt) for p, sid, role, fmt in _PLUGIN_REL)
# `@path` imports. A path into the home directory or from the filesystem root needs no extension (`@~/.ssh/config`).
_IMPORT = regex.compile(r"(?<![\w`@/])@((?:~/|/)[A-Za-z0-9_.\-]+(?:/[A-Za-z0-9_.\-]+)*"
                        r"|(?:\.{1,2}/)*[A-Za-z0-9_.\-]+(?:/[A-Za-z0-9_.\-]+)*\.[A-Za-z0-9]{1,8})")
_PATH_TOKEN = regex.compile(
    r"(?<![\w/@.\-])((?:\$\{?(?:CLAUDE_PROJECT_DIR|CLAUDE_PLUGIN_ROOT|CLAUDE_SKILL_DIR|GITHUB_WORKSPACE|workspaceFolder|PWD)\}?/|\./|\.\./)?"
    r"(?:[A-Za-z0-9_.\-]+/)*[A-Za-z0-9_.\-]+\.(?:sh|bash|zsh|py|js|mjs|cjs|ts|ps1|bat|cmd|rb|pl|php|lua|md|mdc|txt))(?![\w/])")
_SCRIPT_EXT = (".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts", ".ps1", ".bat", ".cmd", ".rb", ".pl", ".php", ".lua")
_REFERENCING_GROUPS = ("hooks", "settings", "ci", "workspace", "plugin", "command", "agent", "instructions", "marketplace")
MAX_IMPORT_HOPS = 5
MAX_PROMOTIONS = 2000


def parse_doc(path: str, surface: Surface, data: bytes) -> Doc:
    text = data.decode("utf-8", "replace")
    fmt = surface.fmt
    lower = path.lower()
    if not fmt:
        fmt = "yaml" if lower.endswith((".yaml", ".yml")) else "json" if lower.endswith((".json", ".jsonc", ".json5")) else ""
    doc = Doc(path=path, surface=surface, fmt=fmt, text=text)
    if fmt == "json":
        parsed = parse_json(text)
        if parsed.error:
            retry = parse_json5(text)
            parsed = retry if retry.error is None else parsed
        doc.value, doc.error = parsed.value, parsed.error
    elif fmt == "json5":
        parsed = parse_json5(text)
        doc.value, doc.error = parsed.value, parsed.error
    elif fmt == "toml":
        parsed = parse_toml(text)
        doc.value, doc.error = parsed.value, parsed.error
    elif fmt == "yaml":
        res = safe_load(text, aliases=True)          # compose files and CI workflows use anchors routinely
        doc.value, doc.error = res.value, res.error
    return doc


def _plugin_surface(rel: str, agent: str) -> Surface | None:
    for rx, sid, role, fmt in _PLUGIN_REL_RX:
        try:
            if rx.search(rel, timeout=TIMEOUT):
                kind = {"hooks": K.hook, "agent": K.subagent, "command": K.command}.get(sid.split(".", 1)[1], K.plugin)
                group = {"plugin.hooks": "hooks", "openclaw.hook": "hooks", "plugin.agent": "agent", "plugin.command": "command",
                         "gemini.command": "command", "gemini.policy": "settings", "plugin.settings": "settings"}.get(sid, "plugin")
                return Surface(sid, kind, role, agent, fmt, 1, group)
        except TimeoutError:
            continue
    return None


def _under(path: str, root: str) -> bool:
    return root == "" or path == root or path.startswith(root + "/")


def _text_role(path: str, data: bytes) -> ArtifactRole:
    """Role of a file shipped inside a plugin, bundle or other agent package: the agent can reach it."""
    kind = binary_kind(data)
    role = generic_role(path, data, kind, language_for(path, data), is_markdown(path))
    if role == R.package_manifest and path.lower().endswith(".py"):
        return R.script                      # `setup.py`: a manifest by name, a program by content
    return {R.repo_code: R.script, R.repo_doc: R.reference}.get(role, role)


def add_surfaces(inv: Inventory, tree: ArtifactTree, limits: LoadLimits,
                 add_artifact: Callable[[str, Component, ArtifactRole], Artifact],
                 new_component: Callable[..., Component], owning_skill: Callable[[str], str | None]) -> None:
    paths = tree.paths()

    # -- plugins, extensions and bundles own their directory ---------------------------------------
    owners: dict[str, Component] = {}          # root dir -> component
    owner_agent: dict[str, str] = {}
    for p in paths:
        for pattern, up, agent in PLUGIN_MANIFESTS:
            if not regex.search(pattern, p, regex.IGNORECASE, timeout=TIMEOUT):
                continue
            root = p
            for _ in range(up):
                root = posixpath.dirname(root)
            if root in owners:
                continue
            surface = surface_for(p, tree.files[p].data[:8192])
            doc = parse_doc(p, surface, tree.files[p].data) if surface else None
            data = doc.data if doc else {}
            author = data.get("author")
            publisher = author.get("name") if isinstance(author, dict) else author if isinstance(author, str) else None
            name = str(data.get("name") or posixpath.basename(root) or "plugin")[:128]
            owners[root] = new_component(
                K.plugin, name, root, version=str(data["version"])[:64] if data.get("version") is not None else None,
                publisher=str(publisher)[:128] if publisher else None, metadata={"agent": agent, "manifest": p})
            owner_agent[root] = agent
    for p in paths:
        if posixpath.basename(p).lower() != "manifest.json" or p in inv.artifacts:
            continue
        surface = surface_for(p, tree.files[p].data[:8192])
        if surface is None or surface.id != "bundle.mcpb":
            continue
        root = posixpath.dirname(p)
        if root in owners:
            continue
        doc = parse_doc(p, surface, tree.files[p].data)
        author = doc.data.get("author")
        owners[root] = new_component(
            K.bundle, str(doc.data.get("name") or posixpath.basename(root) or "bundle")[:128], root,
            version=str(doc.data["version"])[:64] if doc.data.get("version") is not None else None,
            publisher=str(author.get("name"))[:128] if isinstance(author, dict) and author.get("name") else None,
            metadata={"agent": "mcp", "manifest": p})
        owner_agent[root] = "mcp"
        _bundle_definitions(owners[root], doc)
    roots = sorted(owners, key=lambda r: (-len(r), r))

    def owner_of(path: str) -> str | None:
        return next((r for r in roots if _under(path, r)), None)

    repo: Component | None = None

    def repository() -> Component:
        nonlocal repo
        if repo is None:
            label = (tree.display_root or "").replace("\\", "/").rstrip("/").rsplit("/", 1)[-1] or "repository"
            repo = new_component(K.repository, label[:128], "", metadata={"agent": "generic"})
        return repo

    # -- every file gets a surface (where it has one), a parsed document and an owner ----------------
    for p in paths:
        blob = tree.files[p]
        root = owner_of(p)
        surface = surface_for(p, blob.data[:8192])
        if root is not None:
            rel = p[len(root) + 1:] if root else p
            inner = _plugin_surface(rel, owner_agent[root])
            if inner is not None and (surface is None or surface.group in ("instructions", "hooks") or surface.tier == 3):
                surface = inner
            elif surface is not None and surface.id == "plugin.hooks":
                surface = Surface(surface.id, surface.kind, surface.role, owner_agent[root], surface.fmt, 1, surface.group)
        if surface is not None:
            inv.surfaces[p] = surface
            if surface.fmt or surface.id == "descriptor.openapi":
                doc = parse_doc(p, surface, blob.data)
                if doc.fmt in ("json", "json5", "toml", "yaml"):
                    inv.docs[p] = doc
            # A workflow that names a coding agent, or a GitHub agentic workflow (Markdown with frontmatter).
            if surface.group == "ci" and (is_agentic_ci(blob.data.decode("utf-8", "replace"))
                                          or (surface.id == "ci.agentic_md" and blob.data.lstrip().startswith(b"---"))):
                inv.agentic_ci.add(p)
        if p in inv.artifacts:
            continue
        if root is not None:
            comp = owners[root]
            role = surface.role if surface is not None else _text_role(p, blob.data)
            if surface is not None and surface.role == R.script and binary_kind(blob.data):
                role = R.binary
            add_artifact(p, comp, role)
            continue
        if surface is not None and surface.kind != K.repository and not (surface.group == "ci" and p not in inv.agentic_ci
                                                                         and surface.id != "ci.copilot_setup"):
            name = posixpath.basename(p)
            if surface.kind in (K.subagent, K.command):
                name = posixpath.splitext(name)[0]
                name = name[:-len(".agent")] if name.endswith(".agent") else name[:-len(".prompt")] if name.endswith(".prompt") else name
            comp = new_component(surface.kind, name[:128], p, metadata={"agent": surface.agent, "surface": surface.id})
            add_artifact(p, comp, surface.role)
            continue
        kind = binary_kind(blob.data)
        role = surface.role if surface is not None else generic_role(p, blob.data, kind, language_for(p, blob.data), is_markdown(p))
        add_artifact(p, repository(), role)

    for doc in inv.docs.values():
        if doc.error:
            inv.parse_failures.append((doc.path, doc.error, doc.surface.id))

    _link_references(inv, tree, add_artifact, owner_of, owners)


def _bundle_definitions(comp: Component, doc: Doc) -> None:
    """Tools and prompts an MCPB manifest declares: their text reaches the model, so the definition rules read them."""
    from .models import PromptDef, ToolDef

    for t in doc.data.get("tools") if isinstance(doc.data.get("tools"), list) else []:
        if isinstance(t, dict) and isinstance(t.get("name"), str):
            comp.tools.append(ToolDef(name=t["name"][:128], description=t.get("description") if isinstance(t.get("description"), str) else None,
                                      origin="manifest", span=span_of(doc.text, '"tools"', f'"{t["name"]}"', path=doc.path)))
    for pr in doc.data.get("prompts") if isinstance(doc.data.get("prompts"), list) else []:
        if isinstance(pr, dict) and isinstance(pr.get("name"), str):
            comp.prompts.append(PromptDef(name=pr["name"][:128], description=pr.get("description") if isinstance(pr.get("description"), str) else None,
                                          messages=[pr["text"]] if isinstance(pr.get("text"), str) else [],
                                          span=span_of(doc.text, '"prompts"', f'"{pr["name"]}"', path=doc.path)))


def _strings(value: Any, out: list[str], budget: list[int]) -> None:
    if budget[0] <= 0:
        return
    if isinstance(value, str):
        budget[0] -= 1
        if 2 < len(value) < 4000:
            out.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            _strings(v, out, budget)
    elif isinstance(value, list):
        for v in value:
            _strings(v, out, budget)


def _candidates(src: str, token: str, plugin_root: str | None) -> list[str]:
    """Tree paths a reference in ``src`` may name."""
    t = token.replace("\\", "/")
    t = regex.sub(r"^\$\{?(CLAUDE_PLUGIN_ROOT|CLAUDE_SKILL_DIR)\}?/", "\x00plugin/", t)
    t = regex.sub(r"^\$\{?(CLAUDE_PROJECT_DIR|GITHUB_WORKSPACE|workspaceFolder|PWD)\}?/", "\x00root/", t)
    out: list[str] = []
    here = posixpath.dirname(src)
    if t.startswith("\x00plugin/"):
        out.append(posixpath.normpath(posixpath.join(plugin_root if plugin_root is not None else here, t[8:])))
    elif t.startswith("\x00root/"):
        out.append(posixpath.normpath(t[6:]))
    else:
        out.append(posixpath.normpath(posixpath.join(here, t)))
        if plugin_root is not None:
            out.append(posixpath.normpath(posixpath.join(plugin_root, t)))
        # Agent files under a dot-directory (.claude/, .github/…) name files relative to the repository root.
        parts = src.split("/")
        for i, seg in enumerate(parts[:-1]):
            if seg.startswith(".") and len(seg) > 1:
                out.append(posixpath.normpath(posixpath.join("/".join(parts[:i]), t)))
                break
        out.append(posixpath.normpath(t))
    return [c.lstrip("./") if c.startswith("./") else c for c in dict.fromkeys(out) if not c.startswith("..")]


def _link_references(inv: Inventory, tree: ArtifactTree, add_artifact: Callable[[str, Component, ArtifactRole], Artifact],
                     owner_of: Callable[[str], str | None], owners: dict[str, Component]) -> None:
    """Follow imports (``@path`` in instruction files) and named scripts from
    agent-facing files into the catch-all, and record every edge."""
    repo_roles = (R.repo_code, R.repo_doc)
    promoted = 0

    def promote(dst: str, comp: Component, role: ArtifactRole) -> None:
        nonlocal promoted
        art = inv.artifacts.get(dst)
        if art is None or art.role not in repo_roles or promoted >= MAX_PROMOTIONS:
            return
        old = inv.components.get(art.component_id)
        if old is not None and art.id in old.artifact_ids:
            old.artifact_ids.remove(art.id)
        inv.artifacts.pop(dst, None)
        inv.texts.pop(dst, None)
        add_artifact(dst, comp, role)
        promoted += 1

    def scan_file(src: str, hops: int, seen: set[str]) -> None:
        art = inv.artifacts.get(src)
        comp = inv.components.get(art.component_id) if art else None
        if art is None or comp is None or src in seen:
            return
        seen.add(src)
        at = inv.texts.get(src)
        surface = inv.surfaces.get(src)
        plugin_root = owner_of(src)
        is_instruction = art.role in (R.instruction_md, R.skill_md, R.command_md)
        texts: list[tuple[str, int]] = []      # (text, base line) to look for path tokens in
        doc = inv.docs.get(src)
        if doc is not None and doc.value is not None:
            strings: list[str] = []
            _strings(doc.value, strings, [5000])
            texts += [(s, 0) for s in strings]
        elif at is not None and (is_instruction or art.role in (R.hook_config, R.workflow, R.workspace_config, R.dockerfile)):
            texts.append((at.text, 1))
        if at is not None and is_instruction:
            body_start = at.fm.body_offset if at.fm is not None else 0
            try:
                imports = list(_IMPORT.finditer(at.text, body_start, timeout=TIMEOUT))
            except TimeoutError:
                imports = []
            for m in imports[:200]:
                if at.in_code(m.start()):
                    continue
                ref = m.group(1)
                line = at.index.line_col(m.start())[0]
                if ref.startswith(("~/", "/")) or ref.startswith("../") and not any(c in tree.files for c in _candidates(src, ref, plugin_root)):
                    inv.references.append((src, line, ref, "", "import"))
                    continue
                hit = next((c for c in _candidates(src, ref, plugin_root) if c in tree.files), None)
                inv.references.append((src, line, ref, hit or "", "import"))
                if hit is not None and hit != src:
                    if is_markdown(hit) or inv.artifacts.get(hit, art).role == R.repo_doc:
                        promote(hit, comp, R.instruction_md)
                    if hops < MAX_IMPORT_HOPS:
                        scan_file(hit, hops + 1, seen)
        if surface is None and not is_instruction:
            return
        if surface is not None and surface.group not in _REFERENCING_GROUPS and not is_instruction:
            return
        found = 0
        for text, base in texts:
            try:
                hits = list(_PATH_TOKEN.finditer(text, timeout=TIMEOUT))
            except TimeoutError:
                continue
            for m in hits:
                token = m.group(1)
                if found >= 300:
                    break
                hit = next((c for c in _candidates(src, token, plugin_root) if c in tree.files), None)
                line = (text.count("\n", 0, m.start()) + base) if base else 0
                if hit is None or hit == src:
                    if token.lower().endswith(_SCRIPT_EXT) and "/" in token:
                        inv.references.append((src, line, token, "", "names"))
                    elif is_instruction and hit is None and token.lower().endswith((".md", ".mdc", ".txt")):
                        inv.references.append((src, line, token, "", "document"))
                    continue
                found += 1
                inv.references.append((src, line, token, hit, "names"))
                target = inv.artifacts.get(hit)
                if target is not None and target.role in repo_roles:
                    promote(hit, comp, R.script if target.role == R.repo_code else R.reference)
            # A file run with an interpreter is a script whatever its extension says (`python notes.dat`).
            try:
                runs = list(RUN_AS_SCRIPT.finditer(text, timeout=TIMEOUT))
            except TimeoutError:
                runs = []
            for m in runs[:40]:
                token = m.group("file") or m.group("file2") or m.group("file3")
                how = m.group("how") or m.group("how2") or m.group("how3") or ""
                hit = next((c for c in _candidates(src, token, plugin_root) if c in tree.files), None)
                if hit is not None and hit != src and retype(hit, comp, language_of_run(how)):
                    line = (text.count("\n", 0, m.start()) + base) if base else 0
                    inv.references.append((src, line, token, hit, "runs"))

    def retype(dst: str, comp: Component, language: str) -> bool:
        """Analyse ``dst`` as a script: something runs it with an interpreter and it reads as one."""
        nonlocal promoted
        art = inv.artifacts.get(dst)
        if art is None or art.role in (R.script, R.source_code, R.skill_md, R.instruction_md, R.command_md) or promoted >= MAX_PROMOTIONS:
            return False
        data = tree.files[dst].data
        if binary_kind(data) is not None or not is_script(data):
            return False
        old = inv.components.get(art.component_id)
        if old is not None and art.id in old.artifact_ids:
            old.artifact_ids.remove(art.id)
        inv.artifacts.pop(dst, None)
        inv.texts.pop(dst, None)
        owner = comp if art.role in repo_roles or old is None else old
        new = add_artifact(dst, owner, R.script)
        new.language = language_for(dst, data) or language
        promoted += 1
        return True

    seen: set[str] = set()
    for src in sorted(inv.artifacts):
        art = inv.artifacts[src]
        if art.role in repo_roles or art.role in (R.binary, R.archive, R.image, R.document, R.media):
            continue
        scan_file(src, 0, seen)

    # A local file that an MCP client configuration starts is that server's code.
    for comp in sorted(inv.components.values(), key=lambda c: c.id):
        spec = comp.server
        if comp.kind != K.mcp_server or spec is None or not spec.config_path or spec.command is None:
            continue
        for token in [spec.command, *spec.args][:12]:
            if not isinstance(token, str) or not _PATH_TOKEN.fullmatch(token.strip()):
                continue
            hit = next((c for c in _candidates(spec.config_path, token.strip(), None) if c in tree.files), None)
            target = inv.artifacts.get(hit) if hit else None
            if hit is None or target is None:
                continue
            inv.references.append((spec.config_path, spec.config_span.start_line if spec.config_span else 0, token.strip(), hit, "runs"))
            if target.role in repo_roles:
                promote(hit, comp, R.source_code)


def span_of(doc_text: str, *needles: str, path: str) -> Span:
    """Line and column of the last of ``needles``, each searched after the previous
    one (the parsers do not keep positions). Falls back to line 1."""
    pos = 0
    found = False
    for needle in needles:
        if not needle:
            continue
        hit = doc_text.find(needle, pos)
        if hit < 0:
            break
        pos, found = hit, True
    if not found:
        return Span(path=path)
    line = doc_text.count("\n", 0, pos) + 1
    col = pos - (doc_text.rfind("\n", 0, pos) + 1) + 1
    end = doc_text.find("\n", pos)
    end_col = (len(doc_text) if end < 0 else end) - (doc_text.rfind("\n", 0, pos) + 1) + 1
    return Span(path=path, start_line=line, start_col=col, end_line=line, end_col=max(end_col, col))
