"""Agent settings and hooks (the CFG family, spec/ecosystems.md §2 to §8).

One analyzer reads the parsed settings, permission, policy and hook files of
every agent and applies the trust-boundary rules for that agent. A rule about a
"repository file" is evaluated on files that travel with a repository or a
package; on a file in the user's own home directory the same setting is the
user's choice, so those rules are either skipped or reported one level lower.

Pure: works on ``inv.docs`` and on the commands recorded by ``ConfigUnitsBuilder``.
"""

from __future__ import annotations

import posixpath
import unicodedata
import urllib.parse
from dataclasses import dataclass
from typing import Any, ClassVar

import regex

from ..inventory_surfaces import Doc, span_of
from ..models import Span
from ..models.enums import ArtifactRole, CapLabel, EvidenceKind, Severity
from ..secrets import find_secrets, is_placeholder
from ..textutil import TIMEOUT
from .base import Context
from .config_units import ConfigCommand, locate_value
from .heuristics import CREDENTIAL_PATH, EGRESS_CODE, ENV_DUMP, EXEC_CODE, NETWORK_FETCH, TOKEN_ENV, search

_F = regex.IGNORECASE
_ENV_REF = regex.compile(r"\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*\b|%[A-Z_][A-Z0-9_]*%|\$env:[A-Za-z_]\w*|\{\{[^}]+\}\}|\{env:[^}]+\}")
# -- what a hook or helper command does ---------------------------------------------------------
_NET = regex.compile(r"\b(?:curl|wget|nc|ncat|netcat|ssh|scp|rsync|ftp|telnet|socat|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b"
                     r"|https?://(?!localhost\b|127\.0\.0\.1\b|\[::1\])|/dev/tcp/", _F)
_DYN_EXEC = regex.compile(
    r"\beval\b|\|\s*(?:ba|z|da|k)?sh\b|\b(?:ba|z|da)?sh\s+-c\b|\bpython3?\s+-c\b|\bnode\s+(?:-e|--eval)\b|\bperl\s+-e\b|\bruby\s+-e\b"
    r"|\bbase64\s+(?:-d|-D|--decode)\b|\bpowershell(?:\.exe)?\b[^\n]{0,80}-e(?:nc|ncodedcommand)?\b|\bInvoke-Expression\b|\biex\b"
    r"|\$\(\s*curl\b|`\s*curl\b|\bosascript\s+-e\b", _F)
_SIDE_EFFECT = regex.compile(
    r"(?<![<>=|&0-9])>{1,2}(?!&)\s*[^\s&|]|\btee\b|\b(?:rm|mv|cp|mkdir|touch|chmod|chown|ln|install|kill|pkill|launchctl|systemctl|crontab|docker|"
    r"apt(?:-get)?|brew|sudo)\b|\bgit\s+(?:config|clone|pull|push|checkout|commit|remote|reset)\b"
    r"|\b(?:npm|pnpm|yarn|bun)\s+(?:i|install|ci|add|run|exec)\b|\bpip3?\s+install\b|\buv\s+(?:pip|sync|add|run)\b|\bsed\s+-i\b", _F)
_ALLOW = regex.compile(
    r"permissionDecision\W{0,8}allow|\bbehavior\W{0,8}allow|updatedPermissions|\bdecision\W{0,8}(?:approve|allow)\b"
    r"|\bpermission\W{0,8}allow\b|\bcontinue\W{0,8}true\W{0,40}\bsuppressOutput", _F)
_REWRITE = regex.compile(r"updatedInput|updated_input|modifiedArgs|modified_args|\bhookSpecificOutput\W{0,40}tool_input", _F)
_CONTEXT = regex.compile(r"additionalContext|additional_context|agent_message|systemMessage|\bllm_request\b|\bllm_response\b", _F)
_SYNTHETIC = regex.compile(r"\bllm_response\b|syntheticResponse|synthetic_response|\bllm_request\b\W{0,60}\b(?:messages|contents)\b", _F)
_READS_INPUT = regex.compile(r"\bcat\s+[^\s|;&]+|\b(?:head|tail|less)\s+[^\s|;&-][^\s|;&]*|<\s*[^\s<>|&]+|\bcurl\b|\bwget\b|\bgit\s+(?:log|show|diff)\b"
                             r"|\bopen\(|readFile|read_text|\bgh\s+(?:issue|pr|api)\b", _F)
_RUNS_SCRIPT = regex.compile(r"(?:^|[\s\"'=/])[\w.\-/${}~]+\.(?:sh|bash|zsh|py|js|mjs|cjs|ts|ps1|rb|pl)\b", _F)
# Events on which a handler's stdout or `additionalContext` is added to the model's context.
_CONTEXT_EVENTS = {"sessionstart", "userpromptsubmit", "userpromptexpansion", "postmodelswitch", "subagentstart", "pretooluse",
                   "posttooluse", "posttoolusefailure", "posttoolbatch", "stop", "subagentstop", "beforeagent", "beforemodel",
                   "beforesubmitprompt"}
_STDOUT_CONTEXT_EVENTS = {"sessionstart", "userpromptsubmit", "userpromptexpansion", "postmodelswitch", "beforeagent"}
_LOAD_EVENTS = {"sessionstart", "setup", "instructionsloaded", "configchange", "filechanged", "cwdchanged", "directoryadded",
                "workspaceopen"}
_DECISION_EVENTS = {"pretooluse", "permissionrequest", "beforetool", "beforeshellexecution", "beforemcpexecution",
                    "beforereadfile", "beforetoolselection"}
# Hook rule ids per agent: risky command, allow decision, input rewrite, context injection, HTTP hook,
# side effects at load time, fail-open policy hook.
_HOOK_RULES: dict[str, dict[str, str]] = {
    "claude-code": {"risky": "AG-CFG-006", "allow": "AG-CFG-007", "rewrite": "AG-CFG-008", "context": "AG-CFG-009",
                    "http": "AG-CFG-010", "load": "AG-CFG-011", "failopen": "AG-CFG-012"},
    "codex": {"risky": "AG-CFG-035", "allow": "AG-CFG-035"},
    "gemini": {"risky": "AG-CFG-048", "rewrite": "AG-CFG-048", "synthetic": "AG-CFG-048"},
    "cursor": {"risky": "AG-CFG-057", "allow": "AG-CFG-057", "failopen": "AG-CFG-058"},
    "copilot": {"risky": "AG-CFG-065", "allow": "AG-CFG-065", "rewrite": "AG-CFG-065"},
}
_HOOK_SURFACES = ("claude.settings", "plugin.settings", "plugin.hooks", "claude.plugin", "codex.hooks", "codex.config",
                  "gemini.settings", "gemini.extension", "cursor.hooks", "copilot.hooks", "copilot.settings")
# -- Claude Code -----------------------------------------------------------------------------------
_COMMAND_KEYS = ("statusLine", "subagentStatusLine", "fileSuggestion", "apiKeyHelper", "awsAuthRefresh", "awsCredentialExport",
                 "gcpAuthRefresh", "otelHeadersHelper")
_BASE_URL_VARS = regex.compile(r"^(?:ANTHROPIC|OPENAI|GOOGLE_GEMINI|GEMINI|CODEX|AZURE_OPENAI|MISTRAL|OLLAMA|LITELLM|OPENROUTER)_"
                               r"(?:[A-Z_]*_)?(?:BASE_URL|API_BASE|API_URL|ENDPOINT|HOST)$|^(?:OPENAI_API_BASE|ANTHROPIC_BEDROCK_BASE_URL"
                               r"|ANTHROPIC_VERTEX_BASE_URL|CLAUDE_CODE_API_BASE_URL)$")
_SECURITY_VARS = regex.compile(
    r"^(?:HTTPS?_PROXY|ALL_PROXY|NO_PROXY|PATH|NODE_OPTIONS|NODE_PATH|NODE_EXTRA_CA_CERTS|NODE_TLS_REJECT_UNAUTHORIZED|LD_PRELOAD"
    r"|LD_LIBRARY_PATH|DYLD_INSERT_LIBRARIES|DYLD_LIBRARY_PATH|GIT_SSH_COMMAND|GIT_SSH|GIT_ASKPASS|SSH_ASKPASS|PYTHONPATH"
    r"|PYTHONSTARTUP|PYTHONHTTPSVERIFY|BASH_ENV|ENV|ZDOTDIR|SSL_CERT_FILE|SSL_CERT_DIR|REQUESTS_CA_BUNDLE|CURL_CA_BUNDLE"
    r"|GEMINI_SYSTEM_MD|GEMINI_SANDBOX|GEMINI_CLI_SYSTEM_SETTINGS_PATH|CLAUDE_CONFIG_DIR|CODEX_HOME|EDITOR|VISUAL|PAGER"
    r"|GIT_EDITOR|GIT_PAGER|PROMPT_COMMAND|npm_config_registry|PIP_INDEX_URL|PIP_EXTRA_INDEX_URL|UV_INDEX_URL)$", _F)
VENDOR_API_HOSTS = (
    "anthropic.com", "claude.ai", "claude.com", "openai.com", "googleapis.com", "google.com", "azure.com", "amazonaws.com",
    "mistral.ai", "cohere.com", "cohere.ai", "openrouter.ai", "groq.com", "x.ai", "deepseek.com", "together.xyz",
    "fireworks.ai", "perplexity.ai", "githubcopilot.com", "github.com", "cloudflare.com", "vercel.sh", "databricks.com",
)
_PERMISSIVE_MODES = {"bypasspermissions", "auto", "acceptedits", "dontask"}
_BROAD_BASH = regex.compile(
    r"^Bash\(\s*(?:\*|:\*|\*\*|(?:curl|wget|nc|ncat|ssh|scp|rsync|bash|sh|zsh|fish|pwsh|powershell|cmd|python3?|node|deno|bun|perl|ruby|php"
    r"|npx|uvx|pipx|pip3?|npm|pnpm|yarn|eval|exec|sudo|su|rm|chmod|chown|dd|mkfs|docker|kubectl|git|gh|env|xargs|find|osascript)"
    r"(?:\s*:?\s*\*|\s+\*|:\*)?)\s*\)$", _F)
_BROAD_PATH = regex.compile(r"^(?:Read|Edit|Write|MultiEdit|Glob|Grep|NotebookEdit)\(\s*(?:\*\*?|/+\*\*?|//\*\*|~/?\*\*?|~|/|\$HOME/?\*{0,2}|"
                            r"~/\.(?:ssh|aws|config|gnupg|kube|docker)(?:/\*{1,2})?|\*\*/\.env[^)]*|/etc/\*{1,2}|[A-Za-z]:[\\/]+\*{0,2})\s*\)$", _F)
_BROAD_DIR = regex.compile(r"^(?:~|~/|/|\$HOME/?|%USERPROFILE%\\?|[A-Za-z]:[\\/]?|/home/?|/Users/?|/root/?|(?:\.\./){2,}\.?\.?/?|/etc/?|/var/?)$", _F)
_SHARED_PATH = regex.compile(r"^(?:/tmp|/var/tmp|/dev/shm|/shared|/mnt|/Volumes|/net|\\\\|//|~/?$|/$|~/\.(?:ssh|aws|config|gnupg|kube|claude)(?:/|$)"
                             r"|/etc|[A-Za-z]:[\\/](?:Users[\\/]Public|Windows|ProgramData))|(?:^|/)\.\.(?:/|$)", _F)
_SENSITIVE_IMPORT = regex.compile(
    r"(?:^|/)\.(?:ssh|aws|gnupg|kube|docker|azure|config/gcloud|password-store)(?:/|$)|(?:^|/)\.(?:env|npmrc|netrc|pypirc|git-credentials)(?:\.|$)"
    r"|(?:^|/)\.claude\.json$|\.credentials\.json$|(?:^|/)(?:id_rsa|id_ed25519|id_ecdsa|credentials|auth\.json|oauth_creds\.json)$"
    r"|^/etc/(?:passwd|shadow|sudoers)|(?:^|/)\.(?:bash|zsh)_history$|mcp-oauth-tokens", _F)
_OFFICIAL_MARKETPLACE = regex.compile(r"^(?:anthropics?/|https://github\.com/anthropics?/|claude-plugins-official$|anthropic-)", _F)
_USER_STATE_FILES = regex.compile(
    r"(?:^|/)(?:\.claude\.json|claude_desktop_config\.json|\.claude/\.credentials\.json|\.codex/auth\.json|\.gemini/(?:oauth_creds|"
    r"trustedFolders|mcp-oauth-tokens|google_accounts)\.json|\.cursor/cli-config\.json|\.copilot/(?:mcp-config|config)\.json"
    r"|\.claude/plugins/(?:installed_plugins|known_marketplaces)\.json|\.openclaw/(?:openclaw\.json|credentials(?:/.*)?)"
    r"|\.config/gh/hosts\.yml)$", _F)
# Top-level keys of a Claude Code settings file (code.claude.com/docs/en/settings, read 10 November 2026).
_CLAUDE_KEYS = frozenset({
    "$schema", "apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "gcpAuthRefresh", "otelHeadersHelper", "cleanupPeriodDays",
    "companyAnnouncements", "env", "attribution", "includeCoAuthoredBy", "includeGitInstructions", "permissions", "hooks",
    "disableAllHooks", "allowManagedHooksOnly", "allowManagedPermissionRulesOnly", "allowManagedMcpServersOnly", "model",
    "availableModels", "modelOverrides", "effortLevel", "statusLine", "subagentStatusLine", "fileSuggestion", "outputStyle",
    "forceLoginMethod", "forceLoginOrgUUID", "enableAllProjectMcpServers", "enabledMcpjsonServers", "disabledMcpjsonServers",
    "allowedMcpServers", "deniedMcpServers", "strictKnownMarketplaces", "blockedMarketplaces", "extraKnownMarketplaces",
    "enabledPlugins", "pluginConfigs", "sandbox", "skipDangerousModePermissionPrompt", "disableSkillShellExecution",
    "autoMemoryEnabled", "autoMemoryDirectory", "plansDirectory", "claudeMdExcludes", "allowedHttpHookUrls",
    "httpHookAllowedEnvVars", "alwaysThinkingEnabled", "showThinkingSummaries", "spinnerTipsEnabled", "spinnerVerbs",
    "spinnerTipsOverride", "language", "voiceEnabled", "autoUpdatesChannel", "minimumVersion", "prefersReducedMotion",
    "terminalProgressBarEnabled", "showTurnDuration", "respectGitignore", "teammateMode", "fastModePerSessionOptIn",
    "feedbackSurveyRate", "agent", "mcpServers", "managedMcpServers", "worktree", "viewMode", "tui", "syntaxHighlightingDisabled",
    "disableAutoMode", "useAutoModeDuringPlan", "autoMode", "defaultShell", "channelsEnabled", "allowedChannelPlugins",
    "pluginTrustMessage", "fastMode", "promptSuggestionEnabled", "awaySummaryEnabled", "skillOverrides", "disableDeepLinkRegistration",
    "editorMode", "autoCompactEnabled", "claudeMd", "todoFeatureEnabled", "messageIdleNotifThresholdMs", "preferredNotifChannel",
    "theme", "verbose", "autoConnectIde", "autoInstallIdeExtension", "apiKeyHelperTtlMs", "otelHeadersHelperDebounceMs",
})
_HIDDEN_CHARS = regex.compile(r"[\xa0\xad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180e\u2000-\u200f\u2028-\u202f\u205f-\u2064"
                              r"\u2066-\u206f\u3000\u3164\ufeff\uffa0\U000e0000-\U000e007f\ufe00-\ufe0f]|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_URL_OR_PATH = regex.compile(r"^(?:[a-z][a-z0-9+.\-]*://|~?/|\.{1,2}/|[A-Za-z]:[\\/])|\.(?:sh|py|js|ts|ps1|exe|json|ya?ml|toml)$", _F)


def is_repo_file(path: str) -> bool:
    """A file that travels with a repository or a package (not one in the user's home or a system directory)."""
    return not path.startswith(("~/", "@system/"))


def _host(url: str) -> str:
    try:
        return (urllib.parse.urlsplit(url if "://" in url else f"//{url}").hostname or "").lower()
    except ValueError:
        return ""


def is_local_host(host: str) -> bool:
    return host in ("localhost", "127.0.0.1", "::1", "0.0.0.0", "host.docker.internal") or host.endswith((".localhost", ".local", ".internal"))


def is_vendor_host(host: str) -> bool:
    return any(host == v or host.endswith("." + v) for v in VENDOR_API_HOSTS)


def _get(data: Any, *keys: str) -> Any:
    for k in keys:
        if not isinstance(data, dict):
            return None
        data = data.get(k)
    return data


def _strs(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []


def literal_secret(value: Any) -> bool:
    """A value that is a secret itself, not a reference to one."""
    if not isinstance(value, str) or len(value.strip()) < 8 or is_placeholder(value) or _ENV_REF.search(value):
        return False
    return True


@dataclass
class Hook:
    doc: Doc
    event: str
    matcher: str
    handler: dict[str, Any]
    keypath: tuple[str, ...]

    @property
    def kind(self) -> str:
        t = str(self.handler.get("type") or "").lower()
        if t:
            return t
        return "http" if isinstance(self.handler.get("url"), str) and not self.handler.get("command") else "command"


def iter_hooks(doc: Doc) -> list[Hook]:
    """Hook handlers of a settings or hook file. Every agent nests them as
    ``hooks.<Event>[]`` with the handler either directly in the entry (Cursor,
    Copilot) or one level down in ``hooks[]`` beside a ``matcher`` (Claude Code,
    Codex, Gemini CLI)."""
    hooks = doc.data.get("hooks")
    out: list[Hook] = []
    if not isinstance(hooks, dict):
        return out
    for event, entries in hooks.items():
        entries = [entries] if isinstance(entries, dict) else entries
        if not isinstance(entries, list):
            continue
        for i, entry in enumerate(entries[:200]):
            if not isinstance(entry, dict):
                continue
            inner = entry.get("hooks")
            if isinstance(inner, list):
                for k, handler in enumerate(inner[:50]):
                    if isinstance(handler, dict):
                        out.append(Hook(doc, str(event), str(entry.get("matcher") or ""), handler,
                                        ("hooks", str(event), str(i), "hooks", str(k))))
            else:
                out.append(Hook(doc, str(event), str(entry.get("matcher") or ""), entry, ("hooks", str(event), str(i))))
    return out


class SettingsAnalyzer:
    id: ClassVar[str] = "settings"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = (
        *(f"AG-CFG-{n:03d}" for n in (*range(1, 24), *range(30, 40), *range(45, 53), *range(55, 61), 65, 66, 67,
                                      *range(70, 79), 90, 91, 92)),
        "AG-CRED-013", "AG-INJ-026",
    )

    def run(self, ctx: Context) -> None:
        self.ctx = ctx
        inv = ctx.inventory
        cmds: list[ConfigCommand] = ctx.data.get("config_commands", [])  # type: ignore[assignment]
        self.cmds_by_path: dict[str, list[ConfigCommand]] = {}
        for c in cmds:
            self.cmds_by_path.setdefault(c.path, []).append(c)
        for path in sorted(inv.docs):
            doc: Doc = inv.docs[path]
            if doc.value is None or path not in inv.artifacts:
                continue
            sid = doc.surface.id
            if sid in ("claude.settings", "copilot.settings"):
                self._claude_settings(doc)
            elif sid == "codex.config":
                self._codex(doc)
            elif sid == "codex.skill_sidecar":
                self._codex_sidecar(doc)
            elif sid == "gemini.settings":
                self._gemini(doc)
            elif sid == "gemini.policy":
                self._gemini_policy(doc)
            elif sid == "cursor.cli":
                self._cursor_cli(doc)
            elif sid == "openclaw.config":
                self._openclaw(doc)
            if sid in _HOOK_SURFACES:
                self._hooks(doc)
        self._mcp_entries()
        self._env_files()
        self._imports()
        self._cursor_rules()
        self._custom_agents()
        self._openclaw_files()
        self._committed_state()
        self._hidden_values(cmds)

    # -- emit helpers -------------------------------------------------------------------------------
    def _cid(self, path: str) -> str:
        art = self.ctx.inventory.artifacts.get(path)
        return art.component_id if art else ""

    def _vendor_of(self, host: str) -> str:
        """The vendor whose own domain ``host`` is on, from the bundled list (`rules/data/vendor-domains.yaml`)."""
        vendors = (self.ctx.pack.data.get("vendor-domains") or {}).get("vendors") or {}
        for name in sorted(vendors):
            domains = vendors[name]
            if isinstance(domains, list) and any(host == str(d).lower() or host.endswith("." + str(d).lower()) for d in domains):
                return str(name)
        return ""

    def flag(self, rule: str, doc: Doc, keys: tuple[str, ...], message: str, *, value: Any = None, severity: Severity | None = None,
             repo_only: bool = False, lower_for_user: bool = True, snippet: str | None = None, tags: list[str] | None = None) -> None:
        path = doc.path
        user = not is_repo_file(path)
        if user and repo_only:
            return
        det = self.ctx.pack.detectors.get(rule)
        if det is None:
            return
        sev = severity
        if user and lower_for_user:
            sev = (severity or det.severity).bump(-1)
            message += " (in your own user configuration)"
        text = value if isinstance(value, str) else ""
        span = locate_value(doc, keys, text) if text else span_of(doc.text, *[k for k in keys if not k.isdigit()][-2:], path=path)
        cid = self._cid(path)
        shown = snippet if snippet is not None else (f"{keys[-1]}: {value!r}" if value is not None else ".".join(keys))
        self.ctx.emit(rule, component_ids=[cid] if cid else [], span=span, snippet=shown[:300], kind=EvidenceKind.config,
                      match=f"{'.'.join(keys)}={str(value)[:80]}", detail=f"key: {'.'.join(keys)}", message=message, severity=sev,
                      tags=tags)

    # -- Claude Code settings (CFG-001 to 021) ---------------------------------------------------------
    def _claude_settings(self, doc: Doc) -> None:
        d = doc.data
        if d.get("enableAllProjectMcpServers") is True:
            self.flag("AG-CFG-001", doc, ("enableAllProjectMcpServers",), "`enableAllProjectMcpServers` is true: every MCP server a "
                      "repository's `.mcp.json` defines is approved without a prompt once the folder is trusted.", value=True,
                      lower_for_user=False)
        servers = _strs(d.get("enabledMcpjsonServers"))
        if servers:
            self.flag("AG-CFG-002", doc, ("enabledMcpjsonServers",), f"`enabledMcpjsonServers` pre-approves {len(servers)} server(s) "
                      f"from `.mcp.json` ({', '.join(servers[:4])}); they start without asking.", value=servers[0], repo_only=True,
                      snippet=f"enabledMcpjsonServers: {servers[:6]}")
        perms = d.get("permissions") if isinstance(d.get("permissions"), dict) else {}
        for rule_text in _strs(perms.get("allow"))[:300]:
            why = _broad_allow(rule_text)
            if why:
                self.flag("AG-CFG-003", doc, ("permissions", "allow"), f"`permissions.allow` contains `{rule_text}`: {why}; "
                          "matching tool calls run with no prompt.", value=rule_text, snippet=rule_text)
        mode = perms.get("defaultMode")
        if isinstance(mode, str) and mode.lower() in _PERMISSIVE_MODES:
            ignored = " Current Claude Code ignores this value from project files, but it shows what the file is trying to do." \
                if mode.lower() in ("bypasspermissions", "auto") and is_repo_file(doc.path) else ""
            self.flag("AG-CFG-004", doc, ("permissions", "defaultMode"), f"`permissions.defaultMode` is `{mode}`, which removes or "
                      f"reduces permission prompts for everyone who opens this folder.{ignored}", value=mode)
        if d.get("skipDangerousModePermissionPrompt") is True:
            self.flag("AG-CFG-005", doc, ("skipDangerousModePermissionPrompt",), "`skipDangerousModePermissionPrompt` is set: the "
                      "confirmation shown before bypass mode is skipped.", value=True, lower_for_user=False)
        if doc.surface.id == "claude.settings":
            for key in _COMMAND_KEYS:
                v = d.get(key)
                cmd = v if isinstance(v, str) else (v.get("command") if isinstance(v, dict) and isinstance(v.get("command"), str) else None)
                if cmd:
                    self.flag("AG-CFG-013", doc, (key,) if isinstance(v, str) else (key, "command"),
                              f"`{key}` is a shell command (`{cmd[:80]}`) set by a repository file; it runs on the machine of "
                              "everyone who trusts this folder.", value=cmd, repo_only=True)
        env = d.get("env") if isinstance(d.get("env"), dict) else {}
        self._env_overrides(doc, ("env",), env)
        sb = d.get("sandbox") if isinstance(d.get("sandbox"), dict) else {}
        if sb:
            weak: list[tuple[tuple[str, ...], str, Any]] = []
            if sb.get("enabled") is False:
                weak.append((("sandbox", "enabled"), "the sandbox is turned off", False))
            if _strs(sb.get("excludedCommands")):
                weak.append((("sandbox", "excludedCommands"), f"{len(_strs(sb['excludedCommands']))} command(s) run outside the sandbox", sb["excludedCommands"][0]))
            for k in ("allowUnsandboxedCommands", "enableWeakerNestedSandbox", "enableWeakerNetworkIsolation"):
                if sb.get(k) is True:
                    weak.append((("sandbox", k), f"`{k}` is on", True))
            domains = _strs(_get(sb, "network", "allowedDomains"))
            wide = next((x for x in domains if x.strip() in ("*", "*.*", "**") or regex.fullmatch(r"\*\.[a-z]{2,6}", x.strip())), None)
            if wide:
                weak.append((("sandbox", "network", "allowedDomains"), f"network access is allowed to `{wide}`", wide))
            writes = _strs(_get(sb, "filesystem", "allowWrite"))
            broad = next((x for x in writes if _BROAD_DIR.match(x.strip()) or x.strip() in ("/**", "~/**", "**")), None)
            if broad:
                weak.append((("sandbox", "filesystem", "allowWrite"), f"writes are allowed to `{broad}`", broad))
            for keys, what, value in weak:
                self.flag("AG-CFG-015", doc, keys, f"The sandbox is weakened: {what}.", value=value)
        markets = d.get("extraKnownMarketplaces") if isinstance(d.get("extraKnownMarketplaces"), dict) else {}
        unvetted = []
        for name, entry in markets.items():
            src = _get(entry, "source") if isinstance(entry, dict) else None
            where = src if isinstance(src, str) else " ".join(str(v) for v in (src or {}).values() if isinstance(v, str)) if isinstance(src, dict) else ""
            if not _OFFICIAL_MARKETPLACE.search(where.replace("github ", "")) and not _OFFICIAL_MARKETPLACE.search(str(name)):
                unvetted.append((str(name), where))
        if unvetted:
            name, where = unvetted[0]
            self.flag("AG-CFG-016", doc, ("extraKnownMarketplaces", name), f"The repository registers marketplace '{name}'"
                      f"{' (' + where[:80] + ')' if where else ''}; once the folder is trusted its plugins can be offered and enabled.",
                      value=name, repo_only=True, snippet=f"extraKnownMarketplaces.{name}: {where[:120]}")
        plugins = d.get("enabledPlugins") if isinstance(d.get("enabledPlugins"), dict) else {}
        on = [str(k) for k, v in plugins.items() if v is True or (isinstance(v, list) and v)]
        third = [p for p in on if not _OFFICIAL_MARKETPLACE.search(p.rsplit("@", 1)[-1] if "@" in p else "")]
        if third:
            self.flag("AG-CFG-016", doc, ("enabledPlugins", third[0]), f"The repository enables plugin(s) {', '.join(third[:4])} for "
                      "everyone who trusts this folder.", value=third[0], repo_only=True, snippet=f"enabledPlugins: {third[:6]}")
        for directory in _strs(perms.get("additionalDirectories")):
            if _BROAD_DIR.match(directory.strip()):
                self.flag("AG-CFG-017", doc, ("permissions", "additionalDirectories"), f"`additionalDirectories` grants file access "
                          f"to `{directory}`, far beyond the project.", value=directory, snippet=directory)
        for key in ("disableAllHooks", "disableSkillShellExecution"):
            if d.get(key) is False:
                self.flag("AG-CFG-018", doc, (key,), f"`{key}` is set to false in a repository file, which turns a safety switch "
                          "back off for this project if the user had turned it on.", value=False, repo_only=True)
        for key in ("autoMemoryDirectory", "plansDirectory"):
            v = d.get(key)
            if isinstance(v, str) and _SHARED_PATH.search(v.strip()):
                self.flag("AG-CFG-020", doc, (key,), f"`{key}` points at `{v}`, a shared or sensitive location: what the agent "
                          "remembers or plans is written where other users, projects or sessions read it.", value=v, repo_only=True)
        if _strs(d.get("claudeMdExcludes")):
            ex = _strs(d["claudeMdExcludes"])
            self.flag("AG-CFG-021", doc, ("claudeMdExcludes",), f"`claudeMdExcludes` hides {len(ex)} instruction file pattern(s) "
                      f"({', '.join(ex[:3])}) from loading.", value=ex[0], repo_only=True, snippet=f"claudeMdExcludes: {ex[:5]}")
        if doc.surface.id == "claude.settings":
            for key in d:
                if isinstance(key, str) and key not in _CLAUDE_KEYS:
                    self.flag("AG-CFG-091", doc, (key,), f"`{key}` is not a settings key Claude Code documents; it is either a typo, "
                              "a key of another version, or content placed here for another reader.", value=None,
                              lower_for_user=False, snippet=key)

    def _env_overrides(self, doc: Doc, keys: tuple[str, ...], env: dict[str, Any]) -> None:
        for name, value in env.items():
            name = str(name)
            if not isinstance(value, (str, int, float, bool)):
                continue
            text = str(value)
            if _BASE_URL_VARS.match(name):
                host = _host(text)
                self.flag("AG-CFG-014", doc, (*keys, name), f"`env.{name}` redirects the model API to `{text[:80]}` for every session "
                          "and subprocess started in this folder.", value=text, repo_only=True)
                if host and not is_vendor_host(host) and not is_local_host(host):
                    self.flag("AG-CRED-013", doc, (*keys, name), f"`{name}` points the model API at `{host}`, which is not the "
                              "vendor's host: prompts, code and the API key are sent there.", value=text, lower_for_user=False)
            elif _SECURITY_VARS.match(name):
                self.flag("AG-CFG-014", doc, (*keys, name), f"`env.{name}` is set to `{text[:80]}` for every session and subprocess "
                          "started in this folder; this variable changes what code runs or where traffic goes.", value=text,
                          repo_only=True)

    # -- hooks (CFG-006 to 012, 035, 048, 057, 058, 065; INJ-026) -------------------------------------------
    def _script_text(self, path: str, command: str) -> tuple[str, list[Span]]:
        """Text of the scripts in the tree that a command names, and where they are."""
        inv = self.ctx.inventory
        texts, spans = [], []
        for src, _line, ref, dst, _kind in inv.references:
            if src == path and dst and dst in inv.texts and posixpath.basename(ref) in command:
                at = inv.texts[dst]
                if at.artifact.role in (ArtifactRole.script, ArtifactRole.source_code, ArtifactRole.repo_code):
                    texts.append(at.text)
                    spans.append(Span(path=dst))
        return "\n".join(texts), spans[:5]

    def _hooks(self, doc: Doc) -> None:
        agent = doc.surface.agent if doc.surface.agent in _HOOK_RULES else "claude-code"
        rules = _HOOK_RULES[agent]
        ctx = self.ctx
        cid = self._cid(doc.path)
        allowed_urls = _strs(doc.data.get("allowedHttpHookUrls"))
        for hook in iter_hooks(doc):
            h = hook.handler
            event = hook.event
            ev = event.lower()
            cmd = ""
            for key in ("command", "bash", "powershell", "pwsh", "cmd"):
                v = h.get(key)
                if isinstance(v, str) and v.strip():
                    cmd = v if not isinstance(h.get("args"), list) else v + " " + " ".join(str(a) for a in h["args"])
                    break
                if isinstance(v, list) and v:
                    cmd = " ".join(str(x) for x in v)
                    break
            span = locate_value(doc, (*hook.keypath, "command"), cmd) if cmd else span_of(doc.text, event, path=doc.path)
            where = f"{event} hook" + (f" (matcher `{hook.matcher}`)" if hook.matcher else "")

            def emit(kind: str, message: str, *, related: list[Span] | None = None, snippet: str = "", severity: Severity | None = None,
                     rule: str | None = None) -> None:
                rid = rule or rules.get(kind)
                if not rid:
                    return
                sev = severity
                if not is_repo_file(doc.path):
                    sev = (severity or ctx.pack.detector(rid).severity).bump(-1)
                ctx.emit(rid, component_ids=[cid] if cid else [], span=span, snippet=(snippet or cmd or str(h))[:300],
                         kind=EvidenceKind.config, match=f"{kind}:{event}:{(snippet or cmd)[:120]}", message=message, severity=sev,
                         related=related, detail=f"key: {'.'.join(hook.keypath)}")

            if hook.kind == "http" or (isinstance(h.get("url"), str) and not cmd):
                url = str(h.get("url") or "")
                host = _host(url)
                if host and not is_local_host(host) and not any(url.startswith(a.rstrip("*")) for a in allowed_urls):
                    limit = "" if allowed_urls else " No `allowedHttpHookUrls` list limits where hooks may post."
                    emit("http", f"The {where} posts the hook payload (session id, transcript path, tool input) to `{host}`.{limit}",
                         snippet=url)
                continue
            if hook.kind in ("prompt", "agent"):
                continue                                  # the prompt text is scanned as prose (config_prompt units)
            if not cmd:
                continue
            script, script_spans = self._script_text(doc.path, cmd)
            both = f"{cmd}\n{script}"
            reasons = []
            if search(_NET, cmd) or (script and (search(EGRESS_CODE, script) or search(NETWORK_FETCH, script))):
                reasons.append("network access")
            if search(_DYN_EXEC, cmd) or (script and search(EXEC_CODE, script)):
                reasons.append("execution of dynamic content")
            if search(CREDENTIAL_PATH, both) or search(TOKEN_ENV, cmd) or search(ENV_DUMP, both):
                reasons.append("access to credentials or the environment")
            if reasons:
                via = " (in the script it runs)" if script and not (search(_NET, cmd) or search(_DYN_EXEC, cmd)) else ""
                emit("risky", f"The {where} runs a command with {', '.join(reasons)}{via}. Hooks run outside the sandbox, with the "
                              "user's permissions, without asking.", related=script_spans)
            if ev in _DECISION_EVENTS and search(_ALLOW, both):
                emit("allow", f"The {where} answers the permission check itself with an allow decision: tool calls it matches run "
                              "without the user being asked.", related=script_spans)
            if search(_REWRITE, both):
                emit("rewrite", f"The {where} rewrites the tool's input before it runs, so what executes is not what the user or the "
                                "model saw.", related=script_spans)
            if agent == "gemini" and ev in ("beforemodel", "aftermodel", "beforetoolselection") and search(_SYNTHETIC, both):
                emit("synthetic", f"The {where} replaces the model request or supplies a synthetic response.", related=script_spans)
            injects = search(_CONTEXT, both) is not None or ev in _STDOUT_CONTEXT_EVENTS
            if ev in _CONTEXT_EVENTS and injects and search(_READS_INPUT, both):
                emit("context", f"The {where} adds text it reads from files or the network to the model's context as trusted input.",
                     related=script_spans)
                if (search(_NET, cmd) or (script and search(EGRESS_CODE, script))) and "AG-INJ-026" in ctx.pack.detectors:
                    emit("", f"The {where} fetches remote content and feeds it to the model as trusted context: whoever controls "
                             "that content controls the agent's instructions.", related=script_spans, rule="AG-INJ-026")
            if ev in _LOAD_EVENTS and (search(_SIDE_EFFECT, cmd) or search(_NET, cmd) or (not script and search(_RUNS_SCRIPT, cmd))
                                       or (script and search(_SIDE_EFFECT, script))):
                emit("load", f"The {where} has side effects and runs when the session or configuration loads, before the user has "
                             "asked for anything.", related=script_spans)
            if ev in _DECISION_EVENTS:
                closed = str(h.get("onFailure") or "").lower() == "block" or h.get("failClosed") is True
                if not closed:
                    key = "failClosed: true" if agent == "cursor" else 'onFailure: "block"'
                    emit("failopen", f"The {where} is a policy check that fails open: if it crashes or times out the action goes "
                                     f"through. It does not set `{key}`.")

    # -- Codex (CFG-030 to 039) -----------------------------------------------------------------------------
    def _codex(self, doc: Doc) -> None:
        d = doc.data
        scopes: list[tuple[tuple[str, ...], dict[str, Any]]] = [((), d)]
        profiles = d.get("profiles") if isinstance(d.get("profiles"), dict) else {}
        scopes += [(("profiles", str(n)), p) for n, p in profiles.items() if isinstance(p, dict)]
        for prefix, table in scopes:
            if table.get("sandbox_mode") == "danger-full-access":
                self.flag("AG-CFG-030", doc, (*prefix, "sandbox_mode"), '`sandbox_mode = "danger-full-access"` removes the sandbox: '
                          "commands can read and write anything and use the network.", value="danger-full-access")
            if table.get("approval_policy") == "never":
                self.flag("AG-CFG-030", doc, (*prefix, "approval_policy"), '`approval_policy = "never"`: no command is ever shown to '
                          "the user for approval.", value="never")
            sww = table.get("sandbox_workspace_write") if isinstance(table.get("sandbox_workspace_write"), dict) else {}
            if sww.get("network_access") is True:
                self.flag("AG-CFG-031", doc, (*prefix, "sandbox_workspace_write", "network_access"), "`network_access = true` lets "
                          "sandboxed commands reach the network.", value=True)
            for root in _strs(sww.get("writable_roots")):
                if _BROAD_DIR.match(root.strip()):
                    self.flag("AG-CFG-031", doc, (*prefix, "sandbox_workspace_write", "writable_roots"), f"`writable_roots` includes "
                              f"`{root}`: sandboxed commands can write far outside the workspace.", value=root, snippet=root)
            sep = table.get("shell_environment_policy") if isinstance(table.get("shell_environment_policy"), dict) else None
            if sep is not None:
                no_filter = not sep.get("exclude") and not sep.get("include_only")
                if sep.get("ignore_default_excludes") is True or (str(sep.get("inherit") or "").lower() == "all" and no_filter):
                    what = "`ignore_default_excludes = true`" if sep.get("ignore_default_excludes") is True else '`inherit = "all"` with no `exclude`'
                    self.flag("AG-CFG-032", doc, (*prefix, "shell_environment_policy"), f"`shell_environment_policy` has {what}: every "
                              "environment variable, including keys and tokens, is passed to the commands the agent runs.", value=None,
                              snippet="shell_environment_policy")
            if _strs(table.get("notify")) or isinstance(table.get("notify"), str):
                cmd = " ".join(_strs(table.get("notify")))
                ignored = is_repo_file(doc.path)
                self.flag("AG-CFG-033", doc, (*prefix, "notify"), f"`notify` runs `{cmd[:80]}` after each turn."
                          + (" Codex ignores this key in project config; it still shows what the file is trying to do." if ignored else ""),
                          value=_strs(table.get("notify"))[0] if _strs(table.get("notify")) else cmd, severity=Severity.medium,
                          lower_for_user=False)
            for key in ("model_instructions_file", "developer_instructions", "experimental_instructions_file"):
                v = table.get(key)
                if isinstance(v, str) and v.strip():
                    self.flag("AG-CFG-036", doc, (*prefix, key), f"`{key}` replaces or adds to the agent's base instructions for "
                              "every session that loads this configuration.", value=v, repo_only=True, snippet=f"{key} = {v[:120]!r}")
        providers = d.get("model_providers") if isinstance(d.get("model_providers"), dict) else {}
        for name, prov in providers.items():
            cmd = _get(prov, "auth", "command")
            if isinstance(cmd, (str, list)) and cmd:
                text = cmd if isinstance(cmd, str) else " ".join(str(x) for x in cmd)
                self.flag("AG-CFG-033", doc, ("model_providers", str(name), "auth", "command"), f"`model_providers.{name}.auth.command` "
                          f"runs `{text[:80]}` to obtain credentials.", value=cmd if isinstance(cmd, str) else str(cmd[0]),
                          severity=Severity.medium, lower_for_user=False)
            base = prov.get("base_url") if isinstance(prov, dict) else None
            if isinstance(base, str):
                host = _host(base)
                if host and not is_vendor_host(host) and not is_local_host(host) and is_repo_file(doc.path):
                    self.flag("AG-CRED-013", doc, ("model_providers", str(name), "base_url"), f"Model provider '{name}' sends prompts, "
                              f"code and its API key to `{host}`, which is not a model vendor's host.", value=base, lower_for_user=False)
        servers = d.get("mcp_servers") if isinstance(d.get("mcp_servers"), dict) else {}
        for name, srv in servers.items():
            if not isinstance(srv, dict):
                continue
            helper = srv.get("http_headers_helper")
            if isinstance(helper, (str, list)) and helper:
                text = helper if isinstance(helper, str) else " ".join(str(x) for x in helper)
                self.flag("AG-CFG-033", doc, ("mcp_servers", str(name), "http_headers_helper"), f"`mcp_servers.{name}.http_headers_helper` "
                          f"runs `{text[:80]}` every time the server's headers are needed.", value=text if isinstance(helper, str) else str(helper[0]))
            mode = srv.get("default_tools_approval_mode")
            if isinstance(mode, str) and regex.fullmatch(r"(?i)auto|approve|approved|allow|always|always[_-]?allow|never[_-]?ask|trusted|yolo|auto[_-]?approve", mode.strip()):
                self.flag("AG-CFG-034", doc, ("mcp_servers", str(name), "default_tools_approval_mode"), f"MCP server '{name}' has "
                          f"`default_tools_approval_mode = \"{mode}\"`: its tools, including ones that write or delete, run without approval.",
                          value=mode)
            secret = _get(srv, "oauth", "client_secret")
            if literal_secret(secret):
                self.flag("AG-CFG-037", doc, ("mcp_servers", str(name), "oauth", "client_secret"), f"MCP server '{name}' has a literal "
                          "OAuth client secret in the configuration file.", value=secret, snippet="client_secret = <redacted>",
                          lower_for_user=False)
            for key in ("bearer_token", "token", "api_key"):
                if literal_secret(srv.get(key)):
                    self.flag("AG-CFG-037", doc, ("mcp_servers", str(name), key), f"MCP server '{name}' has a literal `{key}` in the "
                              "configuration file; use `bearer_token_env_var` to name an environment variable instead.",
                              value=srv[key], snippet=f"{key} = <redacted>", lower_for_user=False)
            headers = srv.get("http_headers") if isinstance(srv.get("http_headers"), dict) else {}
            for hname, hval in headers.items():
                if regex.search(r"(?i)authorization|api[-_]?key|token|secret", str(hname)) and literal_secret(hval):
                    self.flag("AG-CFG-037", doc, ("mcp_servers", str(name), "http_headers", str(hname)), f"MCP server '{name}' sends a "
                              f"literal credential in the `{hname}` header.", value=hval, snippet=f"{hname} = <redacted>",
                              lower_for_user=False)
        projects = d.get("projects") if isinstance(d.get("projects"), dict) else {}
        for proj, entry in projects.items():
            if isinstance(entry, dict) and str(entry.get("trust_level") or "").lower() == "trusted":
                self.flag("AG-CFG-038", doc, ("projects", str(proj), "trust_level"), f"The file ships a `trust_level = \"trusted\"` "
                          f"entry for `{proj}`: whoever uses this configuration trusts that directory without being asked.",
                          value="trusted", repo_only=True)

    def _codex_sidecar(self, doc: Doc) -> None:
        d = doc.data
        tools = _get(d, "dependencies", "tools")
        for i, tool in enumerate(tools if isinstance(tools, list) else []):
            url = tool.get("url") if isinstance(tool, dict) else None
            if isinstance(url, str) and url.strip():
                host = _host(url)
                # "Unvetted" is the rule: a vendor's own hosted endpoint over HTTPS, from the bundled list of
                # vendor domains, is reported as a note; any other server is the finding.
                vendor = self._vendor_of(host) if url.strip().lower().startswith("https://") else ""
                if vendor:
                    self.flag("AG-CFG-039", doc, ("dependencies", "tools", str(i), "url"), f"The skill sidecar pulls in the hosted MCP "
                              f"server of {vendor} at `{host}`; using the skill connects the agent to it.", value=url,
                              severity=Severity.low, lower_for_user=False)
                else:
                    self.flag("AG-CFG-039", doc, ("dependencies", "tools", str(i), "url"), f"The skill sidecar pulls in an MCP server at "
                              f"`{host or url[:60]}`; using the skill connects the agent to it.", value=url, lower_for_user=False)
        if _get(d, "policy", "allow_implicit_invocation") is True:
            comp = self.ctx.inventory.component_for(doc.path)
            skill = next((c for c in self.ctx.inventory.components.values()
                          if c.kind.value == "skill" and c.root and doc.path.startswith(c.root + "/")), comp)
            sensitive = {CapLabel.code_exec, CapLabel.shell, CapLabel.external_egress, CapLabel.credential_access,
                         CapLabel.destructive, CapLabel.persistence}
            if skill is not None and skill.labels() & sensitive:
                names = ", ".join(sorted(lab.spec_name for lab in skill.labels() & sensitive))
                self.flag("AG-CFG-039", doc, ("policy", "allow_implicit_invocation"), "`allow_implicit_invocation: true` lets the model "
                          f"start this skill on its own, and the skill can do sensitive things ({names}).", value=True,
                          lower_for_user=False)

    # -- Gemini CLI (CFG-045 to 052) ---------------------------------------------------------------------------
    def _gemini(self, doc: Doc) -> None:
        d = doc.data
        servers = d.get("mcpServers") if isinstance(d.get("mcpServers"), dict) else {}
        for name, srv in servers.items():
            if isinstance(srv, dict) and srv.get("trust") is True:
                self.flag("AG-CFG-045", doc, ("mcpServers", str(name), "trust"), f"MCP server '{name}' has `trust: true`: every tool "
                          "call to it skips the confirmation dialog.", value=True)
        mode = _get(d, "general", "defaultApprovalMode") or d.get("defaultApprovalMode") or _get(d, "tools", "approvalMode")
        if isinstance(mode, str) and mode.lower().replace("-", "_") in ("yolo", "auto_edit", "autoedit", "auto"):
            self.flag("AG-CFG-047", doc, ("defaultApprovalMode",), f"The default approval mode is `{mode}`: edits or all tool calls "
                      "are approved automatically.", value=mode)
        if _get(d, "tools", "autoAccept") is True or d.get("autoAccept") is True:
            self.flag("AG-CFG-047", doc, ("autoAccept",), "`autoAccept` is on: tool calls the CLI considers safe run without confirmation.",
                      value=True)
        if _get(d, "security", "folderTrust", "enabled") is False or d.get("folderTrust") is False:
            self.flag("AG-CFG-047", doc, ("folderTrust",), "Folder trust is turned off: project settings, `.env`, MCP servers and "
                      "custom commands of any folder load without the trust prompt.", value=False)
        ctx_name = _get(d, "context", "fileName") or d.get("contextFileName")
        names = _strs(ctx_name)
        odd = [n for n in names if posixpath.basename(n).lower() not in ("gemini.md", "agents.md", "claude.md", "context.md")]
        if odd:
            self.flag("AG-CFG-050", doc, ("fileName",), f"`context.fileName` makes the CLI load `{odd[0]}` as its context file instead "
                      "of `GEMINI.md`; reviewers looking at `GEMINI.md` do not see what the agent is told.", value=odd[0],
                      repo_only=True)
        sandbox = _get(d, "tools", "sandbox") if _get(d, "tools", "sandbox") is not None else d.get("sandbox")
        if sandbox is False or (isinstance(sandbox, str) and sandbox.lower() in ("false", "none", "off", "disabled")):
            self.flag("AG-CFG-051", doc, ("sandbox",), "The sandbox is disabled in this settings file.", value=sandbox)
        for keys in (("tools", "sandboxNetworkAccess"), ("sandbox", "networkAccess"), ("tools", "sandbox", "networkAccess"),
                     ("sandbox", "allowNetwork")):
            if _get(d, *keys) is True:
                self.flag("AG-CFG-051", doc, keys, f"`{'.'.join(keys)}` is on: sandboxed commands can reach the network.", value=True)
        tel = d.get("telemetry") if isinstance(d.get("telemetry"), dict) else {}
        endpoint = tel.get("otlpEndpoint") or tel.get("endpoint")
        if tel.get("enabled") is not False and isinstance(endpoint, str):
            host = _host(endpoint)
            if host and not is_local_host(host) and not is_vendor_host(host) and tel.get("logPrompts") is not False:
                self.flag("AG-CFG-052", doc, ("telemetry", "otlpEndpoint" if "otlpEndpoint" in tel else "endpoint"),
                          f"Telemetry is sent to `{host}` with prompt logging on: every prompt leaves the machine for that host.",
                          value=endpoint)

    def _gemini_policy(self, doc: Doc) -> None:
        rules = doc.data.get("rule")
        for i, rule in enumerate(rules if isinstance(rules, list) else []):
            if not isinstance(rule, dict) or str(rule.get("decision") or "").lower() != "allow":
                continue
            tool = rule.get("toolName")
            tools = _strs(tool)
            narrowed = any(rule.get(k) for k in ("commandPrefix", "commandRegex", "argsPattern", "mcpName"))
            yolo = "yolo" in [m.lower() for m in _strs(rule.get("modes"))]
            broad = not tools or any(t.strip() in ("*", "**") or t.strip().endswith("__*") for t in tools) \
                or (any(t in ("run_shell_command", "shell", "write_file", "replace", "web_fetch") for t in tools) and not narrowed)
            if broad or yolo:
                what = "every tool" if not tools or "*" in tools else f"`{', '.join(tools)}` with no command or argument limit"
                self.flag("AG-CFG-049", doc, ("rule", str(i), "decision"), f"Policy rule {i + 1} allows {what}"
                          f"{' in yolo mode' if yolo else ''} without confirmation.", value="allow",
                          snippet=f"toolName = {tool!r}, decision = \"allow\"")

    # -- Cursor (CFG-055, 056) --------------------------------------------------------------------------------
    def _cursor_cli(self, doc: Doc) -> None:
        d = doc.data
        for rule_text in _strs(_get(d, "permissions", "allow"))[:300]:
            r = rule_text.strip()
            if regex.fullmatch(r"(?i)(?:Shell|Write|Read|WebFetch)(?:\(\s*\*{1,2}\s*\))?|Mcp\(\s*\*\s*:\s*\*\s*\)|Mcp|\*|Shell\(\s*(?:curl|wget|bash|sh|"
                               r"python3?|node|npx|sudo|rm|git|ssh|docker|eval)\s*\)", r):
                self.flag("AG-CFG-055", doc, ("permissions", "allow"), f"The CLI permission `{r}` allows a whole class of actions "
                          "(any shell command, any MCP tool, or writes anywhere) without asking.", value=rule_text, snippet=rule_text)
        mode = d.get("approvalMode") or _get(d, "permissions", "approvalMode")
        if isinstance(mode, str) and mode.lower() == "unrestricted":
            self.flag("AG-CFG-056", doc, ("approvalMode",), '`approvalMode` is "unrestricted": the agent runs every command without '
                      "approval.", value=mode)
        sandbox = d.get("sandbox")
        off = sandbox is False or (isinstance(sandbox, str) and sandbox.lower() in ("off", "disabled", "none", "false")) \
            or (isinstance(sandbox, dict) and (sandbox.get("enabled") is False or str(sandbox.get("mode") or "").lower() in ("off", "disabled", "none")))
        if off:
            self.flag("AG-CFG-056", doc, ("sandbox",), "The sandbox is turned off for the Cursor CLI.", value=None, snippet="sandbox")

    # -- OpenClaw (CFG-070 to 078) -------------------------------------------------------------------------------
    def _openclaw(self, doc: Doc) -> None:
        d = doc.data
        bind = _get(d, "gateway", "bind")
        auth = str(_get(d, "gateway", "auth", "mode") or "").lower()
        exposed = isinstance(bind, str) and bind.lower() not in ("", "loopback", "localhost", "127.0.0.1", "::1")
        if exposed and auth == "none":
            self.flag("AG-CFG-070", doc, ("gateway", "bind"), f"The gateway listens on `{bind}` with `auth.mode: \"none\"`: anyone who "
                      "can reach the port can drive the agent.", value=bind, lower_for_user=False)
        sandbox_mode = str(_get(d, "agents", "defaults", "sandbox", "mode") or "off").lower()
        if str(_get(d, "tools", "profile") or "").lower() == "full" and sandbox_mode in ("off", "none", "disabled"):
            self.flag("AG-CFG-071", doc, ("tools", "profile"), '`tools.profile` is "full" and the sandbox is off: messages from any '
                      "channel reach every tool on the host.", value="full", lower_for_user=False)
        elevated = _get(d, "tools", "elevated")
        if isinstance(elevated, dict) and elevated.get("enabled") is True:
            allow_from = elevated.get("allowFrom")
            flat: list[str] = []
            for v in (allow_from.values() if isinstance(allow_from, dict) else [allow_from]):
                flat += _strs(v)
            if not allow_from or any(x.strip() in ("*", "all") for x in flat):
                self.flag("AG-CFG-072", doc, ("tools", "elevated"), "Elevated execution is enabled and `allowFrom` does not restrict "
                          "who may ask for it.", value=None, snippet="tools.elevated", lower_for_user=False)
        hooks = d.get("hooks") if isinstance(d.get("hooks"), dict) else {}
        if hooks.get("enabled") is True:
            token = hooks.get("token")
            gateway_token = _get(d, "gateway", "auth", "token")
            if isinstance(token, str) and not _ENV_REF.search(token) and (len(token) < 24 or token == gateway_token
                                                                          or regex.fullmatch(r"(?i)(?:secret|token|changeme|password|test|openclaw|hook)\w{0,6}", token)):
                why = "the same as the gateway token" if token == gateway_token else "short or guessable"
                self.flag("AG-CFG-073", doc, ("hooks", "token"), f"Webhooks are enabled and their token is {why}.", value=token,
                          snippet="hooks.token = <redacted>", lower_for_user=False)
            if hooks.get("allowRequestSessionKey") is True:
                self.flag("AG-CFG-073", doc, ("hooks", "allowRequestSessionKey"), "Webhook requests may choose the session they are "
                          "delivered to, so a caller can write into another conversation.", value=True, lower_for_user=False)
        plugins = d.get("plugins") if isinstance(d.get("plugins"), dict) else {}
        entries = plugins.get("entries") if isinstance(plugins.get("entries"), dict) else {}
        if not _strs(plugins.get("allow")):
            for pid, entry in entries.items():
                ph = _get(entry, "hooks") if isinstance(entry, dict) else None
                for key in ("allowPromptModification", "allowConversationAccess"):
                    if isinstance(ph, dict) and ph.get(key) is True:
                        self.flag("AG-CFG-075", doc, ("plugins", "entries", str(pid), "hooks", key), f"Plugin '{pid}' has `{key}` and "
                                  "there is no `plugins.allow` list restricting which plugins load.", value=True, lower_for_user=False)
        skills = d.get("skills") if isinstance(d.get("skills"), dict) else {}
        s_entries = skills.get("entries") if isinstance(skills.get("entries"), dict) else {}
        for key, entry in s_entries.items():
            api_key = entry.get("apiKey") if isinstance(entry, dict) else None
            if literal_secret(api_key):
                self.flag("AG-CFG-077", doc, ("skills", "entries", str(key), "apiKey"), f"`skills.entries.{key}.apiKey` holds a "
                          "literal API key.", value=api_key, snippet="apiKey = <redacted>", lower_for_user=False)
        for extra in _strs(_get(skills, "load", "extraDirs")):
            if extra.startswith(("/", "~", "..")) or regex.match(r"[A-Za-z]:[\\/]", extra):
                self.flag("AG-CFG-078", doc, ("skills", "load", "extraDirs"), f"Skills are also loaded from `{extra}`, outside the "
                          "workspace; whatever is placed there becomes a skill.", value=extra, snippet=extra, lower_for_user=False)

    def _openclaw_files(self) -> None:
        ctx, inv = self.ctx, self.ctx.inventory
        # CFG-074: a workspace hook is a HOOK.md plus a handler that runs inside the gateway process.
        for path, surface in sorted(inv.surfaces.items()):
            if surface.id != "openclaw.hook":
                continue
            base = posixpath.dirname(path)
            for name in ("handler.ts", "handler.js", "handler.mjs", "index.ts", "index.js"):
                at = inv.texts.get(f"{base}/{name}")
                if at is None:
                    continue
                m = search(EXEC_CODE, at.text) or search(EGRESS_CODE, at.text)
                if m:
                    cid = self._cid(path)
                    what = "runs commands" if search(EXEC_CODE, at.text) else "makes network requests"
                    ctx.emit("AG-CFG-074", component_ids=[cid] if cid else [], span=at.span(m.start(), m.end()),
                             snippet=at.line_text(m.start()).strip()[:300], kind=EvidenceKind.config, match=f"{path}:{m.group(0)}",
                             related=[Span(path=path)],
                             message=f"The workspace hook '{posixpath.basename(base)}' {what} from its handler, which runs as "
                                     "trusted code inside the gateway.")
        # CFG-076: `metadata.openclaw.install[]` downloads.
        for at in ctx.texts("skill_md"):
            meta = at.fm.data.get("metadata") if at.fm and isinstance(at.fm.data, dict) else None
            installs = _get(meta, "openclaw", "install") if isinstance(meta, dict) else None
            for entry in installs if isinstance(installs, list) else []:
                if not isinstance(entry, dict) or str(entry.get("kind") or "").lower() != "download":
                    continue
                url = str(entry.get("url") or "")
                problems = []
                if url.lower().startswith("http://"):
                    problems.append("over plain HTTP")
                if not entry.get("sha256"):
                    problems.append("with no `sha256`")
                if problems and url:
                    off = at.text.find(url)
                    span = at.span(off, off + len(url)) if off >= 0 else Span(path=at.path)
                    ctx.emit("AG-CFG-076", component_ids=at.artifact.component_id, span=span, snippet=url, kind=EvidenceKind.config,
                             match=f"install:{url}", message=f"The skill's install step downloads `{url[:100]}` "
                                                             f"{' and '.join(problems)}; what is installed cannot be verified.")

    # -- MCP entries in client configs (CFG-059, 067) ---------------------------------------------------------------
    def _mcp_entries(self) -> None:
        ctx, inv = self.ctx, self.ctx.inventory
        for cfg in inv.configs:
            low = cfg.path.lower()
            for entry in cfg.servers:
                sid = inv.server_components.get((cfg.path, entry.project or "", entry.name))
                span = Span(path=cfg.path, start_line=entry.line)
                raw = entry.raw
                if cfg.client == "cursor" or "/.cursor/" in "/" + low:
                    env_file = raw.get("envFile")
                    if isinstance(env_file, str) and (search(CREDENTIAL_PATH, env_file) or regex.search(r"(?i)(^|/)\.env(\.|$)|secret|credential", env_file)):
                        ctx.emit("AG-CFG-059", component_ids=[sid] if sid else [], span=span, snippet=f"envFile: {env_file}",
                                 kind=EvidenceKind.config, match=f"{entry.name}:envFile",
                                 message=f"Server '{entry.name}' loads its environment from `{env_file}`: every secret in that file "
                                         "is handed to the server process.")
                    secret = _get(raw, "auth", "CLIENT_SECRET")
                    if literal_secret(secret):
                        ctx.emit("AG-CFG-059", component_ids=[sid] if sid else [], span=span, snippet="CLIENT_SECRET: <redacted>",
                                 kind=EvidenceKind.config, match=f"{entry.name}:client_secret",
                                 message=f"Server '{entry.name}' has a literal OAuth `CLIENT_SECRET` in the MCP configuration.")
                if cfg.client == "vscode" or low.endswith(".vscode/mcp.json"):
                    if raw.get("sandboxEnabled") is False:
                        ctx.emit("AG-CFG-067", component_ids=[sid] if sid else [], span=span, snippet="sandboxEnabled: false",
                                 kind=EvidenceKind.config, match=f"{entry.name}:sandbox",
                                 message=f"Server '{entry.name}' has `sandboxEnabled: false`: it runs with the user's full access.")
            if (cfg.client == "vscode" or low.endswith(".vscode/mcp.json")) and isinstance(cfg.value, dict):
                for i, inp in enumerate(cfg.value.get("inputs") if isinstance(cfg.value.get("inputs"), list) else []):
                    default = inp.get("default") if isinstance(inp, dict) else None
                    if isinstance(default, str) and default and (inp.get("password") is True or find_secrets(default, include_placeholders=False)) \
                            and not is_placeholder(default):
                        cc = next((c for c in inv.components.values() if c.root == cfg.path and c.kind.value == "mcp_client_config"), None)
                        ctx.emit("AG-CFG-067", component_ids=[cc.id] if cc else [], span=Span(path=cfg.path), kind=EvidenceKind.config,
                                 snippet=f"inputs[{i}].default: <redacted>", match=f"input:{inp.get('id')}",
                                 message=f"Input '{inp.get('id', i)}' ships a secret as its default value; anyone with the file has it.")

    # -- .env files (CFG-046) ----------------------------------------------------------------------------------------
    def _env_files(self) -> None:
        ctx, inv = self.ctx, self.ctx.inventory
        for path, surface in sorted(inv.surfaces.items()):
            if surface.id not in ("gemini.env", "env.file") or not is_repo_file(path):
                continue
            at = inv.texts.get(path)
            if at is None:
                continue
            gemini = surface.id == "gemini.env"
            for m in regex.finditer(r"(?m)^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*(.*)$", at.text):
                name, value = m.group(1), m.group(2).strip().strip("\"'")
                if not value:
                    continue
                if _BASE_URL_VARS.match(name) or _SECURITY_VARS.match(name):
                    if not gemini and name.upper() in ("PATH", "EDITOR", "VISUAL", "PAGER", "ENV"):
                        continue
                    ctx.emit("AG-CFG-046", component_ids=[self._cid(path)] if self._cid(path) else [],
                             span=at.span(m.start(1), m.end()), snippet=m.group(0).strip()[:200], kind=EvidenceKind.config,
                             match=f"{path}:{name}", severity=None if gemini else Severity.medium,
                             message=f"`{name}` is set in `{path}`, a file the agent loads automatically from the project: it "
                                     "changes where the agent sends traffic or what code runs, without any setting being visible.")

    # -- instruction-file imports (CFG-022, 023) -----------------------------------------------------------------------
    def _imports(self) -> None:
        ctx, inv = self.ctx, self.ctx.inventory
        for src, line, ref, dst, kind in sorted(inv.references):
            if kind != "import" or dst:
                continue
            cid = self._cid(src)
            at = inv.texts.get(src)
            span = Span(path=src, start_line=max(1, line))
            snippet = at.line_text(at.index.line_start(line)).strip()[:200] if at is not None and line >= 1 else f"@{ref}"
            if ref.startswith(("~/", "/")):
                sensitive = bool(_SENSITIVE_IMPORT.search(ref))
                ctx.emit("AG-CFG-022", component_ids=[cid] if cid else [], span=span, snippet=snippet, kind=EvidenceKind.config,
                         match=f"{src}:@{ref}", severity=None if sensitive else Severity.medium,
                         message=f"The instruction file imports `@{ref}`, "
                                 + ("a file that holds credentials or private data: its contents are loaded into the model's context."
                                    if sensitive else "a path outside the project: what the agent is told depends on a file the "
                                                      "repository does not contain."))
            elif ref.startswith("../"):
                ctx.emit("AG-CFG-023", component_ids=[cid] if cid else [], span=span, snippet=snippet, kind=EvidenceKind.config,
                         match=f"{src}:@{ref}", message=f"The import `@{ref}` leaves the repository; the imported instructions are "
                                                        "not part of what was reviewed or scanned.")

    # -- Cursor always-apply rules (CFG-060) ------------------------------------------------------------------------------
    def _cursor_rules(self) -> None:
        ctx, inv = self.ctx, self.ctx.inventory
        risky_families = ("INJ", "EXEC", "EXF", "CRED", "PERSIST", "IMPACT", "MANIP")
        by_path: dict[str, list] = {}
        for r in ctx.raw:
            if r.primary and r.rid.split("-")[1] in risky_families:
                by_path.setdefault(r.primary.path, []).append(r)
        for at in ctx.texts("instruction_md"):
            surface = inv.surfaces.get(at.path)
            if surface is None or surface.id != "cursor.rule" or at.fm is None or not isinstance(at.fm.data, dict):
                continue
            if at.fm.data.get("alwaysApply") is not True or at.path not in by_path:
                continue
            first = by_path[at.path][0]
            off = at.text.find("alwaysApply")
            ctx.emit("AG-CFG-060", component_ids=at.artifact.component_id, span=at.span(max(off, 0)), kind=EvidenceKind.config,
                     snippet="alwaysApply: true", match=f"{at.path}:alwaysApply", related=[first.primary] if first.primary else None,
                     message=f"This rule is loaded into every Cursor request (`alwaysApply: true`) and carries a risky directive "
                             f"({', '.join(sorted({r.rid for r in by_path[at.path]})[:4])}).")

    # -- custom agents (CFG-066) ------------------------------------------------------------------------------------------
    def _custom_agents(self) -> None:
        ctx, inv = self.ctx, self.ctx.inventory
        for at in ctx.texts("instruction_md"):
            surface = inv.surfaces.get(at.path)
            if surface is None or surface.id != "copilot.agent" or at.fm is None or not isinstance(at.fm.data, dict):
                continue
            fm = at.fm.data
            tools = fm.get("tools")
            all_tools = tools is None or tools == "*" or (isinstance(tools, list) and any(str(t).strip() == "*" for t in tools))
            servers = fm.get("mcp-servers") or fm.get("mcpServers")
            if all_tools and isinstance(servers, dict) and servers:
                names = ", ".join(str(n) for n in list(servers)[:4])
                off = at.text.find("mcp-servers") if "mcp-servers" in at.text else at.text.find("mcpServers")
                ctx.emit("AG-CFG-066", component_ids=at.artifact.component_id, span=at.span(max(off, 0)), kind=EvidenceKind.config,
                         snippet=f"tools: {tools!r}; mcp-servers: {names}", match=f"{at.path}:agent",
                         message=f"The custom agent has every tool and brings its own MCP server(s) ({names}); the cloud agent uses "
                                 "MCP tools without asking for approval.")

    # -- user-scope files in a repository (CFG-019, 090) ----------------------------------------------------------------------
    def _committed_state(self) -> None:
        ctx, inv = self.ctx, self.ctx.inventory
        tree = inv.tree
        ignored = ""
        if tree is not None:
            ignored = "\n".join(tree.files[p].data.decode("utf-8", "replace") for p in tree.files
                                if posixpath.basename(p) == ".gitignore" and tree.files[p].size < 200_000)
        for path in sorted(inv.artifacts):
            if not is_repo_file(path):
                continue
            cid = self._cid(path)
            if regex.search(r"(?i)(^|/)\.claude/settings\.local\.json$", path):
                if regex.search(r"(?m)^\s*(?:\*\*/)?(?:/?\.claude/?|(?:\.claude/)?settings\.local\.json|\*\.local\.json|\.claude/\*)\s*$", ignored):
                    continue                              # git-ignored: a local file, not a committed one
                ctx.emit("AG-CFG-019", component_ids=[cid] if cid else [], span=Span(path=path), snippet=path, kind=EvidenceKind.config,
                         match=f"local:{path}", message="`settings.local.json` holds one person's local overrides and personal "
                                                        "permission grants; shipped with the repository, it applies them to everyone.")
            elif _USER_STATE_FILES.search(path):
                ctx.emit("AG-CFG-090", component_ids=[cid] if cid else [], span=Span(path=path), snippet=path, kind=EvidenceKind.config,
                         match=f"userstate:{path}", message=f"`{path}` is a user-level state or configuration file. Committed to a "
                                                            "repository it leaks one person's setup (often tokens and trust "
                                                            "records) and may be picked up by tools that expect it in a home directory.")

    # -- hidden characters in commands, URLs and paths (CFG-092) -------------------------------------------------------------
    def _hidden_values(self, cmds: list[ConfigCommand]) -> None:
        ctx, inv = self.ctx, self.ctx.inventory
        seen: set[tuple[str, str]] = set()

        def check(path: str, cid: str, span: Span, text: str, what: str) -> None:
            m = _HIDDEN_CHARS.search(text)
            if m is None or (path, text) in seen:
                return
            seen.add((path, text))
            ch = m.group(0)
            name = unicodedata.name(ch, f"U+{ord(ch):04X}")
            shown = "".join(c if not _HIDDEN_CHARS.match(c) else f"⟨U+{ord(c):04X}⟩" for c in text[:200])
            ctx.emit("AG-CFG-092", component_ids=[cid] if cid else [], span=span, snippet=shown, kind=EvidenceKind.config,
                     match=f"{path}:{text[:100]}", message=f"The {what} contains an invisible or look-alike whitespace character "
                                                           f"({name}): what runs or is contacted differs from what a reviewer reads.")

        for c in cmds:
            if c.role == "config_command" and c.surface != "ws.envrc":
                check(c.path, c.component_id, c.span, c.text, "command")
        values: dict[str, list[tuple[tuple[str, ...], str, Span]]] = ctx.data.get("config_values", {})  # type: ignore[assignment]
        for path, items in sorted(values.items()):
            cid = self._cid(path)
            for keypath, text, span in items:
                key = next((k.lower() for k in reversed(keypath) if not k.isdigit()), "")
                if len(text) <= 2000 and (_URL_OR_PATH.search(text.strip()) or key in ("url", "uri", "path", "cwd", "endpoint", "source", "repo", "file")):
                    check(path, cid, span, text, f"`{key}` value")
        for cfg in inv.configs:
            for entry in cfg.servers:
                sid = inv.server_components.get((cfg.path, entry.project or "", entry.name)) or ""
                span = Span(path=cfg.path, start_line=entry.line)
                for text in [entry.spec.command or "", *entry.spec.args, entry.spec.url or ""]:
                    if text:
                        check(cfg.path, sid, span, text, f"command or URL of server '{entry.name}'")


def _broad_allow(rule_text: str) -> str:
    """Why a ``permissions.allow`` entry is broad, or ""."""
    r = rule_text.strip()
    try:
        if r in ("*", "Bash", "Bash(*)", "Bash(**)", "Bash(:*)"):
            return "it allows every shell command" if r != "*" else "it allows every tool"
        if _BROAD_BASH.match(r):
            return "it allows a command that can run arbitrary code, reach the network or change the system"
        if _BROAD_PATH.match(r):
            return "it grants file access to the home directory, the filesystem root or credential files"
        if regex.fullmatch(r"(?i)WebFetch(?:\(\s*(?:domain:\s*)?\*\s*\))?", r):
            return "it allows fetching any URL"
        if regex.fullmatch(r"(?i)mcp__\*|mcp__\*__\*|mcp__", r):
            return "it allows every tool of every MCP server"
        if regex.fullmatch(r"(?i)(?:Write|Edit|MultiEdit)", r):
            return "it allows every file edit"
    except TimeoutError:
        return ""
    return ""


__all__ = ["Hook", "SettingsAnalyzer", "is_local_host", "is_repo_file", "is_vendor_host", "iter_hooks", "literal_secret"]
