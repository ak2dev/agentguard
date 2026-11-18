"""Enumerations shared by every model. Values are part of the report schema."""

from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

    @property
    def rank(self) -> int:
        return _SEV_RANK[self]

    def at_least(self, other: Severity) -> bool:
        return self.rank >= other.rank

    def bump(self, levels: int = 1) -> Severity:
        order = list(reversed(_SEV_ORDER))  # info .. critical
        idx = min(max(order.index(self) + levels, 0), len(order) - 1)
        return order[idx]

    @classmethod
    def parse(cls, value: str) -> Severity:
        v = value.strip().lower()
        aliases = {"crit": "critical", "med": "medium", "moderate": "medium", "none": "info"}
        return cls(aliases.get(v, v))


_SEV_ORDER = [Severity.critical, Severity.high, Severity.medium, Severity.low, Severity.info]
_SEV_RANK = {s: len(_SEV_ORDER) - i for i, s in enumerate(_SEV_ORDER)}


class Confidence(StrEnum):
    high = "high"
    medium = "medium"
    low = "low"

    @property
    def rank(self) -> int:
        return {"high": 3, "medium": 2, "low": 1}[self.value]

    def lower(self, levels: int = 1) -> Confidence:
        order = [Confidence.low, Confidence.medium, Confidence.high]
        return order[max(order.index(self) - levels, 0)]

    @staticmethod
    def min(*values: Confidence) -> Confidence:
        return min(values, key=lambda c: c.rank)


class SourceKind(StrEnum):
    local = "local"
    npm = "npm"
    pypi = "pypi"
    oci = "oci"
    github = "github"
    gist = "gist"
    raw_url = "raw_url"
    mcp_registry = "mcp_registry"
    marketplace = "marketplace"
    remote_mcp = "remote_mcp"
    pasted = "pasted"


class ComponentKind(StrEnum):
    agent_host = "agent_host"
    skill = "skill"
    instruction_file = "instruction_file"
    subagent = "subagent"
    command = "command"
    mcp_server = "mcp_server"
    mcp_client_config = "mcp_client_config"
    package = "package"
    # Added with the 23-family catalogue (spec/ecosystems.md).
    plugin = "plugin"
    marketplace = "marketplace"
    settings = "settings"            # agent settings / permission / policy files
    hook = "hook"                    # standalone hook definition files
    ci_workflow = "ci_workflow"
    workspace = "workspace"          # editor tasks, dev containers, direnv, git hooks
    container = "container"          # Dockerfile / compose / image reference
    connector = "connector"          # OpenAPI action descriptor, A2A agent card
    bundle = "bundle"                # MCPB bundle manifest
    repository = "repository"        # everything else in the scanned tree

    @property
    def spec_type(self) -> str:
        """The `type` shown in reports and lock entries (kebab-case)."""
        return self.value.replace("_", "-")


class ArtifactRole(StrEnum):
    skill_md = "skill_md"
    instruction_md = "instruction_md"
    script = "script"
    reference = "reference"
    asset = "asset"
    client_config = "client_config"
    server_json = "server_json"
    tool_manifest = "tool_manifest"
    source_code = "source_code"
    package_manifest = "package_manifest"
    lockfile = "lockfile"
    ui_resource = "ui_resource"
    binary = "binary"
    archive = "archive"
    other = "other"
    # Added with the 23-family catalogue.
    settings = "settings"
    hook_config = "hook_config"
    plugin_manifest = "plugin_manifest"
    marketplace_manifest = "marketplace_manifest"
    bundle_manifest = "bundle_manifest"
    command_md = "command_md"
    workflow = "workflow"
    workspace_config = "workspace_config"
    dockerfile = "dockerfile"
    compose = "compose"
    descriptor = "descriptor"
    env_file = "env_file"
    image = "image"
    document = "document"
    notebook = "notebook"
    html = "html"
    media = "media"
    # Files of the catch-all `repository` component: accounted for and checked for hidden content,
    # secrets and coverage, but not read as agent instructions or agent-run code unless an
    # agent-facing file imports, runs or names them (then they are promoted to script / reference).
    repo_code = "repo_code"
    repo_doc = "repo_doc"


class Transport(StrEnum):
    stdio = "stdio"
    streamable_http = "streamable_http"
    sse_deprecated = "sse_deprecated"
    unknown = "unknown"


class CapLabel(StrEnum):
    reads_private_data = "reads_private_data"
    ingests_untrusted_content = "ingests_untrusted_content"
    external_egress = "external_egress"
    destructive = "destructive"
    code_exec = "code_exec"
    # Sub-labels used for escalation and explanations.
    credential_access = "credential_access"
    persistence = "persistence"
    auto_approved = "auto_approved"
    # Capability set used for the risk tier and least-privilege analysis.
    fs_read = "fs_read"
    fs_write_workspace = "fs_write_workspace"
    fs_write_outside = "fs_write_outside"
    shell = "shell"
    financial = "financial"
    host_elevated = "host_elevated"

    @property
    def spec_name(self) -> str:
        """Capability name as written in reports, lock entries and policy."""
        return _CAP_NAMES.get(self.value, self.value.replace("_", "-"))


TRIFECTA = (
    CapLabel.reads_private_data,
    CapLabel.ingests_untrusted_content,
    CapLabel.external_egress,
)


_CAP_NAMES = {
    "reads_private_data": "sensitive-data",
    "ingests_untrusted_content": "untrusted-content",
    "external_egress": "network-egress",
    "financial": "financial-execution",
}


class FindingSource(StrEnum):
    deterministic = "deterministic"
    llm = "llm"
    intel = "intel"
    policy = "policy"
    dynamic = "dynamic"


class EvidenceKind(StrEnum):
    regex = "regex"
    yara = "yara"
    ast = "ast"
    taint = "taint"
    schema = "schema"
    config = "config"
    metadata = "metadata"
    intel = "intel"
    lock_diff = "lock_diff"
    llm = "llm"
    policy = "policy"
    loader = "loader"
    media = "media"
    flow = "flow"
    dynamic = "dynamic"
    live = "live"


class Category(StrEnum):
    """What a finding is about. The three are never mixed into one list."""

    malice = "malice"
    vulnerability = "vulnerability"
    hygiene = "hygiene"


class Lane(StrEnum):
    """How much a rule may decide alone (spec/rules.md, "Lanes")."""

    block = "block"        # high precision; can produce a BLOCK verdict alone
    evidence = "evidence"  # counts towards a verdict only when corroborated
    hunt = "hunt"          # advisory; off in the balanced policy, on in strict


class FixKind(StrEnum):
    auto = "auto"          # A: safe deterministic edit
    patch = "patch"        # P: proposed patch, kept only after a clean re-scan
    guidance = "guidance"  # G: remediation text
    remove = "remove"      # X: do not install, or remove
    none = "none"


class RuleStatus(StrEnum):
    planned = "planned"            # in the catalogue, no detector yet
    experimental = "experimental"
    stable = "stable"              # at least five positive and five negative fixtures
    deprecated = "deprecated"


class Verdict(StrEnum):
    allow = "ALLOW"
    review = "REVIEW"
    block = "BLOCK"

    @property
    def rank(self) -> int:
        return {"ALLOW": 0, "REVIEW": 1, "BLOCK": 2}[self.value]


class RiskTier(StrEnum):
    """Assigned from capabilities, independently of findings."""

    L0 = "L0"  # only adds instructions
    L1 = "L1"  # writes files inside the workspace; no shell, no network
    L2 = "L2"  # shell, network or credentials
    L3 = "L3"  # persistent or system-level changes, financial, destructive, elevated

    @property
    def rank(self) -> int:
        return int(self.value[1])


FAMILIES: tuple[str, ...] = (
    "INJ", "OBF", "MM", "EXF", "CRED", "EXEC", "PERSIST", "IMPACT", "MANIP", "PRIV", "CFG", "PLUG",
    "MCP", "VULN", "SUPPLY", "META", "FLOW", "CI", "WS", "IMG", "CONN", "EVADE", "HYG",
)
# Scanner-status families outside the 450-rule catalogue (policy outcomes).
SYSTEM_FAMILIES: tuple[str, ...] = ("POL",)

ENGINES: tuple[str, ...] = (
    "text-integrity", "instruction", "code", "config", "supply", "intel", "media", "image",
    "flow", "privilege", "triage", "judge", "dynamic", "live", "coverage", "policy",
)
