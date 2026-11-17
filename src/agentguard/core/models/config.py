"""Scan options, load limits, suppressions, policy, project config, lockfile."""

from __future__ import annotations

import datetime as dt
from typing import Any, Callable, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..intel.feed import IntelFeed
from ..judge_models import JudgeResult
from .enums import CapLabel, RiskTier, Severity
from .network import DependencyFact, PackageFacts, RemoteProbe


class LoadLimits(BaseModel):
    model_config = ConfigDict(frozen=True)

    max_file_bytes: int = 4 * 1024 * 1024
    max_total_bytes: int = 256 * 1024 * 1024
    max_files: int = 20_000
    max_depth: int = 32
    max_archive_ratio: float = 100.0
    max_archive_members: int = 20_000
    max_archive_depth: int = 3
    max_decode_depth: int = 3
    max_decoded_bytes: int = 1 * 1024 * 1024
    max_yaml_nodes: int = 50_000
    max_json_depth: int = 64
    max_line_length_for_regex: int = 20_000
    excluded_dirs: tuple[str, ...] = (
        # __pycache__ is not skipped: a .pyc that does not match its source is a payload (AG-OBF-020).
        ".git", "node_modules", ".venv", "venv", ".tox", ".mypy_cache",
        ".pytest_cache", ".agentguard-cache",
    )

    @classmethod
    def cli(cls) -> LoadLimits:
        return cls()

    @classmethod
    def ci(cls) -> LoadLimits:
        return cls()

    @classmethod
    def web(cls) -> LoadLimits:
        return cls(
            max_file_bytes=2 * 1024 * 1024,
            max_total_bytes=64 * 1024 * 1024,
            max_files=5_000,
            max_archive_members=5_000,
        )


class NetworkOptions(BaseModel):
    """Every network feature is opt-in. Enabled features appear in the report header."""

    live_metadata: bool = False
    auth_checks: bool = False
    provenance: bool = False
    osv: bool = False
    registry: bool = False
    hijackable: bool = False
    llm_judge: bool = False

    def enabled(self) -> list[str]:
        return [k for k, v in self.model_dump().items() if v]


class Suppression(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str | None = None       # a rule id, an old alias, a family ("INJ") or a prefix ("AG-INJ-")
    fingerprint: str | None = None
    path_glob: str | None = None
    reason: str = ""
    approved_by: str = ""
    expires: dt.date | None = None

    @model_validator(mode="after")
    def _has_selector(self) -> Suppression:
        if not (self.rule_id or self.fingerprint or self.path_glob):
            raise ValueError("suppression needs at least one of rule_id, fingerprint, path_glob")
        return self

    def is_valid(self) -> bool:
        return len(self.reason.strip()) >= 10 and self.expires is not None


def _on_off(value: Any) -> Any:
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("on", "true", "yes"):
            return True
        if v in ("off", "false", "no"):
            return False
    return value


class PolicyRequire(BaseModel):
    model_config = ConfigDict(extra="forbid")

    full_coverage: bool = False          # any coverage finding fails the scan with exit code 3
    pinned_sources: bool = False
    signatures: Literal["off", "warn", "require"] = "off"
    max_risk_tier: RiskTier | None = None  # components above this need an approval record
    min_analyzability: float = Field(0.0, ge=0.0, le=1.0)

    @field_validator("signatures", mode="before")
    @classmethod
    def _signatures(cls, v: Any) -> Any:
        return "off" if v is False else v


class PolicyAllow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    publishers: list[str] = Field(default_factory=list)   # glob, e.g. "github.com/my-org/*"
    registries: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    servers: list[str] | None = None                      # glob on name / command / url


class PolicyDeny(BaseModel):
    model_config = ConfigDict(extra="forbid")

    capabilities: list[str] = Field(default_factory=list)  # e.g. financial-execution, host-elevated
    rules: list[str] = Field(default_factory=list)
    servers: list[str] = Field(default_factory=list)
    publishers: list[str] = Field(default_factory=list)


class PolicyLanes(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hunt: bool = False

    @field_validator("hunt", mode="before")
    @classmethod
    def _hunt(cls, v: Any) -> Any:
        return _on_off(v)


POLICY_PRESETS: dict[str, dict[str, Any]] = {
    # Hunt lane on, full coverage and pinning required, REVIEW fails.
    # `min_analyzability` is the share of the content (by bytes) that must have been analysed; below it
    # the scan reports AG-EVADE-021 and cannot end in ALLOW.
    "strict": {"fail_on": "review", "lanes": {"hunt": True},
               "require": {"full_coverage": True, "pinned_sources": True, "min_analyzability": 1.0}},
    "balanced": {"fail_on": "block", "require": {"min_analyzability": 0.8}},
    # For trusted internal sources: only BLOCK fails.
    "permissive": {"fail_on": "block", "require": {"min_analyzability": 0.0}},
}


def _deep_merge(base: dict[str, Any], over: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def normalize_fail_on(value: Any) -> str:
    """``block`` | ``review`` | ``severity:<level>``. A bare severity (the first
    config format) means ``severity:<level>``."""
    v = str(getattr(value, "value", value)).strip().lower()
    if v in ("block", "review"):
        return v
    level = v.split(":", 1)[1] if v.startswith("severity:") else v
    return f"severity:{Severity.parse(level).value}"


class Policy(BaseModel):
    """Policy as code (spec/interfaces.md §5). It is applied last and can only
    tighten a verdict, except through recorded suppressions."""

    model_config = ConfigDict(extra="forbid")

    version: Literal[1] = 1
    name: str = "balanced"
    extends: str | None = None
    engine: Literal["builtin"] = "builtin"  # "rego" / "cel" reserved
    fail_on: str | None = None              # block | review | severity:<level>
    require: PolicyRequire = Field(default_factory=PolicyRequire)
    allow: PolicyAllow = Field(default_factory=PolicyAllow)
    deny: PolicyDeny = Field(default_factory=PolicyDeny)
    severity_overrides: dict[str, Severity] = Field(default_factory=dict)
    lanes: PolicyLanes = Field(default_factory=PolicyLanes)
    suppressions: list[Suppression] = Field(default_factory=list)
    max_severity: Severity | None = None
    trifecta_severity: Severity = Severity.high

    @model_validator(mode="before")
    @classmethod
    def _fold(cls, data: Any) -> Any:
        """Resolve ``extends`` (a preset) and accept the flat keys of the first
        policy format (deny_servers, deny_publishers, allow_servers, require_pinning)."""
        if not isinstance(data, dict):
            return data
        data = dict(data)
        base_name = data.get("extends") or data.get("name") or "balanced"
        if base_name in POLICY_PRESETS:
            merged = _deep_merge(POLICY_PRESETS[base_name], data)
            merged.setdefault("name", base_name)
            data = merged
        for key in ("require", "allow", "deny"):
            data[key] = dict(data.get(key) or {})
        if "deny_servers" in data:
            data["deny"]["servers"] = [*data["deny"].get("servers", []), *data.pop("deny_servers")]
        if "deny_publishers" in data:
            data["deny"]["publishers"] = [*data["deny"].get("publishers", []), *data.pop("deny_publishers")]
        if "allow_servers" in data:
            legacy = data.pop("allow_servers")
            if legacy is not None:
                data["allow"]["servers"] = legacy
        if "require_pinning" in data:
            pin = bool(data.pop("require_pinning"))
            data["require"]["pinned_sources"] = pin or data["require"].get("pinned_sources", False)
        if data.get("fail_on") is not None:
            data["fail_on"] = normalize_fail_on(data["fail_on"])
        return data

    # -- names from the first policy format ---------------------------------
    @property
    def deny_servers(self) -> list[str]:
        return self.deny.servers

    @property
    def deny_publishers(self) -> list[str]:
        return self.deny.publishers

    @property
    def allow_servers(self) -> list[str] | None:
        return self.allow.servers

    @property
    def require_pinning(self) -> bool:
        return self.require.pinned_sources

    @classmethod
    def preset(cls, name: str) -> Policy:
        if name not in POLICY_PRESETS:
            raise ValueError(f"unknown policy preset {name!r} (choose strict, balanced or permissive)")
        return cls.model_validate({"name": name})


class LlmConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: Literal["anthropic", "openai-compatible", "openai_compat", "local", "ollama"] = "anthropic"
    triage_model: str = "claude-haiku-5-5"
    judge_model: str = "claude-opus-5-5"
    endpoint: str | None = None
    consensus_runs: int = Field(1, ge=1, le=9)
    max_cost_usd: float = 2.00
    max_tokens: int = 400_000
    redact_secrets: bool = True


class DynamicConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    runtime: Literal["docker"] = "docker"
    agent_adapter: Literal["claude-code", "opencode", "none"] = "claude-code"
    timeout_seconds: int = 900


class IntelConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    osv: Literal["online", "mirror", "off"] = "off"
    virustotal: Literal["on", "off"] = "off"
    url_reputation: Literal["bundled", "online", "off"] = "bundled"
    # Where `agentguard update` looks when no --from is given: an https:// URL or a path to an update bundle.
    update_source: str | None = None

    @field_validator("osv", "virustotal", "url_reputation", mode="before")
    @classmethod
    def _yaml_bool(cls, v: Any) -> Any:
        # YAML 1.1 reads a bare `off` / `on` as a boolean.
        return {True: "on", False: "off"}[v] if isinstance(v, bool) else v


class CacheConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dir: str = "~/.cache/agentguard"
    ttl_days: int = 30


class OutputConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    redact_snippets: bool = False


class LimitsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_file_bytes: int | None = None
    max_archive_depth: int | None = None
    max_archive_ratio: float | None = None
    timeout_seconds: int | None = None


class ProjectConfig(BaseModel):
    """Contents of .agentguard.yaml (spec/interfaces.md §4)."""

    model_config = ConfigDict(extra="forbid")

    version: Literal[1] = 1
    profile: Literal["quick", "standard", "deep"] | None = None
    fail_on: str | None = None                 # block | review | severity:<level>; a bare level means severity:<level>
    context: str | None = None                 # installed | none | a path
    ecosystems: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)
    suppressions: list[Suppression] = Field(default_factory=list)
    policy: Policy | str | None = None         # a preset name or an inline policy
    popular_skills: list[str] = Field(default_factory=list)
    limits: LimitsConfig = Field(default_factory=LimitsConfig)
    llm: LlmConfig = Field(default_factory=LlmConfig)
    dynamic: DynamicConfig = Field(default_factory=DynamicConfig)
    intel: IntelConfig = Field(default_factory=IntelConfig)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)

    @field_validator("fail_on", mode="before")
    @classmethod
    def _fail_on(cls, v: Any) -> Any:
        return normalize_fail_on(v) if v is not None else None

    def resolved_policy(self) -> Policy | None:
        if isinstance(self.policy, str):
            return Policy.preset(self.policy)
        return self.policy


class ToolSnapshot(BaseModel):
    hash: str
    definition: dict[str, Any]


class LockLaunch(BaseModel):
    """How an MCP server is started or reached. ``sha256`` covers all of it, so a
    changed command, argument or URL under the same name is caught (AG-MCP-012)."""

    command: str | None = None
    args: list[str] = Field(default_factory=list)
    url: str | None = None
    sha256: str = ""


class LockEntry(BaseModel):
    """One approved artifact in ``agentguard.lock`` (spec/interfaces.md §6)."""

    id: str = ""                         # "skill:pdf-helper", "mcp:acme-weather"
    type: str = ""                       # skill | mcp-server | plugin | instruction-file | …
    ecosystem: str = ""
    name: str = ""
    root: str = ""                       # where it lives in the scanned tree
    version: str | None = None
    source: str = ""
    commit: str | None = None
    tree_sha256: str = ""
    files: dict[str, str] | None = None
    external_refs: dict[str, str] = Field(default_factory=dict)   # url -> sha256 of the content that was approved
    capabilities: list[str] = Field(default_factory=list)
    risk_tier: str = ""
    verdict: str = ""
    accepted_findings: list[str] = Field(default_factory=list)    # fingerprints reviewed and accepted
    approved_by: str = ""
    approved_at: str = ""
    review_by: str = ""
    launch: LockLaunch | None = None
    tools: dict[str, str] | None = None                           # tool name -> hash of its canonical definition
    # Kept beside the hashes so `baseline diff` can show what changed, not only that something did.
    tool_definitions: dict[str, dict[str, Any]] | None = None
    server_instructions_sha256: str | None = None

    @model_validator(mode="before")
    @classmethod
    def _legacy(cls, data: Any) -> Any:
        """Entries of the first lock format: key / kind / content_hash /
        skill_files / tools{hash, definition} / capability_labels."""
        if not isinstance(data, dict) or "key" not in data:
            return data
        d = dict(data)
        key = str(d.pop("key"))
        kind = str(d.pop("kind", key.split(":", 1)[0]))
        d.setdefault("type", kind.replace("_", "-"))
        d.setdefault("name", key.split(":", 1)[-1].rsplit("@", 1)[0])
        d.setdefault("root", key.rsplit("@", 1)[-1] if "@" in key else "")
        d.setdefault("id", f"{kind}:{d['name']}")
        if "content_hash" in d:
            d["tree_sha256"] = d.pop("content_hash")
        if "skill_files" in d:
            d["files"] = d.pop("skill_files")
        labels = d.pop("capability_labels", None)
        if labels is not None:
            d["capabilities"] = [CapLabel(x).spec_name for x in labels]
        tools = d.get("tools")
        if isinstance(tools, dict) and any(isinstance(v, dict) for v in tools.values()):
            d["tools"] = {n: v["hash"] for n, v in tools.items()}
            d["tool_definitions"] = {n: v.get("definition", {}) for n, v in tools.items()}
        return d

    # -- names from the first lock format ------------------------------------
    @property
    def kind(self) -> str:
        return self.type.replace("-", "_")

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.name}@{self.root}"

    @property
    def content_hash(self) -> str:
        return self.tree_sha256

    @property
    def skill_files(self) -> dict[str, str] | None:
        return self.files


class Lockfile(BaseModel):
    lock_version: Literal[1, 2] = 2
    tool_hash_version: Literal[1, 2] = Field(
        1, description="What a tool hash covers. 1 (also locks without this field): name, title, description, "
                       "input_schema and annotations. 2: also output_schema, when the tool has one.")
    generated_by: dict[str, str] = Field(default_factory=dict)   # engine, rule_pack, intel
    artifacts: list[LockEntry] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _legacy(cls, data: Any) -> Any:
        if isinstance(data, dict) and "entries" in data and "artifacts" not in data:
            d = dict(data)
            d["artifacts"] = d.pop("entries")
            generator = d.pop("generator", None)
            if generator and "generated_by" not in d:
                d["generated_by"] = {"engine": str(generator)}
            return d
        if isinstance(data, dict) and "generator" in data:
            d = dict(data)
            d.pop("generator")
            return d
        return data

    @property
    def entries(self) -> list[LockEntry]:
        return self.artifacts


class JudgeOptions(BaseModel):
    provider: Literal["anthropic", "openai_compat", "ollama"]
    model: str
    endpoint: str | None = None
    budget_calls: int = 20
    cache_dir: str | None = None


class ProgressEvent(BaseModel):
    stage: str
    done: int
    total: int


class AdjudicationResult(BaseModel):
    """One answer of the model adjudicator about one candidate finding
    (produced on the host; passed into the pure engine as data)."""

    fingerprint: str
    status: Literal["confirmed", "doubted", "dismissed"]
    model: str = ""
    runs: int = 1
    rationale: str = ""
    # "<path>:<line>" the model quoted. A response that cites nothing valid is discarded.
    cited_spans: list[str] = Field(default_factory=list)
    raise_severity: Severity | None = None


class DynamicEvidence(BaseModel):
    """One observation from the detonation tier, mapped to a rule (spec/sandbox.md §7)."""

    rule: str                         # detector key
    path: str = ""                    # static location that caused it (script line, hook entry, instruction span)
    line: int = 1
    detail: str = ""
    trace: list[str] = Field(default_factory=list)   # process / syscall / network lines
    confirmed: bool = True
    component: str = ""               # component root, when known


class ScanOptions(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    intel: IntelFeed | None = None
    remote_probes: list[RemoteProbe] = Field(default_factory=list)
    package_facts: list[PackageFacts] = Field(default_factory=list)
    dependency_facts: list[DependencyFact] = Field(default_factory=list)
    judge_results: list[JudgeResult] = Field(default_factory=list)
    adjudications: list[AdjudicationResult] = Field(default_factory=list)
    dynamic_evidence: list[DynamicEvidence] = Field(default_factory=list)
    dynamic_ran: bool = False
    dynamic_level: str = ""
    dynamic_not_reached: list[str] = Field(default_factory=list)
    # Text recovered from media on the host (OCR, PDF rendering): path -> [(label, text)].
    media_text: dict[str, list[tuple[str, str]]] = Field(default_factory=dict)
    network_hosts: list[str] = Field(default_factory=list)
    # Facts recorded on the host before the scan (network lookups, image and package inspection, sandbox
    # enumeration), so rules that need them stay pure and can be tested offline. Keys in use:
    #   served_tools {component name | root: [tool names]}   artifact_sha256 {identifier: sha256}
    #   images {reference: {...}}   packages {"eco/name": {...}}   sources {url: {...}}   domains {host: {...}}
    #   endpoints {url: {...}}   fetches {url: [sha256, ...]}   ocr {path: bool}
    facts: dict[str, Any] = Field(default_factory=dict)
    llm_tokens: int = 0
    llm_cost_usd: float = 0.0
    llm_calls: int = 0
    llm_complete: bool = True
    llm_model: str = ""
    llm_sent: list[str] = Field(default_factory=list)

    profile: Literal["quick", "standard", "deep"] = "quick"
    fail_on: str = "block"
    limits: LoadLimits = Field(default_factory=LoadLimits)
    analyzers: set[str] | None = None           # None = all available
    rule_filter: set[str] | None = None         # catalogue rule ids to evaluate (None = all)
    ecosystems: set[str] | None = None          # None = all
    network: NetworkOptions = Field(default_factory=NetworkOptions)
    judge: JudgeOptions | None = None
    policy: Policy | None = None
    suppressions: list[Suppression] = Field(default_factory=list)
    # Inline `agentguard-ignore` comments are honoured only in the user's own repository.
    own_repo: bool = False
    baseline: set[str] | None = None            # fingerprints
    changed_paths: set[str] | None = None
    lock: Lockfile | None = None
    popular_skills: list[str] = Field(default_factory=list)
    include_timestamps: bool = False
    today: dt.date | None = None                # for suppression expiry (determinism)
    deadline_s: float | None = None
    agent_safe: bool = False
    # Installed components the candidate is composed with (an ArtifactTree); None = scan alone.
    context: Any = Field(default=None, exclude=True)
    on_progress: Callable[[ProgressEvent], None] | None = Field(default=None, exclude=True)
    # Receives the triage model's feature vectors (component id -> {feature: value}) in any profile; for training.
    on_triage_features: Callable[[dict[str, dict[str, float]]], None] | None = Field(default=None, exclude=True)

    @field_validator("fail_on", mode="before")
    @classmethod
    def _fail_on(cls, v: Any) -> Any:
        return normalize_fail_on(v)

    @field_validator("policy", mode="before")
    @classmethod
    def _policy(cls, v: Any) -> Any:
        # ``ScanOptions(policy="strict")``: a preset by name.
        return Policy.preset(v) if isinstance(v, str) else v

    @property
    def effective_policy(self) -> Policy:
        return self.policy or Policy()
