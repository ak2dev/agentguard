"""The report: the only contract between the engine and any UI.

Top-level shape follows spec/interfaces.md §7: tool, target, profile, coverage,
verdict, score, risk_tier, artifacts, findings, chains, limits, timings_ms.
"""

from __future__ import annotations

import datetime as dt
from typing import Any, Literal

from pydantic import BaseModel, Field

from .component import Artifact, Component
from .enums import RiskTier, Severity, Verdict
from .finding import Chain, Finding, FlowPath
from .source import ImmutableRef, SourceRef

REPORT_SCHEMA_VERSION = 1

EXIT_OK = 0            # verdict ALLOW, or below the --fail-on threshold
EXIT_REVIEW = 1        # verdict REVIEW at or above the threshold
EXIT_BLOCK = 2         # verdict BLOCK
EXIT_INCOMPLETE = 3    # content could not be analysed and policy requires full coverage
EXIT_USAGE = 64        # usage or configuration error
EXIT_INTERNAL = 70     # internal error


class RulePackInfo(BaseModel):
    version: str
    digest: str
    rule_count: int


class ToolInfo(BaseModel):
    name: str = "agentguard"
    version: str = ""
    rule_pack: str = ""
    rule_pack_digest: str = ""
    rule_count: int = 0          # rules in the catalogue
    rules_implemented: int = 0   # rules with a detector in this pack
    intel: str = ""              # intelligence bundle version (its date), "" when none is loaded


class TargetInfo(BaseModel):
    source: str = ""
    kind: str = "local"
    commit: str | None = None          # immutable identifier: commit SHA, version+hash, image digest
    tree_sha256: str = ""
    ref: SourceRef | ImmutableRef | None = None


class UnanalysedItem(BaseModel):
    path: str
    reason: str
    bytes: int = 0


class Coverage(BaseModel):
    files_total: int = 0
    files_analysed: int = 0
    bytes_total: int = 0
    bytes_analysed: int = 0
    analyzability: float = 1.0
    unanalysed: list[UnanalysedItem] = Field(default_factory=list)
    # Dependency and version-control directories that were deliberately not walked (node_modules, .venv, .git…).
    excluded: list[str] = Field(default_factory=list)

    @property
    def complete(self) -> bool:
        return self.files_analysed >= self.files_total and self.bytes_analysed >= self.bytes_total


class LeastPrivilege(BaseModel):
    """The smallest grant that covers what a component was observed to do (engine J, PLAN §6 "policy output").

    ``allowed_tools`` is the value for a skill's ``allowed-tools``; ``permissions`` and ``sandbox`` are in the
    shape of an agent's settings file. It is a proposal for the reviewer, never applied by a scan."""

    allowed_tools: list[str] = Field(default_factory=list)
    permissions: dict[str, list[str]] = Field(default_factory=dict)
    sandbox: dict[str, Any] = Field(default_factory=dict)
    observed: list[str] = Field(default_factory=list)


class ArtifactSummary(BaseModel):
    """One scanned component, as the report lists it."""

    id: str                      # "skill:pdf-helper"
    type: str                    # skill | plugin | mcp-server | instruction-file | …
    ecosystem: str = ""          # claude-code | codex | cursor | gemini | copilot | openclaw | mcp | generic
    name: str = ""
    version: str | None = None
    root: str = ""
    component_id: str = ""       # stable internal id (joins findings[].component_ids)
    capabilities: list[str] = Field(default_factory=list)
    risk_tier: RiskTier = RiskTier.L0
    verdict: Verdict = Verdict.allow
    findings: int = 0
    least_privilege: LeastPrivilege | None = None
    # Probability from the triage model (engine K) that the component is malicious; None when it did not run.
    triage: float | None = None


class AnalyzerRun(BaseModel):
    id: str
    status: Literal["ran", "skipped", "errored"]
    reason: str = ""


class LimitEvent(BaseModel):
    kind: str  # too_large | too_many_files | too_deep | symlink | hardlink | special_file | path_escape | archive_bomb | ...
    path: str
    detail: str = ""
    bytes: int = 0


class LlmLimits(BaseModel):
    tokens: int = 0
    cost_usd: float = 0.0
    calls: int = 0
    complete: bool = True      # False when a budget, timeout or refusal cut model analysis short
    model: str = ""
    sent: list[str] = Field(default_factory=list)   # what left the machine: "<path>:<lines> (<bytes> bytes)"


class DynamicLimits(BaseModel):
    ran: bool = False
    level: str = ""            # baseline | enhanced
    seconds: float = 0.0
    not_reached: list[str] = Field(default_factory=list)


class Limits(BaseModel):
    llm: LlmLimits = Field(default_factory=LlmLimits)
    dynamic: DynamicLimits = Field(default_factory=DynamicLimits)


class ReportStats(BaseModel):
    files_scanned: int = 0
    bytes_scanned: int = 0
    components: int = 0
    rules_evaluated: int = 0
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
    findings_by_category: dict[str, int] = Field(default_factory=dict)
    suppressed: int = 0
    limit_events: list[LimitEvent] = Field(default_factory=list)


class Report(BaseModel):
    schema_version: Literal[1] = REPORT_SCHEMA_VERSION
    tool: ToolInfo = Field(default_factory=ToolInfo)
    target: TargetInfo = Field(default_factory=TargetInfo)
    profile: str = "quick"
    policy: str = "balanced"
    coverage: Coverage = Field(default_factory=Coverage)
    verdict: Verdict = Verdict.allow
    verdict_reasons: list[str] = Field(default_factory=list)
    score: int = 0
    risk_tier: RiskTier = RiskTier.L0
    artifacts: list[ArtifactSummary] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    suppressed_findings: list[Finding] = Field(default_factory=list)
    chains: list[Chain] = Field(default_factory=list)
    limits: Limits = Field(default_factory=Limits)
    timings_ms: dict[str, int] = Field(default_factory=dict)
    # Detail beyond the spec's minimum: what ran, what was found where.
    network_features_used: list[str] = Field(default_factory=list)
    network_hosts: list[str] = Field(default_factory=list)
    analyzers: list[AnalyzerRun] = Field(default_factory=list)
    inventory: list[Component] = Field(default_factory=list)
    files: list[Artifact] = Field(default_factory=list)
    flows: list[FlowPath] = Field(default_factory=list)
    stats: ReportStats = Field(default_factory=ReportStats)
    fail_on: str = "block"          # block | review | severity:<level>
    require_full_coverage: bool = False
    summary: str = ""
    generated_at: dt.datetime | None = None

    # -- names from the first report schema ---------------------------------
    @property
    def engine_version(self) -> str:
        return self.tool.version

    @property
    def rule_pack(self) -> RulePackInfo:
        return RulePackInfo(version=self.tool.rule_pack, digest=self.tool.rule_pack_digest, rule_count=self.tool.rule_count)

    @property
    def incomplete(self) -> bool:
        """Something could not be analysed (a ‡ coverage finding, or an analyzer failed)."""
        return any("coverage" in f.tags for f in self.findings) or any(a.status == "errored" for a in self.analyzers)

    def exit_code(self, fail_on: str | None = None) -> int:
        fail_on = (fail_on or self.fail_on or "block").lower()
        if self.verdict == Verdict.block and not fail_on.startswith("severity:"):
            return EXIT_BLOCK
        if fail_on.startswith("severity:"):
            level = Severity.parse(fail_on.split(":", 1)[1])
            if any(f.severity.at_least(level) for f in self.findings):
                return EXIT_BLOCK if self.verdict == Verdict.block else EXIT_REVIEW
        elif fail_on == "review" and self.verdict == Verdict.review:
            return EXIT_REVIEW
        if self.require_full_coverage and self.incomplete:
            return EXIT_INCOMPLETE
        return EXIT_OK
