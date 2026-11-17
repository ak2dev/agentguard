"""Findings, evidence, locations, mappings, scores, flows, chains.

The JSON shape follows spec/interfaces.md §7. A few older names stay readable
as properties (``rule_id``, ``primary``, ``message``, ``remediation``) so code
written against the first report schema keeps working.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..redact import RedactedText
from .enums import CapLabel, Category, Confidence, EvidenceKind, FindingSource, FixKind, Lane, Severity


class Span(BaseModel):
    model_config = ConfigDict(frozen=True)

    path: str
    start_line: int = 1
    start_col: int = 1
    end_line: int | None = None
    end_col: int | None = None
    # UTF-8 byte offsets in the original file, when the analyzer knows them.
    start_byte: int | None = None
    end_byte: int | None = None

    def key(self) -> tuple[str, int, int]:
        return (self.path, self.start_line, self.start_col)


class Position(BaseModel):
    model_config = ConfigDict(frozen=True)

    line: int = 1
    column: int = 1
    byte: int | None = None


class Location(BaseModel):
    """Where a finding is. Mandatory: a finding about something missing points
    at the line where the fix belongs. Findings inside archives, images and
    bundles give the container path and the inner path."""

    model_config = ConfigDict(frozen=True)

    artifact: str = ""              # e.g. "skill:pdf-helper"
    file: str
    start: Position = Position()
    end: Position | None = None
    container: str | None = None    # outer archive / bundle / image, when nested

    @classmethod
    def of(cls, span: Span, artifact: str = "", container: str | None = None) -> Location:
        end = None
        if span.end_line is not None:
            end = Position(line=span.end_line, column=span.end_col or 1, byte=span.end_byte)
        return cls(artifact=artifact, file=span.path, container=container,
                   start=Position(line=span.start_line, column=span.start_col, byte=span.start_byte), end=end)

    def span(self) -> Span:
        return Span(path=self.file, start_line=self.start.line, start_col=self.start.column,
                    end_line=self.end.line if self.end else None, end_col=self.end.column if self.end else None,
                    start_byte=self.start.byte, end_byte=self.end.byte if self.end else None)


class Evidence(BaseModel):
    kind: EvidenceKind
    location: Span | None = None
    snippet: RedactedText = RedactedText.of("")
    detail: str = ""
    hidden: bool = False
    decode_path: list[str] = Field(default_factory=list)
    taint_path: list[Span] | None = None
    engine: str = ""


class EvidenceSummary(BaseModel):
    """The evidence of a finding as the report shows it."""

    snippet: RedactedText = RedactedText.of("")     # escaped source line
    rendered: str = ""                              # invisible characters made visible
    decoded: RedactedText = RedactedText.of("")     # hidden / encoded payload, decoded
    derivation: list[str] = Field(default_factory=list)  # decode / extract steps back to the original line
    items: list[Evidence] = Field(default_factory=list)  # every engine's evidence


class TraceStep(BaseModel):
    file: str
    line: int = 1
    role: str = ""          # instruction | source | propagator | sink | config | step
    note: str = ""


# Standards the pack maps to. The value is the key used in a finding's `mappings`.
FRAMEWORK_KEYS: dict[str, str] = {
    "owasp-asi-2026": "owasp_asi",
    "owasp-mcp-2025-beta": "owasp_mcp",
    "owasp-ast-1.0": "owasp_ast",
    "owasp-llm-2026": "owasp_llm",
    "nsa-csi-mcp-2026-05": "nsa_csi_mcp",
    "cwe": "cwe",
    "skilltrustbench": "skilltrustbench",
    "malskillbench": "malskillbench",
    "mitre-atlas": "mitre_atlas",
}
FRAMEWORKS = tuple(FRAMEWORK_KEYS)
# Frameworks whose column every catalogue entry must review (a list, possibly empty).
REVIEWED_FRAMEWORKS = (
    "owasp-asi-2026", "owasp-mcp-2025-beta", "owasp-ast-1.0", "owasp-llm-2026", "nsa-csi-mcp-2026-05", "cwe",
)


class Mapping(BaseModel):
    model_config = ConfigDict(frozen=True)

    framework: str
    id: str | None = None
    title: str | None = None
    todo: str | None = None

    @model_validator(mode="after")
    def _id_or_todo(self) -> Mapping:
        if self.framework not in FRAMEWORKS:
            raise ValueError(f"unknown framework {self.framework!r}")
        if self.id is None and not self.todo:
            raise ValueError("a mapping without an id must carry a todo note")
        return self


def mapping_dict(mappings: list[Mapping] | tuple[Mapping, ...]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for m in mappings:
        if m.id:
            out.setdefault(FRAMEWORK_KEYS[m.framework], []).append(m.id)
    return out


class Score(BaseModel):
    scorer: str
    scorer_version: str
    value: float
    vector: str = ""
    components: dict[str, float] = Field(default_factory=dict)


class FlowPath(BaseModel):
    nodes: list[str]
    edges: list[tuple[str, str, str]] = Field(default_factory=list)
    labels: dict[str, list[CapLabel]] = Field(default_factory=dict)
    narrative: str = ""


class SuppressionState(BaseModel):
    status: str  # "active" | "expired"
    reason: str
    expires: str
    approved_by: str = ""
    kind: str = "config"  # config | inline | baseline


class Fix(BaseModel):
    kind: FixKind = FixKind.guidance
    summary: str = ""
    # Unified diff, present once `agentguard fix` (or the report writer) computed one.
    patch: str | None = None
    action: str | None = None


class Adjudication(BaseModel):
    """What the model adjudicator said about a finding. It may raise and add;
    it may lower by one level at most, and never a deterministic block-lane rule."""

    status: Literal["confirmed", "doubted", "dismissed", "added", "not_run"] = "not_run"
    runs: int = 0
    model: str = ""
    rationale: str = ""


class Chain(BaseModel):
    """Linked findings along graph edges: instruction → script → source → sink."""

    id: str
    severity: Severity
    steps: list[str]            # finding fingerprints, in path order
    narrative: str = ""
    sink: str = ""              # what the chain ends in (network, exec, file write, persistence)


class Finding(BaseModel):
    id: str                                      # catalogue rule id, e.g. AG-OBF-001
    variant: str | None = None
    rule_version: int = 1
    fingerprint: str
    title: str
    family: str = ""
    category: Category = Category.malice
    severity: Severity
    confidence: Confidence
    lane: Lane = Lane.evidence
    risk: str = ""                               # what could happen, in plain language, for this match
    explanation: str = ""                        # why the rule exists
    location: Location | None = None
    related: list[Span] = Field(default_factory=list)
    evidence: EvidenceSummary = Field(default_factory=EvidenceSummary)
    trace: list[TraceStep] = Field(default_factory=list)
    chain: str | None = None
    fix: Fix = Field(default_factory=Fix)
    mappings: dict[str, list[str]] = Field(default_factory=dict)
    engines: list[str] = Field(default_factory=list)
    adjudication: Adjudication | None = None
    suppressed: bool = False
    suppression: SuppressionState | None = None
    # Counts towards the verdict: a block-lane finding, or an evidence-lane one
    # that another engine, a chain, dynamic evidence or the adjudicator backs up.
    corroborated: bool = True
    source: FindingSource = FindingSource.deterministic
    component_ids: list[str] = Field(default_factory=list)
    aivss: Score | None = None
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    flow: FlowPath | None = None
    baseline_state: str | None = None            # "new" | "unchanged"

    # -- names from the first report schema ---------------------------------
    @property
    def rule_id(self) -> str:
        return self.id

    @property
    def key(self) -> str:
        return f"{self.id}/{self.variant}" if self.variant else self.id

    @property
    def primary(self) -> Span | None:
        return self.location.span() if self.location else None

    @property
    def message(self) -> str:
        return self.risk

    @property
    def remediation(self) -> str:
        return self.fix.summary

    @property
    def score(self) -> Score | None:
        return self.aivss

    def sort_key(self) -> tuple:
        loc = self.location
        return (
            -self.severity.rank,
            self.id,
            self.variant or "",
            loc.file if loc else "",
            loc.start.line if loc else 0,
            loc.start.column if loc else 0,
            self.fingerprint,
        )
