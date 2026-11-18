"""Rule definitions (the rule pack is data; see rules/).

The pack has two layers:

* the **catalogue** (``rules/catalog/*.yaml``): one head per rule in the
  23-family catalogue, with its title, default severity, fix type, category,
  lane and engine;
* **detection entries** (every other ``rules/**/*.yaml``): the matching logic
  for a catalogue rule. A rule may have several *variants*, each a narrower
  detector with its own wording and, where it is a weaker or stronger signal
  than the head, its own severity. A variant is addressed as ``<id>/<key>``.

``Detector`` is the resolved view analyzers work with: head defaults with the
entry's (or variant's) overrides applied.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .enums import Category, Confidence, FixKind, Lane, RuleStatus, Severity
from .finding import Mapping

RULE_ID_RE = r"^AG-[A-Z]{2,7}-\d{3}$"
# Rule ids of the pre-catalogue pack; they stay valid as aliases.
LEGACY_ID_RE = r"^AG-[A-Z]+(?:-[A-Z]+)?-\d{3}$"
VARIANT_KEY_RE = r"^[a-z0-9][a-z0-9-]{0,39}$"

# Role groups a rule may name in `applies_to` instead of listing roles. They are expanded when the pack is loaded.
ROLE_GROUPS: dict[str, tuple[str, ...]] = {
    # Text an agent reads as instructions (config_prompt: prompt-like values of parsed configuration).
    "@prose": ("skill_md", "instruction_md", "command_md", "reference", "config_prompt"),
    # Code an agent runs or a server is made of.
    "@code": ("script", "source_code"),
    # Commands a configuration file would run: hooks, command-valued settings, lifecycle commands, tasks.
    "@commands": ("config_command",),
    # Every other string value of parsed configuration.
    "@values": ("config_text",),
    # Steps of CI workflows that run an agent, and Dockerfile instructions.
    "@ci": ("ci_command",),
    "@build": ("build_command",),
}


def expand_roles(roles: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    out: list[str] = []
    for role in roles:
        if role.startswith("@"):
            if role not in ROLE_GROUPS:
                raise ValueError(f"unknown role group {role!r} (choose from {', '.join(ROLE_GROUPS)})")
            out.extend(ROLE_GROUPS[role])
        else:
            out.append(role)
    return tuple(dict.fromkeys(out))


TextScope = Literal[
    "body",          # visible markdown body / whole text for non-markdown
    "frontmatter",   # serialized frontmatter values
    "hidden",        # comments, alt text, post-whitespace text, tag-char payloads
    "decoded",       # decoded blobs (base64/hex/…)
    "code",          # script / source files
    "resolved",      # lines whose path joins are folded into one literal path
    "tool_text",     # MCP tool/param/prompt/resource descriptive text
    "server_instructions",
    "command",       # shell commands (config commands, `!` injections, hooks)
    "media_text",    # text recovered from images, PDFs, Office files, notebooks
    "config_value",  # string values of parsed agent settings and manifests
    "prose_fold",    # prose with leetspeak / reversed / spaced-out text folded
]


class Downgrade(BaseModel):
    """Report a regex match at a lower severity (and one level lower
    confidence) when it is a *mention* rather than a directive. Every
    condition given must hold; the first matching downgrade wins. Hidden or
    decoded matches are still escalated one level afterwards.

    A downgraded match never counts on its own: a ``block``-lane rule reports
    it in the ``evidence`` lane (the finding carries the ``mention`` tag)."""

    model_config = ConfigDict(extra="forbid")

    severity: Severity
    # Confidence to report instead of one level below the rule's (`low` for
    # behaviour the component's declared purpose explains).
    confidence: Confidence | None = None
    # Only when the match sits in a fenced code block of a prose document
    # (a configuration or code sample, not a sentence addressed to the agent).
    in_code: bool = False
    # Only for artifacts in these roles (empty: any role).
    roles: list[str] = Field(default_factory=list)
    # Only when the match sits inside "double quotes", “curly quotes”, an
    # inline `code span`, or 'single quotes' hugging the match, on its line.
    quoted: bool = False
    # Only when one of these matches within `window` lines (default: the rule's).
    patterns: list[str] = Field(default_factory=list)
    window: int | None = None
    # Only when one of these matches the component's declared purpose (its
    # SKILL.md `description`): the behavior is what the skill says it does.
    declared: list[str] = Field(default_factory=list)


class RegexMatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["regex"] = "regex"
    patterns: list[str]
    scopes: list[TextScope] = Field(default_factory=lambda: ["body", "hidden", "decoded"])
    # All of these must also match within `window` lines of the primary match.
    require: list[str] = Field(default_factory=list)
    # A match is discarded if any of these match within `window` lines.
    unless: list[str] = Field(default_factory=list)
    window: int = 3
    ignore_case: bool = True
    # Only match inside sections whose heading matches one of these.
    sections: list[str] = Field(default_factory=list)
    # Only match in files whose path matches one of these (regex on the POSIX path).
    paths: list[str] = Field(default_factory=list)
    # Never match in files whose path matches one of these.
    not_paths: list[str] = Field(default_factory=list)
    # Confidence is lowered one level when the match sits in a fenced code block.
    lower_confidence_in_code: bool = False
    # Whether a match inside a comment of a script or source file counts. Unset:
    # no for the families that describe what code does (a comment does nothing),
    # yes for the rest (a comment is text an agent reads).
    comments: bool | None = None
    downgrade: list[Downgrade] = Field(default_factory=list)
    max_matches: int = 5


class AnalyzerMatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["analyzer"] = "analyzer"
    analyzer: str
    params: dict = Field(default_factory=dict)


class YaraMatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["yara"] = "yara"
    rule_file: str


MatchSpec = Annotated[RegexMatch | AnalyzerMatch | YaraMatch, Field(discriminator="type")]


class AivssDefaults(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Threat Multiplier status per AIVSS v0.8: attacked | poc | unreported
    threat: Literal["attacked", "poc", "unreported"] = "poc"
    # CVSS v4.0 base score computed with the FIRST calculator for cvss4_vector.
    # When absent the scorer falls back to a severity default and says so.
    cvss_base: float | None = None


class RuleVariant(BaseModel):
    """A narrower detector under a catalogue rule. Unset fields come from the head."""

    model_config = ConfigDict(extra="forbid")

    key: str = Field(pattern=VARIANT_KEY_RE)
    aliases: list[str] = Field(default_factory=list)
    version: int = Field(1, ge=1)
    title: str | None = None
    description: str | None = None
    why: str | None = None
    severity: Severity | None = None
    confidence: Confidence | None = None
    lane: Lane | None = None
    category: Category | None = None
    applies_to: list[str] | None = None
    match: MatchSpec | None = None
    remediation: str | None = None
    fix: FixKind | None = None
    fix_action: str | None = None
    references: list[str] = Field(default_factory=list)
    cvss4_vector: str | None = None
    aivss: AivssDefaults | None = None
    tags: list[str] = Field(default_factory=list)
    network: bool | None = None
    enabled: bool = True


class RuleDef(BaseModel):
    """A catalogue rule: the head merged with its detection entry."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=RULE_ID_RE)
    version: int = Field(1, ge=1)
    title: str
    description: str = ""
    family: str = ""
    category: Category = Category.malice
    severity: Severity
    # Floor: engines can raise it, the adjudicator cannot go below it.
    confidence: Confidence = Confidence.medium
    lane: Lane = Lane.evidence
    engine: str = "instruction"
    applies_to: list[str] = Field(default_factory=list)
    match: MatchSpec | None = None
    # Filled from the family defaults and mappings/crosswalk.yaml at load time.
    mappings: list[Mapping] = Field(default_factory=list)
    remediation: str = ""
    fix: FixKind = FixKind.guidance
    # Name of the deterministic edit `agentguard fix` applies (fix: auto).
    fix_action: str | None = None
    why: str = ""
    references: list[str] = Field(default_factory=list)
    cvss4_vector: str | None = None
    aivss: AivssDefaults = Field(default_factory=AivssDefaults)
    tags: list[str] = Field(default_factory=list)
    network: bool = False  # rule only evaluates with an opt-in network feature
    enabled: bool = True
    status: RuleStatus = RuleStatus.planned
    aliases: list[str] = Field(default_factory=list)
    # A coverage finding (marked ‡ in the catalogue): it prevents an ALLOW verdict.
    blocks_allow: bool = False
    # Severity comes from the matched content (e.g. a CVSS score); `severity` is the default.
    severity_from_content: bool = False
    # Carried over from the pre-catalogue pack; not one of the catalogue's 450 rules.
    extension: bool = False
    variants: list[RuleVariant] = Field(default_factory=list)

    @field_validator("title")
    @classmethod
    def _short_title(cls, v: str) -> str:
        if len(v) > 240:
            raise ValueError("title too long")
        return v

    @property
    def implemented(self) -> bool:
        return self.status != RuleStatus.planned

    def variant(self, key: str) -> RuleVariant | None:
        return next((v for v in self.variants if v.key == key), None)


class Detector(BaseModel):
    """What an analyzer evaluates and emits: a rule head, or one of its
    variants, with every field resolved."""

    model_config = ConfigDict(frozen=True)

    key: str                 # "AG-EXEC-001" or "AG-EXEC-001/vendor-installer"
    rule_id: str
    variant: str | None = None
    version: int = 1
    title: str
    description: str = ""
    why: str = ""
    family: str = ""
    category: Category
    severity: Severity
    confidence: Confidence
    lane: Lane
    engine: str
    applies_to: tuple[str, ...] = ()
    match: MatchSpec | None = None
    remediation: str = ""
    fix: FixKind = FixKind.guidance
    fix_action: str | None = None
    references: tuple[str, ...] = ()
    cvss4_vector: str | None = None
    aivss: AivssDefaults = Field(default_factory=AivssDefaults)
    tags: tuple[str, ...] = ()
    network: bool = False
    enabled: bool = True
    blocks_allow: bool = False
    aliases: tuple[str, ...] = ()
    mappings: tuple[Mapping, ...] = ()

    @property
    def id(self) -> str:
        """The catalogue rule id (what reports show)."""
        return self.rule_id


def split_key(key: str) -> tuple[str, str | None]:
    """``"AG-X-001/variant"`` → ``("AG-X-001", "variant")``."""
    rule_id, _, variant = key.partition("/")
    return rule_id, (variant or None)


def resolve(rule: RuleDef, variant: RuleVariant | None = None) -> Detector:
    v = variant
    pick = lambda name: getattr(v, name) if v is not None and getattr(v, name) is not None else getattr(rule, name)  # noqa: E731
    return Detector(
        key=f"{rule.id}/{v.key}" if v else rule.id,
        rule_id=rule.id,
        variant=v.key if v else None,
        version=v.version if v else rule.version,
        title=pick("title"),
        description=pick("description"),
        why=pick("why"),
        family=rule.family,
        category=pick("category"),
        severity=pick("severity"),
        confidence=pick("confidence"),
        lane=pick("lane"),
        engine=rule.engine,
        applies_to=expand_roles(pick("applies_to") or ()),
        match=v.match if v else rule.match,
        remediation=pick("remediation"),
        fix=pick("fix"),
        fix_action=pick("fix_action"),
        references=tuple(dict.fromkeys([*rule.references, *(v.references if v else [])])),
        cvss4_vector=pick("cvss4_vector"),
        aivss=pick("aivss"),
        tags=tuple(sorted({*rule.tags, *(v.tags if v else [])})),
        network=pick("network"),
        enabled=rule.enabled and (v.enabled if v else True),
        blocks_allow=rule.blocks_allow,
        aliases=tuple(v.aliases if v else rule.aliases),
        mappings=tuple(rule.mappings),
    )
