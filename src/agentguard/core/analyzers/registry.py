"""Analyzer registry. Order matters: unit builders and evidence producers run
before rules that consume their output; correlators run last."""

from __future__ import annotations

import importlib.util

from ..correlate.cred_egress import CredEgressCorrelator
from ..correlate.composition import CompositionAnalyzer
from ..correlate.flows import FlowAnalyzer
from ..policy.analyzer import PolicyAnalyzer
from .capabilities import CapabilityAnalyzer
from .config_units import ConfigUnitsBuilder
from .code import CodeAnalyzer
from .media import MediaAnalyzer
from .mcp_impl import McpImplAnalyzer
from .shipped import ShippedContentAnalyzer
from .meta import MetaAnalyzer
from .instructions import InstructionAnalyzer
from .workspace import WorkspaceAnalyzer
from .images import ImageAnalyzer
from .connectors import ConnectorAnalyzer
from .evasion import EvasionAnalyzer
from .integrity import CodeObfuscationAnalyzer, FileIntegrityAnalyzer, TextIntegrityAnalyzer
from .ci import CiAnalyzer
from .hidden import HiddenContentAnalyzer
from .judge_rules import JudgeAnalyzer
from .mcp import McpClientAuthAnalyzer, McpConfigAnalyzer, McpMetaAnalyzer, McpUnitsBuilder
from .plugins import PluginAnalyzer
from .privilege import PrivilegeAnalyzer
from .network_rules import AuthAnalyzer, HijackableAnalyzer, OsvAnalyzer, PackageAgeAnalyzer, ProvenanceAnalyzer
from .regex_rules import RegexRuleAnalyzer
from .settings import SettingsAnalyzer
from .staged import StagedExecutionAnalyzer
from .supply_chain import DriftAnalyzer, IntelAnalyzer, RegistryOfflineAnalyzer
from .supply_deps import DependencyAnalyzer, HygieneAnalyzer
from .skill import (
    BundleAnalyzer,
    SkillExecAnalyzer,
    SkillPrivilegeAnalyzer,
    SkillSpecAnalyzer,
    TyposquatAnalyzer,
)
from .system import CoverageAnalyzer, LimitsAnalyzer
from .treesitter import TreeSitterAnalyzer
from .yara_rules import YaraAnalyzer

ANALYZERS: list[type] = [
    LimitsAnalyzer,
    CoverageAnalyzer,
    McpUnitsBuilder,
    ConfigUnitsBuilder,
    MediaAnalyzer,
    SkillSpecAnalyzer,
    SkillExecAnalyzer,
    McpConfigAnalyzer,
    HiddenContentAnalyzer,
    RegexRuleAnalyzer,
    TextIntegrityAnalyzer,
    FileIntegrityAnalyzer,
    CodeObfuscationAnalyzer,
    EvasionAnalyzer,
    InstructionAnalyzer,
    MetaAnalyzer,
    McpMetaAnalyzer,
    McpClientAuthAnalyzer,
    CodeAnalyzer,
    TreeSitterAnalyzer,
    McpImplAnalyzer,
    SkillPrivilegeAnalyzer,
    CapabilityAnalyzer,
    PrivilegeAnalyzer,
    SettingsAnalyzer,
    CiAnalyzer,
    WorkspaceAnalyzer,
    TyposquatAnalyzer,
    BundleAnalyzer,
    StagedExecutionAnalyzer,
    YaraAnalyzer,
    IntelAnalyzer,
    RegistryOfflineAnalyzer,
    DependencyAnalyzer,
    AuthAnalyzer,
    ProvenanceAnalyzer,
    OsvAnalyzer,
    PackageAgeAnalyzer,
    HijackableAnalyzer,
    PluginAnalyzer,
    HygieneAnalyzer,
    ShippedContentAnalyzer,
    ConnectorAnalyzer,
    ImageAnalyzer,
    JudgeAnalyzer,
]

CORRELATORS: list[type] = [
    CredEgressCorrelator,
    FlowAnalyzer,
    CompositionAnalyzer,
    DriftAnalyzer,
    PolicyAnalyzer,
]


def native_available(analyzer_cls: type) -> bool:
    modules = getattr(analyzer_cls, "native_modules", ())
    return all(importlib.util.find_spec(m) is not None for m in modules)


def all_stages() -> list[type]:
    return [*ANALYZERS, *CORRELATORS]
