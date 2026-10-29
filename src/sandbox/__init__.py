"""VulnOS 2.0 isolated verification subsystem."""

from src.common.models import SandboxStageResult, SandboxStatus, SandboxVerdict
from src.sandbox.adapters import (
    DEFAULT_PROFILE_REGISTRY,
    ExecutionProfile,
    ExecutionProfileRegistry,
)
from src.sandbox.configuration_checks import (
    ConfigurationFinding,
    check_project_configuration,
)
from src.sandbox.discovery import ProjectDiscoveryReport, discover_project
from src.sandbox.models import (
    ApprovedProjectRegistry,
    ControlledVerificationRequest,
    VerificationRequest,
)
from src.sandbox.os_inventory import (
    InstalledPackage,
    KnownAdvisory,
    OSInventoryReport,
    scan_local_os,
)
from src.sandbox.source_analysis import SourceAnalysisReport, analyze_project
from src.sandbox.verifier import SandboxVerifier, verify_patch

__all__ = [
    "ApprovedProjectRegistry",
    "ControlledVerificationRequest",
    "ConfigurationFinding",
    "DEFAULT_PROFILE_REGISTRY",
    "ExecutionProfile",
    "ExecutionProfileRegistry",
    "InstalledPackage",
    "KnownAdvisory",
    "OSInventoryReport",
    "ProjectDiscoveryReport",
    "SandboxStageResult",
    "SandboxStatus",
    "SandboxVerdict",
    "SandboxVerifier",
    "SourceAnalysisReport",
    "VerificationRequest",
    "analyze_project",
    "check_project_configuration",
    "discover_project",
    "scan_local_os",
    "verify_patch",
]
