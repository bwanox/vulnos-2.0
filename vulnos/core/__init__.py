"""VulnOS 2.0 CORE module (Dev 1 - Core Architect).

Public surface:
    contracts   - Pydantic models + Dev 2 / Dev 3 service protocols
    slicer      - deterministic tree-sitter / Semgrep taint slicer
    manifests   - dependency manifest parsing
    state       - LangGraph shared state (Pydantic)
    graph       - cyclic red/blue self-healing graph
    telemetry   - structured event models + async event bus
    orchestrator- public entry point ``run_scan(...)``
    mocks       - canned AIEngine / SandboxRunner for offline dev
"""

from vulnos.core.contracts import (  # noqa: F401
    AIEngine,
    CodeSlice,
    Dependency,
    ExploitTest,
    FindingStatus,
    HardenedPatch,
    PatchDiff,
    SandboxRunner,
    SandboxVerdict,
    SinkType,
    VulnAssessment,
)
from vulnos.core.mocks import MockAIEngine, MockSandboxRunner  # noqa: F401

__all__ = [
    "AIEngine",
    "CodeSlice",
    "Dependency",
    "ExploitTest",
    "FindingStatus",
    "HardenedPatch",
    "MockAIEngine",
    "MockSandboxRunner",
    "PatchDiff",
    "SandboxRunner",
    "SandboxVerdict",
    "SinkType",
    "VulnAssessment",
]
