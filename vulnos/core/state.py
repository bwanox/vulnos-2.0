"""Typed shared state (Pydantic) for the LangGraph self-healing security pipeline.

This is the single source of truth carried through every graph node.  The graph
never imports Dev 2 or Dev 3 code directly — only the protocols from
``vulnos.core.contracts``.

The pipeline execution is a manual async loop (the "graph structure" is defined
using LangGraph types for documentation, but the loop gives us full control
over state so that extra service references (_ai, _sandbox, _bus) are never
lost during serialisation.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional, List

from pydantic import BaseModel, ConfigDict, Field

from vulnos.core.contracts import (
    CodeSlice,
    VulnAssessment,
    ExploitTest,
    PatchDiff,
    SandboxVerdict,
    HardenedPatch,
    FindingStatus,
    Dependency,
)


class FindingStatus(str, Enum):
    OPEN = "OPEN"
    TRIAGED_FALSE_POSITIVE = "FALSE_POSITIVE"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED_VERIFIED = "RESOLVED_VERIFIED"
    UNRESOLVED = "UNRESOLVED"


class ScanState(BaseModel):
    """Shared state for one finding through the cyclic red/blue verification graph."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    # --- input ---
    repo_path: str
    slices: List[CodeSlice]
    slice_index: int = 0  # which slice we are currently processing
    slice: CodeSlice | None = None  # current slice being processed

    # --- AI / sandbox references (set once before the loop starts) ---
    _service_ai: object | None = None  # AIEngine protocol instance
    _service_sandbox: object | None = None  # SandboxRunner protocol instance
    _service_bus: asyncio.Queue | None = None  # telemetry event bus

    # --- AI outputs (filled node by node) ---
    assessment: Optional[VulnAssessment] = None
    cve_references: List[str] = Field(default_factory=list)
    exploit: Optional[ExploitTest] = None
    patch: Optional[PatchDiff] = None
    hardened_patch: Optional[HardenedPatch] = None

    # --- sandbox verification state ---
    verdict: Optional[SandboxVerdict] = None

    # --- retry budget ---
    iteration_count: int = 0
    max_iterations: int = 3

    # --- lifecycle ---
    status: FindingStatus = FindingStatus.OPEN  # OPEN | TRIAGED_FALSE_POSITIVE | IN_PROGRESS | RESOLVED_VERIFIED | UNRESOLVED

    # --- telemetry / cost counters ---
    tokens_used: float = 0.0
    cost_usd: float = 0.0
    model_used: str = ""