"""Typed data contracts and service protocols for the VulnOS 2.0 CORE module.

Dev 1 (Core Architect) owns this module. It defines the Pydantic models that
flow through the LangGraph state machine and the :class:`AIEngine` /
:class:`SandboxRunner` protocols that Dev 2 (AI) and Dev 3 (Sandbox) implement.

This module intentionally never imports Dev 2 or Dev 3 concrete code. The core
graph depends only on these protocols, so teammates can swap in real
implementations without touching ``vulnos/core``.

Alignment note
--------------
The exact field names/types here are placeholders to be confirmed with Dev 2
and Dev 3. Every model is a plain Pydantic v2 ``BaseModel`` so schemas can be
adjusted in one place when the teammates finalize their interfaces.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Protocol, runtime_checkable
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


def utc_now() -> str:
    """Return an ISO-8601 UTC timestamp string (used for telemetry events)."""
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class FindingStatus(str, Enum):
    """Lifecycle status of a single finding through the graph."""

    OPEN = "OPEN"
    TRIAGED_FALSE_POSITIVE = "FALSE_POSITIVE"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED_VERIFIED = "RESOLVED_VERIFIED"
    UNRESOLVED = "UNRESOLVED"


class SinkType(str, Enum):
    """Dangerous sinks the AST slicer maps taint sources to."""

    SQL_BUILD = "sql_build"
    SUBPROCESS = "subprocess"
    EVAL_EXEC = "eval_exec"
    PICKLE = "pickle"
    FILE_OPEN = "file_open"
    TEMPLATE_RENDER = "template_render"
    OTHER = "other"


# ---------------------------------------------------------------------------
# Core data models
# ---------------------------------------------------------------------------


class CodeSlice(BaseModel):
    """A minimal taint-flow slice: only the functions/lines on the taint path.

    Small enough to stuff into a single LLM prompt. Carries file, line numbers
    and surrounding context so the graph can point Dev 4's UI at the exact code.
    """

    model_config = ConfigDict(frozen=True)

    slice_id: str = Field(default_factory=lambda: str(uuid4()))
    file_path: str
    start_line: int
    end_line: int
    function_name: str
    function_body: str
    caller_context: str = ""
    entry_point: str = ""  # e.g. Flask route "/users/<id>" or CLI argument
    sink_type: SinkType = SinkType.OTHER
    sink_line: int | None = None  # line of the dangerous call, if identifiable
    imports: list[str] = Field(default_factory=list)
    language: str = "python"
    context_snippet: str = ""  # N lines above/below for the LLM prompt


class Dependency(BaseModel):
    """A parsed ``(package, version)`` from a dependency manifest."""

    package: str
    version: str | None = None
    manifest_file: str  # e.g. "requirements.txt", "pyproject.toml", "package.json"


class VulnAssessment(BaseModel):
    """Triage result from Nemotron-Nano (Dev 2).

    ``is_vulnerable == False`` means the finding is a false positive and exits
    the graph early (no Ultra tokens spent).
    """

    slice_id: str
    is_vulnerable: bool
    severity: str = ""  # low | medium | high | critical
    cwe: str = ""  # e.g. "CWE-89"
    reasoning: str = ""
    confidence: float = Field(ge=0.0, le=1.0)
    related_cves: list[str] = Field(default_factory=list)


class ExploitTest(BaseModel):
    """Red-Team PoC exploit / test (Dev 2)."""

    language: str = "python"
    code: str
    expected_behavior: str = ""  # what should happen if the vulnerability is present
    runner_command: str = "pytest"


class PatchDiff(BaseModel):
    """Blue-Team patch (Dev 2)."""

    unified_diff: str
    explanation: str = ""
    files_modified: list[str] = Field(default_factory=list)


class SandboxVerdict(BaseModel):
    """Sandbox verification result (Dev 3): exit codes, logs, pass/fail counts.

    ``verified`` is True ONLY when:
        (a) the red exploit worked on unpatched code,
        (b) the red exploit is blocked after the patch, AND
        (c) 100% of unit tests pass.
    """

    exploit_blocked_after_patch: bool = False
    exploit_worked_before_patch: bool = False
    tests_passed: int = 0
    tests_total: int = 0
    exit_codes: list[int] = Field(default_factory=list)
    logs: str = ""
    reason: str = ""
    security_verification_performed: bool = False

    @property
    def verified(self) -> bool:
        if self.tests_total <= 0:
            return False
        return (
            self.exploit_worked_before_patch
            and self.exploit_blocked_after_patch
            and self.tests_passed == self.tests_total
        )

    @property
    def test_pass_rate(self) -> float:
        if self.tests_total <= 0:
            return 0.0
        return self.tests_passed / self.tests_total


class HardenedPatch(BaseModel):
    """Final verified output of the pipeline (Dev 1).

    Consumed by Dev 4's telemetry HUD and, eventually, turned into a Verified PR.
    """

    finding_id: str
    file_path: str
    unified_diff: str
    explanation: str = ""
    exploit_used: ExploitTest
    sandbox_verdict: SandboxVerdict
    iterations_used: int = 0
    cve_references: list[str] = Field(default_factory=list)
    status: FindingStatus = FindingStatus.OPEN


# ---------------------------------------------------------------------------
# Service protocols (Dev 2 = AIEngine, Dev 3 = SandboxRunner)
# ---------------------------------------------------------------------------


@runtime_checkable
class AIEngine(Protocol):
    """Dev 2 interface: Nemotron-Nano triage + Nemotron-Ultra exploit/patch.

    Concrete implementations live in ``vulnos.ai`` and call the LLM. The core
    graph depends only on this protocol.
    """

    async def triage(self, code_slice: CodeSlice) -> VulnAssessment:
        """Classify a slice as vulnerable or false positive."""
        ...

    async def enrich_cve(
        self, deps: list[Dependency], code_slice: CodeSlice
    ) -> list[str]:
        """Return live CVE IDs relevant to the slice's dependencies."""
        ...

    async def generate_exploit(
        self, code_slice: CodeSlice, assessment: VulnAssessment
    ) -> ExploitTest:
        """Generate a Red-Team PoC exploit test for the slice."""
        ...

    async def generate_patch(
        self,
        code_slice: CodeSlice,
        assessment: VulnAssessment,
        prev_failure_logs: str | None = None,
    ) -> PatchDiff:
        """Generate a Blue-Team patch, optionally informed by prior failure logs."""
        ...


@runtime_checkable
class SandboxRunner(Protocol):
    """Dev 3 interface: isolated verification of exploit + patch.

    Concrete implementations live in ``vulnos.sandbox`` (Docker, --network none,
    512 MB RAM, 1 CPU). The core graph depends only on this protocol.
    """

    async def verify(
        self,
        repo_path: str | Path,
        exploit: ExploitTest,
        patch: PatchDiff,
    ) -> SandboxVerdict:
        """Run exploit before/after patch + unit tests in the sandbox."""
        ...
