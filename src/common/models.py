"""Shared data models and type definitions for VulnOS 2.0."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class AgentState(str, Enum):
    """Pipeline state machine states."""

    INGEST = "INGEST"
    NANO_TRIAGE = "NANO_TRIAGE"
    TAVILY_ENRICH = "TAVILY_ENRICH"
    RED_TEAM_EXPLOIT = "RED_TEAM_EXPLOIT"
    BLUE_TEAM_PATCH = "BLUE_TEAM_PATCH"
    SANDBOX_VERIFY = "SANDBOX_VERIFY"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"


class CodeSlice(BaseModel):
    """A taint-flow slice extracted from the AST."""

    file_path: str
    function_name: str
    function_body: str
    caller_context: str = ""
    imports: list[str] = Field(default_factory=list)
    sink_type: str = ""  # e.g., "sql_query", "subprocess", "deserializer", "buffer_overflow"
    entry_point: str = ""  # e.g., API route or CLI input
    target_language: str = "python"  # python, c, cpp, go, rust, javascript, etc.
    attack_vector: str = "code_logic"  # "code_logic", "rce_shell", "network_socket", "privesc_endpoint"


class DependencyInfo(BaseModel):
    """Parsed dependency with version information."""

    name: str
    current_version: str
    manifest_file: str  # e.g., "requirements.txt", "package.json"


class VulnAssessment(BaseModel):
    """Triage result from Nemotron-Nano."""

    slice: CodeSlice
    is_vulnerable: bool
    confidence: float = Field(ge=0.0, le=1.0)
    vulnerability_type: str = ""  # e.g., "SQL Injection", "Command Injection"
    cwe_id: str = ""  # e.g., "CWE-89"
    reasoning: str = ""


class TavilyIntelligence(BaseModel):
    """Threat intelligence fetched via Tavily."""

    cve_ids: list[str] = Field(default_factory=list)
    advisory_urls: list[str] = Field(default_factory=list)
    safe_version: str = ""
    mitigation_pattern: str = ""
    raw_context: str = ""


class ExploitTest(BaseModel):
    """Red-Team generated PoC exploit test or harness."""

    test_code: str
    test_filename: str = "test_exploit.py"
    exploit_description: str = ""
    target_language: str = "python"
    runner_command: str = "pytest"  # e.g., "pytest", "gcc -o exploit exploit.c && ./exploit", "go test", "cargo test"
    attack_vector: str = "code_logic"


class PatchDiff(BaseModel):
    """Blue-Team generated patch."""

    diff: str
    patch_description: str = ""
    files_modified: list[str] = Field(default_factory=list)


class SandboxVerdict(BaseModel):
    """Result from the ephemeral sandbox verification."""

    exploit_triggers_on_unpatched: bool = False
    exploit_blocked_after_patch: bool = False
    existing_tests_pass: bool = False
    verified: bool = False
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    retry_count: int = 0


class TelemetryEvent(BaseModel):
    """Event emitted for the telemetry HUD."""

    state: AgentState
    timestamp: float = 0.0
    model_used: str = ""
    tokens_used: int = 0
    latency_ms: float = 0.0
    cost_estimate: float = 0.0
    tavily_urls: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class HardenedPatch(BaseModel):
    """Final verified output of the pipeline."""

    assessment: VulnAssessment
    intelligence: TavilyIntelligence
    exploit: ExploitTest
    patch: PatchDiff
    verdict: SandboxVerdict
    pr_url: str = ""
