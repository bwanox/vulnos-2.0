"""Pydantic schemas for structured LLM outputs from Nemotron."""

from __future__ import annotations

from pydantic import BaseModel, Field


class TriageResponseSchema(BaseModel):
    """Schema for Nemotron-Nano triage output."""

    is_vulnerable: bool
    confidence: float = Field(ge=0.0, le=1.0)
    vulnerability_type: str = ""
    cwe_id: str = ""
    reasoning: str = ""


class ExploitResponseSchema(BaseModel):
    """Schema for Red-Team PoC exploit test or harness output."""

    test_code: str
    test_filename: str = "test_exploit.py"
    exploit_description: str = ""
    runner_command: str = "pytest"


class PatchResponseSchema(BaseModel):
    """Schema for Blue-Team patch output."""

    diff: str
    patch_description: str = ""
    files_modified: list[str] = Field(default_factory=list)
