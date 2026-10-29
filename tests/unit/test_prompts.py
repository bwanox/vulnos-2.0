"""Tests for prompt builders and response schemas."""

from __future__ import annotations

import pytest

from src.common.models import (
    EXPLOIT_FAILURE_MARKER,
    CodeSlice,
    TavilyIntelligence,
    VulnAssessment,
)
from src.inference.prompts import (
    build_blue_team_messages,
    build_red_team_messages,
    build_triage_messages,
)
from src.inference.schemas import (
    ExploitResponseSchema,
    TriageResponseSchema,
)


@pytest.fixture
def sample_slice():
    return CodeSlice(
        file_path="app.py",
        function_name="query_db",
        function_body="def query_db(q): return db.execute(q)",
        sink_type="sql_query",
    )


@pytest.fixture
def sample_assessment(sample_slice):
    return VulnAssessment(
        slice=sample_slice,
        is_vulnerable=True,
        confidence=0.95,
        vulnerability_type="SQL Injection",
        cwe_id="CWE-89",
    )


@pytest.fixture
def sample_intel():
    return TavilyIntelligence(
        cve_ids=["CVE-2021-1234"],
        advisory_urls=["https://nvd.nist.gov"],
        safe_version="2.1.0",
        mitigation_pattern="Use parameterized queries.",
    )


@pytest.fixture
def sample_exploit():
    from src.common.models import ExploitTest

    return ExploitTest(
        test_code="def test_exploit(): assert query_db('OR 1=1')",
        test_filename="test_exploit.py",
        exploit_description="Triggers SQL injection",
    )


def test_triage_messages_contain_function_body(sample_slice):
    msgs = build_triage_messages(sample_slice)
    user_msg = next(m for m in msgs if m["role"] == "user")
    assert sample_slice.function_body in user_msg["content"]


def test_red_team_messages_include_cve_context(sample_assessment, sample_intel):
    msgs = build_red_team_messages(sample_assessment, sample_intel)
    combined = " ".join(m["content"] for m in msgs)
    assert "CVE-2021-1234" in combined or sample_intel.mitigation_pattern in combined
    assert EXPLOIT_FAILURE_MARKER in combined
    assert "same test must pass after the vulnerability is fixed" in combined


def test_blue_team_messages_include_exploit_code(sample_assessment, sample_intel, sample_exploit):
    msgs = build_blue_team_messages(sample_assessment, sample_intel, sample_exploit)
    combined = " ".join(m["content"] for m in msgs)
    assert "def test_" in combined
    assert "diff` field to a valid unified diff accepted by `git apply`" in combined


def test_blue_team_retry_includes_error(sample_assessment, sample_intel, sample_exploit):
    msgs = build_blue_team_messages(
        sample_assessment,
        sample_intel,
        sample_exploit,
        failed_patch_error="SyntaxError line 42",
    )
    combined = " ".join(m["content"] for m in msgs)
    assert "SyntaxError" in combined


def test_triage_schema_validates():
    obj = TriageResponseSchema(
        is_vulnerable=True,
        confidence=0.9,
        vulnerability_type="SQLi",
        cwe_id="CWE-89",
        reasoning="...",
    )
    assert obj.is_vulnerable


def test_exploit_schema_validates():
    obj = ExploitResponseSchema(
        test_code="def test_exploit(): ...",
        test_filename="test_exploit.py",
        exploit_description="...",
    )
    assert "def test_" in obj.test_code
