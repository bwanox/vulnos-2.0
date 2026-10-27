"""Tests for generate_patch."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock

from src.common.models import CodeSlice, ExploitTest, PatchDiff, TavilyIntelligence, VulnAssessment
from src.inference.blue_team import generate_patch
from src.inference.client import NebisResponse


@pytest.fixture
def sample_assessment():
    s = CodeSlice(file_path="app.py", function_name="f", function_body="...")
    return VulnAssessment(slice=s, is_vulnerable=True, confidence=0.95, vulnerability_type="SQLi", cwe_id="CWE-89")


@pytest.fixture
def sample_intel():
    return TavilyIntelligence(cve_ids=["CVE-2021-1234"], mitigation_pattern="param")


@pytest.fixture
def sample_exploit():
    return ExploitTest(test_code="def test_exploit(): pass", test_filename="test_exploit.py")


@pytest.mark.asyncio
async def test_generates_patch_diff(sample_assessment, sample_intel, sample_exploit):
    client = AsyncMock()
    client.complete_ultra.return_value = NebisResponse(
        content='{"diff": "@@ -1,1 +1,1 @@\\n-vuln\\n+fixed", "patch_description": "Use parameterized query", "files_modified": ["app.py"]}',
        model="ultra",
        prompt_tokens=150,
        completion_tokens=60,
        latency_ms=300.0,
        cost=0.0015,
    )

    patch = await generate_patch(client, sample_assessment, sample_intel, sample_exploit)
    assert isinstance(patch, PatchDiff)
    assert patch.diff != ""
    assert "app.py" in patch.files_modified
