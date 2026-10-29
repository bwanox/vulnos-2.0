"""Tests for generate_exploit."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock

from src.common.models import CodeSlice, ExploitTest, TavilyIntelligence, VulnAssessment
from src.inference.client import NebisResponse
from src.inference.red_team import generate_exploit


@pytest.fixture
def sample_assessment():
    s = CodeSlice(file_path="app.py", function_name="f", function_body="...")
    return VulnAssessment(slice=s, is_vulnerable=True, confidence=0.95, vulnerability_type="SQLi", cwe_id="CWE-89")


@pytest.fixture
def sample_intel():
    return TavilyIntelligence(cve_ids=["CVE-2021-1234"], mitigation_pattern="param")


@pytest.mark.asyncio
async def test_generates_exploit_test(sample_assessment, sample_intel):
    client = AsyncMock()
    client.complete_ultra.return_value = NebisResponse(
        content='{"test_code": "def test_exploit(): assert False", "test_filename": "test_exploit.py", "exploit_description": "Triggers vulnerability"}',
        model="ultra",
        prompt_tokens=100,
        completion_tokens=50,
        latency_ms=200.0,
        cost=0.001,
    )

    exploit = await generate_exploit(client, sample_assessment, sample_intel)
    assert isinstance(exploit, ExploitTest)
    assert "def test_" in exploit.test_code
    assert exploit.test_filename == "test_exploit.py"
