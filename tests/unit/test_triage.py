"""Tests for triage_slice."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock

from src.common.models import CodeSlice, VulnAssessment
from src.inference.client import NebisResponse
from src.inference.exceptions import ModelResponseError
from src.inference.triage import triage_slice


@pytest.fixture
def sample_slice():
    return CodeSlice(
        file_path="app.py",
        function_name="get_user",
        function_body="def get_user(id): return db.execute(f'SELECT * FROM users WHERE id = {id}')",
        sink_type="sql_query",
    )


@pytest.mark.asyncio
async def test_triage_returns_vuln_assessment(sample_slice):
    client = AsyncMock()
    client.complete_nano.return_value = NebisResponse(
        content='{"is_vulnerable": true, "confidence": 0.95, "vulnerability_type": "SQL Injection", "cwe_id": "CWE-89", "reasoning": "Unescaped f-string."}',
        model="nano",
        prompt_tokens=50,
        completion_tokens=20,
        latency_ms=100.0,
        cost=0.0001,
    )

    assessment = await triage_slice(client, sample_slice)
    assert isinstance(assessment, VulnAssessment)
    assert assessment.is_vulnerable
    assert assessment.cwe_id == "CWE-89"


@pytest.mark.asyncio
async def test_triage_handles_malformed_json_with_retry(sample_slice):
    client = AsyncMock()
    # First call returns bad JSON, second call returns valid JSON
    client.complete_nano.side_effect = [
        NebisResponse(content="not json", model="nano", prompt_tokens=50, completion_tokens=10, latency_ms=50.0, cost=0.0),
        NebisResponse(
            content='{"is_vulnerable": true, "confidence": 0.9, "vulnerability_type": "SQLi", "cwe_id": "CWE-89", "reasoning": "fixed"}',
            model="nano",
            prompt_tokens=60,
            completion_tokens=20,
            latency_ms=60.0,
            cost=0.0,
        ),
    ]

    assessment = await triage_slice(client, sample_slice)
    assert isinstance(assessment, VulnAssessment)
    assert assessment.is_vulnerable


@pytest.mark.asyncio
async def test_triage_raises_on_persistent_bad_json(sample_slice):
    client = AsyncMock()
    client.complete_nano.return_value = NebisResponse(
        content="still not json", model="nano", prompt_tokens=50, completion_tokens=10, latency_ms=50.0, cost=0.0
    )

    with pytest.raises(ModelResponseError):
        await triage_slice(client, sample_slice)
