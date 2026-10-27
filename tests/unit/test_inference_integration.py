"""Integration tests for InferenceEngine façade."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch as mock_patch

from src.common.config import NebisConfig, TavilyConfig, VulnOSConfig
from src.common.models import CodeSlice, TavilyIntelligence, VulnAssessment
from src.inference import InferenceEngine
from src.inference.client import NebisResponse


@pytest.fixture
def test_vulnos_config():
    return VulnOSConfig(
        nebius=NebisConfig(api_key="test-nebius"),
        tavily=TavilyConfig(api_key="test-tavily"),
    )


@pytest.fixture
def sample_slice():
    return CodeSlice(
        file_path="app.py",
        function_name="get_user",
        function_body="def get_user(id): return db.execute(f'SELECT * FROM users WHERE id = {id}')",
        sink_type="sql_query",
    )


@pytest.mark.asyncio
async def test_full_pipeline_triage_to_patch(test_vulnos_config, sample_slice):
    telemetry_events = []

    mock_nebis_response = NebisResponse(
        content='{"is_vulnerable": true, "confidence": 0.95, "vulnerability_type": "SQLi", "cwe_id": "CWE-89", "reasoning": "vuln"}',
        model="nano",
        prompt_tokens=50,
        completion_tokens=20,
        latency_ms=100.0,
        cost=0.0001,
    )
    mock_ultra_response = NebisResponse(
        content='{"test_code": "def test_exploit(): pass", "test_filename": "test_exploit.py", "exploit_description": "desc"}',
        model="ultra",
        prompt_tokens=100,
        completion_tokens=50,
        latency_ms=200.0,
        cost=0.001,
    )
    mock_patch_response = NebisResponse(
        content='{"diff": "@@ -1 +1 @@\\n-old\\n+new", "patch_description": "fixed", "files_modified": ["app.py"]}',
        model="ultra",
        prompt_tokens=120,
        completion_tokens=60,
        latency_ms=250.0,
        cost=0.0012,
    )

    with mock_patch("src.inference.client.openai.AsyncOpenAI") as mock_openai_cls, \
         mock_patch("src.inference.tavily_engine.TavilyClient") as mock_tavily_cls:

        mock_oai = AsyncMock()
        mock_oai.chat.completions.create.side_effect = [
            MagicMock(choices=[MagicMock(message=MagicMock(content=mock_nebis_response.content))], usage=MagicMock(prompt_tokens=50, completion_tokens=20)),
            MagicMock(choices=[MagicMock(message=MagicMock(content=mock_ultra_response.content))], usage=MagicMock(prompt_tokens=100, completion_tokens=50)),
            MagicMock(choices=[MagicMock(message=MagicMock(content=mock_patch_response.content))], usage=MagicMock(prompt_tokens=120, completion_tokens=60)),
        ]
        mock_openai_cls.return_value = mock_oai

        mock_tvly = MagicMock()
        mock_tvly.search.return_value = {"results": [{"url": "https://cve.org/CVE-2021-1234", "content": "Advisory"}]}
        mock_tvly.extract.return_value = {"results": [{"url": "https://cve.org/CVE-2021-1234", "raw_content": "Fixed in 2.0"}]}
        mock_tavily_cls.return_value = mock_tvly

        engine = InferenceEngine(
            config=test_vulnos_config,
            on_telemetry=lambda e: telemetry_events.append(e),
        )

        assessment = await engine.triage(sample_slice)
        assert assessment.is_vulnerable

        intel = await engine.enrich(assessment)
        assert isinstance(intel, TavilyIntelligence)

        exploit = await engine.generate_exploit(assessment, intel)
        assert "def test_" in exploit.test_code

        patch_diff = await engine.generate_patch(assessment, intel, exploit)
        assert patch_diff.diff != ""

        assert len(telemetry_events) >= 3
