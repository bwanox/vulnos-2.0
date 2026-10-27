"""Tests for TavilyThreatEngine."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.common.config import TavilyConfig
from src.common.models import CodeSlice, DependencyInfo, VulnAssessment
from src.inference.exceptions import ConfigError
from src.inference.tavily_engine import TavilyThreatEngine
from src.inference.telemetry import TelemetryEmitter


@pytest.fixture
def test_config():
    return TavilyConfig(api_key="tvly-test-key")


@pytest.fixture
def sample_assessment():
    slice_obj = CodeSlice(
        file_path="app/routes.py",
        function_name="get_user",
        function_body="def get_user(uid): return db.execute(f'SELECT * FROM users WHERE id = {uid}')",
        sink_type="sql_query",
    )
    return VulnAssessment(
        slice=slice_obj,
        is_vulnerable=True,
        confidence=0.95,
        vulnerability_type="SQL Injection",
        cwe_id="CWE-89",
    )


def test_raises_config_error_without_api_key():
    with pytest.raises(ConfigError):
        TavilyThreatEngine(config=TavilyConfig(api_key=""))


@pytest.mark.asyncio
async def test_search_returns_intelligence_with_cves(test_config, sample_assessment):
    mock_search_result = {
        "results": [
            {
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-1234",
                "content": "SQL injection vulnerability in user query handling.",
            }
        ]
    }
    mock_extract_result = {
        "results": [
            {
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-1234",
                "raw_content": "Fixed in version 2.1.0. Use parameterized queries.",
            }
        ]
    }

    with patch("src.inference.tavily_engine.TavilyClient") as mock_client_cls:
        mock_client = MagicMock()
        mock_client.search.return_value = mock_search_result
        mock_client.extract.return_value = mock_extract_result
        mock_client_cls.return_value = mock_client

        engine = TavilyThreatEngine(config=test_config)
        intel = await engine.search_threat_intel(sample_assessment)

        assert "CVE-2021-1234" in intel.cve_ids
        assert len(intel.advisory_urls) > 0


@pytest.mark.asyncio
async def test_returns_empty_intelligence_on_no_results(test_config, sample_assessment):
    mock_search_result = {"results": []}

    with patch("src.inference.tavily_engine.TavilyClient") as mock_client_cls:
        mock_client = MagicMock()
        mock_client.search.return_value = mock_search_result
        mock_client_cls.return_value = mock_client

        engine = TavilyThreatEngine(config=test_config)
        intel = await engine.search_threat_intel(sample_assessment)

        assert intel.cve_ids == []
        assert intel.mitigation_pattern == ""


@pytest.mark.asyncio
async def test_emits_telemetry_with_tavily_urls(test_config, sample_assessment):
    events = []
    emitter = TelemetryEmitter(callback=lambda e: events.append(e))

    mock_search_result = {
        "results": [
            {
                "url": "https://github.com/advisories/GHSA-xxxx",
                "content": "Advisory text",
            }
        ]
    }
    mock_extract_result = {
        "results": [
            {
                "url": "https://github.com/advisories/GHSA-xxxx",
                "raw_content": "Mitigation info",
            }
        ]
    }

    with patch("src.inference.tavily_engine.TavilyClient") as mock_client_cls:
        mock_client = MagicMock()
        mock_client.search.return_value = mock_search_result
        mock_client.extract.return_value = mock_extract_result
        mock_client_cls.return_value = mock_client

        engine = TavilyThreatEngine(config=test_config, emitter=emitter)
        await engine.search_threat_intel(sample_assessment)

        assert len(events) >= 1
        assert len(events[0].tavily_urls) > 0
