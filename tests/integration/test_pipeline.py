"""Integration tests for VulnOSPipeline wiring Dev 2 and Dev 3."""

from __future__ import annotations

import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from src.common.config import NebisConfig, TavilyConfig, VulnOSConfig, SandboxConfig
from src.common.models import CodeSlice, HardenedPatch, SandboxStatus, SandboxVerdict
from src.common.pipeline import VulnOSPipeline
from src.inference.client import NebisResponse


@pytest.fixture
def test_pipeline_config():
    return VulnOSConfig(
        nebius=NebisConfig(api_key="test-nebius"),
        tavily=TavilyConfig(api_key="test-tavily"),
        sandbox=SandboxConfig(approved_images=["trusted-runtime:local"]),
    )


@pytest.mark.asyncio
async def test_pipeline_execution(test_pipeline_config, tmp_path):
    # Setup dummy project files
    (tmp_path / "app.py").write_text("def query_db(q): return db.execute(q)\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\nname='test'\n", encoding="utf-8")

    slice_obj = CodeSlice(
        file_path="app.py",
        function_name="query_db",
        function_body="def query_db(q): return db.execute(q)",
        sink_type="sql_query",
    )

    mock_triage = NebisResponse(
        content='{"is_vulnerable": true, "confidence": 0.95, "vulnerability_type": "SQLi", "cwe_id": "CWE-89", "reasoning": "vuln"}',
        model="nano",
        prompt_tokens=50,
        completion_tokens=20,
        latency_ms=100.0,
        cost=0.0001,
    )
    mock_exploit = NebisResponse(
        content='{"test_code": "def test_exploit(): pass", "test_filename": "test_exploit.py", "runner_command": "pytest", "exploit_description": "desc"}',
        model="ultra",
        prompt_tokens=100,
        completion_tokens=50,
        latency_ms=200.0,
        cost=0.001,
    )
    mock_patch = NebisResponse(
        content='{"diff": "@@ -1 +1 @@\\n-old\\n+new", "patch_description": "fixed", "files_modified": ["app.py"]}',
        model="ultra",
        prompt_tokens=120,
        completion_tokens=60,
        latency_ms=250.0,
        cost=0.0012,
    )

    with patch("src.inference.client.openai.AsyncOpenAI") as mock_openai_cls, \
         patch("src.inference.tavily_engine.TavilyClient") as mock_tavily_cls, \
         patch("src.sandbox.controlled_verifier.ControlledVerifier.verify") as mock_verify:

        mock_oai = AsyncMock()
        mock_oai.chat.completions.create.side_effect = [
            MagicMock(choices=[MagicMock(message=MagicMock(content=mock_triage.content))], usage=MagicMock(prompt_tokens=50, completion_tokens=20)),
            MagicMock(choices=[MagicMock(message=MagicMock(content=mock_exploit.content))], usage=MagicMock(prompt_tokens=100, completion_tokens=50)),
            MagicMock(choices=[MagicMock(message=MagicMock(content=mock_patch.content))], usage=MagicMock(prompt_tokens=120, completion_tokens=60)),
        ]
        mock_openai_cls.return_value = mock_oai

        mock_tvly = MagicMock()
        mock_tvly.search.return_value = {"results": [{"url": "https://cve.org/CVE-2021-1234", "content": "Advisory"}]}
        mock_tvly.extract.return_value = {"results": [{"url": "https://cve.org/CVE-2021-1234", "raw_content": "Fixed in 2.0"}]}
        mock_tavily_cls.return_value = mock_tvly

        mock_verify.return_value = SandboxVerdict(
            status=SandboxStatus.TESTS_PASSED,
            verified=True,
            exploit_triggers_on_unpatched=True,
            exploit_blocked_after_patch=True,
            existing_tests_pass=True,
        )

        pipeline = VulnOSPipeline(config=test_pipeline_config)
        result = await pipeline.run_pipeline(tmp_path, slice_obj, profile_id="python-pytest")

        assert isinstance(result, HardenedPatch)
        assert result.assessment.is_vulnerable
        assert result.patch.diff != ""
        assert result.verdict.status == SandboxStatus.TESTS_PASSED
