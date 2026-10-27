"""Tests for NebisClient."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.common.config import NebisConfig
from src.common.models import AgentState
from src.inference.client import NebisClient, NebisResponse
from src.inference.exceptions import ConfigError, InferenceError
from src.inference.telemetry import TelemetryEmitter


@pytest.fixture
def test_config():
    return NebisConfig(
        api_key="test-nebius-key",
        api_base="https://api.tokenfactory.nebius.com/v1",
        nano_model="nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B",
        ultra_model="nvidia/Nemotron-3-Ultra-550b-a55b",
    )


def test_raises_config_error_without_api_key():
    with pytest.raises(ConfigError):
        NebisClient(config=NebisConfig(api_key=""))


@pytest.mark.asyncio
async def test_complete_nano_returns_structured_response(test_config):
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = '{"result": "ok"}'
    mock_response.usage.prompt_tokens = 100
    mock_response.usage.completion_tokens = 50

    with patch("openai.AsyncOpenAI") as mock_openai_cls:
        mock_client = AsyncMock()
        mock_client.chat.completions.create.return_value = mock_response
        mock_openai_cls.return_value = mock_client

        client = NebisClient(config=test_config)
        resp = await client.complete_nano(messages=[{"role": "user", "content": "test"}])

        assert isinstance(resp, NebisResponse)
        assert resp.content == '{"result": "ok"}'
        assert resp.prompt_tokens == 100
        assert resp.completion_tokens == 50
        assert resp.model == test_config.nano_model
        assert resp.cost > 0.0


@pytest.mark.asyncio
async def test_complete_ultra_uses_ultra_model(test_config):
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = '{"patch": "diff"}'
    mock_response.usage.prompt_tokens = 200
    mock_response.usage.completion_tokens = 100

    with patch("openai.AsyncOpenAI") as mock_openai_cls:
        mock_client = AsyncMock()
        mock_client.chat.completions.create.return_value = mock_response
        mock_openai_cls.return_value = mock_client

        client = NebisClient(config=test_config)
        resp = await client.complete_ultra(messages=[{"role": "user", "content": "test"}])

        assert resp.model == test_config.ultra_model


@pytest.mark.asyncio
async def test_emits_telemetry_on_completion(test_config):
    events = []
    emitter = TelemetryEmitter(callback=lambda e: events.append(e))

    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = "ok"
    mock_response.usage.prompt_tokens = 10
    mock_response.usage.completion_tokens = 10

    with patch("openai.AsyncOpenAI") as mock_openai_cls:
        mock_client = AsyncMock()
        mock_client.chat.completions.create.return_value = mock_response
        mock_openai_cls.return_value = mock_client

        client = NebisClient(config=test_config, emitter=emitter)
        await client.complete_nano(
            messages=[{"role": "user", "content": "test"}],
            state=AgentState.NANO_TRIAGE,
        )

        assert len(events) == 1
        assert events[0].state == AgentState.NANO_TRIAGE
        assert events[0].tokens_used == 20
        assert events[0].cost_estimate > 0.0
