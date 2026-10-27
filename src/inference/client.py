"""Async Nebius Token Factory dual-tier client."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any

import openai

from src.common.config import NebisConfig
from src.common.models import AgentState
from src.inference.exceptions import ConfigError, InferenceError
from src.inference.telemetry import TelemetryEmitter, compute_cost


@dataclass
class NebisResponse:
    """Response container from Nebius Token Factory completion."""

    content: str
    model: str
    prompt_tokens: int
    completion_tokens: int
    latency_ms: float
    cost: float


class NebisClient:
    """OpenAI-compatible client targeting Nebius Token Factory."""

    def __init__(
        self,
        config: NebisConfig,
        emitter: TelemetryEmitter | None = None,
    ) -> None:
        if not config.api_key:
            raise ConfigError("Nebius API key is required (NEBIUS_API_KEY)")
        self.config = config
        self.emitter = emitter or TelemetryEmitter()
        self._openai = openai.AsyncOpenAI(
            api_key=config.api_key,
            base_url=config.api_base,
        )

    async def _complete(
        self,
        model: str,
        messages: list[dict[str, str]],
        response_format: dict[str, Any] | None = None,
        state: AgentState = AgentState.NANO_TRIAGE,
    ) -> NebisResponse:
        """Execute chat completion with automatic retry and telemetry emission."""
        start_time = time.perf_counter()
        retries = 3
        backoff = 1.0

        last_error = None
        for attempt in range(retries):
            try:
                kwargs: dict[str, Any] = {
                    "model": model,
                    "messages": messages,
                }
                if response_format:
                    kwargs["response_format"] = response_format

                response = await self._openai.chat.completions.create(**kwargs)
                elapsed_ms = (time.perf_counter() - start_time) * 1000.0

                choice = response.choices[0]
                content = choice.message.content or ""
                usage = response.usage
                prompt_tokens = usage.prompt_tokens if usage else 0
                completion_tokens = usage.completion_tokens if usage else 0

                cost = compute_cost(model, prompt_tokens, completion_tokens)
                total_tokens = prompt_tokens + completion_tokens

                self.emitter.emit(
                    state=state,
                    model_used=model,
                    tokens_used=total_tokens,
                    latency_ms=elapsed_ms,
                    cost_estimate=cost,
                )

                return NebisResponse(
                    content=content,
                    model=model,
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                    latency_ms=elapsed_ms,
                    cost=cost,
                )
            except (openai.RateLimitError, openai.APITimeoutError) as e:
                last_error = e
                if attempt < retries - 1:
                    await asyncio.sleep(backoff)
                    backoff *= 2.0
                continue
            except Exception as e:
                raise InferenceError(
                    f"Nebius API completion failed for {model}: {e}",
                    details={"model": model, "error": str(e)},
                ) from e

        raise InferenceError(
            f"Nebius API completion failed after {retries} retries: {last_error}",
            details={"model": model},
        )

    async def complete_nano(
        self,
        messages: list[dict[str, str]],
        response_format: dict[str, Any] | None = None,
        state: AgentState = AgentState.NANO_TRIAGE,
    ) -> NebisResponse:
        """Complete using Nemotron-Nano (fast triage)."""
        return await self._complete(
            model=self.config.nano_model,
            messages=messages,
            response_format=response_format,
            state=state,
        )

    async def complete_ultra(
        self,
        messages: list[dict[str, str]],
        response_format: dict[str, Any] | None = None,
        state: AgentState = AgentState.RED_TEAM_EXPLOIT,
    ) -> NebisResponse:
        """Complete using Nemotron-Ultra (deep reasoning / Red & Blue)."""
        return await self._complete(
            model=self.config.ultra_model,
            messages=messages,
            response_format=response_format,
            state=state,
        )
