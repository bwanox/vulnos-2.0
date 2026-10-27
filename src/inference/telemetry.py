"""Telemetry event emission and cost calculation for Nebius models."""

from __future__ import annotations

import time
from typing import Callable

from src.common.models import AgentState, TelemetryEvent

# Pricing per 1M tokens: (input_cost, output_cost)
NEBIUS_PRICING: dict[str, tuple[float, float]] = {
    "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B": (0.06, 0.24),
    "nvidia/Nemotron-3-Ultra-550b-a55b": (1.00, 3.00),
    "nvidia/Nemotron-3.5-Lightning": (0.06, 0.24),
    "nvidia/Nemotron-3.5-Super-VL": (0.30, 0.90),
}


def compute_cost(model_id: str, prompt_tokens: int, completion_tokens: int) -> float:
    """Compute estimated cost in USD based on Nebius Token Factory pricing."""
    if model_id not in NEBIUS_PRICING:
        return 0.0
    input_price, output_price = NEBIUS_PRICING[model_id]
    cost = (prompt_tokens * input_price / 1_000_000) + (
        completion_tokens * output_price / 1_000_000
    )
    return cost


class TelemetryEmitter:
    """Emits TelemetryEvents to a registered callback handler."""

    def __init__(
        self, callback: Callable[[TelemetryEvent], None] | None = None
    ) -> None:
        self.callback = callback

    def emit(
        self,
        state: AgentState,
        model_used: str,
        tokens_used: int,
        latency_ms: float,
        cost_estimate: float,
        tavily_urls: list[str] | None = None,
        metadata: dict | None = None,
    ) -> None:
        """Construct and emit a TelemetryEvent."""
        event = TelemetryEvent(
            state=state,
            timestamp=time.time(),
            model_used=model_used,
            tokens_used=tokens_used,
            latency_ms=latency_ms,
            cost_estimate=cost_estimate,
            tavily_urls=tavily_urls or [],
            metadata=metadata or {},
        )
        if self.callback:
            self.callback(event)
