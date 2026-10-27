"""Tests for telemetry and cost calculation."""

from __future__ import annotations

import pytest

from src.common.models import AgentState
from src.inference.telemetry import TelemetryEmitter, compute_cost


def test_compute_cost_nano():
    cost = compute_cost("nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B", 1000, 500)
    expected = (1000 * 0.06 / 1_000_000) + (500 * 0.24 / 1_000_000)
    assert abs(cost - expected) < 1e-9


def test_compute_cost_ultra():
    cost = compute_cost("nvidia/Nemotron-3-Ultra-550b-a55b", 1000, 500)
    expected = (1000 * 1.00 / 1_000_000) + (500 * 3.00 / 1_000_000)
    assert abs(cost - expected) < 1e-9


def test_compute_cost_unknown_model():
    cost = compute_cost("unknown/model", 1000, 500)
    assert cost == 0.0


def test_telemetry_emitter_calls_callback():
    events = []
    emitter = TelemetryEmitter(callback=lambda e: events.append(e))
    emitter.emit(
        state=AgentState.NANO_TRIAGE,
        model_used="nano",
        tokens_used=100,
        latency_ms=50.0,
        cost_estimate=0.001,
    )
    assert len(events) == 1
    assert events[0].state == AgentState.NANO_TRIAGE
    assert events[0].tokens_used == 100
