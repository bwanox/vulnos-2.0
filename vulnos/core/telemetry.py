"""Async telemetry event bus for Dev 4's WebSocket HUD.

Provides an ``asyncio.Queue``-based event bus that emits structured events at
every state transition.  Dev 4 can subscribe to this queue and render a real-time
HUD — the core module never imports Dev 4 code directly.

Event format (JSON-serialisable):
    { "type": "...", "timestamp": "...", "finding_id": "...",
      "payload": { ... } }
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any, DefaultDict, Literal

from pydantic import BaseModel, Field

from vulnos.core.contracts import FindingStatus, HardenedPatch


class TelemetryEvent(BaseModel):
    """One structured event emitted by the core pipeline."""

    type: Literal[
        "stage_started",
        "stage_completed",
        "triage_result",
        "cve_found",
        "exploit_result",
        "patch_proposed",
        "sandbox_verdict",
        "iteration_retry",
        "finding_resolved",
        "token_usage",
    ]
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finding_id: str = ""
    payload: dict = Field(default_factory=dict)


#: Global-ish event bus — Dev 4 can ``asyncio.Queue`` instance and subscribe.
#: The core module puts events onto this queue; the runner passes the queue in.
event_bus: asyncio.Queue | None = None


def set_bus(bus: asyncio.Queue) -> None:
    """Set the global event bus (called once at pipeline initialisation)."""
    global event_bus
    event_bus = bus


def emit(event_type: str, state: Any, payload: dict | None = None) -> None:
    """Push a telemetry event onto the global bus.

    Args:
        event_type: one of the Literal types in ``TelemetryEvent.type``.
        state: a ``ScanState`` (or dict-like) from which we extract
               ``finding_id`` and the fields listed in ``TelemetryEvent.payload``.
        payload: optional extra fields to merge into the event payload.
    """
    global event_bus
    if event_bus is None:
        return

    # Resolve finding_id from a HardenedPatch if present.
    fp = getattr(state, "hardened_patch", None)
    fid = fp.finding_id if fp and hasattr(fp, "finding_id") else ""

    # Gather payload fields from the state object — keep it stable.
    safe_keys = {
        "tokens_used",
        "cost_usd",
        "model_used",
        "iteration_count",
        "status",
        "slice_index",
    }
    extra = {k: v for k, v in state.model_dump().items() if k in safe_keys}
    extra["finding_id"] = fid

    event = TelemetryEvent(type=event_type, finding_id=fid, payload={**extra, **(payload or {})})
    event_bus.put_nowait(event.model_dump())


# Convenience wrappers used by the graph nodes (they receive the bus via state
# injection, but this helper exists for external callers).
def stage_started(state: Any, stage: str, payload: dict | None = None) -> None:
    emit("stage_started", state, {"stage": stage, **(payload or {})})


def stage_completed(state: Any, total: int = 0, payload: dict | None = None) -> None:
    emit("stage_completed", state, {"total": total, **(payload or {})})


def triage_result(state: Any, is_vulnerable: bool, confidence: float, cwe: str, payload: dict | None = None) -> None:
    emit("triage_result", state, {"is_vulnerable": is_vulnerable, "confidence": confidence, "cwe": cwe, **(payload or {})})


def cve_found(state: Any, cve_ids: list[str], payload: dict | None = None) -> None:
    emit("cve_found", state, {"cve_ids": cve_ids, **(payload or {})})


def exploit_result(state: Any, description: str, runner_command: str, payload: dict | None = None) -> None:
    emit("exploit_result", state, {"exploit_description": description, "runner_command": runner_command, **(payload or {})})


def patch_proposed(state: Any, unified_diff: str, files_modified: list[str], payload: dict | None = None) -> None:
    emit("patch_proposed", state, {"unified_diff": unified_diff, "files_modified": files_modified, **(payload or {})})


def sandbox_verdict(state: Any, exploit_blocked_after_patch: bool, exploit_worked_before_patch: bool,
                    tests_passed: int, tests_total: int, verified: bool, payload: dict | None = None) -> None:
    emit("sandbox_verdict", state, {"exploit_blocked_after_patch": exploit_blocked_after_patch,
                                     "exploit_worked_before_patch": exploit_worked_before_patch,
                                     "tests_passed": tests_passed, "tests_total": tests_total,
                                     "verified": verified, **(payload or {})})


def iteration_retry(state: Any, iteration: int, max_iterations: int, payload: dict | None = None) -> None:
    emit("iteration_retry", state, {"iteration": iteration, "max_iterations": max_iterations, **(payload or {})})


def finding_resolved(state: Any, payload: dict | None = None) -> None:
    emit("finding_resolved", state, **(payload or {}))


def token_usage(state: Any, payload: dict | None = None) -> None:
    emit("token_usage", state, **(payload or {}))