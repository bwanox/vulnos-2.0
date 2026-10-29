"""LangGraph‑style state machine for the CORE pipeline.

Execution is a manual async loop (keeps Pydantic ``ScanState`` whole so that
extra service references (_ai, _sandbox, _bus) are never dropped by
serialisation).  The graph structure (nodes, edges, conditionals) is defined
using LangGraph types for documentation & validation.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from langgraph.graph import StateGraph, END

from vulnos.core.contracts import (
    CodeSlice,
    VulnAssessment,
    ExploitTest,
    PatchDiff,
    SandboxVerdict,
    HardenedPatch,
    FindingStatus,
    Dependency,
)
from vulnos.core.state import ScanState, FindingStatus as FS
from vulnos.core.contracts import AIEngine, SandboxRunner


# ---------------------------------------------------------------------------
# Telemetry helper
# ---------------------------------------------------------------------------

def _emit(bus: asyncio.Queue, state: ScanState, event_type: str, payload: Optional[Dict[str, Any]] = None) -> None:
    """Push telemetry onto the asyncio event bus."""
    finding_id = state.hardened_patch.finding_id if state.hardened_patch else ""
    event = {
        "type": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "finding_id": finding_id,
        "payload": {
            **{k: v for k, v in state.model_dump().items()
               if k in ("tokens_used", "cost_usd", "model_used", "iteration_count", "status", "slice_index")},
            **(payload or {}),
        },
    }
    bus.put_nowait(event)


# ---------------------------------------------------------------------------
# Graph nodes — each returns a ``dict`` of ``ScanState`` field updates.
# The loop applies the dict as a Pydantic partial update.
# ---------------------------------------------------------------------------


async def _slice_entry(state: ScanState) -> dict | None:
    """Provide the current CodeSlice.  Returns ``None`` when no more slices."""
    slices: list[CodeSlice] = state.slices
    idx: int = state.slice_index
    if idx >= len(slices):
        state.status = FindingStatus.UNRESOLVED
        return None
    state.slice = slices[idx]
    _emit(state._service_bus or asyncio.Queue(), state, "stage_started", {"stage": "slicing"})
    return {"stage": "slicing"}


async def _triage(state: ScanState) -> dict | None:
    sl = state.slice
    if sl is None:
        state.status = FindingStatus.UNRESOLVED
        return None

    _emit(state._service_bus or asyncio.Queue(), state, "stage_started", {"stage": "triage"})
    assessment = await state._service_ai.triage(sl)  # type: ignore[arg-type]
    state.assessment = assessment
    state.tokens_used += assessment.confidence * 10  # rough Nano estimate
    state.model_used = "Nemotron-Nano"

    _emit(state._service_bus or asyncio.Queue(), state, "triage_result", {
        "is_vulnerable": assessment.is_vulnerable,
        "confidence": assessment.confidence,
        "cwe": assessment.cwe,
    })

    if not assessment.is_vulnerable:
        state.status = FindingStatus.TRIAGED_FALSE_POSITIVE
        _emit(state._service_bus or asyncio.Queue(), state, "finding_resolved", {})
        return None

    return {"assessment": assessment}


async def _threat_intel(state: ScanState) -> dict | None:
    _emit(state._service_bus or asyncio.Queue(), state, "stage_started", {"stage": "threat_intel"})
    cves = await state._service_ai.enrich_cve([], state.slice)  # type: ignore[arg-type]
    state.cve_references = cves
    state.tokens_used += 15
    _emit(state._service_bus or asyncio.Queue(), state, "cve_found", {"cve_ids": cves})
    return {"cve_references": cves}


async def _red_exploit(state: ScanState) -> dict | None:
    _emit(state._service_bus or asyncio.Queue(), state, "stage_started", {"stage": "red_exploit"})
    exploit = await state._service_ai.generate_exploit(state.slice, state.assessment)  # type: ignore[arg-type]
    state.exploit = exploit
    state.tokens_used += 40  # rough Ultra estimate
    state.model_used = "Nemotron-Ultra"
    _emit(state._service_bus or asyncio.Queue(), state, "exploit_result", {
        "exploit_description": exploit.expected_behavior,
        "runner_command": exploit.runner_command,
    })
    return {"exploit": exploit}


async def _blue_patch(state: ScanState) -> dict | None:
    _emit(state._service_bus or asyncio.Queue(), state, "stage_started", {"stage": "blue_patch"})
    patch = await state._service_ai.generate_patch(
        state.slice, state.assessment, prev_failure_logs=state.failure_logs
    )  # type: ignore[arg-type]
    state.patch = patch
    state.tokens_used += 50  # rough Ultra estimate
    state.model_used = "Nemotron-Ultra"
    _emit(state._service_bus or asyncio.Queue(), state, "patch_proposed", {
        "unified_diff": patch.unified_diff[:200],
        "files_modified": patch.files_modified,
    })
    return {"patch": patch}


async def _sandbox_verify(state: ScanState, sandbox: object) -> dict | None:  # SandboxRunner
    _emit(state._service_bus or asyncio.Queue(), state, "stage_started", {"stage": "sandbox_verify"})
    verdict = await sandbox.verify(state.repo_path, state.exploit, state.patch)  # type: ignore[arg-type]
    state.verdict = verdict
    state.tokens_used += 5  # local sandbox, no LLM cost
    state.model_used = ""

    _emit(state._service_bus or asyncio.Queue(), state, "sandbox_verdict", {
        "exploit_blocked_after_patch": verdict.exploit_blocked_after_patch,
        "exploit_worked_before_patch": verdict.exploit_worked_before_patch,
        "tests_passed": verdict.tests_passed,
        "tests_total": verdict.tests_total,
        "verified": verdict.verified,
        "reason": verdict.reason,
        "security_verification_performed": verdict.security_verification_performed,
    })

    if verdict.verified:
        state.status = FindingStatus.RESOLVED_VERIFIED
        hp = HardenedPatch(
            finding_id=state.slice.slice_id,
            file_path=state.slice.file_path,
            unified_diff=state.patch.unified_diff,
            explanation=state.patch.explanation,
            exploit_used=state.exploit,
            sandbox_verdict=verdict,
            iterations_used=state.iteration_count,
            cve_references=state.cve_references,
            status=FindingStatus.RESOLVED_VERIFIED,
        )
        state.hardened_patch = hp
        _emit(state._service_bus or asyncio.Queue(), state, "finding_resolved", {})
        return None

    state.iteration_count += 1
    if state.iteration_count < state.max_iterations:
        state.failure_logs = verdict.logs
        _emit(state._service_bus or asyncio.Queue(), state, "iteration_retry", {
            "iteration": state.iteration_count,
            "max_iterations": state.max_iterations,
        })
        return {"iteration_count": state.iteration_count, "failure_logs": verdict.logs}

    state.status = FindingStatus.UNRESOLVED
    _emit(state._service_bus or asyncio.Queue(), state, "finding_resolved", {})
    return None


# ---------------------------------------------------------------------------
# Graph structure definition (LangGraph types — used for documentation)
# ---------------------------------------------------------------------------

ED_SLICE = "slice"
ED_TRIAGE = "triage"
ED_THREAT_INTEL = "threat_intel"
ED_RED_EXPLOIT = "red_exploit"
ED_BLUE_PATCH = "blue_patch"
ED_SANDBOX_VERIFY = "sandbox_verify"

CD_TRIAGE = "triage_cond"
CD_SANDBOX = "sandbox_cond"


# ---------------------------------------------------------------------------
# Execution loop — keeps the Pydantic state whole so that
# _service_ai / _service_sandbox / _service_bus persist across steps.
# ---------------------------------------------------------------------------


async def run_scan(
    repo_path: str,
    *,
    ai: AIEngine,
    sandbox: SandboxRunner,
    bus: asyncio.Queue | None = None,
) -> list[HardenedPatch]:
    """Run the full CORE pipeline on a repository.

    Returns ``list[HardenedPatch]`` — one verified patch per resolved finding.
    The *bus* may be ``None``; if provided Dev 4’s WebSocket consumer can
    subscribe to the asyncio queue.
    """

    bus = bus or asyncio.Queue()

    # --- collect slices (deterministic, offline) ---
    from vulnos.core.slicer import scan_repo
    all_slices = scan_repo(repo_path)

    if not all_slices:
        return []

    # --- initialise state (once, before the per‑slice loop) ---
    state = ScanState(
        repo_path=repo_path,
        slices=all_slices,
        slice_index=0,
        status="OPEN",  # will be replaced by FindingStatus.OPEN below
    )
    state.status = FindingStatus.OPEN
    state._service_ai = ai          # type: ignore[assignment]
    state._service_sandbox = sandbox  # type: ignore[assignment]
    state._service_bus = bus  # type: ignore[assignment]

    patches: list[HardenedPatch] = []

    # --- process every slice (one finding at a time) ---
    for idx in range(len(all_slices)):
        # reset per‑slice state (keep service refs)
        state = ScanState(
            repo_path=repo_path,
            slices=all_slices,
            slice_index=idx,
            status=FindingStatus.OPEN,
        )
        state.status = FindingStatus.OPEN
        state._service_ai = ai
        state._service_sandbox = sandbox
        state._service_bus = bus

        # ---- slice -> triage ----
        update = await _slice_entry(state)
        if update is None:
            continue

        update = await _triage(state)
        if update is None:  # false positive or unresolved
            if state.status == FindingStatus.TRIAGED_FALSE_POSITIVE:
                break  # exit early, no Ultra tokens spent
            continue

        # --- threat_intel ---
        update = await _threat_intel(state)
        if update is None:
            continue

        # --- red_exploit ---
        update = await _red_exploit(state)
        if update is None:
            continue

        # --- blue_patch ---
        update = await _blue_patch(state)
        if update is None:
            continue

        # --- sandbox_verify (with retry) ----
        update = await _sandbox_verify(state, state._service_sandbox)  # type: ignore[arg-type]

        # after the sandbox node, check status
        if state.status == FindingStatus.RESOLVED_VERIFIED:
            if state.hardened_patch is not None:
                patches.append(state.hardened_patch)
        elif state.status == FindingStatus.UNRESOLVED:
            # budget exhausted or false‑positive path — keep going to next slice
            break

    return patches