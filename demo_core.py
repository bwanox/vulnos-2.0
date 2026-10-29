"""Demo script: run the full CORE pipeline with mocks and print telemetry events.

This script exercises the entire CORE module end-to-end using the canned
``MockAIEngine`` and ``MockSandboxRunner`` from ``vulnos.core.mocks``, so it
runs fully offline — no network, no LLM, no Docker.  It is suitable for
running on a Jetson Orin Nano.

The demo prints every telemetry event to ``stdout`` (JSON lines) so Dev 4 can
wire a WebSocket consumer to the same ``asyncio.Queue``.
"""

from __future__ import annotations

import asyncio
import json
import sys

from vulnos.core.contracts import AIEngine, SandboxRunner, FindingStatus
from vulnos.core.graph import run_scan
from vulnos.core.mocks import MockAIEngine, MockSandboxRunner
from vulnos.core.slicer import scan_repo
from vulnos.core.telemetry import set_bus, emit, TelemetryEvent


def _print_event(event: dict) -> None:
    """Print a single telemetry event as compact JSON."""
    # Tag the event type for pretty printing
    et = event.get("type", "unknown")
    payload = event.get("payload", {})
    # Truncate large blobs for console width
    diff = payload.get("unified_diff", "")
    if len(diff) > 120:
        diff = diff[:120] + "..."
    print(f"  [{et}] {json.dumps({k: (v[:80] if isinstance(v, str) and len(v) > 80 else v) for k, v in payload.items()})}") 


async def main() -> None:
    """Run the full pipeline and dump telemetry events."""
    # --- setup ---------------------------------------------------------
    ai = MockAIEngine()
    sb = MockSandboxRunner(fail_first_n=0, tests_passed=3, tests_total=3)

    # Discover slices in the example vulnerable app
    slices = scan_repo("examples/vulnerable_app")
    print(f"Scanning repository — found {len(slices)} slices\n")

    # --- telemetry bus -------------------------------------------------
    bus = asyncio.Queue()
    set_bus(bus)  # wire the global emit() used by graph nodes

    # --- run the pipeline -----------------------------------------------
    print("=" * 60)
    print("VulnOS 2.0 CORE — Full Pipeline Demo")
    print("=" * 60)

    patches = await run_scan(
        "examples/vulnerable_app",
        ai=ai,
        sandbox=sb,
        bus=bus,
    )

    # --- drain and print all telemetry events -------------------------
    print("\n--- Telemetry Events ---")
    while True:
        try:
            ev = await asyncio.wait_for(bus.get(), timeout=0.5)
            _print_event(ev)
        except asyncio.TimeoutError:
            break

    print("\n--- Results ---")
    if patches:
        print(f"Verified {len(patches)} hardened patch(es):")
        for i, hp in enumerate(patches, start=1):
            print(f"  {i}. finding_id={hp.finding_id}")
            print(f"     status={hp.status}")
            print(f"     iterations={hp.iterations_used}")
            print(f"     verified={hp.sandbox_verdict.verified}")
            print(f"     cves={hp.cve_references}")
            print(f"     diff snippet={hp.unified_diff[:80]}...")
            print(f"     exploit runner={hp.exploit_used.runner_command}")
    else:
        print("No verified patches (all findings resolved or unresolved).")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    asyncio.run(main())