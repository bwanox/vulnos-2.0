"""Live demo script: run the VulnOS 2.0 pipeline with RealAIEngine (Nebius + Tavily) and RealSandboxRunner (Dev 3 Docker Sandbox)."""

from __future__ import annotations

import asyncio
import sys

from vulnos.core.graph import run_scan
from vulnos.ai_adapter import RealAIEngine
from vulnos.sandbox_adapter import RealSandboxRunner
from vulnos.core.telemetry import set_bus


async def main() -> None:
    print("=" * 60)
    print("VulnOS 2.0 — Live Production Pipeline (Nebius + Tavily + Sandbox)")
    print("=" * 60)

    ai = RealAIEngine()
    sandbox = RealSandboxRunner()

    bus = asyncio.Queue()
    set_bus(bus)

    print("Starting autonomous scan on examples/vulnerable_app...")
    try:
        patches = await run_scan(
            "examples/vulnerable_app",
            ai=ai,
            sandbox=sandbox,
            bus=bus,
        )
        print(f"\nPipeline completed successfully! Found {len(patches)} hardened patch(es).")
    except Exception as e:
        print(f"\nPipeline encountered error (ensure NEBIUS_API_KEY and TAVILY_API_KEY are set): {e}")


if __name__ == "__main__":
    asyncio.run(main())
