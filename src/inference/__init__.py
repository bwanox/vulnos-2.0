"""Inference & Threat Intelligence Engine Façade for VulnOS 2.0."""

from __future__ import annotations

from typing import Callable

from src.common.config import VulnOSConfig
from src.common.models import (
    CodeSlice,
    DependencyInfo,
    ExploitTest,
    PatchDiff,
    TavilyIntelligence,
    TelemetryEvent,
    VulnAssessment,
)
from src.inference.blue_team import generate_patch
from src.inference.client import NebisClient
from src.inference.red_team import generate_exploit
from src.inference.triage import triage_slice
from src.inference.tavily_engine import TavilyThreatEngine
from src.inference.telemetry import TelemetryEmitter

__all__ = [
    "InferenceEngine",
    "NebisClient",
    "TavilyThreatEngine",
    "triage_slice",
    "generate_exploit",
    "generate_patch",
]


class InferenceEngine:
    """Unified façade combining Nebius Token Factory inference and Tavily threat intelligence."""

    def __init__(
        self,
        config: VulnOSConfig,
        on_telemetry: Callable[[TelemetryEvent], None] | None = None,
    ) -> None:
        self.config = config
        self.emitter = TelemetryEmitter(callback=on_telemetry)
        self.nebis = NebisClient(config=config.nebius, emitter=self.emitter)
        self.tavily = TavilyThreatEngine(config=config.tavily, emitter=self.emitter)

    async def triage(self, slice_obj: CodeSlice) -> VulnAssessment:
        """Triage code slice via Nemotron-Nano."""
        return await triage_slice(self.nebis, slice_obj)

    async def enrich(
        self,
        assessment: VulnAssessment,
        dependencies: list[DependencyInfo] | None = None,
    ) -> TavilyIntelligence:
        """Enrich assessment with live CVE/advisory data via Tavily."""
        return await self.tavily.search_threat_intel(assessment, dependencies)

    async def generate_exploit(
        self,
        assessment: VulnAssessment,
        intelligence: TavilyIntelligence,
    ) -> ExploitTest:
        """Generate Red-Team PoC exploit test via Nemotron-Ultra."""
        return await generate_exploit(self.nebis, assessment, intelligence)

    async def generate_patch(
        self,
        assessment: VulnAssessment,
        intelligence: TavilyIntelligence,
        exploit: ExploitTest,
        failed_patch_error: str | None = None,
    ) -> PatchDiff:
        """Generate Blue-Team patch diff via Nemotron-Ultra."""
        return await generate_patch(
            self.nebis, assessment, intelligence, exploit, failed_patch_error
        )
