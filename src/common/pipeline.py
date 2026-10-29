"""End-to-end pipeline wiring connecting Dev 2 (Inference & Threat Engine) and Dev 3 (Sandbox Verifier)."""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from src.common.config import VulnOSConfig, load_config
from src.common.models import (
    CodeSlice,
    HardenedPatch,
    TelemetryEvent,
)
from src.inference import InferenceEngine
from src.sandbox.models import ApprovedProjectRegistry, ControlledVerificationRequest
from src.sandbox.verifier import SandboxVerifier


class VulnOSPipeline:
    """End-to-end autonomous security and patching pipeline."""

    def __init__(
        self,
        config: VulnOSConfig | None = None,
        on_telemetry: Callable[[TelemetryEvent], None] | None = None,
    ) -> None:
        self.config = config or load_config()
        self.inference = InferenceEngine(config=self.config, on_telemetry=on_telemetry)
        self.sandbox_verifier = SandboxVerifier(config=self.config.sandbox)
        self.project_registry = ApprovedProjectRegistry()

    async def run_pipeline(
        self,
        repo_path: str | Path,
        slice_obj: CodeSlice,
        profile_id: str = "python-pytest",
    ) -> HardenedPatch:
        """Execute the full Dev 2 -> Dev 3 secure patching pipeline on a target repository slice."""
        path = Path(repo_path).expanduser().resolve(strict=True)

        # 1. Dev 2 Phase 1: Nemotron-Nano Triage
        assessment = await self.inference.triage(slice_obj)
        if not assessment.is_vulnerable:
            raise ValueError(f"Slice in {slice_obj.file_path} determined non-vulnerable by triage.")

        # 2. Dev 2 Phase 2: Tavily Threat Intelligence Enrichment
        intelligence = await self.inference.enrich(assessment)

        # 3. Dev 2 Phase 3: Red-Team Exploit Harness Generation (Nemotron-Ultra)
        exploit = await self.inference.generate_exploit(assessment, intelligence)

        # 4. Dev 2 Phase 4: Blue-Team Patch Synthesis (Nemotron-Ultra)
        patch = await self.inference.generate_patch(assessment, intelligence, exploit)

        # 5. Dev 3 Phase: Ephemeral Sandbox Verification
        target_id = self.project_registry.approve_project(path)
        request = ControlledVerificationRequest(
            target_id=target_id,
            profile_id=profile_id,
            patch=patch,
        )
        verdict = self.sandbox_verifier.verify_controlled(request, self.project_registry)

        return HardenedPatch(
            assessment=assessment,
            intelligence=intelligence,
            exploit=exploit,
            patch=patch,
            verdict=verdict,
        )
