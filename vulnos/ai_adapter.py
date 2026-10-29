"""Real AI Engine adapter connecting Dev 1 protocols to Dev 2 (Nebius Token Factory & Tavily API)."""

from __future__ import annotations

from pathlib import Path

from src.common.config import load_config
from src.inference import InferenceEngine
from src.common.models import CodeSlice as Dev2CodeSlice, DependencyInfo as Dev2DependencyInfo
from vulnos.core.contracts import (
    AIEngine,
    CodeSlice as CoreCodeSlice,
    Dependency,
    VulnAssessment,
    ExploitTest,
    PatchDiff,
)


class RealAIEngine(AIEngine):
    """Concrete implementation of Dev 1 AIEngine protocol using Nebius Token Factory and Tavily."""

    def __init__(self) -> None:
        self.config = load_config()
        self.engine = InferenceEngine(config=self.config)

    async def triage(self, code_slice: CoreCodeSlice) -> VulnAssessment:
        """Triage code slice via Nemotron-Nano on Nebius Token Factory."""
        dev2_slice = Dev2CodeSlice(
            file_path=code_slice.file_path,
            function_name=code_slice.function_name,
            function_body=code_slice.function_body,
            caller_context=code_slice.caller_context,
            imports=code_slice.imports,
            sink_type=code_slice.sink_type.value if hasattr(code_slice.sink_type, "value") else str(code_slice.sink_type),
            entry_point=code_slice.entry_point,
            target_language=code_slice.language,
        )
        assessment = await self.engine.triage(dev2_slice)
        return VulnAssessment(
            slice_id=code_slice.slice_id,
            is_vulnerable=assessment.is_vulnerable,
            severity="high" if assessment.confidence > 0.8 else "medium",
            cwe=assessment.cwe_id,
            reasoning=assessment.reasoning,
            confidence=assessment.confidence,
            related_cves=[],
        )

    async def enrich_cve(
        self, deps: list[Dependency], code_slice: CoreCodeSlice
    ) -> list[str]:
        """Query Tavily API for live CVEs and advisories."""
        dev2_slice = Dev2CodeSlice(
            file_path=code_slice.file_path,
            function_name=code_slice.function_name,
            function_body=code_slice.function_body,
            target_language=code_slice.language,
        )
        dev2_deps = [
            Dev2DependencyInfo(name=d.package, current_version=d.version or "latest", manifest_file=d.manifest_file)
            for d in deps
        ]
        assessment = await self.engine.triage(dev2_slice)
        intel = await self.engine.enrich(assessment, dev2_deps)
        return intel.cve_ids

    async def generate_exploit(
        self, code_slice: CoreCodeSlice, assessment: VulnAssessment
    ) -> ExploitTest:
        """Generate Red-Team PoC exploit test via Nemotron-Ultra on Nebius Token Factory."""
        dev2_slice = Dev2CodeSlice(
            file_path=code_slice.file_path,
            function_name=code_slice.function_name,
            function_body=code_slice.function_body,
            target_language=code_slice.language,
        )
        dev2_assessment = await self.engine.triage(dev2_slice)
        dev2_intel = await self.engine.enrich(dev2_assessment)
        exploit = await self.engine.generate_exploit(dev2_assessment, dev2_intel)
        return ExploitTest(
            language=exploit.target_language,
            code=exploit.test_code,
            expected_behavior=exploit.exploit_description,
            runner_command=exploit.runner_command,
        )

    async def generate_patch(
        self,
        code_slice: CoreCodeSlice,
        assessment: VulnAssessment,
        prev_failure_logs: str | None = None,
    ) -> PatchDiff:
        """Generate Blue-Team patch via Nemotron-Ultra on Nebius Token Factory."""
        dev2_slice = Dev2CodeSlice(
            file_path=code_slice.file_path,
            function_name=code_slice.function_name,
            function_body=code_slice.function_body,
            target_language=code_slice.language,
        )
        dev2_assessment = await self.engine.triage(dev2_slice)
        dev2_intel = await self.engine.enrich(dev2_assessment)
        
        # Create dummy exploit for patch context
        from src.common.models import ExploitTest as Dev2Exploit
        dummy_exploit = Dev2Exploit(test_code="def test_exploit(): pass")

        patch = await self.engine.generate_patch(
            dev2_assessment, dev2_intel, dummy_exploit, failed_patch_error=prev_failure_logs
        )
        return PatchDiff(
            unified_diff=patch.diff,
            explanation=patch.patch_description,
            files_modified=patch.files_modified or [code_slice.file_path],
        )
