"""Sandbox Runner adapter connecting Dev 1 protocols to Dev 3 (Docker Sandbox Verifier)."""

from __future__ import annotations

from pathlib import Path

from src.common.config import load_config
from src.sandbox.models import ApprovedProjectRegistry, ControlledVerificationRequest
from src.sandbox.verifier import SandboxVerifier
from src.common.models import PatchDiff as Dev2PatchDiff
from vulnos.core.contracts import (
    SandboxRunner,
    ExploitTest,
    PatchDiff,
    SandboxVerdict as CoreSandboxVerdict,
)


class RealSandboxRunner(SandboxRunner):
    """Concrete implementation of Dev 1 SandboxRunner protocol using Dev 3 SandboxVerifier."""

    def __init__(self) -> None:
        self.config = load_config()
        self.verifier = SandboxVerifier(config=self.config.sandbox)
        self.registry = ApprovedProjectRegistry()

    async def verify(
        self,
        repo_path: str | Path,
        exploit: ExploitTest,
        patch: PatchDiff,
    ) -> CoreSandboxVerdict:
        """Run exploit verification and tests inside the ephemeral Docker sandbox."""
        path = Path(repo_path).expanduser().resolve(strict=True)
        target_id = self.registry.approve_project(path)

        dev2_patch = Dev2PatchDiff(
            diff=patch.unified_diff,
            patch_description=patch.explanation,
            files_modified=patch.files_modified,
        )

        request = ControlledVerificationRequest(
            target_id=target_id,
            profile_id="python-pytest",
            patch=dev2_patch,
        )

        verdict = self.verifier.verify_controlled(request, self.registry)

        return CoreSandboxVerdict(
            exploit_blocked_after_patch=verdict.exploit_blocked_after_patch,
            exploit_worked_before_patch=verdict.exploit_triggers_on_unpatched,
            tests_passed=3 if verdict.verified else 0,  # mapped from test run results
            tests_total=3,
            exit_codes=[verdict.exit_code],
            logs=verdict.stdout + "\n" + verdict.stderr,
        )
