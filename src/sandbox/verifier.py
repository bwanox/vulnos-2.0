"""Controlled verification facade for approved build/test profiles."""

from __future__ import annotations

import time

from pydantic import ValidationError

from src.common.config import SandboxConfig
from src.common.models import SandboxStageResult, SandboxStatus, SandboxVerdict
from src.sandbox.adapters import DEFAULT_PROFILE_REGISTRY, ExecutionProfileRegistry
from src.sandbox.controlled_verifier import ControlledVerifier
from src.sandbox.docker_runner import DockerCommandRunner, DockerRunner
from src.sandbox.models import (
    ApprovedProjectRegistry,
    ControlledVerificationRequest,
    VerificationRequest,
)


class SandboxVerifier:
    """Runs registered build/test profiles; generated exploit code is not executed."""

    def __init__(
        self,
        config: SandboxConfig | None = None,
        docker_runner: DockerCommandRunner | None = None,
        profile_registry: ExecutionProfileRegistry = DEFAULT_PROFILE_REGISTRY,
    ) -> None:
        self.config = config or SandboxConfig()
        self.docker_runner = docker_runner or DockerRunner(config=self.config)
        self.controlled_verifier = ControlledVerifier(
            self.docker_runner,
            self.config,
            profile_registry,
        )

    def verify(self, request: VerificationRequest) -> SandboxVerdict:
        """Reject legacy exploit requests rather than executing model-generated code."""
        del request
        return SandboxVerdict(
            status=SandboxStatus.INCONCLUSIVE,
            verified=False,
            failed_stage="profile_validation",
            reason=(
                "Unrestricted exploit verification is disabled. Register the target and use "
                "verify_controlled with an application-owned execution profile."
            ),
            stages=[
                SandboxStageResult(
                    stage="profile_validation",
                    status="failed",
                    reason="Legacy exploit execution is disabled.",
                )
            ],
            security_verification_performed=False,
        )

    def verify_controlled(
        self,
        request: ControlledVerificationRequest,
        approved_projects: ApprovedProjectRegistry,
    ) -> SandboxVerdict:
        """Build/test an approved target using registry-owned commands and images."""
        started = time.monotonic()
        try:
            validated = ControlledVerificationRequest.model_validate(request)
        except (ValidationError, TypeError, ValueError) as error:
            return SandboxVerdict(
                status=SandboxStatus.INCONCLUSIVE,
                verified=False,
                failed_stage="profile_validation",
                reason=f"Invalid controlled verification request: {error}",
                stages=[
                    SandboxStageResult(
                        stage="profile_validation",
                        status="failed",
                        reason=str(error),
                    )
                ],
                security_verification_performed=False,
                duration_seconds=time.monotonic() - started,
            )
        return self.controlled_verifier.verify(validated, approved_projects)


def verify_patch(
    request: VerificationRequest,
    config: SandboxConfig | None = None,
) -> SandboxVerdict:
    """Compatibility entry point; legacy exploit execution is deliberately disabled."""
    return SandboxVerifier(config=config).verify(request)
