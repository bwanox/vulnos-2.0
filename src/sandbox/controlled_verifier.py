"""Build/test verification using approved targets and trusted execution profiles."""

from __future__ import annotations

import time
from pathlib import Path

from src.common.config import SandboxConfig
from src.common.models import SandboxStageResult, SandboxStatus, SandboxVerdict
from src.sandbox.adapters import DEFAULT_PROFILE_REGISTRY, ExecutionProfileRegistry
from src.sandbox.discovery import discover_project
from src.sandbox.docker_runner import (
    DockerCommandRunner,
    SandboxInfrastructureError,
)
from src.sandbox.models import (
    ApprovedProjectRegistry,
    ContainerResult,
    ControlledVerificationRequest,
)
from src.sandbox.patch_applier import PatchApplier
from src.sandbox.workspace import temporary_workspaces


class ControlledVerifier:
    """Run only registered build/test commands against explicitly approved projects."""

    def __init__(
        self,
        docker_runner: DockerCommandRunner,
        config: SandboxConfig,
        profile_registry: ExecutionProfileRegistry = DEFAULT_PROFILE_REGISTRY,
    ) -> None:
        self.docker_runner = docker_runner
        self.config = config
        self.profile_registry = profile_registry
        self.patch_applier = PatchApplier(docker_runner)

    def verify(
        self,
        request: ControlledVerificationRequest,
        approved_projects: ApprovedProjectRegistry,
    ) -> SandboxVerdict:
        started = time.monotonic()
        stages: list[SandboxStageResult] = []
        target_path: Path | None = None
        profile_id = request.profile_id
        languages: list[str] = []
        try:
            target_path = approved_projects.resolve(request.target_id)
            discovery = discover_project(target_path)
            languages = [language.name for language in discovery.languages]
            profile = self.profile_registry.validate_for(profile_id, discovery)
        except (OSError, ValueError) as error:
            return self._verdict(
                SandboxStatus.INCONCLUSIVE,
                "profile_validation",
                str(error),
                started,
                stages,
                request,
                languages,
            )

        timeout = min(
            request.timeout_seconds or profile.timeout_seconds,
            profile.timeout_seconds,
            self.config.timeout,
        )
        current_stage = "workspace"
        try:
            with temporary_workspaces(target_path) as workspaces:
                current_stage = "baseline_build"
                failed = self._run_commands(
                    profile.runtime_image,
                    workspaces.original_path,
                    profile.build_commands,
                    timeout,
                    "baseline_build",
                    stages,
                )
                if failed is not None:
                    return self._failure_verdict(
                        failed,
                        stages,
                        started,
                        request,
                        languages,
                        build=True,
                    )

                current_stage = "baseline_tests"
                failed = self._run_commands(
                    profile.runtime_image,
                    workspaces.original_path,
                    profile.test_commands,
                    timeout,
                    "baseline_tests",
                    stages,
                )
                if failed is not None:
                    return self._failure_verdict(
                        failed,
                        stages,
                        started,
                        request,
                        languages,
                        baseline=True,
                    )

                current_stage = "patch_apply"
                patch_stages, applied = self.patch_applier.apply(
                    profile.runtime_image,
                    workspaces.patched_path,
                    request.patch,
                    timeout,
                )
                stages.extend(patch_stages)
                if not applied:
                    failed_stage = stages[-1]
                    if failed_stage.timed_out:
                        status = SandboxStatus.INCONCLUSIVE
                    elif failed_stage.exit_code == 127:
                        status = SandboxStatus.ENVIRONMENT_ERROR
                    else:
                        status = SandboxStatus.PATCH_FAILED
                    return self._verdict(
                        status,
                        failed_stage.stage,
                        failed_stage.reason or "Proposed patch was not applied.",
                        started,
                        stages,
                        request,
                        languages,
                    )

                current_stage = "patched_build"
                failed = self._run_commands(
                    profile.runtime_image,
                    workspaces.patched_path,
                    profile.build_commands,
                    timeout,
                    "patched_build",
                    stages,
                )
                if failed is not None:
                    return self._failure_verdict(
                        failed,
                        stages,
                        started,
                        request,
                        languages,
                        build=True,
                    )

                current_stage = "patched_tests"
                failed = self._run_commands(
                    profile.runtime_image,
                    workspaces.patched_path,
                    profile.test_commands,
                    timeout,
                    "patched_tests",
                    stages,
                )
                if failed is not None:
                    if failed.timed_out or failed.exit_code == 127:
                        return self._failure_verdict(
                            failed,
                            stages,
                            started,
                            request,
                            languages,
                        )
                    return self._verdict(
                        SandboxStatus.REGRESSION_FAILED,
                        failed.stage,
                        failed.reason,
                        started,
                        stages,
                        request,
                        languages,
                    )

                return self._verdict(
                    SandboxStatus.TESTS_PASSED,
                    None,
                    (
                        "Approved baseline and patched build/test profiles passed. "
                        "This is not exploit verification or proof of security."
                    ),
                    started,
                    stages,
                    request,
                    languages,
                    existing_tests_pass=True,
                )
        except SandboxInfrastructureError as error:
            stages.append(
                SandboxStageResult(
                    stage=current_stage,
                    status="environment_error",
                    command=error.command,
                    duration_seconds=error.duration_seconds,
                    reason=str(error),
                )
            )
            return self._verdict(
                SandboxStatus.ENVIRONMENT_ERROR,
                current_stage,
                str(error),
                started,
                stages,
                request,
                languages,
            )
        except (OSError, ValueError) as error:
            stages.append(
                SandboxStageResult(
                    stage=current_stage,
                    status="environment_error",
                    reason=str(error),
                )
            )
            return self._verdict(
                SandboxStatus.ENVIRONMENT_ERROR,
                current_stage,
                str(error),
                started,
                stages,
                request,
                languages,
            )

    def _run_commands(
        self,
        image: str,
        workspace: Path,
        commands: tuple[tuple[str, ...], ...],
        timeout: int,
        stage_name: str,
        stages: list[SandboxStageResult],
    ) -> SandboxStageResult | None:
        for index, command in enumerate(commands, start=1):
            stage = stage_name if len(commands) == 1 else f"{stage_name}_{index}"
            result = self.docker_runner.run(image, list(command), workspace, timeout)
            passed = result.exit_code == 0 and not result.timed_out
            reason = "" if passed else _command_failure_reason(result)
            stage_result = _stage_result(stage, result, passed, reason)
            stages.append(stage_result)
            if not passed:
                return stage_result
        return None

    def _failure_verdict(
        self,
        failed: SandboxStageResult,
        stages: list[SandboxStageResult],
        started: float,
        request: ControlledVerificationRequest,
        languages: list[str],
        *,
        build: bool = False,
        baseline: bool = False,
    ) -> SandboxVerdict:
        if failed.timed_out:
            status = SandboxStatus.INCONCLUSIVE
        elif failed.exit_code == 127:
            status = SandboxStatus.ENVIRONMENT_ERROR
        elif build:
            status = SandboxStatus.BUILD_FAILED
        else:
            status = SandboxStatus.INCONCLUSIVE
        reason = failed.reason
        if baseline:
            reason = f"Baseline tests did not pass; patch comparison is inconclusive. {reason}"
        return self._verdict(
            status,
            failed.stage,
            reason,
            started,
            stages,
            request,
            languages,
        )

    @staticmethod
    def _verdict(
        status: SandboxStatus,
        failed_stage: str | None,
        reason: str,
        started: float,
        stages: list[SandboxStageResult],
        request: ControlledVerificationRequest,
        languages: list[str],
        existing_tests_pass: bool = False,
    ) -> SandboxVerdict:
        return SandboxVerdict(
            status=status,
            verified=False,
            failed_stage=failed_stage,
            reason=reason,
            stages=stages,
            existing_tests_pass=existing_tests_pass,
            stdout="\n".join(stage.stdout for stage in stages if stage.stdout),
            stderr="\n".join(stage.stderr for stage in stages if stage.stderr),
            exit_code=stages[-1].exit_code if stages and stages[-1].exit_code is not None else -1,
            duration_seconds=time.monotonic() - started,
            target_id=request.target_id,
            execution_profile_id=request.profile_id,
            build_profile_id=f"{request.profile_id}-build",
            test_profile_id=f"{request.profile_id}-test",
            detected_languages=languages,
            security_verification_performed=False,
        )


def _command_failure_reason(result: ContainerResult) -> str:
    if result.timed_out:
        return "Approved build/test profile timed out."
    if result.exit_code == 127:
        return "A required executable is unavailable in the approved runtime image."
    return "Approved build/test profile returned a non-zero or missing exit code."


def _stage_result(
    stage: str,
    result: ContainerResult,
    passed: bool,
    reason: str,
) -> SandboxStageResult:
    return SandboxStageResult(
        stage=stage,
        status="passed" if passed else ("timed_out" if result.timed_out else "failed"),
        command=result.command,
        exit_code=result.exit_code,
        stdout=result.stdout,
        stderr=result.stderr,
        duration_seconds=result.duration_seconds,
        timed_out=result.timed_out,
        reason=reason,
    )
