"""Red/Blue patch verification orchestration."""

from __future__ import annotations

import time
from pathlib import Path

from pydantic import ValidationError

from src.common.config import SandboxConfig
from src.common.models import (
    SandboxStageResult,
    SandboxStatus,
    SandboxVerdict,
)
from src.sandbox.docker_runner import (
    DockerCommandRunner,
    DockerRunner,
    SandboxInfrastructureError,
)
from src.sandbox.exploit_runner import (
    ExploitRunner,
    exploit_command,
    interpret_exploit_result,
    validate_exploit_filename,
    write_exploit,
)
from src.sandbox.models import ContainerResult, VerificationRequest
from src.sandbox.patch_applier import PatchApplier
from src.sandbox.test_runner import RegressionTestRunner
from src.sandbox.workspace import temporary_workspaces


class SandboxVerifier:
    """Verify one patch attempt without owning any retry/orchestration loop."""

    def __init__(
        self,
        config: SandboxConfig | None = None,
        docker_runner: DockerCommandRunner | None = None,
    ) -> None:
        self.config = config or SandboxConfig()
        self.docker_runner = docker_runner or DockerRunner(config=self.config)
        self.exploit_runner = ExploitRunner(self.docker_runner)
        self.patch_applier = PatchApplier(self.docker_runner)
        self.test_runner = RegressionTestRunner(self.docker_runner)

    def verify(self, request: VerificationRequest) -> SandboxVerdict:
        """Run baseline exploit, apply patch, rerun exploit, and regressions once."""
        started = time.monotonic()
        try:
            validated = VerificationRequest.model_validate(request)
            source_path = Path(validated.source_path).expanduser().resolve(strict=True)
            if not source_path.is_dir():
                raise ValueError(f"Source path is not a directory: {source_path}")
            validate_exploit_filename(validated.exploit.test_filename)
            if not validated.exploit.test_code.strip():
                raise ValueError("Exploit test code must not be empty")
        except (ValidationError, OSError, ValueError) as error:
            return self._verdict(
                SandboxStatus.INCONCLUSIVE,
                "validation",
                f"Invalid verification request: {error}",
                started,
                [
                    SandboxStageResult(
                        stage="validation",
                        status="failed",
                        reason=str(error),
                    )
                ],
            )

        timeout = validated.timeout_seconds or self.config.timeout
        stages: list[SandboxStageResult] = []
        current_stage = "workspace"
        try:
            with temporary_workspaces(source_path) as workspaces:
                current_stage = "original_exploit"
                original_stage, reproduced = self.exploit_runner.run(
                    validated.image,
                    workspaces.original_path,
                    validated.exploit,
                    timeout,
                    validated.exploit_command,
                )
                stages.append(original_stage)
                if not reproduced:
                    return self._verdict(
                        SandboxStatus.INCONCLUSIVE,
                        "original_exploit",
                        original_stage.reason,
                        started,
                        stages,
                        exit_code=original_stage.exit_code,
                    )

                current_stage = "patch_apply"
                patch_stages, patch_applied = self.patch_applier.apply(
                    validated.image,
                    workspaces.patched_path,
                    validated.patch,
                    timeout,
                )
                stages.extend(patch_stages)
                if not patch_applied:
                    if stages[-1].timed_out:
                        return self._verdict(
                            SandboxStatus.INCONCLUSIVE,
                            stages[-1].stage,
                            "Patch application timed out",
                            started,
                            stages,
                            exploit_triggers_on_unpatched=True,
                            exit_code=stages[-1].exit_code,
                        )
                    if stages[-1].exit_code == 127:
                        return self._verdict(
                            SandboxStatus.ENVIRONMENT_ERROR,
                            stages[-1].stage,
                            "The runtime image does not provide the required git executable",
                            started,
                            stages,
                            exploit_triggers_on_unpatched=True,
                            exit_code=stages[-1].exit_code,
                        )
                    return self._verdict(
                        SandboxStatus.PATCH_FAILED,
                        stages[-1].stage,
                        "The proposed patch did not apply cleanly",
                        started,
                        stages,
                        exploit_triggers_on_unpatched=True,
                        exit_code=stages[-1].exit_code,
                    )

                current_stage = "patched_exploit"
                patched_name = write_exploit(workspaces.patched_path, validated.exploit)
                patched_command = exploit_command(patched_name, validated.exploit_command)
                patched_result = self.docker_runner.run(
                    validated.image,
                    patched_command,
                    workspaces.patched_path,
                    timeout,
                )
                patched_outcome, patched_reason = interpret_exploit_result(patched_result)
                blocked = patched_outcome == "blocked"
                stages.append(
                    _command_stage(
                        "patched_exploit",
                        patched_result,
                        blocked,
                        patched_reason,
                    )
                )
                if not blocked:
                    if patched_outcome == "vulnerable":
                        return self._verdict(
                            SandboxStatus.PATCH_FAILED,
                            "patched_exploit",
                            "The marked exploit assertion still fails after patching",
                            started,
                            stages,
                            exploit_triggers_on_unpatched=True,
                            exit_code=patched_result.exit_code,
                        )
                    return self._verdict(
                        SandboxStatus.INCONCLUSIVE,
                        "patched_exploit",
                        patched_reason,
                        started,
                        stages,
                        exploit_triggers_on_unpatched=True,
                        exit_code=patched_result.exit_code,
                    )

                current_stage = "regression_tests"
                regression, tests_passed = self.test_runner.run(
                    validated.image,
                    workspaces.patched_path,
                    validated.regression_command,
                    timeout,
                )
                stages.append(regression)
                if not tests_passed:
                    if regression.timed_out:
                        return self._verdict(
                            SandboxStatus.INCONCLUSIVE,
                            "regression_tests",
                            regression.reason,
                            started,
                            stages,
                            exploit_triggers_on_unpatched=True,
                            exploit_blocked_after_patch=True,
                            exit_code=regression.exit_code,
                        )
                    if regression.exit_code == 127:
                        return self._verdict(
                            SandboxStatus.ENVIRONMENT_ERROR,
                            "regression_tests",
                            "The runtime image could not start the configured regression command",
                            started,
                            stages,
                            exploit_triggers_on_unpatched=True,
                            exploit_blocked_after_patch=True,
                            exit_code=regression.exit_code,
                        )
                    return self._verdict(
                        SandboxStatus.REGRESSION_FAILED,
                        "regression_tests",
                        regression.reason,
                        started,
                        stages,
                        exploit_triggers_on_unpatched=True,
                        exploit_blocked_after_patch=True,
                        exit_code=regression.exit_code,
                    )

                return self._verdict(
                    SandboxStatus.VERIFIED,
                    None,
                    (
                        "Original vulnerability reproduced, patched exploit blocked, "
                        "and regressions passed"
                    ),
                    started,
                    stages,
                    exploit_triggers_on_unpatched=True,
                    exploit_blocked_after_patch=True,
                    existing_tests_pass=True,
                    exit_code=regression.exit_code,
                )
        except SandboxInfrastructureError as error:
            failed_stage = current_stage
            if error.command and error.command[0] == "git" and "--check" in error.command:
                failed_stage = "patch_check"
            stages.append(
                SandboxStageResult(
                    stage=failed_stage,
                    status="environment_error",
                    command=error.command,
                    duration_seconds=error.duration_seconds,
                    reason=str(error),
                )
            )
            return self._verdict(
                SandboxStatus.ENVIRONMENT_ERROR,
                failed_stage,
                str(error),
                started,
                stages,
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
                f"Workspace or sandbox operation failed: {error}",
                started,
                stages,
            )

    @staticmethod
    def _verdict(
        status: SandboxStatus,
        failed_stage: str | None,
        reason: str,
        started: float,
        stages: list[SandboxStageResult] | None = None,
        exploit_triggers_on_unpatched: bool = False,
        exploit_blocked_after_patch: bool = False,
        existing_tests_pass: bool = False,
        exit_code: int | None = None,
    ) -> SandboxVerdict:
        stage_results = stages or []
        return SandboxVerdict(
            status=status,
            verified=status == SandboxStatus.VERIFIED,
            failed_stage=failed_stage,
            reason=reason,
            stages=stage_results,
            exploit_triggers_on_unpatched=exploit_triggers_on_unpatched,
            exploit_blocked_after_patch=exploit_blocked_after_patch,
            existing_tests_pass=existing_tests_pass,
            stdout="\n".join(stage.stdout for stage in stage_results if stage.stdout),
            stderr="\n".join(stage.stderr for stage in stage_results if stage.stderr),
            exit_code=exit_code if exit_code is not None else -1,
            duration_seconds=time.monotonic() - started,
        )


def verify_patch(
    request: VerificationRequest,
    config: SandboxConfig | None = None,
) -> SandboxVerdict:
    """Convenience function for callers that do not need a reusable verifier."""
    return SandboxVerifier(config=config).verify(request)


def _command_stage(
    stage: str,
    result: ContainerResult,
    success: bool,
    reason: str,
) -> SandboxStageResult:
    return SandboxStageResult(
        stage=stage,
        status="passed" if success else ("timed_out" if result.timed_out else "failed"),
        command=result.command,
        exit_code=result.exit_code,
        stdout=result.stdout,
        stderr=result.stderr,
        duration_seconds=result.duration_seconds,
        timed_out=result.timed_out,
        reason=reason,
    )
