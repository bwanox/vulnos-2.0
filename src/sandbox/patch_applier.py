"""Application of Blue-Team unified diffs inside a disposable workspace."""

from __future__ import annotations

from pathlib import Path

from src.common.models import PatchDiff, SandboxStageResult
from src.sandbox.docker_runner import DockerCommandRunner
from src.sandbox.models import ContainerResult

_PATCH_FILENAME = ".vulnos-proposed.patch"


class PatchApplier:
    """Checks and applies a patch using git only inside the Docker container."""

    def __init__(self, docker_runner: DockerCommandRunner) -> None:
        self.docker_runner = docker_runner

    def apply(
        self,
        image: str,
        workspace: Path,
        patch: PatchDiff,
        timeout_seconds: int | None = None,
    ) -> tuple[list[SandboxStageResult], bool]:
        if not patch.diff.strip():
            failed = SandboxStageResult(
                stage="patch_apply",
                status="failed",
                reason="Patch diff is empty",
            )
            return [failed], False

        patch_file = workspace / _PATCH_FILENAME
        patch_file.write_text(patch.diff, encoding="utf-8")
        stages: list[SandboxStageResult] = []
        check = self.docker_runner.run(
            image,
            ["git", "apply", "--check", f"/workspace/{_PATCH_FILENAME}"],
            workspace,
            timeout_seconds,
        )
        check_ok = check.exit_code == 0 and not check.timed_out
        stages.append(_patch_stage("patch_check", check, check_ok))
        if not check_ok:
            patch_file.unlink(missing_ok=True)
            return stages, False

        applied = self.docker_runner.run(
            image,
            ["git", "apply", f"/workspace/{_PATCH_FILENAME}"],
            workspace,
            timeout_seconds,
        )
        apply_ok = applied.exit_code == 0 and not applied.timed_out
        stages.append(_patch_stage("patch_apply", applied, apply_ok))
        patch_file.unlink(missing_ok=True)
        return stages, apply_ok


def _patch_stage(stage: str, result: ContainerResult, success: bool) -> SandboxStageResult:
    return SandboxStageResult(
        stage=stage,
        status="passed" if success else ("timed_out" if result.timed_out else "failed"),
        command=result.command,
        exit_code=result.exit_code,
        stdout=result.stdout,
        stderr=result.stderr,
        duration_seconds=result.duration_seconds,
        timed_out=result.timed_out,
        reason="" if success else "git apply could not apply the proposed patch",
    )
