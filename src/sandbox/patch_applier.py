"""Application of Blue-Team unified diffs inside a disposable workspace."""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath

from src.common.models import PatchDiff, SandboxStageResult
from src.sandbox.docker_runner import DockerCommandRunner
from src.sandbox.models import ContainerResult

_PATCH_FILENAME = ".vulnos-proposed.patch"
_DIFF_HEADER = re.compile(r"^diff --git a/(.+) b/(.+)$")


def _validate_patch_paths(patch: PatchDiff) -> None:
    if "\x00" in patch.diff:
        raise ValueError("Patch diff cannot contain NUL bytes")
    if "GIT binary patch" in patch.diff or "Binary files " in patch.diff:
        raise ValueError("Binary patches are not permitted")
    if re.search(r"(?m)^(?:old|new) mode 120000$", patch.diff):
        raise ValueError("Symbolic-link patches are not permitted")
    paths: list[str] = []
    for line in patch.diff.splitlines():
        match = _DIFF_HEADER.match(line)
        if match:
            paths.extend(match.groups())
        elif line.startswith(("--- a/", "+++ b/")):
            paths.append(line[6:])
        elif line.startswith(("rename from ", "rename to ", "copy from ", "copy to ")):
            raise ValueError("Rename and copy patch metadata are not permitted")
    if not paths:
        raise ValueError("Patch must identify at least one workspace-relative file")
    for value in paths:
        if value == "/dev/null":
            continue
        if "\\" in value or '"' in value or any(ord(char) < 32 for char in value):
            raise ValueError("Patch paths must use workspace-relative POSIX separators")
        candidate = PurePosixPath(value)
        if (
            candidate.is_absolute()
            or not candidate.parts
            or any(part in {"", ".", "..", ".git"} for part in candidate.parts)
            or candidate.name == _PATCH_FILENAME
        ):
            raise ValueError(f"Patch path is outside the authorized workspace: {value}")


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
        try:
            _validate_patch_paths(patch)
        except ValueError as error:
            failed = SandboxStageResult(
                stage="patch_check",
                status="failed",
                reason=str(error),
            )
            return [failed], False

        patch_file = workspace / _PATCH_FILENAME
        if patch_file.exists() or patch_file.is_symlink():
            return [
                SandboxStageResult(
                    stage="patch_check",
                    status="failed",
                    reason=f"Workspace reserves the patch staging filename {_PATCH_FILENAME}",
                )
            ], False
        stages: list[SandboxStageResult] = []
        try:
            patch_file.write_text(patch.diff, encoding="utf-8")
            check = self.docker_runner.run(
                image,
                ["git", "apply", "--check", f"/workspace/{_PATCH_FILENAME}"],
                workspace,
                timeout_seconds,
            )
            check_ok = check.exit_code == 0 and not check.timed_out
            stages.append(_patch_stage("patch_check", check, check_ok))
            if not check_ok:
                return stages, False

            applied = self.docker_runner.run(
                image,
                ["git", "apply", f"/workspace/{_PATCH_FILENAME}"],
                workspace,
                timeout_seconds,
            )
            apply_ok = applied.exit_code == 0 and not applied.timed_out
            stages.append(_patch_stage("patch_apply", applied, apply_ok))
            return stages, apply_ok
        finally:
            patch_file.unlink(missing_ok=True)


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
