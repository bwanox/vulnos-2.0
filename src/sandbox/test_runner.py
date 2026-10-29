"""Execution of caller-supplied regression test commands."""

from __future__ import annotations

from pathlib import Path

from src.common.models import SandboxStageResult
from src.sandbox.docker_runner import DockerCommandRunner


class RegressionTestRunner:
    """Runs the repository's configured regression command in Docker."""

    def __init__(self, docker_runner: DockerCommandRunner) -> None:
        self.docker_runner = docker_runner

    def run(
        self,
        image: str,
        workspace: Path,
        command: list[str],
        timeout_seconds: int | None = None,
    ) -> tuple[SandboxStageResult, bool]:
        result = self.docker_runner.run(image, command, workspace, timeout_seconds)
        passed = result.exit_code == 0 and not result.timed_out
        reason = (
            ""
            if passed
            else (
                "Regression tests timed out"
                if result.timed_out
                else "Regression command returned a non-zero or missing exit code"
            )
        )
        return (
            SandboxStageResult(
                stage="regression_tests",
                status="passed" if passed else ("timed_out" if result.timed_out else "failed"),
                command=result.command,
                exit_code=result.exit_code,
                stdout=result.stdout,
                stderr=result.stderr,
                duration_seconds=result.duration_seconds,
                timed_out=result.timed_out,
                reason=reason,
            ),
            passed,
        )
