"""Unit tests for sandbox execution and Red/Blue verdict mapping."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock

import docker
import pytest
import requests

from src.common.models import (
    EXPLOIT_FAILURE_MARKER,
    ExploitTest,
    PatchDiff,
    SandboxStatus,
)
from src.sandbox.docker_runner import DockerRunner, SandboxInfrastructureError
from src.sandbox.exploit_runner import interpret_exploit_result
from src.sandbox.models import ContainerResult, VerificationRequest
from src.sandbox.verifier import SandboxVerifier
from src.sandbox.workspace import temporary_workspaces


def _request(source: Path) -> VerificationRequest:
    return VerificationRequest(
        source_path=source,
        exploit=ExploitTest(
            test_code=(
                "def test_exploit():\n"
                "    assert exploit_succeeded(), "
                f"'{EXPLOIT_FAILURE_MARKER} vulnerable behavior observed'\n"
            ),
            test_filename="test_exploit.py",
        ),
        patch=PatchDiff(diff="diff --git a/app.py b/app.py\n"),
        image="trusted-runtime:local",
        regression_command=["python", "-m", "pytest", "-q"],
    )


def _container_result(
    command: list[str],
    exit_code: int | None,
    stdout: str = "",
    stderr: str = "",
    timed_out: bool = False,
) -> ContainerResult:
    return ContainerResult(
        command=command,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        duration_seconds=0.01,
        timed_out=timed_out,
    )


class FakeDockerRunner:
    def __init__(
        self,
        *,
        patch_failure: bool = False,
        regression_failure: bool = False,
        regression_timeout: bool = False,
        inconclusive_original: bool = False,
        still_vulnerable: bool = False,
    ) -> None:
        self.patch_failure = patch_failure
        self.regression_failure = regression_failure
        self.regression_timeout = regression_timeout
        self.inconclusive_original = inconclusive_original
        self.still_vulnerable = still_vulnerable
        self.calls: list[tuple[list[str], Path, str, int | None]] = []

    def run(
        self,
        image: str,
        command: list[str],
        workspace: str | Path,
        timeout_seconds: int | None = None,
    ) -> ContainerResult:
        path = Path(workspace)
        self.calls.append((command, path, image, timeout_seconds))
        if command[0] == "git":
            failed = self.patch_failure
            return _container_result(
                command,
                1 if failed else 0,
                stderr="patch rejected" if failed else "",
            )
        if "test_exploit.py" in command:
            if path.name == "original":
                if self.inconclusive_original:
                    return _container_result(command, 1, stderr="1 failed")
                return _container_result(
                    command,
                    1,
                    stderr=(
                        f"AssertionError: {EXPLOIT_FAILURE_MARKER} vulnerable behavior observed\n"
                        "1 failed in 0.01s"
                    ),
                )
            if self.still_vulnerable:
                return _container_result(
                    command,
                    1,
                    stderr=(
                        f"AssertionError: {EXPLOIT_FAILURE_MARKER} vulnerable behavior observed\n"
                        "1 failed in 0.01s"
                    ),
                )
            return _container_result(command, 0, stdout="1 passed in 0.01s")
        if self.regression_timeout:
            return _container_result(command, None, timed_out=True)
        return _container_result(
            command,
            1 if self.regression_failure else 0,
            stdout="2 passed in 0.02s" if not self.regression_failure else "",
            stderr="regression assertion failed" if self.regression_failure else "",
        )


def test_docker_runner_collects_logs_and_nonzero_exit(tmp_path: Path) -> None:
    container = Mock()
    container.wait.return_value = {"StatusCode": 23}
    container.logs.side_effect = [iter([b"standard output"]), iter([b"standard error"])]
    client = Mock()
    client.containers.create.return_value = container

    result = DockerRunner(client=client).run(
        "trusted-runtime:local", ["python", "-c", "print('x')"], tmp_path
    )

    assert result.exit_code == 23
    assert result.stdout == "standard output"
    assert result.stderr == "standard error"
    container.remove.assert_called_once_with(force=True)


def test_docker_runner_applies_resource_and_security_limits(tmp_path: Path) -> None:
    client = Mock()
    container = client.containers.create.return_value
    container.wait.return_value = {"StatusCode": 0}
    container.logs.return_value = iter([])

    DockerRunner(client=client).run("trusted-runtime:local", ["true"], tmp_path)

    options = client.containers.create.call_args.kwargs
    assert options["network_mode"] == "none"
    assert options["mem_limit"] == "512m"
    assert options["memswap_limit"] == "512m"
    assert options["nano_cpus"] == 1_000_000_000
    assert options["read_only"] is True
    assert options["user"] != "0:0"
    assert options["cap_drop"] == ["ALL"]
    assert options["security_opt"] == ["no-new-privileges:true"]


def test_docker_runner_times_out_and_removes_container(tmp_path: Path) -> None:
    container = Mock()
    container.wait.side_effect = requests.exceptions.ReadTimeout("wait timed out")
    container.logs.side_effect = [iter([]), iter([])]
    client = Mock()
    client.containers.create.return_value = container

    result = DockerRunner(client=client).run(
        "trusted-runtime:local", ["sleep", "infinity"], tmp_path, timeout_seconds=1
    )

    assert result.timed_out
    assert result.exit_code is None
    container.kill.assert_called_once()
    container.remove.assert_called_once_with(force=True)


def test_docker_runner_bounds_collected_logs(tmp_path: Path) -> None:
    container = Mock()
    container.wait.return_value = {"StatusCode": 0}
    container.logs.side_effect = [
        iter([b"x" * (1_048_576 + 1)]),
        iter([]),
    ]
    client = Mock()
    client.containers.create.return_value = container

    result = DockerRunner(client=client).run("trusted-runtime:local", ["true"], tmp_path)

    assert len(result.stdout) < 1_048_576 + 64
    assert result.stdout.endswith("...[sandbox log truncated at 1 MiB]")


def test_docker_runner_surfaces_image_startup_failure(tmp_path: Path) -> None:
    client = Mock()
    client.images.get.side_effect = docker.errors.DockerException("image unavailable")

    with pytest.raises(SandboxInfrastructureError, match="Docker command failed"):
        DockerRunner(client=client).run("missing:local", ["true"], tmp_path)


def test_interpret_exploit_result_rejects_unrelated_failure() -> None:
    result = _container_result(
        ["python", "-m", "pytest"],
        1,
        stderr="ImportError: missing test dependency\n1 failed in 0.01s",
    )

    outcome, _ = interpret_exploit_result(result)

    assert outcome == "inconclusive"


def test_interpret_exploit_result_requires_the_expected_assertion_message() -> None:
    result = _container_result(
        ["python", "-m", "pytest"],
        1,
        stderr=(
            "AssertionError: unrelated assertion failed\n"
            f"assert condition, '{EXPLOIT_FAILURE_MARKER} marker in source only'\n"
            "1 failed in 0.01s"
        ),
    )

    outcome, _ = interpret_exploit_result(result)

    assert outcome == "inconclusive"


def test_interpret_exploit_timeout_is_inconclusive() -> None:
    result = _container_result(
        ["python", "-m", "pytest"],
        None,
        timed_out=True,
    )

    outcome, _ = interpret_exploit_result(result)

    assert outcome == "inconclusive"


def test_workspace_copies_are_isolated_and_cleaned(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("original", encoding="utf-8")
    (source / ".git").mkdir()
    (source / ".git" / "config").write_text("ignored", encoding="utf-8")
    (source / "venv").mkdir()
    (source / "venv" / "state").write_text("ignored", encoding="utf-8")

    with temporary_workspaces(source) as workspaces:
        original_path = workspaces.original_path
        patched_path = workspaces.patched_path
        assert original_path != patched_path
        (patched_path / "app.py").write_text("patched", encoding="utf-8")
        assert (original_path / "app.py").read_text(encoding="utf-8") == "original"
        assert not (original_path / ".git").exists()
        assert not (patched_path / "venv").exists()

    assert not original_path.exists()
    assert not patched_path.exists()


def test_verifier_maps_success_and_cleans_workspaces(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("source", encoding="utf-8")
    docker_runner = FakeDockerRunner()

    verdict = SandboxVerifier(docker_runner=docker_runner).verify(_request(source))

    assert verdict.status == SandboxStatus.VERIFIED
    assert verdict.verified
    assert verdict.exploit_triggers_on_unpatched
    assert verdict.exploit_blocked_after_patch
    assert verdict.existing_tests_pass
    assert [stage.stage for stage in verdict.stages] == [
        "original_exploit",
        "patch_check",
        "patch_apply",
        "patched_exploit",
        "regression_tests",
    ]
    original_workspace = docker_runner.calls[0][1]
    patched_workspace = docker_runner.calls[1][1]
    assert original_workspace != patched_workspace
    assert not original_workspace.exists()
    assert not patched_workspace.exists()
    assert (source / "app.py").read_text(encoding="utf-8") == "source"


def test_verifier_maps_patch_application_failure(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()

    verdict = SandboxVerifier(docker_runner=FakeDockerRunner(patch_failure=True)).verify(
        _request(source)
    )

    assert verdict.status == SandboxStatus.PATCH_FAILED
    assert verdict.failed_stage == "patch_check"
    assert not verdict.verified


def test_verifier_maps_regression_failure(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()

    verdict = SandboxVerifier(docker_runner=FakeDockerRunner(regression_failure=True)).verify(
        _request(source)
    )

    assert verdict.status == SandboxStatus.REGRESSION_FAILED
    assert verdict.failed_stage == "regression_tests"
    assert verdict.exploit_blocked_after_patch
    assert not verdict.existing_tests_pass


def test_verifier_maps_regression_timeout_to_inconclusive(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()

    verdict = SandboxVerifier(docker_runner=FakeDockerRunner(regression_timeout=True)).verify(
        _request(source)
    )

    assert verdict.status == SandboxStatus.INCONCLUSIVE
    assert verdict.failed_stage == "regression_tests"
    assert verdict.stages[-1].timed_out


def test_verifier_marks_unrecognized_original_failure_inconclusive(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()

    verdict = SandboxVerifier(docker_runner=FakeDockerRunner(inconclusive_original=True)).verify(
        _request(source)
    )

    assert verdict.status == SandboxStatus.INCONCLUSIVE
    assert verdict.failed_stage == "original_exploit"
    assert not verdict.exploit_triggers_on_unpatched


def test_verifier_detects_patch_that_does_not_block_exploit(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()

    verdict = SandboxVerifier(docker_runner=FakeDockerRunner(still_vulnerable=True)).verify(
        _request(source)
    )

    assert verdict.status == SandboxStatus.PATCH_FAILED
    assert verdict.failed_stage == "patched_exploit"
    assert verdict.exploit_triggers_on_unpatched
    assert not verdict.exploit_blocked_after_patch


def test_verifier_classifies_docker_startup_as_environment_error(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()

    class FailedDockerRunner:
        def run(
            self,
            image: str,
            command: list[str],
            workspace: str | Path,
            timeout_seconds: int | None = None,
        ) -> ContainerResult:
            raise SandboxInfrastructureError(
                f"Docker daemon unavailable for {image}, {command}, {workspace}, "
                f"timeout={timeout_seconds}"
            )

    verdict = SandboxVerifier(docker_runner=FailedDockerRunner()).verify(_request(source))

    assert verdict.status == SandboxStatus.ENVIRONMENT_ERROR
    assert verdict.failed_stage == "original_exploit"
    assert "Docker daemon unavailable" in verdict.reason
    assert verdict.stages[-1].status == "environment_error"
