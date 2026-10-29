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
        DockerRunner(client=client).run("trusted-runtime:local", ["true"], tmp_path)


def test_docker_runner_removes_container_when_start_raises(tmp_path: Path) -> None:
    container = Mock()
    container.start.side_effect = docker.errors.DockerException("start failed")
    client = Mock()
    client.containers.create.return_value = container

    with pytest.raises(SandboxInfrastructureError, match="Docker command failed"):
        DockerRunner(client=client).run("trusted-runtime:local", ["true"], tmp_path)

    container.remove.assert_called_once_with(force=True)


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


def test_verifier_disables_legacy_generated_exploit_execution(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    docker_runner = Mock()

    verdict = SandboxVerifier(docker_runner=docker_runner).verify(_request(source))

    assert verdict.status == SandboxStatus.INCONCLUSIVE
    assert verdict.security_verification_performed is False
    docker_runner.run.assert_not_called()
