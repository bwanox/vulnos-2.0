"""Opt-in harmless Docker smoke test for a locally prepared runtime image."""

from __future__ import annotations

import os
from pathlib import Path

import docker
import pytest

from src.sandbox.docker_runner import DockerRunner, SandboxInfrastructureError


def test_harmless_python_command_in_docker(tmp_path: Path) -> None:
    image = os.environ.get("VULNOS_TEST_DOCKER_IMAGE")
    if not image:
        pytest.skip("Set VULNOS_TEST_DOCKER_IMAGE to a trusted local Python image")

    runner = DockerRunner()
    try:
        result = runner.run(
            image,
            ["python", "-c", "print('sandbox-smoke-ok')"],
            tmp_path,
            timeout_seconds=15,
        )
    except SandboxInfrastructureError as error:
        pytest.skip(f"Docker image or daemon is unavailable: {error}")
    except docker.errors.DockerException as error:
        pytest.skip(f"Docker is unavailable: {error}")

    assert result.exit_code == 0
    assert result.stdout.strip() == "sandbox-smoke-ok"
