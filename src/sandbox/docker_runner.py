"""Hardened, network-disabled Docker command execution."""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, Protocol

import docker
import requests

from src.common.config import SandboxConfig
from src.sandbox.models import ContainerResult

_MEMORY_LIMIT = "512m"
_CPU_LIMIT_NANO_CPUS = 1_000_000_000
_MAX_LOG_BYTES = 1_048_576
_TEMP_FILESYSTEM = "rw,noexec,nosuid,size=64m"
_CONTAINER_WORKSPACE = "/workspace"


class DockerCommandRunner(Protocol):
    """Narrow interface used by sandbox stages and Docker test doubles."""

    def run(
        self,
        image: str,
        command: list[str],
        workspace: str | Path,
        timeout_seconds: int | None = None,
    ) -> ContainerResult: ...


class SandboxInfrastructureError(RuntimeError):
    """Raised when Docker cannot create, run, or clean up a sandbox container."""

    def __init__(
        self,
        message: str,
        command: list[str] | None = None,
        duration_seconds: float = 0.0,
    ) -> None:
        super().__init__(message)
        self.command = command or []
        self.duration_seconds = duration_seconds


class DockerRunner:
    """Runs a single command in a hardened container with no network access."""

    def __init__(
        self,
        config: SandboxConfig | None = None,
        client: Any | None = None,
    ) -> None:
        self.config = config or SandboxConfig()
        self.client = client

    def _docker_client(self) -> Any:
        if self.client is None:
            try:
                self.client = docker.from_env()
            except (docker.errors.DockerException, requests.exceptions.RequestException) as error:
                raise SandboxInfrastructureError(
                    f"Unable to connect to the Docker daemon: {error}"
                ) from error
        return self.client

    def run(
        self,
        image: str,
        command: list[str],
        workspace: str | Path,
        timeout_seconds: int | None = None,
    ) -> ContainerResult:
        """Run argv directly (without a host or container shell) and remove its container."""
        if not command or any(not argument for argument in command):
            raise ValueError("command must be a non-empty argument list")
        workspace_path = Path(workspace).resolve(strict=True)
        if not workspace_path.is_dir():
            raise ValueError(f"Workspace is not a directory: {workspace_path}")

        timeout = self.config.timeout if timeout_seconds is None else timeout_seconds
        if timeout < 1:
            raise ValueError("timeout_seconds must be at least one")

        started = time.monotonic()
        try:
            client = self._docker_client()
        except SandboxInfrastructureError as error:
            raise SandboxInfrastructureError(
                str(error),
                command=command,
                duration_seconds=time.monotonic() - started,
            ) from error
        container = None
        operation_error: Exception | None = None
        timed_out = False
        exit_code: int | None = None
        stdout = ""
        stderr = ""
        try:
            client.images.get(image)
            container = client.containers.create(
                image=image,
                command=command,
                detach=True,
                working_dir=_CONTAINER_WORKSPACE,
                user=_non_root_user(),
                network_mode="none",
                mem_limit=_MEMORY_LIMIT,
                memswap_limit=_MEMORY_LIMIT,
                nano_cpus=_CPU_LIMIT_NANO_CPUS,
                pids_limit=64,
                read_only=True,
                cap_drop=["ALL"],
                security_opt=["no-new-privileges:true"],
                tmpfs={"/tmp": _TEMP_FILESYSTEM},
                volumes={
                    str(workspace_path): {
                        "bind": _CONTAINER_WORKSPACE,
                        "mode": "rw",
                    }
                },
            )
            container.start()
            try:
                response = container.wait(timeout=timeout)
                exit_code = int(response["StatusCode"])
            except requests.exceptions.ReadTimeout:
                timed_out = True
                container.kill()
            stdout = _collect_logs(container, stdout=True, stderr=False)
            stderr = _collect_logs(container, stdout=False, stderr=True)
        except (
            docker.errors.DockerException,
            requests.exceptions.RequestException,
            KeyError,
        ) as error:
            operation_error = SandboxInfrastructureError(
                f"Docker command failed for image {image!r}: {error}",
                command=command,
                duration_seconds=time.monotonic() - started,
            )
        finally:
            if container is not None:
                try:
                    container.remove(force=True)
                except (
                    docker.errors.DockerException,
                    requests.exceptions.RequestException,
                ) as error:
                    if operation_error is None:
                        operation_error = SandboxInfrastructureError(
                            f"Unable to remove sandbox container: {error}",
                            command=command,
                            duration_seconds=time.monotonic() - started,
                        )

        if operation_error is not None:
            raise operation_error

        return ContainerResult(
            command=command,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=time.monotonic() - started,
            timed_out=timed_out,
        )


def _collect_logs(container: Any, stdout: bool, stderr: bool) -> str:
    chunks: list[bytes] = []
    collected = 0
    truncated = False
    for chunk in container.logs(stdout=stdout, stderr=stderr, stream=True):
        remaining = _MAX_LOG_BYTES - collected
        if remaining <= 0:
            truncated = True
            break
        chunks.append(chunk[:remaining])
        collected += min(len(chunk), remaining)
        if len(chunk) > remaining:
            truncated = True
            break
    output = b"".join(chunks).decode("utf-8", errors="replace")
    if truncated:
        output += "\n...[sandbox log truncated at 1 MiB]"
    return output


def _non_root_user() -> str:
    uid = getattr(os, "getuid", lambda: 65532)()
    gid = getattr(os, "getgid", lambda: 65532)()
    if uid == 0:
        return "65532:65532"
    return f"{uid}:{gid}"
