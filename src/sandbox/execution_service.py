"""Stateless execution of one application-approved profile command."""

from __future__ import annotations

import time
import uuid

from src.common.config import SandboxConfig
from src.sandbox.adapters import DEFAULT_PROFILE_REGISTRY, ExecutionProfileRegistry
from src.sandbox.discovery import discover_project
from src.sandbox.docker_runner import DockerCommandRunner, SandboxInfrastructureError
from src.sandbox.models import (
    ApprovedProjectRegistry,
    SandboxExecutionRequest,
    SandboxExecutionResult,
)
from src.sandbox.workspace import temporary_workspace


class SandboxExecutor:
    """Run one trusted build or test command and return execution facts only."""

    def __init__(
        self,
        docker_runner: DockerCommandRunner,
        config: SandboxConfig,
        profile_registry: ExecutionProfileRegistry = DEFAULT_PROFILE_REGISTRY,
    ) -> None:
        self.docker_runner = docker_runner
        self.config = config
        self.profile_registry = profile_registry

    def execute(
        self,
        request: SandboxExecutionRequest,
        approved_projects: ApprovedProjectRegistry,
    ) -> SandboxExecutionResult:
        request_id = uuid.uuid4().hex
        started = time.monotonic()
        profile = None
        command: tuple[str, ...] = ()
        try:
            target_path = approved_projects.resolve(request.target_id)
            discovery = discover_project(target_path)
            profile = self.profile_registry.validate_for(request.profile_id, discovery)
            if profile.runtime_image not in self.config.approved_images:
                raise ValueError(
                    f"Runtime image {profile.runtime_image!r} is not approved by SandboxConfig"
                )
            commands = (
                profile.build_commands if request.operation == "build" else profile.test_commands
            )
            if request.command_index >= len(commands):
                raise ValueError(
                    f"Command index {request.command_index} is unavailable for "
                    f"{request.operation} profile {request.profile_id!r}"
                )
            command = commands[request.command_index]
            timeout = min(
                request.timeout_seconds or profile.timeout_seconds,
                profile.timeout_seconds,
                self.config.timeout,
            )
            if timeout < 1:
                raise ValueError("Configured sandbox timeout must be at least one second")

            with temporary_workspace(target_path) as workspace:
                result = self.docker_runner.run(
                    profile.runtime_image,
                    list(command),
                    workspace,
                    timeout,
                    request.working_directory,
                )
            return SandboxExecutionResult(
                request_id=request_id,
                status="timed_out" if result.timed_out else "completed",
                target_id=request.target_id,
                profile_id=profile.profile_id,
                operation=request.operation,
                runtime_image=profile.runtime_image,
                toolchain=profile.toolchain,
                command=result.command,
                process_started=True,
                exit_code=result.exit_code,
                stdout=result.stdout,
                stderr=result.stderr,
                duration_seconds=result.duration_seconds,
                timed_out=result.timed_out,
            )
        except SandboxInfrastructureError as error:
            return SandboxExecutionResult(
                request_id=request_id,
                status="timed_out" if error.timed_out else "execution_error",
                target_id=request.target_id,
                profile_id=request.profile_id,
                operation=request.operation,
                runtime_image=profile.runtime_image if profile else None,
                toolchain=profile.toolchain if profile else None,
                command=error.command or list(command),
                process_started=error.process_started,
                stdout=error.stdout,
                stderr=error.stderr,
                duration_seconds=error.duration_seconds,
                timed_out=error.timed_out,
                setup_error=not error.process_started,
                reason=str(error),
            )
        except (OSError, ValueError) as error:
            return SandboxExecutionResult(
                request_id=request_id,
                status="execution_error",
                target_id=request.target_id,
                profile_id=request.profile_id,
                operation=request.operation,
                runtime_image=profile.runtime_image if profile else None,
                toolchain=profile.toolchain if profile else None,
                command=list(command),
                duration_seconds=time.monotonic() - started,
                setup_error=True,
                reason=str(error),
            )
