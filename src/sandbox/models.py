"""Public request and execution-result models for sandbox verification."""

from __future__ import annotations

import uuid
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from src.common.models import ExploitTest, PatchDiff


class SandboxExecutionRequest(BaseModel):
    """Request one command selected from a trusted profile."""

    model_config = ConfigDict(extra="forbid")

    target_id: str
    profile_id: str
    operation: Literal["build", "test"]
    command_index: int = Field(default=0, ge=0)
    working_directory: str = "."
    timeout_seconds: int | None = Field(default=None, ge=1, le=600)

    @field_validator("target_id", "profile_id")
    @classmethod
    def validate_registry_ids(cls, value: str) -> str:
        if not value or value.strip() != value or any(char.isspace() for char in value):
            raise ValueError("target_id and profile_id must be registry identifiers")
        return value

    @field_validator("working_directory")
    @classmethod
    def validate_working_directory(cls, value: str) -> str:
        candidate = PurePosixPath(value)
        if (
            not value
            or "\\" in value
            or candidate.is_absolute()
            or any(part == ".." for part in candidate.parts)
        ):
            raise ValueError("working_directory must remain inside the project workspace")
        return value


class ControlledVerificationRequest(BaseModel):
    """Request a registered build/test profile against a previously approved target."""

    model_config = ConfigDict(extra="forbid")

    target_id: str
    profile_id: str
    patch: PatchDiff
    exploit: ExploitTest | None = None
    timeout_seconds: int | None = Field(default=None, ge=1, le=600)

    @field_validator("target_id", "profile_id")
    @classmethod
    def validate_registry_ids(cls, value: str) -> str:
        if not value or value.strip() != value or any(char.isspace() for char in value):
            raise ValueError("target_id and profile_id must be registry identifiers")
        return value


class ApprovedProjectRegistry:
    """In-memory registry for project paths explicitly approved by the caller."""

    def __init__(self) -> None:
        self._projects: dict[str, Path] = {}

    def approve_project(self, source_path: str | Path) -> str:
        """Register a project after an explicit authorization decision by the caller."""
        path = Path(source_path).expanduser().resolve(strict=True)
        if not path.is_dir():
            raise ValueError(f"Approved project path is not a directory: {path}")
        if path == Path(path.anchor):
            raise ValueError("A filesystem root cannot be registered as a project")
        target_id = uuid.uuid4().hex
        self._projects[target_id] = path
        return target_id

    def resolve(self, target_id: str) -> Path:
        """Resolve only a previously registered target identifier."""
        try:
            path = self._projects[target_id]
        except KeyError as error:
            raise ValueError("Target is not registered as explicitly approved") from error
        if not path.is_dir():
            raise ValueError("Approved project is no longer available")
        if path.is_symlink() or path.resolve(strict=True) != path:
            raise ValueError("Approved project path changed after registration")
        return path


class VerificationRequest(BaseModel):
    """Legacy exploit payload retained for compatibility; execution is disabled."""

    source_path: Path
    exploit: ExploitTest
    patch: PatchDiff
    image: str
    regression_command: list[str]
    exploit_command: list[str] | None = None
    timeout_seconds: int | None = None

    @field_validator("image")
    @classmethod
    def validate_image(cls, image: str) -> str:
        if not image.strip():
            raise ValueError("A trusted, prebuilt Docker image is required")
        return image.strip()

    @field_validator("regression_command")
    @classmethod
    def validate_regression_command(cls, command: list[str]) -> list[str]:
        if not command or any(not item for item in command):
            raise ValueError("regression_command must be a non-empty argument list")
        return command

    @field_validator("exploit_command")
    @classmethod
    def validate_exploit_command(cls, command: list[str] | None) -> list[str] | None:
        if command is not None and (not command or any(not item for item in command)):
            raise ValueError("exploit_command must be a non-empty argument list")
        return command

    @field_validator("timeout_seconds")
    @classmethod
    def validate_timeout(cls, timeout: int | None) -> int | None:
        if timeout is not None and timeout < 1:
            raise ValueError("timeout_seconds must be at least one")
        return timeout


class ContainerResult(BaseModel):
    """Result from executing one command in a disposable container."""

    command: list[str]
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    duration_seconds: float = 0.0
    timed_out: bool = False


class SandboxExecutionResult(BaseModel):
    """Execution evidence only; it does not interpret security outcomes."""

    request_id: str
    status: Literal["completed", "timed_out", "execution_error"]
    target_id: str
    profile_id: str
    operation: Literal["build", "test"]
    runtime_image: str | None = None
    toolchain: str | None = None
    command: list[str] = Field(default_factory=list)
    process_started: bool = False
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    duration_seconds: float = 0.0
    timed_out: bool = False
    setup_error: bool = False
    reason: str = ""


class WorkspacePair(BaseModel):
    """Disposable source copies used for original and patched verification."""

    original_path: Path
    patched_path: Path
    root_path: Path

    model_config = {"arbitrary_types_allowed": True}
