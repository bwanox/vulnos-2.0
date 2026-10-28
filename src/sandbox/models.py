"""Public request and execution-result models for sandbox verification."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, field_validator

from src.common.models import ExploitTest, PatchDiff


class VerificationRequest(BaseModel):
    """Inputs required to verify a patch using a trusted local Docker image."""

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


class WorkspacePair(BaseModel):
    """Disposable source copies used for original and patched verification."""

    original_path: Path
    patched_path: Path
    root_path: Path

    model_config = {"arbitrary_types_allowed": True}
