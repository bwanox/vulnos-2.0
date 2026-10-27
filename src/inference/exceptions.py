"""Module-specific exceptions for VulnOS 2.0 inference engine."""

from __future__ import annotations

from typing import Any


class InferenceError(Exception):
    """Base exception for all inference and threat intelligence errors."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ConfigError(InferenceError):
    """Raised when configuration or API keys are missing or invalid."""

    pass


class ModelResponseError(InferenceError):
    """Raised when an LLM response cannot be parsed or validated."""

    pass


class ThreatIntelError(InferenceError):
    """Raised when Tavily search or extraction fails."""

    pass
