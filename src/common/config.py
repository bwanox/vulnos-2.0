"""Configuration management for VulnOS 2.0."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from dotenv import load_dotenv


@dataclass
class NebisConfig:
    """Nebius Token Factory configuration."""

    api_key: str = ""
    api_base: str = "https://api.tokenfactory.nebius.com/v1/"
    nano_model: str = "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B"
    ultra_model: str = "nvidia/Nemotron-3-Ultra-550b-a55b"


@dataclass
class TavilyConfig:
    """Tavily API configuration."""

    api_key: str = ""


@dataclass
class SandboxConfig:
    """Docker sandbox configuration."""

    memory_limit: str = "512m"
    cpu_limit: int = 1
    timeout: int = 120
    network_mode: str = "none"


@dataclass
class TelemetryConfig:
    """Telemetry HUD configuration."""

    port: int = 3000
    ws_port: int = 8765


@dataclass
class VulnOSConfig:
    """Top-level configuration."""

    nebius: NebisConfig = field(default_factory=NebisConfig)
    tavily: TavilyConfig = field(default_factory=TavilyConfig)
    sandbox: SandboxConfig = field(default_factory=SandboxConfig)
    telemetry: TelemetryConfig = field(default_factory=TelemetryConfig)
    github_token: str = ""
    log_level: str = "INFO"
    max_retries: int = 3


def load_config(env_file: str = ".env") -> VulnOSConfig:
    """Load configuration from environment variables."""
    load_dotenv(env_file)

    return VulnOSConfig(
        nebius=NebisConfig(
            api_key=os.getenv("NEBIUS_API_KEY", ""),
            api_base=os.getenv(
                "NEBIUS_API_BASE", "https://api.tokenfactory.nebius.com/v1/"
            ),
            nano_model=os.getenv(
                "NEMOTRON_NANO_MODEL", "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B"
            ),
            ultra_model=os.getenv(
                "NEMOTRON_ULTRA_MODEL", "nvidia/Nemotron-3-Ultra-550b-a55b"
            ),
        ),
        tavily=TavilyConfig(
            api_key=os.getenv("TAVILY_API_KEY", ""),
        ),
        sandbox=SandboxConfig(
            memory_limit=os.getenv("SANDBOX_MEMORY_LIMIT", "512m"),
            cpu_limit=int(os.getenv("SANDBOX_CPU_LIMIT", "1")),
            timeout=int(os.getenv("SANDBOX_TIMEOUT", "120")),
        ),
        telemetry=TelemetryConfig(
            port=int(os.getenv("TELEMETRY_PORT", "3000")),
            ws_port=int(os.getenv("TELEMETRY_WS_PORT", "8765")),
        ),
        github_token=os.getenv("GITHUB_TOKEN", ""),
        log_level=os.getenv("LOG_LEVEL", "INFO"),
    )
