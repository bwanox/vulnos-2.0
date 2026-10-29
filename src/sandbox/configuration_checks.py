"""Read-only checks for project configuration exposure and file permissions."""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Iterator
from itertools import islice
from pathlib import Path

from pydantic import BaseModel

_CONFIG_SUFFIXES = {".conf", ".cfg", ".ini", ".json", ".toml", ".yaml", ".yml"}
_CONFIG_NAMES = {".env", ".env.local", "config"}
_SECRET_PATTERN = re.compile(
    r"(?i)(?:^|[\s_])[A-Za-z0-9_-]*(?:password|passwd|secret|api[_-]?key|access[_-]?token)"
    r"\b\s*[:=]\s*['\"]?[^'\"\s]{6,}"
)


class ConfigurationFinding(BaseModel):
    """A configuration indicator without copying potentially sensitive values."""

    rule_id: str
    file_path: str
    line: int | None = None
    message: str


def check_project_configuration(source_path: str | Path) -> list[ConfigurationFinding]:
    """Check selected config files for likely hard-coded secrets and writable modes."""
    root = Path(source_path).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError(f"Configuration scan path is not a directory: {root}")

    config_files = list(islice(_configuration_files(root), 2001))
    findings: list[ConfigurationFinding] = []
    for file_path in config_files[:2000]:
        relative = file_path.relative_to(root).as_posix()
        try:
            mode = file_path.stat().st_mode
            if _supports_posix_permissions() and mode & stat.S_IWOTH:
                findings.append(
                    ConfigurationFinding(
                        rule_id="world_writable_configuration",
                        file_path=relative,
                        message="Configuration file is world-writable.",
                    )
                )
            content = file_path.read_text(encoding="utf-8", errors="replace")[:250_000]
        except OSError as error:
            raise OSError(f"Unable to inspect configuration file {relative}: {error}") from error
        for line_number, line in enumerate(content.splitlines(), start=1):
            if _SECRET_PATTERN.search(line):
                findings.append(
                    ConfigurationFinding(
                        rule_id="possible_hard_coded_secret",
                        file_path=relative,
                        line=line_number,
                        message=(
                            "Configuration contains a value that resembles a hard-coded secret."
                        ),
                    )
                )

    if len(config_files) > 2000:
        findings.append(
            ConfigurationFinding(
                rule_id="scan_limit",
                file_path=".",
                message="Configuration scan stopped after the 2,000-file limit.",
            )
        )
    return findings


def _configuration_files(root: Path) -> Iterator[Path]:
    for current, directory_names, file_names in os.walk(
        root,
        followlinks=False,
        onerror=_raise_walk_error,
    ):
        current_path = Path(current)
        directory_names[:] = sorted(
            name
            for name in directory_names
            if name not in {".git", ".venv", "node_modules", "venv", "build", "dist"}
            and not (current_path / name).is_symlink()
        )
        for name in sorted(file_names):
            file_path = current_path / name
            if file_path.is_symlink() or not (
                name in _CONFIG_NAMES or file_path.suffix.lower() in _CONFIG_SUFFIXES
            ):
                continue
            yield file_path


def _raise_walk_error(error: OSError) -> None:
    raise error


def _supports_posix_permissions() -> bool:
    return os.name != "nt"
