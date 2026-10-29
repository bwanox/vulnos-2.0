"""Read-only discovery of project languages and build manifests."""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, Field

_IGNORED_DIRECTORIES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "target",
    "venv",
}

_EXTENSION_LANGUAGES: dict[str, tuple[str, ...]] = {
    ".c": ("C",),
    ".h": ("C", "C++"),
    ".cc": ("C++",),
    ".cpp": ("C++",),
    ".cxx": ("C++",),
    ".hpp": ("C++",),
    ".hh": ("C++",),
    ".py": ("Python",),
    ".java": ("Java",),
    ".js": ("JavaScript",),
    ".jsx": ("JavaScript",),
    ".mjs": ("JavaScript",),
    ".cjs": ("JavaScript",),
    ".ts": ("TypeScript",),
    ".tsx": ("TypeScript",),
    ".go": ("Go",),
    ".rs": ("Rust",),
    ".cs": ("C#",),
    ".php": ("PHP",),
}

_MANIFEST_LANGUAGES: dict[str, tuple[str, ...]] = {
    "pyproject.toml": ("Python",),
    "requirements.txt": ("Python",),
    "pom.xml": ("Java",),
    "build.gradle": ("Java",),
    "build.gradle.kts": ("Java",),
    "settings.gradle": ("Java",),
    "settings.gradle.kts": ("Java",),
    "package.json": ("JavaScript", "TypeScript"),
    "go.mod": ("Go",),
    "Cargo.toml": ("Rust",),
    "composer.json": ("PHP",),
}
_BUILD_ONLY_MANIFESTS = {"CMakeLists.txt", "Makefile", "makefile", "GNUmakefile"}


class DetectedLanguage(BaseModel):
    """A detected project language and the evidence supporting it."""

    name: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)


class ProjectDiscoveryReport(BaseModel):
    """Language/build-system discovery without executing project content."""

    target_kind: str
    languages: list[DetectedLanguage] = Field(default_factory=list)
    build_files: list[str] = Field(default_factory=list)
    unsupported_components: list[str] = Field(default_factory=list)


def discover_project(source_path: str | Path) -> ProjectDiscoveryReport:
    """Detect known source types and manifests from regular files only."""
    root = Path(source_path).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError(f"Project path is not a directory: {root}")

    evidence: dict[str, set[str]] = {}
    build_files: set[str] = set()
    unsupported_files: set[str] = set()

    for current, directory_names, file_names in os.walk(
        root,
        followlinks=False,
        onerror=_raise_walk_error,
    ):
        current_path = Path(current)
        retained_directories = []
        for name in directory_names:
            directory = current_path / name
            if name in _IGNORED_DIRECTORIES:
                continue
            if directory.is_symlink():
                unsupported_files.add(_relative_path(root, directory))
                continue
            retained_directories.append(name)
        directory_names[:] = sorted(retained_directories)
        for file_name in sorted(file_names):
            file_path = current_path / file_name
            if file_path.is_symlink():
                unsupported_files.add(_relative_path(root, file_path))
                continue
            relative = _relative_path(root, file_path)
            languages = _MANIFEST_LANGUAGES.get(file_name, ())
            if file_name.endswith(".csproj") or file_name.endswith(".sln"):
                languages = ("C#",)
            if (
                languages
                or file_name in _BUILD_ONLY_MANIFESTS
                or file_name.endswith((".csproj", ".sln"))
            ):
                build_files.add(relative)
                for language in languages:
                    evidence.setdefault(language, set()).add(f"manifest:{relative}")

            extension_languages = _EXTENSION_LANGUAGES.get(file_path.suffix.lower(), ())
            if extension_languages:
                for language in extension_languages:
                    evidence.setdefault(language, set()).add(f"source:{relative}")
            elif file_path.suffix and file_path.suffix.lower() not in {
                ".md",
                ".txt",
                ".json",
                ".xml",
                ".toml",
                ".yaml",
                ".yml",
                ".ini",
                ".cfg",
                ".conf",
                ".lock",
            }:
                unsupported_files.add(relative)

    languages_report: list[DetectedLanguage] = []
    for name in sorted(evidence):
        language_evidence = sorted(evidence[name])
        confidence = (
            0.95 if any(item.startswith("manifest:") for item in language_evidence) else 0.75
        )
        if (
            name in {"C", "C++"}
            and all(
                item.endswith((".h",)) for item in language_evidence if item.startswith("source:")
            )
            and not any(item.startswith("manifest:") for item in language_evidence)
        ):
            confidence = 0.5
        languages_report.append(
            DetectedLanguage(name=name, confidence=confidence, evidence=language_evidence)
        )

    return ProjectDiscoveryReport(
        target_kind="source_project" if languages_report else "unknown",
        languages=languages_report,
        build_files=sorted(build_files),
        unsupported_components=sorted(unsupported_files),
    )


def _relative_path(root: Path, file_path: Path) -> str:
    return file_path.relative_to(root).as_posix()


def _raise_walk_error(error: OSError) -> None:
    raise error
