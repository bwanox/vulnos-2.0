"""Trusted language adapters and predefined sandbox execution profiles."""

from __future__ import annotations

import re
import shutil
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator

from src.sandbox.discovery import ProjectDiscoveryReport

_PROFILE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{1,63}$")
_SHELL_LAUNCHERS = {"sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "pwsh"}


class ExecutionProfile(BaseModel):
    """Reviewed build/test recipe; commands are never supplied by a model."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    profile_id: str
    target_kind: str = "source_project"
    languages: tuple[str, ...]
    toolchain: str
    test_language: str
    runtime_image: str
    required_build_files: tuple[str, ...]
    build_commands: tuple[tuple[str, ...], ...] = ()
    test_commands: tuple[tuple[str, ...], ...]
    test_framework: str
    expected_behavior: str = "baseline_and_patched_commands_exit_zero"
    timeout_seconds: int = Field(default=120, ge=1, le=300)
    memory_limit: Literal["512m"] = "512m"
    cpu_limit: Literal[1] = 1
    process_limit: Literal[64] = 64
    supported: bool = True

    @computed_field
    @property
    def build_profile_id(self) -> str:
        return f"{self.profile_id}-build"

    @computed_field
    @property
    def test_profile_id(self) -> str:
        return f"{self.profile_id}-test"

    @field_validator("profile_id")
    @classmethod
    def validate_profile_id(cls, value: str) -> str:
        if not _PROFILE_ID.fullmatch(value):
            raise ValueError("profile_id must be a lowercase registry identifier")
        return value

    @field_validator("runtime_image")
    @classmethod
    def validate_runtime_image(cls, value: str) -> str:
        if not value or any(char.isspace() for char in value) or "://" in value:
            raise ValueError("runtime_image must be a registry image reference")
        return value

    @field_validator("build_commands", "test_commands")
    @classmethod
    def validate_commands(
        cls, commands: tuple[tuple[str, ...], ...]
    ) -> tuple[tuple[str, ...], ...]:
        for command in commands:
            if not command or any(not item for item in command):
                raise ValueError("profile commands must be non-empty argument vectors")
            if command[0].lower() in _SHELL_LAUNCHERS:
                raise ValueError("shell launcher commands are not permitted in profiles")
            if any(
                "\x00" in item
                or item in {"-v", "--volume", "--mount"}
                or "docker.sock" in item.lower()
                for item in command
            ):
                raise ValueError("profile contains a prohibited command argument")
        return commands

    @field_validator("test_commands")
    @classmethod
    def require_test_commands(
        cls, commands: tuple[tuple[str, ...], ...]
    ) -> tuple[tuple[str, ...], ...]:
        if not commands:
            raise ValueError("a profile must define at least one test command")
        return commands


class LanguageAdapter(Protocol):
    """Interface implemented by profile providers for one or more languages."""

    @property
    def name(self) -> str: ...

    def profile_ids(self, report: ProjectDiscoveryReport) -> Iterable[str]: ...


@dataclass(frozen=True)
class ManifestLanguageAdapter:
    """Associates known project evidence with registry-owned profile IDs."""

    name: str
    languages: tuple[str, ...]
    manifest_to_profile: tuple[tuple[str, str], ...]
    source_to_profile: tuple[tuple[str, str], ...] = ()

    def profile_ids(self, report: ProjectDiscoveryReport) -> Iterable[str]:
        language_evidence = {language.name: language.evidence for language in report.languages}
        adapter_languages = set(self.languages)
        if not adapter_languages.intersection(language_evidence):
            return ()
        root_manifests = {
            path for path in report.build_files if "/" not in path and "\\" not in path
        }
        selected: list[str] = []
        for manifest, profile_id in self.manifest_to_profile:
            if manifest not in root_manifests:
                continue
            if profile_id not in selected:
                selected.append(profile_id)

        for language, profile_id in self.source_to_profile:
            evidence = language_evidence.get(language, ())
            if language in adapter_languages and any(
                item.startswith("source:") for item in evidence
            ):
                if profile_id not in selected:
                    selected.append(profile_id)
        return tuple(selected)


class ExecutionProfileRegistry:
    """Resolves profile IDs and adapters from application-owned definitions."""

    def __init__(
        self,
        profiles: Iterable[ExecutionProfile],
        adapters: Iterable[LanguageAdapter],
    ) -> None:
        self._profiles: dict[str, ExecutionProfile] = {}
        self._adapters: dict[str, LanguageAdapter] = {}
        for profile in profiles:
            if profile.profile_id in self._profiles:
                raise ValueError(f"Duplicate execution profile: {profile.profile_id}")
            self._profiles[profile.profile_id] = profile
        for adapter in adapters:
            if adapter.name in self._adapters:
                raise ValueError(f"Duplicate language adapter: {adapter.name}")
            self._adapters[adapter.name] = adapter
        if not self._profiles:
            raise ValueError("at least one execution profile is required")

    def get(self, profile_id: str) -> ExecutionProfile:
        try:
            profile = self._profiles[profile_id]
        except KeyError as error:
            raise ValueError(f"Unsupported execution profile: {profile_id}") from error
        if not profile.supported:
            raise ValueError(f"Execution profile is not supported: {profile_id}")
        return profile

    def register_profile(self, profile: ExecutionProfile) -> None:
        """Add a reviewed profile from application code, rejecting ID replacement."""
        if profile.profile_id in self._profiles:
            raise ValueError(f"Execution profile already exists: {profile.profile_id}")
        self._profiles[profile.profile_id] = profile

    def register_adapter(self, adapter: LanguageAdapter) -> None:
        """Register an application-owned adapter implementation."""
        if adapter.name in self._adapters:
            raise ValueError(f"Language adapter already exists: {adapter.name}")
        self._adapters[adapter.name] = adapter

    def available_for(self, report: ProjectDiscoveryReport) -> list[str]:
        selected: set[str] = set()
        for adapter in self._adapters.values():
            selected.update(adapter.profile_ids(report))
        return sorted(
            profile_id
            for profile_id in selected
            if profile_id in self._profiles and self._profiles[profile_id].supported
        )

    def validate_for(self, profile_id: str, report: ProjectDiscoveryReport) -> ExecutionProfile:
        profile = self.get(profile_id)
        if profile_id not in self.available_for(report):
            raise ValueError(
                f"Profile {profile_id!r} does not match the discovered project manifests"
            )
        root_manifests = {
            path for path in report.build_files if "/" not in path and "\\" not in path
        }
        if profile.required_build_files and not any(
            required in root_manifests for required in profile.required_build_files
        ):
            raise ValueError(
                f"Profile {profile_id!r} requires one of these root build files: "
                f"{', '.join(profile.required_build_files)}"
            )
        nested_profile_manifests = [
            path
            for path in report.build_files
            if ("/" in path or "\\" in path) and Path(path).name in profile.required_build_files
        ]
        if nested_profile_manifests:
            raise ValueError(
                f"Profile {profile_id!r} has nested build manifests that are not run from "
                f"the workspace root: {', '.join(nested_profile_manifests)}"
            )
        detected = {language.name for language in report.languages}
        if not detected.intersection(profile.languages):
            raise ValueError(
                f"Profile {profile_id!r} does not support detected languages: "
                f"{', '.join(sorted(detected)) or 'none'}"
            )
        return profile

    @property
    def profiles(self) -> tuple[ExecutionProfile, ...]:
        return tuple(self._profiles[key] for key in sorted(self._profiles))


def missing_host_tools(profile: ExecutionProfile) -> list[str]:
    """Report profile executables absent from the host PATH (not the container)."""
    commands = profile.build_commands + profile.test_commands
    missing = {command[0] for command in commands if shutil.which(command[0]) is None}
    return sorted(missing)


def default_profile_registry() -> ExecutionProfileRegistry:
    """Create the built-in, reviewed profile and adapter registry."""
    profiles = [
        ExecutionProfile(
            profile_id="python-pytest",
            languages=("Python",),
            toolchain="Python 3.12",
            test_language="Python",
            runtime_image="vulnos/python:3.12",
            required_build_files=(),
            build_commands=(("python", "-m", "compileall", "-q", "."),),
            test_commands=(("python", "-m", "pytest", "-q"),),
            test_framework="pytest",
        ),
        ExecutionProfile(
            profile_id="cpp-cmake",
            languages=("C", "C++"),
            toolchain="CMake and C/C++ compiler",
            test_language="C/C++ via CTest",
            runtime_image="vulnos/cpp:stable",
            required_build_files=("CMakeLists.txt",),
            build_commands=(
                ("cmake", "-S", ".", "-B", "build"),
                ("cmake", "--build", "build", "--parallel", "1"),
            ),
            test_commands=(("ctest", "--test-dir", "build", "--output-on-failure"),),
            test_framework="CTest",
        ),
        ExecutionProfile(
            profile_id="cpp-make",
            languages=("C", "C++"),
            toolchain="Make and C/C++ compiler",
            test_language="C/C++ via Make test target",
            runtime_image="vulnos/cpp:stable",
            required_build_files=("Makefile", "makefile", "GNUmakefile"),
            build_commands=(("make", "--jobs=1"),),
            test_commands=(("make", "test"),),
            test_framework="Make test target",
        ),
        ExecutionProfile(
            profile_id="java-maven",
            languages=("Java",),
            toolchain="JDK 21 and Maven",
            test_language="Java",
            runtime_image="vulnos/java:21",
            required_build_files=("pom.xml",),
            build_commands=(("mvn", "-B", "-DskipTests", "package"),),
            test_commands=(("mvn", "-B", "test"),),
            test_framework="JUnit via Maven",
        ),
        ExecutionProfile(
            profile_id="java-gradle",
            languages=("Java",),
            toolchain="JDK 21 and Gradle",
            test_language="Java",
            runtime_image="vulnos/java:21",
            required_build_files=("build.gradle", "build.gradle.kts"),
            build_commands=(("gradle", "--no-daemon", "assemble"),),
            test_commands=(("gradle", "--no-daemon", "test"),),
            test_framework="JUnit via Gradle",
        ),
        ExecutionProfile(
            profile_id="javascript-npm",
            languages=("JavaScript", "TypeScript"),
            toolchain="Node.js 22 and npm",
            test_language="JavaScript/TypeScript",
            runtime_image="vulnos/node:22",
            required_build_files=("package.json",),
            build_commands=(
                ("npm", "install", "--offline", "--ignore-scripts"),
                ("npm", "run", "build", "--if-present"),
            ),
            test_commands=(("npm", "test", "--", "--watch=false"),),
            test_framework="npm-configured test runner",
        ),
    ]
    adapters = [
        ManifestLanguageAdapter(
            name="python",
            languages=("Python",),
            manifest_to_profile=(
                ("pyproject.toml", "python-pytest"),
                ("requirements.txt", "python-pytest"),
            ),
            source_to_profile=(("Python", "python-pytest"),),
        ),
        ManifestLanguageAdapter(
            name="c-cpp",
            languages=("C", "C++"),
            manifest_to_profile=(
                ("CMakeLists.txt", "cpp-cmake"),
                ("Makefile", "cpp-make"),
                ("makefile", "cpp-make"),
                ("GNUmakefile", "cpp-make"),
            ),
        ),
        ManifestLanguageAdapter(
            name="java",
            languages=("Java",),
            manifest_to_profile=(
                ("pom.xml", "java-maven"),
                ("build.gradle", "java-gradle"),
                ("build.gradle.kts", "java-gradle"),
            ),
        ),
        ManifestLanguageAdapter(
            name="javascript-typescript",
            languages=("JavaScript", "TypeScript"),
            manifest_to_profile=(("package.json", "javascript-npm"),),
        ),
    ]
    return ExecutionProfileRegistry(profiles, adapters)


DEFAULT_PROFILE_REGISTRY = default_profile_registry()
