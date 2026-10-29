"""Heuristic source and dependency-manifest analysis; no project code is executed."""

from __future__ import annotations

import json
import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from pydantic import BaseModel, Field

from src.sandbox.adapters import (
    DEFAULT_PROFILE_REGISTRY,
    ExecutionProfileRegistry,
    missing_host_tools,
)
from src.sandbox.discovery import ProjectDiscoveryReport, discover_project

_SKIP = {
    ".git",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "target",
    "venv",
}
_SOURCE_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hh",
    ".hpp",
    ".java",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".py",
    ".go",
    ".rs",
    ".cs",
    ".php",
}
_PATTERNS: dict[str, tuple[tuple[str, re.Pattern[str]], ...]] = {
    "Python": (
        ("dynamic_code_execution", re.compile(r"\b(?:eval|exec)\s*\(")),
        ("unsafe_deserialization", re.compile(r"\bpickle\.(?:loads|load)\s*\(")),
        ("shell_execution", re.compile(r"\bsubprocess\.\w+\s*\([^)]*shell\s*=\s*True")),
    ),
    "C": (
        ("unsafe_input_or_copy", re.compile(r"\b(?:gets|strcpy|strcat)\s*\(")),
        ("shell_execution", re.compile(r"\bsystem\s*\(")),
    ),
    "C++": (
        ("unsafe_input_or_copy", re.compile(r"\b(?:gets|strcpy|strcat)\s*\(")),
        ("shell_execution", re.compile(r"\bsystem\s*\(")),
    ),
    "Java": (("shell_execution", re.compile(r"Runtime\.getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(")),),
    "JavaScript": (
        ("dynamic_code_execution", re.compile(r"\beval\s*\(")),
        ("shell_execution", re.compile(r"\bchild_process\.(?:exec|execSync)\s*\(")),
    ),
    "TypeScript": (
        ("dynamic_code_execution", re.compile(r"\beval\s*\(")),
        ("shell_execution", re.compile(r"\bchild_process\.(?:exec|execSync)\s*\(")),
    ),
    "Go": (("shell_execution", re.compile(r"\bexec\.Command\s*\(")),),
    "Rust": (("shell_execution", re.compile(r"\bCommand::new\s*\(")),),
    "C#": (("shell_execution", re.compile(r"\bProcess\.Start\s*\(")),),
    "PHP": (
        ("dynamic_code_execution", re.compile(r"\beval\s*\(")),
        ("shell_execution", re.compile(r"\b(?:shell_exec|system|passthru)\s*\(")),
    ),
}


class DependencyRecord(BaseModel):
    """A dependency reference extracted from a source manifest."""

    name: str
    version_specifier: str = ""
    manifest_file: str


class StaticFinding(BaseModel):
    """A heuristic source indicator that requires human review."""

    rule_id: str
    file_path: str
    line: int
    message: str


class SourceAnalysisReport(BaseModel):
    """Read-only source/dependency results and suggested supported profiles."""

    discovery: ProjectDiscoveryReport
    dependencies: list[DependencyRecord] = Field(default_factory=list)
    findings: list[StaticFinding] = Field(default_factory=list)
    profile_ids: list[str] = Field(default_factory=list)
    unsupported_languages: list[str] = Field(default_factory=list)
    host_tool_warnings: dict[str, list[str]] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)


def analyze_project(
    source_path: str | Path,
    profile_registry: ExecutionProfileRegistry = DEFAULT_PROFILE_REGISTRY,
) -> SourceAnalysisReport:
    """Collect manifest dependencies and high-signal code patterns without execution."""
    root = Path(source_path).expanduser().resolve(strict=True)
    discovery = discover_project(root)
    dependencies: list[DependencyRecord] = []
    findings: list[StaticFinding] = []

    for relative in discovery.build_files:
        manifest = root / relative
        if manifest.is_file() and not manifest.is_symlink():
            dependencies.extend(_parse_manifest(root, manifest))

    language_by_suffix = {
        suffix: language
        for language, suffixes in {
            "C": {".c", ".h"},
            "C++": {".cc", ".cpp", ".cxx", ".hh", ".hpp"},
            "Python": {".py"},
            "Java": {".java"},
            "JavaScript": {".js", ".jsx", ".mjs", ".cjs"},
            "TypeScript": {".ts", ".tsx"},
            "Go": {".go"},
            "Rust": {".rs"},
            "C#": {".cs"},
            "PHP": {".php"},
        }.items()
        for suffix in suffixes
    }

    visited = 0
    for current, directory_names, file_names in os.walk(root, followlinks=False):
        current_path = Path(current)
        directory_names[:] = sorted(
            name
            for name in directory_names
            if name not in _SKIP and not (current_path / name).is_symlink()
        )
        for name in sorted(file_names):
            source = current_path / name
            if source.is_symlink() or source.suffix.lower() not in _SOURCE_SUFFIXES:
                continue
            visited += 1
            if visited > 5000:
                break
            language = language_by_suffix.get(source.suffix.lower())
            if language is None:
                continue
            try:
                text = source.read_text(encoding="utf-8", errors="replace")[:1_000_000]
            except OSError as error:
                raise OSError(f"Unable to read source file {source}: {error}") from error
            patterns = _PATTERNS.get(language, ())
            for line_number, line in enumerate(text.splitlines(), start=1):
                for rule_id, pattern in patterns:
                    if pattern.search(line):
                        findings.append(
                            StaticFinding(
                                rule_id=rule_id,
                                file_path=source.relative_to(root).as_posix(),
                                line=line_number,
                                message=(
                                    "Potentially security-sensitive API use; "
                                    "review context and validation."
                                ),
                            )
                        )
        if visited > 5000:
            break

    profile_ids = profile_registry.available_for(discovery)
    host_tool_warnings = {
        profile_id: missing
        for profile_id in profile_ids
        if (missing := missing_host_tools(profile_registry.get(profile_id)))
    }
    profiled_languages = {
        language
        for profile_id in profile_ids
        for language in profile_registry.get(profile_id).languages
    }
    detected_languages = {language.name for language in discovery.languages}
    unsupported_languages = sorted(detected_languages - profiled_languages)
    limitations = ["Heuristic source indicators are not proof of exploitability or safety."]
    if unsupported_languages:
        limitations.append(
            "No built-in execution profile is available for: " + ", ".join(unsupported_languages)
        )
    if host_tool_warnings:
        limitations.append(
            "Host PATH tool checks are advisory only; Docker images may provide different tools."
        )
    if visited > 5000:
        limitations.append("Source analysis stopped after the 5,000-file limit.")

    return SourceAnalysisReport(
        discovery=discovery,
        dependencies=dependencies,
        findings=findings,
        profile_ids=profile_ids,
        unsupported_languages=unsupported_languages,
        host_tool_warnings=host_tool_warnings,
        limitations=limitations,
    )


def _parse_manifest(root: Path, manifest: Path) -> list[DependencyRecord]:
    relative = manifest.relative_to(root).as_posix()
    name = manifest.name
    try:
        text = manifest.read_text(encoding="utf-8", errors="replace")[:1_000_000]
    except OSError as error:
        raise OSError(f"Unable to read dependency manifest {manifest}: {error}") from error

    if name == "requirements.txt":
        dependencies = []
        for line in text.splitlines():
            value = line.split("#", 1)[0].strip()
            match = re.match(r"^([A-Za-z0-9_.-]+)\s*(?:(==|===|~=|!=|<=|>=|<|>)\s*(.+))?$", value)
            if match:
                specifier = (match.group(2) or "") + (match.group(3) or "")
                dependencies.append(
                    DependencyRecord(
                        name=match.group(1), version_specifier=specifier, manifest_file=relative
                    )
                )
        return dependencies

    if name == "pyproject.toml":
        dependencies: list[DependencyRecord] = []
        for section in re.findall(
            r"(?ms)^\[(?:project|project\.optional-dependencies)\]\s*(.*?)(?=^\[|\Z)", text
        ):
            matches = re.findall(
                r"(?m)^\s*(?:dependencies|[A-Za-z0-9_-]+)\s*=\s*\[(.*?)\]", section
            )
            for block in matches:
                for requirement in re.findall(r'"([^"]+)"|\'([^\']+)\'', block):
                    value = next((part for part in requirement if part), "")
                    parsed = re.match(r"^([A-Za-z0-9_.-]+)\s*(.*)$", value)
                    if parsed:
                        dependencies.append(
                            DependencyRecord(
                                name=parsed.group(1),
                                version_specifier=parsed.group(2).strip(),
                                manifest_file=relative,
                            )
                        )
        return dependencies

    if name in {"package.json", "composer.json"}:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as error:
            raise ValueError(f"Invalid JSON dependency manifest {relative}: {error}") from error
        keys = (
            ("dependencies", "devDependencies")
            if name == "package.json"
            else ("require", "require-dev")
        )
        return [
            DependencyRecord(name=package, version_specifier=str(version), manifest_file=relative)
            for key in keys
            for package, version in (data.get(key, {}) or {}).items()
            if isinstance(package, str) and isinstance(version, (str, int, float))
        ]

    if name == "go.mod":
        return [
            DependencyRecord(name=module, version_specifier=version, manifest_file=relative)
            for module, version in re.findall(
                r"(?m)^\s*([A-Za-z0-9_./-]+)\s+(v[0-9][^\s]+)\s*$", text
            )
        ]

    if name == "Cargo.toml":
        dependencies: list[DependencyRecord] = []
        in_dependencies = False
        for line in text.splitlines():
            section = re.match(r"^\s*\[([^\]]+)\]\s*$", line)
            if section:
                in_dependencies = section.group(1) in {
                    "dependencies",
                    "dev-dependencies",
                    "build-dependencies",
                }
                continue
            if in_dependencies:
                entry = re.match(r'^\s*([A-Za-z0-9_-]+)\s*=\s*"([^"]+)"', line)
                if entry:
                    dependencies.append(
                        DependencyRecord(
                            name=entry.group(1),
                            version_specifier=entry.group(2),
                            manifest_file=relative,
                        )
                    )
        return dependencies

    if name == "pom.xml":
        try:
            document = ET.fromstring(text)
        except ET.ParseError as error:
            raise ValueError(f"Invalid XML dependency manifest {relative}: {error}") from error
        found: list[DependencyRecord] = []
        for dependency in document.iter():
            if dependency.tag.rsplit("}", 1)[-1] != "dependency":
                continue
            children = {child.tag.rsplit("}", 1)[-1]: child.text for child in dependency}
            if children.get("groupId") and children.get("artifactId"):
                found.append(
                    DependencyRecord(
                        name=f"{children['groupId']}:{children['artifactId']}",
                        version_specifier=children.get("version") or "",
                        manifest_file=relative,
                    )
                )
        return found

    if name.endswith(".csproj"):
        return [
            DependencyRecord(name=package, version_specifier=version, manifest_file=relative)
            for package, version in re.findall(
                r'<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"', text
            )
        ]

    return []
