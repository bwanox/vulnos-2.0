"""Dependency manifest parsing into a list of ``(package, version)`` tuples.

Parses ``requirements.txt``, ``pyproject.toml`` and ``package.json`` into
:class:`~vulnos.core.contracts.Dependency` records for the Tavily CVE step.

Fully deterministic and offline — no network, no external tools.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from typing import Iterable

from vulnos.core.contracts import Dependency

# Requirement specifiers: package[extras]==version ; marker
_REQ_SPLIT = re.compile(r"(==|>=|<=|~=|!=|>|<|===)")
_MARKER_SPLIT = re.compile(r"\s*;\s*")
_EXTRAS_SPLIT = re.compile(r"\s*\[[^\]]*\]")


def _clean_package(name: str) -> str:
    """Strip extras and surrounding whitespace from a package name."""
    name = _EXTRAS_SPLIT.sub("", name).strip()
    return name


def _parse_requirement_line(line: str) -> tuple[str, str | None]:
    """Parse a single requirements-style line into ``(package, version)``.

    Handles ``pkg==1.2.3``, ``pkg>=1.0``, ``pkg[extra]==1.2; python>='3'``,
    and bare ``pkg`` (version = None).
    """
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("-"):
        return "", None

    # Drop environment markers.
    line = _MARKER_SPLIT.split(line, maxsplit=1)[0]

    parts = _REQ_SPLIT.split(line, maxsplit=1)
    package = _clean_package(parts[0])

    version: str | None = None
    if len(parts) == 3:
        version = parts[2].strip().strip('"').strip("'")

    return package, version


def parse_requirements_txt(path: str | Path) -> list[Dependency]:
    """Parse a ``requirements.txt`` file into ``Dependency`` records."""
    path = Path(path)
    deps: list[Dependency] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        package, version = _parse_requirement_line(line)
        if package:
            deps.append(
                Dependency(package=package, version=version, manifest_file=path.name)
            )
    return deps


def _flatten_dependency_spec(spec: str) -> tuple[str, str | None]:
    """Flatten a PEP 508 dependency string into ``(package, version)``."""
    package, version = _parse_requirement_line(spec)
    return package, version


def parse_pyproject_toml(path: str | Path) -> list[Dependency]:
    """Parse a ``pyproject.toml`` into ``Dependency`` records.

    Reads ``[project] dependencies`` (PEP 621) and, as a fallback,
    ``[tool.poetry] dependencies``.
    """
    path = Path(path)
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    deps: list[Dependency] = []

    for spec in data.get("project", {}).get("dependencies", []):
        package, version = _flatten_dependency_spec(spec)
        if package:
            deps.append(
                Dependency(package=package, version=version, manifest_file=path.name)
            )

    # Poetry fallback: [tool.poetry.dependencies] (exclude "python" key).
    # The dict key is the package name; the value is a version spec string or
    # a table like {version = "1.1"}.
    poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    for package, value in poetry.items():
        if package == "python":
            continue
        version: str | None = None
        if isinstance(value, str):
            version = value
        elif isinstance(value, dict):
            version = value.get("version")
        if package:
            deps.append(
                Dependency(package=package, version=version, manifest_file=path.name)
            )

    return deps


def parse_package_json(path: str | Path) -> list[Dependency]:
    """Parse a ``package.json`` into ``Dependency`` records.

    Reads ``dependencies`` and ``devDependencies``.
    """
    path = Path(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    deps: list[Dependency] = []
    for section in ("dependencies", "devDependencies"):
        for package, version in data.get(section, {}).items():
            deps.append(
                Dependency(package=package, version=str(version), manifest_file=path.name)
            )
    return deps


_MANIFEST_PARSERS = {
    "requirements.txt": parse_requirements_txt,
    "pyproject.toml": parse_pyproject_toml,
    "package.json": parse_package_json,
}


def parse_manifest(path: str | Path) -> list[Dependency]:
    """Parse a single manifest file by its name."""
    path = Path(path)
    parser = _MANIFEST_PARSERS.get(path.name)
    if parser is None:
        return []
    return parser(path)


def scan_manifests(repo_path: str | Path) -> list[Dependency]:
    """Find and parse every supported manifest under ``repo_path``.

    Results are sorted deterministically by (manifest_file, package).
    """
    repo = Path(repo_path)
    deps: list[Dependency] = []
    if not repo.exists():
        return deps

    for manifest_name in _MANIFEST_PARSERS:
        for path in sorted(repo.rglob(manifest_name)):
            deps.extend(parse_manifest(path))

    deps.sort(key=lambda d: (d.manifest_file, d.package))
    return deps
