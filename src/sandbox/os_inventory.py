"""Read-only local OS and package inventory with explicit advisory matching."""

from __future__ import annotations

import platform
import re
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field


class OSIdentity(BaseModel):
    """Best-effort identity of the currently running local OS and kernel."""

    system: str
    release: str
    machine: str
    distribution: str = ""
    distribution_version: str = ""


class InstalledPackage(BaseModel):
    """Package version parsed from a local package database."""

    name: str
    version: str
    package_manager: str


class KnownAdvisory(BaseModel):
    """Trusted, caller-provided exact affected-version advisory record."""

    model_config = ConfigDict(extra="forbid")

    advisory_id: str
    package_name: str
    affected_versions: set[str] = Field(min_length=1)
    summary: str = ""


class AdvisoryMatch(BaseModel):
    advisory_id: str
    package_name: str
    installed_version: str
    summary: str = ""


class OSInventoryReport(BaseModel):
    """OS identity, available package inventory, and exact advisory matches."""

    identity: OSIdentity
    packages: list[InstalledPackage] = Field(default_factory=list)
    advisory_matches: list[AdvisoryMatch] = Field(default_factory=list)
    package_manager: str | None = None
    limitations: list[str] = Field(default_factory=list)


def identify_local_os(root: str | Path = "/") -> OSIdentity:
    """Identify the running OS/kernel and parse os-release when present."""
    root_path = Path(root).expanduser().resolve(strict=True)
    if not root_path.is_dir():
        raise ValueError(f"OS inventory root is not a directory: {root_path}")
    os_release = root_path / "etc" / "os-release"
    values: dict[str, str] = {}
    if os_release.is_file() and not os_release.is_symlink():
        for line in os_release.read_text(encoding="utf-8", errors="replace").splitlines():
            match = re.match(r"^([A-Z_]+)=(.*)$", line)
            if match:
                values[match.group(1)] = match.group(2).strip().strip('"')

    return OSIdentity(
        system=platform.system(),
        release=platform.release(),
        machine=platform.machine(),
        distribution=values.get("PRETTY_NAME", values.get("NAME", "")),
        distribution_version=values.get("VERSION_ID", ""),
    )


def parse_dpkg_status(status_path: str | Path) -> list[InstalledPackage]:
    """Read installed package records from a Debian-family dpkg status file."""
    path = Path(status_path)
    if not path.is_file() or path.is_symlink():
        return []
    content = path.read_text(encoding="utf-8", errors="replace")

    packages: list[InstalledPackage] = []
    for stanza in re.split(r"\n\s*\n", content):
        fields: dict[str, str] = {}
        for line in stanza.splitlines():
            if line and not line[0].isspace() and ": " in line:
                key, value = line.split(": ", 1)
                fields[key] = value
        if (
            fields.get("Status") == "install ok installed"
            and fields.get("Package")
            and fields.get("Version")
        ):
            packages.append(
                InstalledPackage(
                    name=fields["Package"],
                    version=fields["Version"],
                    package_manager="dpkg",
                )
            )
    return packages


def scan_local_os(
    root: str | Path = "/",
    advisories: list[KnownAdvisory] | None = None,
) -> OSInventoryReport:
    """Collect available local OS/package facts; matching is exact and offline."""
    root_path = Path(root).expanduser().resolve(strict=True)
    if not root_path.is_dir():
        raise ValueError(f"OS inventory root is not a directory: {root_path}")
    packages = parse_dpkg_status(root_path / "var" / "lib" / "dpkg" / "status")
    matches: list[AdvisoryMatch] = []
    package_versions = {(item.name.casefold(), item.version): item for item in packages}
    for advisory in advisories or []:
        for package_name, version in package_versions:
            if (
                package_name == advisory.package_name.casefold()
                and version in advisory.affected_versions
            ):
                matches.append(
                    AdvisoryMatch(
                        advisory_id=advisory.advisory_id,
                        package_name=advisory.package_name,
                        installed_version=version,
                        summary=advisory.summary,
                    )
                )
    limitations = [
        "Package inventory is available only for Debian dpkg databases in this implementation.",
        (
            "Advisory results use exact versions from caller-supplied records; "
            "no complete feed is bundled."
        ),
        "Container-based checks do not isolate the host kernel.",
    ]
    return OSInventoryReport(
        identity=identify_local_os(root_path),
        packages=packages,
        advisory_matches=matches,
        package_manager="dpkg" if (root_path / "var/lib/dpkg/status").is_file() else None,
        limitations=limitations,
    )
