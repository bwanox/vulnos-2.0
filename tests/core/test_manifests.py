"""Tests for dependency manifest parsing (Dev 1)."""

from __future__ import annotations

import json
from pathlib import Path

from vulnos.core.manifests import (
    parse_package_json,
    parse_pyproject_toml,
    parse_requirements_txt,
    scan_manifests,
)

FIXTURE = Path(__file__).resolve().parents[2] / "examples" / "vulnerable_app"


def test_parse_requirements_txt():
    deps = parse_requirements_txt(FIXTURE / "requirements.txt")
    by_pkg = {d.package: d.version for d in deps}
    assert by_pkg["flask"] == "3.0.0"
    assert by_pkg["some-vulnerable-pkg"] == "1.2.3"
    assert by_pkg["another-pkg"] == "2.0.0"
    assert all(d.manifest_file == "requirements.txt" for d in deps)


def test_scan_manifests_collects_requirements():
    deps = scan_manifests(FIXTURE)
    packages = {d.package for d in deps}
    assert "flask" in packages
    assert "some-vulnerable-pkg" in packages
    assert all(isinstance(d.package, str) for d in deps)


def test_parse_pyproject_toml(tmp_path):
    content = {
        "project": {
            "dependencies": ["requests>=2.31.0", "rich==13.0.0"],
        },
        "tool": {
            "poetry": {
                "dependencies": {
                    "python": "^3.11",
                    "pytest": "^8.0",
                    "html5lib": {"version": "1.1"},
                }
            }
        },
    }
    path = tmp_path / "pyproject.toml"
    path.write_text(
        '[project]\ndependencies = ["requests>=2.31.0", "rich==13.0.0"]\n\n'
        '[tool.poetry.dependencies]\npython = "^3.11"\npytest = "^8.0"\n[tool.poetry.dependencies.html5lib]\nversion = "1.1"\n',
        encoding="utf-8",
    )
    deps = parse_pyproject_toml(path)
    by_pkg = {d.package: d.version for d in deps}
    assert by_pkg["requests"] == "2.31.0"
    assert by_pkg["rich"] == "13.0.0"
    assert by_pkg["pytest"] == "^8.0"
    assert by_pkg["html5lib"] == "1.1"
    assert "python" not in by_pkg


def test_parse_package_json(tmp_path):
    path = tmp_path / "package.json"
    path.write_text(
        json.dumps(
            {
                "dependencies": {"express": "4.18.0", "lodash": "^4.17.0"},
                "devDependencies": {"pytest": "8.0.0"},
            }
        ),
        encoding="utf-8",
    )
    deps = parse_package_json(path)
    by_pkg = {d.package: d.version for d in deps}
    assert by_pkg["express"] == "4.18.0"
    assert by_pkg["lodash"] == "^4.17.0"
    assert by_pkg["pytest"] == "8.0.0"
    assert all(d.manifest_file == "package.json" for d in deps)


def test_scan_manifests_sorted_deterministic(tmp_path):
    (tmp_path / "requirements.txt").write_text("zeta==1.0\nalpha==2.0\n", encoding="utf-8")
    deps = scan_manifests(tmp_path)
    packages = [d.package for d in deps]
    assert packages == sorted(packages)
