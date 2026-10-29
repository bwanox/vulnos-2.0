"""Deterministic tests for read-only discovery and controlled profile verification."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from src.common.config import SandboxConfig
from src.common.models import PatchDiff, SandboxStatus
from src.sandbox.adapters import (
    DEFAULT_PROFILE_REGISTRY,
    ExecutionProfile,
    ExecutionProfileRegistry,
    ManifestLanguageAdapter,
)
from src.sandbox.configuration_checks import check_project_configuration
from src.sandbox.discovery import discover_project
from src.sandbox.docker_runner import DockerRunner, SandboxInfrastructureError
from src.sandbox.models import (
    ApprovedProjectRegistry,
    ContainerResult,
    ControlledVerificationRequest,
)
from src.sandbox.os_inventory import KnownAdvisory, scan_local_os
from src.sandbox.source_analysis import analyze_project
from src.sandbox.verifier import SandboxVerifier

_PATCH = PatchDiff(
    diff=("diff --git a/app.c b/app.c\n--- a/app.c\n+++ b/app.c\n@@ -1 +1 @@\n-old\n+new\n")
)


class FixtureRunner:
    def __init__(self, fail: str | None = None) -> None:
        self.fail = fail
        self.calls: list[tuple[str, list[str], Path, int | None]] = []

    def run(
        self,
        image: str,
        command: list[str],
        workspace: str | Path,
        timeout_seconds: int | None = None,
    ) -> ContainerResult:
        path = Path(workspace)
        self.calls.append((image, command, path, timeout_seconds))
        if command[0] == "git":
            return self._result(command, 0)
        patched = path.name == "patched"
        if command[0] == "python" and "compileall" in command:
            fail_build = self.fail == "build" or (self.fail == "patched_build" and patched)
            return self._result(command, 2 if fail_build else 0)
        if command[0] == "python" and "pytest" in command:
            if self.fail == "timeout" and not patched:
                return self._result(command, None, timed_out=True)
            if self.fail == "regression" and patched:
                return self._result(command, 1)
            return self._result(command, 0)
        if command[0] in {"cmake", "ctest"}:
            return self._result(command, 0)
        return self._result(command, 127)

    @staticmethod
    def _result(
        command: list[str],
        exit_code: int | None,
        timed_out: bool = False,
    ) -> ContainerResult:
        return ContainerResult(
            command=command,
            exit_code=exit_code,
            duration_seconds=0.01,
            timed_out=timed_out,
        )


def _controlled_request(target_id: str, profile_id: str) -> ControlledVerificationRequest:
    return ControlledVerificationRequest(
        target_id=target_id,
        profile_id=profile_id,
        patch=_PATCH,
    )


def _verify(source: Path, profile_id: str, runner: FixtureRunner) -> tuple[object, list[Path]]:
    registry = ApprovedProjectRegistry()
    target_id = registry.approve_project(source)
    verdict = SandboxVerifier(
        docker_runner=runner,
        config=SandboxConfig(),
    ).verify_controlled(_controlled_request(target_id, profile_id), registry)
    return verdict, [call[2] for call in runner.calls if call[1][0] != "git"]


def test_discovers_c_and_runs_registered_cmake_profile_without_python(tmp_path: Path) -> None:
    (tmp_path / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.15)\nproject(sample C CXX)\n",
        encoding="utf-8",
    )
    (tmp_path / "app.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    (tmp_path / "app.cpp").write_text("int main() { return 0; }\n", encoding="utf-8")
    runner = FixtureRunner()

    verdict, workspaces = _verify(tmp_path, "cpp-cmake", runner)

    assert verdict.status == SandboxStatus.TESTS_PASSED
    assert verdict.detected_languages == ["C", "C++"]
    assert verdict.security_verification_performed is False
    assert not verdict.exploit_triggers_on_unpatched
    assert [call[1][0] for call in runner.calls if call[1][0] != "git"] == [
        "cmake",
        "cmake",
        "ctest",
        "cmake",
        "cmake",
        "ctest",
    ]
    assert workspaces and all(not path.exists() for path in workspaces)
    assert (tmp_path / "app.c").read_text(encoding="utf-8") == "int main(void) { return 0; }\n"


def test_python_profile_and_mixed_language_discovery(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies = ["demo-lib==1.2.3"]\n', encoding="utf-8"
    )
    (tmp_path / "app.py").write_text("eval(user_input)\n", encoding="utf-8")
    (tmp_path / "native.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")

    report = analyze_project(tmp_path)
    verdict, _ = _verify(tmp_path, "python-pytest", FixtureRunner())

    assert {language.name for language in report.discovery.languages} == {"C", "Python"}
    assert "python-pytest" in report.profile_ids
    assert "C" in report.unsupported_languages
    assert [item.name for item in report.dependencies] == ["demo-lib"]
    assert report.findings[0].rule_id == "dynamic_code_execution"
    assert verdict.status == SandboxStatus.TESTS_PASSED
    assert verdict.detected_languages == ["C", "Python"]


def test_python_source_only_profile_selection_reads_language_evidence(
    tmp_path: Path,
) -> None:
    (tmp_path / "module.py").write_text("value = 1\n", encoding="utf-8")
    report = discover_project(tmp_path)

    assert DEFAULT_PROFILE_REGISTRY.available_for(report) == ["python-pytest"]
    profile = DEFAULT_PROFILE_REGISTRY.validate_for("python-pytest", report)
    assert profile.required_build_files == ()


def test_manifest_and_source_profiles_are_deduplicated_and_registry_filtered(
    tmp_path: Path,
) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname='fixture'\n", encoding="utf-8")
    (tmp_path / "module.py").write_text("value = 1\n", encoding="utf-8")
    report = discover_project(tmp_path)
    adapter = ManifestLanguageAdapter(
        name="python-duplicate",
        languages=("Python",),
        manifest_to_profile=(("pyproject.toml", "python-pytest"),),
        source_to_profile=(("Python", "python-pytest"),),
    )
    registry = ExecutionProfileRegistry(
        DEFAULT_PROFILE_REGISTRY.profiles,
        [adapter],
    )

    assert registry.available_for(report) == ["python-pytest"]


@pytest.mark.parametrize(
    ("manifest", "profile_id"),
    [
        ("pom.xml", "java-maven"),
        ("package.json", "javascript-npm"),
    ],
)
def test_java_and_javascript_adapters_are_registered(
    tmp_path: Path,
    manifest: str,
    profile_id: str,
) -> None:
    contents = "<project/>" if manifest == "pom.xml" else '{"scripts":{"test":"vitest"}}'
    (tmp_path / manifest).write_text(contents, encoding="utf-8")
    (tmp_path / ("App.java" if manifest == "pom.xml" else "app.ts")).write_text(
        "class App {}\n", encoding="utf-8"
    )

    report = discover_project(tmp_path)

    assert profile_id in DEFAULT_PROFILE_REGISTRY.available_for(report)
    profile = DEFAULT_PROFILE_REGISTRY.validate_for(profile_id, report)
    assert profile.runtime_image in SandboxConfig().approved_images
    assert profile.build_profile_id == f"{profile_id}-build"
    assert profile.test_profile_id == f"{profile_id}-test"


@pytest.mark.parametrize(
    ("manifest", "source", "language"),
    [
        ("go.mod", "main.go", "Go"),
        ("Cargo.toml", "main.rs", "Rust"),
        ("solution.sln", "Program.cs", "C#"),
        ("composer.json", "index.php", "PHP"),
    ],
)
def test_discovered_languages_without_approved_images_have_no_execution_profile(
    tmp_path: Path,
    manifest: str,
    source: str,
    language: str,
) -> None:
    (tmp_path / manifest).write_text("{}", encoding="utf-8")
    (tmp_path / source).write_text("source\n", encoding="utf-8")
    report = discover_project(tmp_path)

    assert language in {item.name for item in report.languages}
    assert DEFAULT_PROFILE_REGISTRY.available_for(report) == []


def test_nested_manifests_do_not_select_root_working_directory_profile(tmp_path: Path) -> None:
    nested = tmp_path / "service"
    nested.mkdir()
    (nested / "pom.xml").write_text("<project/>", encoding="utf-8")
    (nested / "App.java").write_text("class App {}\n", encoding="utf-8")
    report = discover_project(tmp_path)

    assert "java-maven" not in DEFAULT_PROFILE_REGISTRY.available_for(report)


def test_required_root_build_files_are_enforced(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text("<project/>", encoding="utf-8")
    report = discover_project(tmp_path)

    with pytest.raises(ValueError, match="does not match"):
        DEFAULT_PROFILE_REGISTRY.validate_for("java-gradle", report)


def test_build_failure_is_not_reported_as_patched_success(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname='fixture'\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("pass\n", encoding="utf-8")

    verdict, _ = _verify(tmp_path, "python-pytest", FixtureRunner(fail="build"))

    assert verdict.status == SandboxStatus.BUILD_FAILED
    assert verdict.failed_stage == "baseline_build"
    assert verdict.security_verification_performed is False


def test_patched_build_failure_is_not_treated_as_security_success(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname='fixture'\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("pass\n", encoding="utf-8")

    verdict, _ = _verify(tmp_path, "python-pytest", FixtureRunner(fail="patched_build"))

    assert verdict.status == SandboxStatus.BUILD_FAILED
    assert verdict.failed_stage == "patched_build"
    assert not verdict.verified


def test_timeout_is_inconclusive_and_regression_failure_is_not_verified(
    tmp_path: Path,
) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname='fixture'\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("pass\n", encoding="utf-8")

    timed_out, _ = _verify(tmp_path, "python-pytest", FixtureRunner(fail="timeout"))
    regression, _ = _verify(tmp_path, "python-pytest", FixtureRunner(fail="regression"))

    assert timed_out.status == SandboxStatus.INCONCLUSIVE
    assert timed_out.stages[-1].timed_out
    assert regression.status == SandboxStatus.REGRESSION_FAILED
    assert regression.failed_stage == "patched_tests"
    assert not regression.verified


def test_unknown_language_and_unregistered_profile_are_inconclusive(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text("module sample\n", encoding="utf-8")
    (tmp_path / "main.go").write_text("package main\n", encoding="utf-8")
    runner = FixtureRunner()
    registry = ApprovedProjectRegistry()
    target_id = registry.approve_project(tmp_path)

    verdict = SandboxVerifier(docker_runner=runner).verify_controlled(
        _controlled_request(target_id, "go-test"),
        registry,
    )

    assert verdict.status == SandboxStatus.INCONCLUSIVE
    assert "Unsupported execution profile" in verdict.reason
    assert runner.calls == []


def test_profile_model_rejects_shell_and_socket_commands() -> None:
    common = {
        "profile_id": "unsafe-profile",
        "languages": ("Python",),
        "toolchain": "Python",
        "runtime_image": "vulnos/python:3.12",
        "required_build_files": ("pyproject.toml",),
        "test_commands": (("python", "-m", "pytest"),),
        "test_framework": "pytest",
    }

    with pytest.raises(ValidationError):
        ExecutionProfile(**{**common, "build_commands": (("sh", "-c", "id"),)})
    with pytest.raises(ValidationError):
        ExecutionProfile(
            **{
                **common,
                "build_commands": (("python", "/var/run/docker.sock"),),
            }
        )


def test_controlled_request_rejects_commands_images_environment_and_host_paths() -> None:
    request = {
        "target_id": "registered-target",
        "profile_id": "python-pytest",
        "patch": _PATCH,
    }
    for untrusted_field in (
        {"command": ["sh", "-c", "anything"]},
        {"image": "attacker/image:latest"},
        {"environment": {"TOKEN": "secret"}},
        {"source_path": "C:/host"},
    ):
        with pytest.raises(ValidationError):
            ControlledVerificationRequest.model_validate({**request, **untrusted_field})


def test_docker_runner_rejects_unregistered_images_and_socket_paths(tmp_path: Path) -> None:
    runner = DockerRunner(client=object())

    with pytest.raises(ValueError, match="approved image registry"):
        runner.run("attacker/image:latest", ["true"], tmp_path)
    with pytest.raises(ValueError, match="Docker socket"):
        runner.run("trusted-runtime:local", ["cat", "/var/run/docker.sock"], tmp_path)


def test_missing_profile_image_is_reported_without_running_container(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("pass\n", encoding="utf-8")
    runner = FixtureRunner()
    target_registry = ApprovedProjectRegistry()
    target_id = target_registry.approve_project(tmp_path)
    restricted_config = SandboxConfig(approved_images=("trusted-runtime:local",))
    verdict = SandboxVerifier(
        docker_runner=runner,
        config=restricted_config,
    ).verify_controlled(
        _controlled_request(target_id, "python-pytest"),
        target_registry,
    )

    assert verdict.status == SandboxStatus.ENVIRONMENT_ERROR
    assert "not approved" in verdict.reason
    assert runner.calls == []


def test_controlled_verifier_cleans_workspace_when_runner_raises(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname='fixture'\n", encoding="utf-8")

    class RaisingRunner:
        workspace: Path | None = None

        def run(
            self,
            _image: str,
            command: list[str],
            workspace: str | Path,
            _timeout_seconds: int | None = None,
        ) -> ContainerResult:
            self.workspace = Path(workspace)
            raise SandboxInfrastructureError(
                f"fixture runner failure for {_image}, timeout={_timeout_seconds}",
                command=command,
                duration_seconds=0.1,
            )

    runner = RaisingRunner()
    registry = ApprovedProjectRegistry()
    target_id = registry.approve_project(tmp_path)
    verdict = SandboxVerifier(docker_runner=runner).verify_controlled(
        _controlled_request(target_id, "python-pytest"),
        registry,
    )

    assert verdict.status == SandboxStatus.ENVIRONMENT_ERROR
    assert runner.workspace is not None
    assert not runner.workspace.exists()


def test_patch_path_escape_is_rejected(tmp_path: Path) -> None:
    from src.sandbox.patch_applier import PatchApplier

    class NoRunRunner:
        def run(
            self,
            _image: str,
            _command: list[str],
            _workspace: str | Path,
            _timeout_seconds: int | None = None,
        ) -> ContainerResult:
            raise AssertionError(
                f"Unexpected execution request: {_image}, {_command}, "
                f"{_workspace}, {_timeout_seconds}"
            )

    unsafe = PatchDiff(diff="diff --git a/../outside b/../outside\n")
    stages, applied = PatchApplier(NoRunRunner()).apply("trusted-runtime:local", tmp_path, unsafe)

    assert not applied
    assert stages[0].status == "failed"
    assert "outside" in stages[0].reason


def test_project_configuration_and_dpkg_advisory_checks_are_read_only(tmp_path: Path) -> None:
    config = tmp_path / ".env"
    config.write_text("SERVICE_API_KEY=sample-secret-value\n", encoding="utf-8")
    config_findings = check_project_configuration(tmp_path)
    assert any(item.rule_id == "possible_hard_coded_secret" for item in config_findings)

    status_file = tmp_path / "var" / "lib" / "dpkg" / "status"
    status_file.parent.mkdir(parents=True)
    status_file.write_text(
        "Package: sample\nStatus: install ok installed\nVersion: 1.0.0\n\n",
        encoding="utf-8",
    )
    report = scan_local_os(
        tmp_path,
        [KnownAdvisory(advisory_id="ADV-1", package_name="sample", affected_versions={"1.0.0"})],
    )

    assert len(report.packages) == 1
    assert report.advisory_matches[0].advisory_id == "ADV-1"
    assert any("exact versions" in item for item in report.limitations)
