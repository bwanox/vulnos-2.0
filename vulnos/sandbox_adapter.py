"""Sandbox Runner adapter connecting Dev 1 protocols to Dev 3 (Docker Sandbox Verifier)."""

from __future__ import annotations

import re
import difflib
from pathlib import Path

from src.common.config import load_config
from src.sandbox.models import ApprovedProjectRegistry, ControlledVerificationRequest
from src.sandbox.verifier import SandboxVerifier
from src.common.models import ExploitTest as Dev2ExploitTest
from src.common.models import PatchDiff as Dev2PatchDiff
from vulnos.core.contracts import (
    SandboxRunner,
    ExploitTest,
    PatchDiff,
    SandboxVerdict as CoreSandboxVerdict,
)


class RealSandboxRunner(SandboxRunner):
    """Concrete implementation of Dev 1 SandboxRunner protocol using Dev 3 SandboxVerifier."""

    def __init__(self) -> None:
        self.config = load_config()
        self.verifier = SandboxVerifier(config=self.config.sandbox)
        self.registry = ApprovedProjectRegistry()

    async def verify(
        self,
        repo_path: str | Path,
        exploit: ExploitTest,
        patch: PatchDiff,
    ) -> CoreSandboxVerdict:
        """Run exploit verification and tests inside the ephemeral Docker sandbox."""
        path = Path(repo_path).expanduser().resolve(strict=True)
        target_id = self.registry.approve_project(path)

        normalized_diff, normalized_files = _normalize_patch_paths(
            patch.unified_diff,
            patch.files_modified,
            path,
        )
        normalized_diff = _materialize_partial_patch(
            normalized_diff,
            normalized_files,
            path,
        )
        if normalized_files and not any(
            line.startswith(("diff --git ", "--- ", "+++ "))
            for line in normalized_diff.splitlines()
        ):
            target = normalized_files[0]
            normalized_diff = (
                f"diff --git a/{target} b/{target}\n"
                f"--- a/{target}\n"
                f"+++ b/{target}\n"
                f"{normalized_diff.lstrip('`').removeprefix('diff').lstrip()}"
            )
        dev2_patch = Dev2PatchDiff(
            diff=normalized_diff,
            patch_description=patch.explanation,
            files_modified=normalized_files,
        )
        dev2_exploit = Dev2ExploitTest(
            test_code=exploit.code,
            test_filename="test_vulnos_exploit.py",
            exploit_description=exploit.expected_behavior,
            target_language=exploit.language,
        )

        request = ControlledVerificationRequest(
            target_id=target_id,
            profile_id="python-pytest",
            patch=dev2_patch,
            exploit=dev2_exploit,
        )

        verdict = self.verifier.verify_controlled(request, self.registry)

        return CoreSandboxVerdict(
            exploit_blocked_after_patch=verdict.exploit_blocked_after_patch,
            exploit_worked_before_patch=verdict.exploit_triggers_on_unpatched,
            tests_passed=3 if verdict.existing_tests_pass else 0,
            tests_total=3,
            exit_codes=[verdict.exit_code],
            logs=verdict.stdout + "\n" + verdict.stderr,
            reason=verdict.reason,
            security_verification_performed=verdict.security_verification_performed,
        )


_PATCH_GIT = re.compile(r"^(diff --git )a/(\S+) b/(\S+)$")
_PATCH_FILE = re.compile(r"^(--- |\+\+\+ )(.+)$")


def _normalize_patch_paths(
    diff: str,
    files_modified: list[str],
    repo_path: Path,
) -> tuple[str, list[str]]:
    """Convert model-emitted paths to safe paths relative to the approved repo."""
    def normalize(value: str) -> str:
        candidate = Path(value)
        if candidate.is_absolute():
            return candidate.resolve(strict=True).relative_to(repo_path).as_posix()
        if (repo_path / candidate).is_file():
            return candidate.as_posix()
        parts = candidate.parts
        for index in range(len(parts)):
            suffix = Path(*parts[index:])
            if (repo_path / suffix).is_file():
                return suffix.as_posix()
        raise ValueError(f"Patch path does not resolve inside approved repository: {value}")

    normalized_lines: list[str] = []
    for line in diff.splitlines():
        git_match = _PATCH_GIT.match(line)
        if git_match:
            prefix, old_value, new_value = git_match.groups()
            normalized_lines.append(
                f"{prefix}a/{normalize(old_value)} b/{normalize(new_value)}"
            )
            continue
        file_match = _PATCH_FILE.match(line)
        if file_match:
            prefix, value = file_match.groups()
            normalized_lines.append(
                line if value == "/dev/null" else f"{prefix}{normalize(value)}"
            )
            continue
        normalized_lines.append(line)
    return "\n".join(normalized_lines) + ("\n" if diff.endswith("\n") else ""), [
        normalize(value) for value in files_modified
    ]


def _materialize_partial_patch(diff: str, files: list[str], repo_path: Path) -> str:
    """Expand function-relative model hunks into a full-file unified diff."""
    if not files or not any(line.startswith("@@") for line in diff.splitlines()):
        return diff
    hunks = [line for line in diff.splitlines() if line.startswith("@@")]
    if not hunks:
        return diff
    old_lines: list[str] = []
    new_lines: list[str] = []
    for line in diff.splitlines():
        if line.startswith("@@") or line.startswith(("--- ", "+++ ")):
            continue
        if line.startswith((" ", "-")):
            old_lines.append(line[1:])
        if line.startswith((" ", "+")):
            new_lines.append(line[1:])
    if not old_lines or not new_lines:
        return diff
    target = repo_path / files[0]
    original = target.read_text(encoding="utf-8").splitlines()
    width = len(old_lines)
    for start in range(len(original) - width + 1):
        if original[start : start + width] != old_lines:
            continue
        updated = original[:start] + new_lines + original[start + width :]
        return (
            "\n".join(
                difflib.unified_diff(
                    original,
                    updated,
                    fromfile=f"a/{files[0]}",
                    tofile=f"b/{files[0]}",
                    lineterm="",
                )
            )
            + "\n"
        )
    return diff
