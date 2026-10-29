"""Canned fake implementations of ``AIEngine`` and ``SandboxRunner``.

These let the CORE pipeline run end-to-end TODAY with no network, no LLM, and
no Docker — exactly the constraint for running on a Jetson Orin Nano.

Swap in real Dev 2 / Dev 3 implementations later; the graph never changes
because it depends only on the protocols in :mod:`vulnos.core.contracts`.
"""

from __future__ import annotations

from pathlib import Path

from vulnos.core.contracts import (
    AIEngine,
    CodeSlice,
    Dependency,
    ExploitTest,
    FindingStatus,
    HardenedPatch,
    PatchDiff,
    SandboxRunner,
    SandboxVerdict,
    SinkType,
    VulnAssessment,
)

# Sink types the mock triage flags as genuinely vulnerable.
_VULNERABLE_SINKS = {SinkType.SUBPROCESS, SinkType.SQL_BUILD, SinkType.EVAL_EXEC}

# Canned exploit / patch templates keyed by sink type so output looks realistic.
_EXPLOIT_CODE: dict[SinkType, str] = {
    SinkType.SUBPROCESS: (
        "import subprocess\n\n"
        "def test_command_injection():\n"
        "    # PoC: user-controlled input reaches subprocess without sanitization\n"
        "    payload = '; cat /etc/passwd #'\n"
        "    result = subprocess.run(f'echo {payload}', shell=True, capture_output=True)\n"
        "    assert b'root:' in result.stdout  # exploit worked\n"
    ),
    SinkType.SQL_BUILD: (
        "import sqlite3\n\n"
        "def test_sql_injection():\n"
        "    # PoC: user-controlled input concatenated into a SQL query\n"
        "    payload = \"' OR '1'='1 --\"\n"
        "    conn = sqlite3.connect(':memory:')\n"
        "    cur = conn.cursor()\n"
        "    cur.execute(\"SELECT * FROM users WHERE name = '\" + payload + \"'\")\n"
        "    assert len(cur.fetchall()) > 0  # exploit worked (auth bypass)\n"
    ),
    SinkType.EVAL_EXEC: (
        "def test_eval_injection():\n"
        "    # PoC: user-controlled input reaches eval()\n"
        "    payload = \"__import__('os').system('id')\"\n"
        "    result = eval(payload)  # noqa: S307 (intentional PoC)\n"
        "    assert result is not None  # exploit worked\n"
    ),
}

_PATCH_DIFFS: dict[SinkType, str] = {
    SinkType.SUBPROCESS: (
        "diff --git a/app/main.py b/app/main.py\n"
        "--- a/app/main.py\n"
        "+++ b/app/main.py\n"
        "@@ -10,7 +10,7 @@\n"
        "-    subprocess.run(f\"{user_input}\", shell=True)\n"
        "+    subprocess.run(shlex.split(user_input), shell=False)\n"
    ),
    SinkType.SQL_BUILD: (
        "diff --git a/app/main.py b/app/main.py\n"
        "--- a/app/main.py\n"
        "+++ b/app/main.py\n"
        "@@ -10,7 +10,7 @@\n"
        "-    cur.execute(\"SELECT * FROM users WHERE name = '\" + user_input + \"'\")\n"
        "+    cur.execute(\"SELECT * FROM users WHERE name = ?\", (user_input,))\n"
    ),
    SinkType.EVAL_EXEC: (
        "diff --git a/app/main.py b/app/main.py\n"
        "--- a/app/main.py\n"
        "+++ b/app/main.py\n"
        "@@ -10,7 +10,7 @@\n"
        "-    result = eval(user_input)  # noqa: S307\n"
        "+    result = ast.literal_eval(user_input)\n"
    ),
}


class MockAIEngine(AIEngine):
    """Deterministic canned AI engine. No network, no LLM, fully offline."""

    def __init__(
        self,
        *,
        false_positive_sinks: frozenset[SinkType] | None = None,
    ) -> None:
        """Arg: sinks that triage should mark as NOT vulnerable (false positives)."""
        self.false_positive_sinks = frozenset(
            false_positive_sinks or {SinkType.PICKLE, SinkType.FILE_OPEN}
        )

    async def triage(self, code_slice: CodeSlice) -> VulnAssessment:
        """Mark subprocess/SQL/eval slices as vulnerable; others as false positive."""
        is_vuln = code_slice.sink_type in _VULNERABLE_SINKS and (
            code_slice.sink_type not in self.false_positive_sinks
        )
        if is_vuln:
            cwe = {
                SinkType.SUBPROCESS: "CWE-78",
                SinkType.SQL_BUILD: "CWE-89",
                SinkType.EVAL_EXEC: "CWE-94",
            }.get(code_slice.sink_type, "CWE-OTHER")
            severity = "critical" if code_slice.sink_type == SinkType.SUBPROCESS else "high"
            reasoning = (
                f"Taint from entry point reaches {code_slice.sink_type.value} sink "
                f"at {code_slice.file_path}:{code_slice.sink_line} without sanitization."
            )
            confidence = 0.96
        else:
            cwe = ""
            severity = "low"
            reasoning = (
                f"Sink {code_slice.sink_type.value} is either unreachable from a "
                "user-controlled entry point or already sanitized upstream."
            )
            confidence = 0.12
        return VulnAssessment(
            slice_id=code_slice.slice_id,
            is_vulnerable=is_vuln,
            severity=severity,
            cwe=cwe,
            reasoning=reasoning,
            confidence=confidence,
            related_cves=[],
        )

    async def enrich_cve(
        self, deps: list[Dependency], code_slice: CodeSlice
    ) -> list[str]:
        """Return a canned CVE when a dependency manifest was parsed."""
        if not deps:
            return []
        return [f"CVE-2024-{abs(hash(code_slice.file_path)) % 100000:05d}"]

    async def generate_exploit(
        self, code_slice: CodeSlice, assessment: VulnAssessment
    ) -> ExploitTest:
        """Generate a canned Red-Team PoC exploit test."""
        code = _EXPLOIT_CODE.get(
            code_slice.sink_type,
            "def test_exploit():\n    assert True  # placeholder PoC\n",
        )
        return ExploitTest(
            language="python",
            code=code,
            expected_behavior=(
                f"The {code_slice.sink_type.value} sink executes attacker-controlled input."
            ),
            runner_command="pytest",
        )

    async def generate_patch(
        self,
        code_slice: CodeSlice,
        assessment: VulnAssessment,
        prev_failure_logs: str | None = None,
    ) -> PatchDiff:
        """Generate a canned Blue-Team patch (unified diff)."""
        diff = _PATCH_DIFFS.get(
            code_slice.sink_type,
            "diff --git a/unknown b/unknown\n+    # apply input sanitization here\n",
        )
        explanation = (
            "Canned patch: sanitize user-controlled input before it reaches the sink."
            + (
                f" Previous failure logs considered: {prev_failure_logs[:80]}..."
                if prev_failure_logs
                else ""
            )
        )
        return PatchDiff(
            unified_diff=diff,
            explanation=explanation,
            files_modified=[code_slice.file_path],
        )


class MockSandboxRunner(SandboxRunner):
    """Deterministic canned sandbox. Returns realistic verdicts without Docker."""

    def __init__(
        self,
        *,
        fail_first_n: int = 0,
        tests_passed: int = 3,
        tests_total: int = 3,
    ) -> None:
        """Args:
        fail_first_n: number of ``verify`` calls to fail (for retry-loop testing).
        tests_passed/tests_total: unit-test results reported in the verdict.
        """
        self._calls = 0
        self.fail_first_n = fail_first_n
        self.tests_passed = tests_passed
        self.tests_total = tests_total

    async def verify(
        self,
        repo_path: str | Path,
        exploit: ExploitTest,
        patch: PatchDiff,
    ) -> SandboxVerdict:
        """Return a canned verdict. Fails the first ``fail_first_n`` calls."""
        self._calls += 1
        attempt = self._calls

        if attempt <= self.fail_first_n:
            # Simulate a patch that doesn't block the exploit / breaks tests.
            return SandboxVerdict(
                exploit_blocked_after_patch=False,
                exploit_worked_before_patch=True,
                tests_passed=0,
                tests_total=self.tests_total,
                exit_codes=[1],
                logs=(
                    f"FAIL (attempt {attempt}): exploit still works after patch; "
                    "unit tests regression. Need another patch iteration."
                ),
            )

        return SandboxVerdict(
            exploit_blocked_after_patch=True,
            exploit_worked_before_patch=True,
            tests_passed=self.tests_passed,
            tests_total=self.tests_total,
            exit_codes=[0, 0],
            logs=(
                f"PASS (attempt {attempt}): red exploit blocked after patch; "
                f"all {self.tests_passed}/{self.tests_total} unit tests passed."
            ),
        )


def make_hardened_patch(
    *,
    finding_id: str,
    file_path: str,
    code_slice: CodeSlice,
    assessment: VulnAssessment,
    exploit: ExploitTest,
    patch: PatchDiff,
    verdict: SandboxVerdict,
    iterations_used: int,
    cve_references: list[str] | None = None,
) -> HardenedPatch:
    """Assemble a :class:`HardenedPatch` from graph outputs (helper for tests/demo)."""
    status = (
        FindingStatus.RESOLVED_VERIFIED
        if verdict.verified
        else FindingStatus.UNRESOLVED
    )
    return HardenedPatch(
        finding_id=finding_id,
        file_path=file_path,
        unified_diff=patch.unified_diff,
        explanation=patch.explanation,
        exploit_used=exploit,
        sandbox_verdict=verdict,
        iterations_used=iterations_used,
        cve_references=cve_references or assessment.related_cves,
        status=status,
    )
