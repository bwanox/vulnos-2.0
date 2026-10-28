# Sandbox verifier integration

The sandbox is a one-attempt verification operation. It does not own the
orchestrator retry loop or generate patches. Dev 1 may call `verify_patch()` or
reuse a `SandboxVerifier`; the returned shared `SandboxVerdict` includes a
top-level status, stage-by-stage exit codes/logs/timing, and the legacy boolean
fields.

## Request contract

`VerificationRequest` requires:

- `source_path`: a local source directory (remote URLs are not accepted).
- `exploit`: the Dev 2 `ExploitTest`.
- `patch`: the Dev 2 `PatchDiff` containing a unified diff accepted by `git apply`.
- `image`: an already-present, trusted Docker runtime image. The verifier never
  builds or pulls images and never executes repository build scripts on the host.
- `regression_command`: a non-empty argv list for the project's regression suite.
  Supply a command appropriate to the repository and image, such as
  `["python", "-m", "pytest", "-q"]`.
- Optional `exploit_command`: argv list for the generated PoC. The default runs
  `python -m pytest -q --tb=short --color=no <test_filename>`. A custom command
  may use `{test_file}` where the test filename belongs.
- Optional `timeout_seconds`: positive per-container command timeout; otherwise
  `SandboxConfig.timeout` is used.

Example:

```python
from src.common.models import ExploitTest, PatchDiff
from src.sandbox import VerificationRequest, verify_patch

verdict = verify_patch(
    VerificationRequest(
        source_path="./target",
        image="vulnos-python-runtime:stable",
        exploit=ExploitTest(
            test_code="def test_poc():\n    assert vulnerable() is False, "
            "'VULNOS_EXPECTED_EXPLOIT_FAILURE: vulnerable behavior observed'\n",
        ),
        patch=PatchDiff(diff=unified_diff),
        regression_command=["python", "-m", "pytest", "-q"],
    )
)
```

## Dev 2 exploit-test contract

Generate exactly one pytest test whose vulnerability-specific assertion fails
on the original code with an assertion message starting with
`VULNOS_EXPECTED_EXPLOIT_FAILURE:`. The same test must pass after the patch.
Collection errors, import errors, crashes, timeouts, missing assertion markers,
or any result other than exactly one expected failure are inconclusive; a
non-zero exit code alone is never evidence of reproduction. A clean single-test
pass after patching is required to establish blocking.

## Verdict semantics

| Status | Meaning |
|---|---|
| `VERIFIED` | Marked exploit reproduced before patch, the same test passed after patch, and the configured regression command passed. |
| `PATCH_FAILED` | Patch application failed, or the marked vulnerability assertion still failed after patching. |
| `REGRESSION_FAILED` | Exploit was blocked, but the configured regression command failed. |
| `INCONCLUSIVE` | Invalid request, exploit evidence was ambiguous, or a verification command timed out. |
| `ENVIRONMENT_ERROR` | Docker startup/daemon/image failure, required patch utility unavailable, or workspace operation failed. |

`failed_stage`, `reason`, and `stages` provide diagnostic evidence. The legacy
`exploit_triggers_on_unpatched`, `exploit_blocked_after_patch`,
`existing_tests_pass`, `verified`, `stdout`, `stderr`, and `exit_code` fields
remain available. `retry_count` is left to Dev 1's state machine and is not
incremented here.

## Isolation and image preparation

Each stage runs in a newly created container with `network_mode="none"`, a
512-MB memory/swap limit, one CPU, PID cap, dropped capabilities, no-new-
privileges, a non-root UID, read-only container root, and a small no-exec `/tmp`.
Only the disposable workspace is bind-mounted writable. Containers are force-
removed after each command, and paired temporary source copies are removed when
verification exits, including on failures. Symlinks and special files abort
workspace preparation; common VCS, virtual-environment, and build-cache
directories are excluded. The process uses the current non-root host UID/GID
inside Linux containers when available, falling back to UID/GID 65532. A root
host process transfers ownership of only the disposable workspace to UID/GID
65532 so that the non-root container user can read and modify it.

Prepare a trusted runtime image and all dependencies before calling the
verifier. The image must contain the tools needed by the supplied commands
(Python/pytest for the default exploit runner and `git` for patch application).
The verifier does not promise that Docker completely contains hostile code;
isolation is defense in depth. Use this only for authorized local source trees
and controlled tests.

Run unit tests with:

```powershell
.\venv\Scripts\python.exe -m pytest tests\unit\test_sandbox.py -q
```

An optional Docker smoke test runs only when `VULNOS_TEST_DOCKER_IMAGE` points
to a pre-pulled trusted image containing Python.

## Remaining integration

`src/orchestrator/main.py` is currently a module stub. Dev 1 must call this
single-attempt verifier from the existing LangGraph state, preserve the
returned stage evidence for telemetry, and own the maximum-three-attempt retry
budget. Dev 2 should keep emitted PoCs within the assertion-marker contract
above. The sandbox does not emit telemetry events or retry a patch itself.
