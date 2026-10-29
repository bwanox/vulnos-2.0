# Defensive scanning and sandbox integration

## Read-only discovery

`discover_project(path)` identifies known source extensions and manifests without
running target content. `analyze_project(path)` adds heuristic source indicators,
dependency references, profile suggestions, and host-PATH tool warnings.
`check_project_configuration(path)` reports likely hard-coded secrets and
world-writable configuration files without returning secret values.
`scan_local_os(root, advisories)` reports local OS/kernel identity, Debian dpkg
packages when available, and exact-version matches against caller-provided
advisory records.

These are triage signals. Source patterns are heuristic, the included OS package
inventory is dpkg-only, and advisory matching does not replace a maintained CVE
feed or prove the security of an installed operating system.

## Approved profile verification

The verifier accepts a target ID and profile ID, not an image, shell command,
environment mapping, or arbitrary target path. A caller must explicitly approve
a local source directory with `ApprovedProjectRegistry.approve_project()`.
Profile IDs resolve to application-owned images and argv vectors in
`DEFAULT_PROFILE_REGISTRY`.

```python
from src.common.models import PatchDiff
from src.sandbox import (
    ApprovedProjectRegistry,
    ControlledVerificationRequest,
    SandboxVerifier,
)

approved = ApprovedProjectRegistry()
target_id = approved.approve_project("./authorized-fixture")
request = ControlledVerificationRequest(
    target_id=target_id,
    profile_id="python-pytest",
    patch=PatchDiff(diff=unified_diff),
)
verdict = SandboxVerifier().verify_controlled(request, approved)
```

Built-in profile IDs are `python-pytest`, `cpp-cmake`, `cpp-make`,
`java-maven`, `java-gradle`, and `javascript-npm`. They use fixed local image
names (`vulnos/python:3.12`, `vulnos/cpp:stable`, `vulnos/java:21`, and
`vulnos/node:22`). The images must be reviewed and pre-pulled by the operator.
No project commands or dependencies are installed on the host. Project build
and test scripts may execute inside the isolated container, so only register
projects that are explicitly authorized for this testing.

Verification creates disposable original/patched copies, runs the same
registered build/test commands on each, applies the patch only to the patched
copy, and removes workspaces after completion. `TESTS_PASSED` means those
configured commands passed before and after the patch; it is not proof that a
security vulnerability was reproduced or fixed. Generated exploit code is not
run. Unsupported project types and profiles return `INCONCLUSIVE`.

The older `VerificationRequest` and `verify_patch()` signatures remain callable
for compatibility, but `SandboxVerifier.verify()` refuses them without
executing their generated exploit or caller-supplied commands. Use
`verify_controlled()` for the new safe path.

## Isolation

Docker keeps the existing non-root UID, network-disabled mode, memory/CPU/PID
limits, dropped capabilities, no-new-privileges, read-only root filesystem,
bounded logs, and forced container removal. Only a disposable workspace is
mounted writable. The runner rejects images not in `SandboxConfig.approved_images`;
the controlled verifier resolves images only from registered profiles. The
host Docker socket is never mounted. A container shares the host kernel and is
not an appropriate environment for kernel-level vulnerability tests.

The orchestrator entry point remains a stub, so callers must currently perform
explicit target approval and invoke the scan/verifier APIs themselves.

Run unit tests with:

```powershell
.\venv\Scripts\python.exe -m pytest tests\unit\test_sandbox.py tests\unit\test_defensive_scanning.py -q
```

An optional Docker smoke test runs only when `VULNOS_TEST_DOCKER_IMAGE` points
to a pre-pulled trusted image.
