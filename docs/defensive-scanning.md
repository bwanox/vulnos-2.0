# Defensive scanning and controlled verification

## Baseline limitations

Before the defensive scanning additions, the sandbox path had these limitations:

- `ExploitRunner` defaulted to `python -m pytest`, generated test filenames were
  constrained to a single file, and vulnerability detection depended on a
  pytest-specific failure summary and assertion marker.
- `SandboxVerifier` ran that test before and after applying a patch, but did not
  discover the target language, prepare or build the target, or validate a
  language/runtime profile. The request supplied the Docker image and regression
  command, and could supply the exploit command.
- `DockerRunner` already used non-root execution, disabled networking, resource
  limits, dropped capabilities, no-new-privileges, bounded logs, a read-only
  container root, a workspace-only mount, and forced container cleanup. It did
  not restrict image names to an application-owned registry.
- Shared exploit data and the Dev 2 response schema described Python test code,
  not the target language, test language, toolchain, or a reviewed execution
  profile. The Dev 1 orchestrator entry point contains only a module docstring;
  there is no active orchestration path to extend.
- There was no OS/package inventory, configuration-permission inspection,
  multi-language project discovery, or source/dependency manifest analysis.

## Defensive scanning

`src.sandbox.discovery` identifies languages and recognized manifests without
executing project files. `src.sandbox.source_analysis` and
`src.sandbox.os_inventory` provide heuristic source/dependency checks and
read-only local OS/package inventory. These checks are evidence for review, not
proof that a complete OS or application is secure.

`src.sandbox.adapters` owns reviewed command vectors and runtime images. A
caller must explicitly register a project with `ApprovedProjectRegistry` and
request a registered profile by identifier. Requests cannot supply commands,
images, or environment variables. `SandboxVerifier.verify_controlled` applies
patches and runs only the selected profile in disposable workspaces. This
procedure compares configured build/test results; it does not run generated
exploit code and does not claim that a vulnerability was reproduced or fixed.

## Limitations

- The initial profiles cover Python/pytest, C/C++ with CMake or Make, Java with
  Maven or Gradle, and JavaScript/TypeScript with npm. They require corresponding
  locally available, reviewed Docker images and toolchains.
- Go, Rust, C#, PHP, and other ecosystems are detected where possible but do
  not have built-in execution profiles yet.
- Package vulnerability matching only compares inventory versions against
  advisory records explicitly supplied by a trusted caller. It does not fetch
  or certify against a complete vulnerability database.
- OS inventory reads local platform information and Debian dpkg status when
  available. It cannot infer kernel/runtime behavior from a source checkout.
- Source checks are heuristic. Dynamic testing is limited to human-approved
  projects and predefined profiles; kernel-level and other VM-requiring tests
  are out of scope.
