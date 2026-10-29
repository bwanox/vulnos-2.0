# Dev 2 Systems-Security & Network Attack Extension — Implementation Plan

**Goal:** Extend Dev 2 (`src/inference/`) to support advanced systems-security attack vectors beyond basic code functions: Shell Command Injection / RCE payloads, Network Socket & HTTP Fuzzing, and Endpoint Security / Privilege Escalation (PrivEsc) validation and hardening.

**Architecture:** Add specialized prompt handlers and schema support for system/network attack vectors (`rce_shell`, `network_socket`, `privesc_endpoint`). Nemotron-Ultra will generate tailored exploit harnesses (`exploit_rce.py`, `exploit_net.py`, `exploit_sec.py`) and robust system/code hardening patches.

**Tech Stack:** Python 3.10+, Pydantic, OpenAI (Nebius Token Factory), Tavily API, pytest

---

## Task Breakdown

### Task 1: Extend Data Models for Attack Vectors
**Files:** Modify `src/common/models.py`
- Add `attack_vector: str = "code_logic"` (`"code_logic"`, `"rce_shell"`, `"network_socket"`, `"privesc_endpoint"`) to `CodeSlice` and `ExploitTest`.

### Task 2: Specialized Prompt Templates for Systems Attacks
**Files:** Modify `src/inference/prompts.py`
- Add prompt instructions for Nemotron-Ultra to generate:
  - **Shell RCE / Command Injection:** Safe injection payload tests checking process execution.
  - **Network / HTTP Fuzzing:** Socket/HTTP request fuzzers targeting local ports.
  - **Endpoint Security / PrivEsc:** Config & permission checks (e.g., file permissions, SUID, systemd hardening).

### Task 3: Specialized Blue-Team Hardening Patches
**Files:** Modify `src/inference/blue_team.py` and `prompts.py`
- Enhance Blue-Team prompt to generate secure process spawning (`subprocess.run` with `shell=False`), input sanitization, and systemd/permission hardening diffs.

### Task 4: Unit Tests for Systems Attack Generation
**Files:** Create `tests/unit/test_systems_attacks.py`
- Test generation of RCE shell exploits, network fuzzers, and endpoint security harnesses.
