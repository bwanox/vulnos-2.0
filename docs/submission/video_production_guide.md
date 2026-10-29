# VulnOS 2.0: 3-Minute Video Production Guide & Script

> **Nebius × NVIDIA Global AI Hackathon**  
> **Repository:** [https://github.com/bwanox/vulnos-2.0](https://github.com/bwanox/vulnos-2.0)

---

## Video Timeline & Recording Sequence

### 0:00–0:15 — Introduce the Problem & Solution
* **Visual on Screen:** GitHub repository (`https://github.com/bwanox/vulnos-2.0`) and title slide.
* **Spoken Script:**
  > *"Passing unit tests only proves you didn't break functionality—it does not prove you fixed the vulnerability. Meet **VulnOS 2.0**, an autonomous security runtime that detects vulnerabilities, generates an exploit, creates a patch, and verifies that the exploit is blocked without breaking existing tests."*

### 0:15–0:35 — Architecture Overview
* **Visual on Screen:** Brief architectural flow diagram.
  ```text
  AST analysis → Nemotron triage on Nebius → Tavily threat intelligence → Red-team exploit → Blue-team patch → Docker verification
  ```
* **Spoken Script:**
  > *"Our closed-loop agentic kernel combines deterministic AST slicing, high-speed Nemotron-Nano triage on Nebius Token Factory, live CVE context enrichment via Tavily, adversarial Red-Team exploit verification, and secure Docker sandboxing."*

### 0:35–0:55 — Show the Vulnerable Code
* **Visual on Screen:** Open `examples/vulnerable_app/app/main.py` highlighting the vulnerable Flask route (`/ping` command injection or `/user` SQL injection).
* **Spoken Script:**
  > *"This demo application contains an intentionally vulnerable endpoint. VulnOS first analyzes the code statically and identifies the suspicious taint flow."*
  *(Note: Do not show API keys or `.env` file contents).*

### 0:55–1:20 — Live Nebius & Tavily Usage
* **Visual on Screen:** Terminal executing the live pipeline:
  ```bash
  .venv/bin/python demo_live.py
  ```
* **Spoken Script:**
  > *"Nemotron running through Nebius Token Factory performs fast triage and deep reasoning, while Tavily provides live CVE and security-advisory context beyond the model’s training data."*

### 1:20–1:45 — The Red-Team Exploit
* **Visual on Screen:** Terminal output highlighting:
  ```text
  baseline exploit succeeded (or exploit triggered successfully on unpatched code)
  ```
* **Spoken Script:**
  > *"The Red-Team agent generates a proof-of-concept test. It must demonstrate that the vulnerability is exploitable on the original, unpatched code."*

### 1:45–2:05 — The Blue-Team Patch
* **Visual on Screen:** Displaying the generated unified git diff fixing the vulnerable code.
* **Spoken Script:**
  > *"The Blue-Team agent then synthesizes a surgical patch. The patch is applied strictly inside our controlled verification workflow."*

### 2:05–2:35 — Docker Sandbox Verification
* **Visual on Screen:** Terminal showing Docker container execution and verification stages:
  1. Exploit succeeds before patch
  2. Patch applies successfully
  3. Exploit is blocked after patch
  4. Existing regression tests pass
* **Spoken Script:**
  > *"The patch is accepted only if the original exploit is blocked and the application’s existing tests still pass inside an isolated Docker sandbox."*
  *(Highlight visible output: `exploit blocked after patch`, `regression tests passed`).*

### 2:35–2:50 — Final Results & Test Suite
* **Visual on Screen:** Terminal output showing:
  ```text
  Found 1 hardened patch(es).
  ```
  And running pytest:
  ```bash
  .venv/bin/pytest tests/ -v
  ```
  Showing:
  ```text
  94 passed, 1 skipped
  ```
* **Spoken Script:**
  > *"VulnOS successfully generates hardened patches and our comprehensive test suite reports 94 tests passed successfully."*

### 2:50–3:00 — Conclusion & Open Source Links
* **Visual on Screen:** GitHub repo URL (`https://github.com/bwanox/vulnos-2.0`), MIT License badge, and logos for Nebius, NVIDIA Nemotron, and Tavily.
* **Spoken Script:**
  > *"VulnOS 2.0 is open source, reproducible, and demonstrates a complete red-team to verified-blue-team security loop using Nebius, NVIDIA Nemotron, Tavily, and Docker. Thank you!"*

---

## Compliance Checklist for Recording
* [x] Public repository URL visible (`https://github.com/bwanox/vulnos-2.0`)
* [x] Live Nebius / Nemotron inference in logs
* [x] Live Tavily search / extraction in logs
* [x] Vulnerable code displayed in editor
* [x] Red-team exploit succeeds before patch
* [x] Generated unified diff patch displayed
* [x] Docker sandbox execution shown
* [x] Exploit blocked after patch confirmed
* [x] Regression tests pass (94 tests passed)
* [x] Final hardened patch count shown
* [x] No API keys or `.env` contents shown
* [x] Total video length $\le$ 3:00 minutes
