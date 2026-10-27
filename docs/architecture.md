# VulnOS 2.0: Autonomous Red-vs-Blue Security & Patching Kernel

> **Nebius x NVIDIA Global AI Hackathon**  
> **Track:** Coding and Agentic Engineering  
> **Contending Awards:** Grand Prize (\$20,000) | Coding Track Prize (NVIDIA Jetson Orin Nano) | Best Use of Tavily (\$3,000)

---

## 1. Executive Summary & One-Line Pitch

> **VulnOS 2.0** is an autonomous, closed-loop security runtime that slices codebases via deterministic AST analysis, enriches zero-day and CVE context live via the Tavily API, proves exploitability using an adversarial Red-Team agent, and synthesizes regression-tested patches inside an isolated sandbox using multi-tier NVIDIA Nemotron models on Nebius Token Factory.

$$\text{AST Slicing} \longrightarrow \text{Nemotron-Nano Triage} \longrightarrow \text{Tavily Live CVE Sync} \longrightarrow \text{Red-Team PoC Exploit} \longrightarrow \text{Nemotron-Ultra Patch} \longrightarrow \text{Verified PR}$$

---

## 2. The Three Winning Upgrades

1. **Red-vs-Blue Adversarial Verification (The Killer Demo Feature):** Passing existing unit tests only proves you didn't break the app—it does not prove you fixed the vulnerability. VulnOS first spawns a **Red-Team Agent** that writes a sandboxed Proof-of-Concept (PoC) exploit test that actively breaks the unpatched code. The **Blue-Team Agent** then synthesizes the patch. A patch is only verified when the **Red-Team exploit is blocked** AND **all existing unit tests pass**.
2. **Deterministic AST + Neural Triage (Edge-Ready Architecture):** Instead of burning tokens asking an LLM to parse raw syntax, VulnOS uses `tree-sitter` and `Semgrep` to extract exact taint-flow slices first, then routes those slices to **NVIDIA Nemotron-Nano** to filter out false positives at high speed (an architecture compact enough to run locally on an **NVIDIA Jetson Orin Nano**).
3. **Zero-Day Reachability via Tavily (Securing the \$3,000 Tavily Track):** LLMs already know how to fix generic SQL injection. To make Tavily indispensable, VulnOS uses **Tavily Search + Extract** to pull live CVEs, GitHub Security Advisories (GHSA), and breaking library changelogs disclosed *after* the model's training cutoff—verifying whether a vulnerable third-party dependency function is actually reachable in the codebase.

---

## 3. Deep Explanation of the 4 Product Subsystems

```text
+-----------------------------------------------------------------------------------+
| 4. TELEMETRY & COMMAND HUD (Next.js / Textual TUI)                                |
|    Live Cost/Latency Savings | Red-vs-Blue Execution Logs | Side-by-Side Git Diff |
+-----------------------------------------------------------------------------------+
                                         ^
                                         | (WebSockets / Event Bus)
+-----------------------------------------------------------------------------------+
| 1. DETERMINISTIC AST & STATE ORCHESTRATOR (LangGraph + Tree-Sitter)               |
|    Builds Call Graphs -> Extracts Taint Slices -> Manages Red/Blue Retry Loops    |
+----------------------------------------+------------------------------------------+
                                         |
         +-------------------------------+-------------------------------+
         v                                                               v
+----------------------------------------+     +------------------------------------+
| 2. HYBRID INFERENCE & THREAT ENGINE    |     | 3. EPHEMERAL SANDBOX VERIFIER      |
| - Nebius Token Factory (Nano vs Ultra) |     | - Isolated Docker Container Runner |
| - Tavily Live CVE & Advisory Extractor |     | - Runs Red-Team Exploit + Pytest   |
+----------------------------------------+     +------------------------------------+
```

### Subsystem A: The Call-Graph & State Orchestrator
* **What it does:** Acts as the kernel scheduler. Before calling any AI model, it parses the target repository using `tree-sitter` and `Semgrep` to map entry points (API routes, CLI inputs) to dangerous sinks (SQL queries, subprocess calls, deserializers) and parses dependency manifests (`requirements.txt`, `package.json`).
* **How it works:** It slices only the connected functions (saving $\sim 85\%$ of context window tokens) and feeds them into a cyclic state machine:
  $$\text{TRIAGE} \longrightarrow \text{INTEL\_LOOKUP} \longrightarrow \text{EXPLOIT\_GEN} \longrightarrow \text{PATCH\_SYNTHESIS} \longrightarrow \text{SANDBOX\_VERIFY}$$
  If a patch breaks an existing test, it captures the traceback and loops back to `PATCH_SYNTHESIS` with a strict retry budget (max 3 self-healing iterations).

### Subsystem B: Multi-Tier Nebius Inference & Tavily Threat Bus
* **What it does:** Acts as the reasoning engine and live threat intelligence feed.
* **How it works:**
  * **Tier 1 (NVIDIA Nemotron-Nano on Nebius):** Receives raw static analysis alerts and eliminates false positives (e.g., recognizing that an input is already sanitized by an upstream middleware).
  * **Threat Bus (Tavily API):** Queries live NVD databases, GHSA advisories, and official package documentation for exact CVE mitigation patterns and safe version upgrades.
  * **Tier 2 (NVIDIA Nemotron-Ultra on Nebius):** Combines the vulnerable code slice and Tavily's live advisory data to generate both the **Red-Team PoC exploit test** and the **Blue-Team minimal surgical patch** using structured JSON outputs.

### Subsystem C: Ephemeral Sandbox & Exploit Verifier
* **What it does:** Provides zero-trust execution proof that the vulnerability is real and the fix works without breaking production behavior.
* **How it works:** Spins up an isolated, network-disabled Docker container (`--network none`, CPU/RAM quotas, and read-only root mounting) holding a clone of the repository:
  1. Runs the generated **Red-Team Exploit Test** on the unpatched code (must **fail/trigger** to prove the bug exists).
  2. Applies the **Blue-Team Git Patch** via `git apply`.
  3. Re-runs the **Red-Team Exploit Test** (must **pass/block**) and the repository's **existing test suite** (must **pass $100\%$**).

### Subsystem D: Real-Time Telemetry & ROI Command Center
* **What it does:** Turns invisible backend execution into an undeniable visual showcase for hackathon judges.
* **How it works:** Streams real-time WebSocket events from the orchestrator to display four judge-critical metrics:
  1. **Nebius Token Factory Router Metrics:** Live counter comparing tokens/cost spent on `Nemotron-Nano` vs. `Nemotron-Ultra` (proving your $\sim 70\%$ inference cost reduction claim).
  2. **Live Tavily Intelligence Feed:** Shows the exact live URLs and CVE advisories fetched during reasoning.
  3. **Red-vs-Blue Terminal Stream:** Shows the exploit failing before the patch and passing after the patch.
  4. **One-Click Hardened PR:** Side-by-side AST diff with automated PR creation.

---

## 4. Team of 4: Deep Role Separation & Interfaces

To prevent merge conflicts and bottlenecks, each developer owns an isolated module separated by strict data contracts.

| Role | Ownership Module | Inputs Received | Outputs Delivered | Prize Alignment |
| :--- | :--- | :--- | :--- | :--- |
| **Dev 1** | **AST Slicer & Agent State Machine** | Repo URL / Local Path | Final `HardenedPatch` + Telemetry Events | Coding & Agentic Track |
| **Dev 2** | **Nebius Router & Tavily Threat Engine** | `CodeSlice` + `DependencyList` | `VulnAssessment`, `ExploitTest`, `PatchDiff` | Nebius Grand Prize + Tavily (\$3k) |
| **Dev 3** | **Docker Sandbox & Red/Blue Runner** | `ExploitTest` + `PatchDiff` | `SandboxVerdict` (Exit codes, Stdout/Stderr) | Technical Execution Score |
| **Dev 4** | **Live Telemetry HUD & Pitch Production** | WebSocket State Stream | Interactive Dashboard + 3-Min Video | Presentation & Judge Impact |

### Person 1: Core Architect — AST Slicing & Agentic State Machine
**Mission:** Build the deterministic code parser and the cyclic self-healing control loop so the system never hallucinates file paths or gets stuck in infinite loops.
* **Deep Responsibilities:**
  * **Static Taint Slicer:** Integrate `Semgrep` or `tree-sitter` to scan the target repo and extract compact JSON bundles (`file_path`, `function_body`, `caller_context`, `imports`) rather than dumping entire repositories into the prompt.
  * **Cyclic State Graph (LangGraph / Async Python):** Implement the state transitions: `INGEST` $\rightarrow$ `NANO_TRIAGE` $\rightarrow$ `TAVILY_ENRICH` $\rightarrow$ `RED_TEAM_EXPLOIT` $\rightarrow$ `BLUE_TEAM_PATCH` $\rightarrow$ `SANDBOX_VERIFY`.
  * **Self-Healing Memory Manager:** When Dev 3's sandbox returns a test regression or syntax error, append the compressed compiler `stderr` to the state history and trigger a targeted re-patch (capped at 3 retries).
  * **Event Emitter:** Broadcast structured JSON state updates at every transition so Dev 4's UI updates in real time.

### Person 2: AI & Intelligence Lead — Nebius Token Factory & Tavily Pipeline
**Mission:** Maximize model intelligence, enforce structured outputs, prove multi-tier cost optimization on Nebius, and make Tavily indispensable.
* **Deep Responsibilities:**
  * **Nebius Token Factory Dual-Client:** Build an async OpenAI-compatible wrapper targeting Nebius endpoints with built-in telemetry that logs exact latency (ms), tokens/sec, and cost saved by routing initial triage to **Nemotron-Nano** vs. deep reasoning on **Nemotron-Ultra**.
  * **Tavily Threat Intelligence Pipeline:** Build a two-stage Tavily module:
    1. Use `tavily.search(search_depth="advanced")` to query specific CVEs, CWE mitigation patterns, and package security advisories.
    2. Use `tavily.extract()` on the top advisory URL to pull exact patched version numbers and secure code idioms into the prompt context.
  * **Adversarial & Defensive Prompt Engineering:** Design strict Pydantic/JSON-schema prompts for **Nemotron-Ultra**: one system prompt for the **Red-Team Agent** (writes a standalone `pytest` function that exploits the vulnerability) and one for the **Blue-Team Agent** (outputs a clean unified diff or exact search/replace block).

### Person 3: Systems & Security Lead — Ephemeral Sandbox & Patch Verifier
**Mission:** Build the isolated execution environment that proves the vulnerability is exploitable before the patch and neutralized after the patch.
* **Deep Responsibilities:**
  * **Containerized Execution Engine:** Build a Python Docker SDK (or isolated bubblewrap/subprocess) manager that clones the target repo into a temporary, network-isolated container (`--network none`, `--memory 512m`, `--cpus 1` to prevent runaway execution).
  * **Red-vs-Blue Verification Protocol:** Automate the 3-step verification check inside the container:
    1. Inject Dev 2's Red-Team test and run `pytest` $\rightarrow$ verify it triggers the vulnerability.
    2. Apply Dev 2's Blue-Team patch via `git apply` (with fallback fuzzy line-matching so minor line-number drift from the LLM never breaks patch application).
    3. Run both the Red-Team test and the full existing unit test suite $\rightarrow$ capture exit codes, `stdout`, and `stderr` tracebacks.
  * **Automated Git PR Generator:** Once verification passes, automatically create a new branch, commit the fix, and format a detailed Pull Request report containing the CVE summary, Tavily citations, and test execution logs.

### Person 4: Experience & Storytelling Lead — Telemetry HUD, Demo Repo & Video
**Mission:** Make the backend engineering visually unmistakable within 10 seconds of watching the demo, and craft the winning 3-minute submission.
* **Deep Responsibilities:**
  * **Real-Time Command HUD (Next.js or Python Textual):** Build a sleek split-screen interface featuring:
    * **Top Bar:** Live Nebius Token Factory telemetry (Latency, Tokens/sec, $\%$ Workload handled by Nemotron-Nano vs. Nemotron-Ultra, and estimated $\$$ saved).
    * **Left Pane:** The live state machine graph lighting up as nodes execute, alongside live Tavily search queries and extracted CVE sources.
    * **Right Pane:** Side-by-side Git diff viewer and the live terminal output from Dev 3's sandbox showing the Red-Team exploit blocked and unit tests turning green.
  * **Curated Target Repository ("VulnerableApp"):** Build a realistic microservice repo for the live demo containing 3 intentional flaws:
    1. A subtle SQL Injection or Command Injection flaw (shows AST taint analysis + Red-Team PoC exploit).
    2. A post-cutoff vulnerable dependency CVE (shows Tavily live advisory retrieval).
    3. A tricky patch scenario where the first naive fix breaks an existing unit test, forcing **Nemotron-Ultra** to visibly self-correct on attempt #2 during the video.

---

## 5. How This Locks In Every Prize Track

* **Grand Prize (\$20,000) & Nebius Judges:** You aren't just calling an API—you are showcasing **enterprise inference economics** on Nebius Token Factory by routing $80\%$ of noisy triage to **Nemotron-Nano** and $20\%$ of complex exploit/patch synthesis to **Nemotron-Ultra**, backed by a live cost/latency counter on the UI.
* **Coding Track Prize (NVIDIA Jetson Orin Nano):** Explicitly highlight in your `README.md` and video that the Phase 1 deterministic AST slicer + **Nemotron-Nano** triage layer is designed to run locally on air-gapped edge hardware like the **Jetson Orin Nano**, ensuring proprietary code never leaves the building unless a high-confidence vulnerability slice requires escalation.
* **Best Use of Tavily (\$3,000):** Tavily isn't tacked on as a generic web search. It powers **Zero-Day & Dependency Advisory Grounding** via both `search` and `extract` APIs, pulling live CVE patches and library migration docs that no static LLM weights contain.

---

## 6. Mandatory Submission Checklist

- [ ] **Nebius Token Factory Verification:** The codebase visibly calls Nebius endpoints using an active API key and logs Nano vs. Ultra routing telemetry.
- [ ] **NVIDIA Nemotron Usage:** Model choices explicitly feature Nemotron variants (`Nemotron-Nano` for fast triage and `Nemotron-Ultra` for Red/Blue reasoning).
- [ ] **Tavily API Integration:** Uses both `tavily.search` and `tavily.extract` for live CVE and advisory grounding.
- [ ] **Public GitHub Repository:** Hosted under an OSI-approved open source license (MIT or Apache 2.0).
- [ ] **Comprehensive `README.md`:** Clearly explains the architecture, edge-deployment compatibility (Jetson Orin Nano), setup commands, and reproducible test cases.
- [ ] **3-Minute YouTube Video:** Public or unlisted link strictly $\le 3:00$ minutes demonstrating live Nebius Token Factory telemetry, Tavily CVE lookup, Red-vs-Blue sandbox verification, and autonomous self-correction.
- [ ] **Written Feedback Form:** Concise notes evaluating developer experience on Nebius Token Factory and NVIDIA Nemotron for the submission portal.