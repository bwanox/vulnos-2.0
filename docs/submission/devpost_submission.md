# Devpost Submission: VulnOS 2.0

## Inspiration
Modern software engineering moves at breakneck speed, but application security remains manual, reactive, and bottlenecked by human code review. Traditional AI code fixers are blind to post-cutoff zero-days, and passing existing unit tests does not prove a vulnerability was actually neutralized. We were inspired to build an autonomous, closed-loop security runtime that proves vulnerabilities exist and verifies patches against adversarial exploits before ever touching production.

## What It Does
**VulnOS 2.0** is an autonomous security kernel that:
1. **Parses & Slices Code:** Uses deterministic AST analysis (`tree-sitter` and `Semgrep`) to extract compact taint-flow slices, saving ~85% of context window tokens.
2. **Triages with Nemotron-Nano:** Routes static alerts to NVIDIA Nemotron-Nano on Nebius Token Factory to filter false positives at high speed.
3. **Enriches via Tavily:** Queries live NVD databases and GitHub Security Advisories using `tavily.search()` and `tavily.extract()` for post-training-cutoff zero-day grounding.
4. **Proves & Patches (Red-vs-Blue):** Spawns an adversarial Red-Team agent to write a sandboxed PoC exploit test (which must fail on unpatched code) and a Blue-Team agent to synthesize a surgical patch.
5. **Verifies in Sandbox:** Runs the complete verification protocol inside an isolated, network-disabled Docker container.

## How We Built It
- **Dev 1 (Orchestration & AST):** Python, LangGraph state machine, Semgrep/tree-sitter taint analysis.
- **Dev 2 (AI & Intelligence):** Async OpenAI-compatible client targeting Nebius Token Factory (`api.tokenfactory.nebius.com/v1/`) with Nemotron-Nano and Nemotron-Ultra, plus Tavily API integration.
- **Dev 3 (Systems & Sandbox):** Docker SDK container manager with strict memory/CPU quotas and network isolation (`--network none`).
- **Dev 4 (Telemetry & Storytelling):** Real-time event bus, telemetry HUD, comprehensive test suite (94 passing tests), and public GitHub repository (`https://github.com/bwanox/vulnos-2.0`).

## Accomplishments That We're Proud Of
- Achieving 100% test coverage with **94 passing unit and integration tests**.
- Successfully demonstrating closed-loop self-healing patch retries when sandbox verifications encounter compiler or test regressions.
- Proving enterprise inference economics on Nebius Token Factory with real-time cost and token telemetry.

## What We Learned
Combining deterministic static analysis with multi-tier neural reasoning and live web threat intelligence creates a remarkably robust agentic runtime capable of securing complex polyglot codebases.
