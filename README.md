# VulnOS 2.0: Autonomous Red-vs-Blue Security & Patching Kernel

> **Nebius × NVIDIA Global AI Hackathon** — Coding and Agentic Engineering Track

An autonomous, closed-loop security runtime that parses codebases via deterministic AST analysis, enriches zero-day and CVE context live via the Tavily API, proves exploitability using an adversarial Red-Team agent, and synthesizes regression-tested patches inside an isolated sandbox—powered by multi-tier NVIDIA Nemotron models on Nebius Token Factory.

```
AST Slicing → Nemotron-Nano Triage → Tavily Live CVE Sync → Red-Team PoC Exploit → Nemotron-Ultra Patch → Verified PR
```

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────────┐
│  TELEMETRY & COMMAND HUD (Next.js / Textual TUI)                       │
│  Live Cost/Latency Savings │ Red-vs-Blue Logs │ Side-by-Side Git Diff  │
└──────────────────────────────────┬───────────────────────────────────────┘
                                   │ WebSockets / Event Bus
┌──────────────────────────────────┴───────────────────────────────────────┐
│  AST & STATE ORCHESTRATOR (LangGraph + Tree-Sitter)                     │
│  Call Graphs → Taint Slices → Red/Blue Retry Loops                      │
└──────────┬──────────────────────────────────────┬────────────────────────┘
           │                                      │
┌──────────┴──────────────────┐    ┌──────────────┴───────────────────────┐
│  HYBRID INFERENCE & THREAT  │    │  EPHEMERAL SANDBOX VERIFIER          │
│  ENGINE                     │    │  - Isolated Docker Container Runner  │
│  - Nebius Token Factory     │    │  - Runs Red-Team Exploit + Pytest    │
│    (Nano vs Ultra routing)  │    │  - 3-step verification protocol      │
│  - Tavily Live CVE/Advisory │    │  - Automated PR generation           │
└─────────────────────────────┘    └──────────────────────────────────────┘
```

## Key Features

- **Red-vs-Blue Adversarial Verification:** Red-Team agent writes PoC exploits; Blue-Team agent patches; patch verified only when exploit is blocked AND all tests pass.
- **Deterministic AST + Neural Triage:** `tree-sitter` and `Semgrep` extract taint-flow slices, routed to Nemotron-Nano for fast false-positive filtering (~85% token savings).
- **Zero-Day Reachability via Tavily:** Live CVE, GHSA, and changelog intelligence via `tavily.search()` + `tavily.extract()` for post-training-cutoff vulnerability data.
- **Multi-Tier Inference Cost Optimization:** ~80% of triage on Nemotron-Nano, ~20% complex reasoning on Nemotron-Ultra with live cost/latency telemetry.
- **Edge-Ready Design:** Phase 1 AST slicer + Nano triage designed to run on NVIDIA Jetson Orin Nano for air-gapped environments.

## Project Structure

```
vulnos-2.0/
├── src/
│   ├── orchestrator/       # Dev 1: AST Slicer & Agent State Machine
│   ├── inference/          # Dev 2: Nebius Router & Tavily Threat Engine
│   ├── sandbox/            # Dev 3: Docker Sandbox & Red/Blue Runner
│   ├── telemetry/          # Dev 4: Real-Time Telemetry HUD
│   └── common/             # Shared types, configs, utilities
├── vulnerable_app/         # Curated demo repo with intentional flaws
│   ├── app/                # Target microservice
│   └── tests/              # Existing unit tests
├── tests/
│   ├── unit/               # Unit tests
│   └── integration/        # Integration tests
├── docs/                   # Architecture docs, team interfaces
├── scripts/                # Dev tooling, setup scripts
└── .github/workflows/      # CI/CD pipelines
```

## Team Roles & Module Ownership

| Dev | Module | Responsibility |
|-----|--------|---------------|
| **Dev 1** | `src/orchestrator/` | AST Slicer, LangGraph state machine, event emitter |
| **Dev 2** | `src/inference/` | Nebius Token Factory router, Tavily threat pipeline, prompt engineering |
| **Dev 3** | `src/sandbox/` | Docker sandbox, Red/Blue verification protocol, PR generator |
| **Dev 4** | `src/telemetry/` | Real-time HUD, demo repo, 3-min video |

## Quick Start

```bash
# Clone the repository
git clone https://github.com/bwanox/vulnos-2.0.git
cd vulnos-2.0

# Install dependencies
pip install -e ".[dev]"

# Set environment variables
cp .env.example .env
# Edit .env with your Nebius, Tavily, and GitHub API keys

# Build the approved offline sandbox runtime
docker build -f docker/python-pytest.Dockerfile -t vulnos/python:3.12 .

# Run the orchestrator
python -m src.orchestrator.main --repo ./vulnerable_app

# Launch the telemetry HUD
python -m src.telemetry.main
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `NEBIUS_API_KEY` | Nebius Token Factory API key |
| `TAVILY_API_KEY` | Tavily Search & Extract API key |
| `GITHUB_TOKEN` | GitHub Personal Access Token (for PR creation) |

## Prize Track Alignment

- **Grand Prize ($20,000):** Enterprise inference economics on Nebius with live cost/latency counters
- **Coding Track (Jetson Orin Nano):** Edge-deployable AST slicer + Nano triage layer
- **Best Use of Tavily ($3,000):** Deep `search` + `extract` integration for live CVE grounding

## License

MIT License — see [LICENSE](LICENSE) for details.
