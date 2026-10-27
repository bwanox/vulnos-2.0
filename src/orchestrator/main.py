"""Dev 1: AST Slicer & Agent State Machine.

Core orchestrator that:
- Parses target repos via tree-sitter / Semgrep
- Extracts taint-flow slices
- Manages the cyclic state machine (LangGraph)
- Emits telemetry events at every transition
"""
