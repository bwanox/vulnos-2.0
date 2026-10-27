"""Basic tests for shared data models."""

from src.common.models import AgentState, CodeSlice, VulnAssessment


def test_agent_state_values():
    assert AgentState.INGEST == "INGEST"
    assert AgentState.COMPLETE == "COMPLETE"


def test_code_slice_creation():
    s = CodeSlice(
        file_path="app.py",
        function_name="get_user",
        function_body="def get_user(id): ...",
    )
    assert s.file_path == "app.py"
    assert s.imports == []


def test_vuln_assessment_defaults():
    s = CodeSlice(file_path="x.py", function_name="f", function_body="...")
    v = VulnAssessment(slice=s, is_vulnerable=True, confidence=0.95)
    assert v.is_vulnerable
    assert v.cwe_id == ""
