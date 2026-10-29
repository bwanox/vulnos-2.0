"""Tests for the deterministic AST taint slicer (Dev 1).

Scans the deliberately vulnerable fixture at ``examples/vulnerable_app`` and
asserts that real sources reach real sinks, that safe parameterized queries are
not flagged, and that slicing is deterministic and offline.
"""

from __future__ import annotations

from pathlib import Path

from vulnos.core.contracts import SinkType
from vulnos.core.slicer import scan_repo

FIXTURE = Path(__file__).resolve().parents[2] / "examples" / "vulnerable_app"


def _slices_by_function(slices):
    return {s.function_name: s for s in slices}


def test_slicer_flags_command_injection():
    slices = scan_repo(FIXTURE)
    by_fn = _slices_by_function(slices)

    assert "ping" in by_fn, f"expected a ping slice, got: {list(by_fn)}"
    ping = by_fn["ping"]
    assert ping.sink_type == SinkType.SUBPROCESS
    assert "subprocess" in ping.function_body
    assert "shell=True" in ping.function_body
    assert ping.entry_point == "/ping"
    assert ping.sink_line is not None


def test_slicer_flags_sql_injection():
    slices = scan_repo(FIXTURE)
    by_fn = _slices_by_function(slices)

    assert "user" in by_fn, f"expected a user slice, got: {list(by_fn)}"
    user = by_fn["user"]
    assert user.sink_type == SinkType.SQL_BUILD
    assert "WHERE id = " + "user_id" in user.function_body or "+ user_id" in user.function_body


def test_slicer_flags_file_open():
    slices = scan_repo(FIXTURE)
    by_fn = _slices_by_function(slices)

    assert "open_file" in by_fn, f"expected an open_file slice, got: {list(by_fn)}"
    assert by_fn["open_file"].sink_type == SinkType.FILE_OPEN


def test_slicer_does_not_flag_parameterized_query():
    """user_safe uses ? placeholders — must NOT be flagged as a sink."""
    slices = scan_repo(FIXTURE)
    by_fn = _slices_by_function(slices)
    assert "user_safe" not in by_fn, (
        f"false positive: user_safe was sliced: {by_fn['user_safe'].context_snippet}"
    )


def test_slices_have_required_fields():
    slices = scan_repo(FIXTURE)
    assert slices, "expected at least one slice"
    for s in slices:
        assert s.slice_id
        assert s.file_path
        assert s.start_line >= 1
        assert s.end_line >= s.start_line
        assert s.function_name
        assert s.function_body
        assert s.language == "python"
        assert isinstance(s.imports, list)
        assert isinstance(s.context_snippet, str)
        assert s.sink_line is not None and s.sink_line >= 1


def test_slicer_is_deterministic():
    first = scan_repo(FIXTURE)
    second = scan_repo(FIXTURE)
    assert [(s.file_path, s.start_line, s.sink_type, s.function_name) for s in first] == [
        (s.file_path, s.start_line, s.sink_type, s.function_name) for s in second
    ]


def test_scan_nonexistent_repo_returns_empty():
    assert scan_repo(Path("/tmp/opencode/does-not-exist-12345")) == []
