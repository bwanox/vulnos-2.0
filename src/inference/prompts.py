"""Prompt templates for triage, Red-Team exploitation, and Blue-Team patching."""

from __future__ import annotations

from src.common.models import (
    CodeSlice,
    ExploitTest,
    TavilyIntelligence,
    VulnAssessment,
)


def build_triage_messages(slice_obj: CodeSlice) -> list[dict[str, str]]:
    """Build messages for Nemotron-Nano triage."""
    system_prompt = (
        "You are an expert static security analyst. "
        "Analyze the provided code slice and determine if it contains a genuine security vulnerability "
        "(e.g., SQL injection, command injection, path traversal, deserialization flaw). "
        "Filter out false positives where sanitization or upstream validation already neutralizes the sink. "
        "You must respond with valid JSON matching this schema:\n"
        "{\n"
        '  "is_vulnerable": boolean,\n'
        '  "confidence": float (0.0 to 1.0),\n'
        '  "vulnerability_type": string,\n'
        '  "cwe_id": string,\n'
        '  "reasoning": string\n'
        "}"
    )

    user_content = (
        f"File Path: {slice_obj.file_path}\n"
        f"Function Name: {slice_obj.function_name}\n"
        f"Sink Type: {slice_obj.sink_type}\n"
        f"Entry Point: {slice_obj.entry_point}\n"
        f"Imports: {', '.join(slice_obj.imports)}\n\n"
        f"Function Body:\n```python\n{slice_obj.function_body}\n```\n\n"
        f"Caller Context:\n```python\n{slice_obj.caller_context}\n```"
    )

    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_content},
    ]


def build_red_team_messages(
    assessment: VulnAssessment,
    intelligence: TavilyIntelligence,
) -> list[dict[str, str]]:
    """Build messages for Red-Team exploit test generation."""
    system_prompt = (
        "You are an adversarial Red-Team penetration testing agent. "
        "Given a vulnerable code slice and live threat intelligence (CVE/advisory context), "
        "write a standalone pytest test function that actively exploits the vulnerability and fails/triggers "
        "on the unpatched code. "
        "You must respond with valid JSON matching this schema:\n"
        "{\n"
        '  "test_code": string (valid python pytest function),\n'
        '  "test_filename": string (e.g., "test_exploit.py"),\n'
        '  "exploit_description": string\n'
        "}"
    )

    user_content = (
        f"Vulnerability Type: {assessment.vulnerability_type} ({assessment.cwe_id})\n"
        f"File: {assessment.slice.file_path}, Function: {assessment.slice.function_name}\n\n"
        f"Code Body:\n```python\n{assessment.slice.function_body}\n```\n\n"
        f"Live Threat Intelligence (Tavily):\n"
        f"CVE IDs: {', '.join(intelligence.cve_ids)}\n"
        f"Mitigation Pattern: {intelligence.mitigation_pattern}\n"
    )

    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_content},
    ]


def build_blue_team_messages(
    assessment: VulnAssessment,
    intelligence: TavilyIntelligence,
    exploit: ExploitTest,
    failed_patch_error: str | None = None,
) -> list[dict[str, str]]:
    """Build messages for Blue-Team patch synthesis."""
    system_prompt = (
        "You are a Blue-Team defensive security engineer. "
        "Given a vulnerable code slice, live threat intelligence, and a Red-Team PoC exploit test, "
        "synthesize a minimal surgical git unified diff or patch that neutralizes the vulnerability "
        "while ensuring all normal execution and existing tests continue to pass. "
        "You must respond with valid JSON matching this schema:\n"
        "{\n"
        '  "diff": string (unified diff format),\n'
        '  "patch_description": string,\n'
        '  "files_modified": array of strings\n'
        "}"
    )

    user_content = (
        f"Vulnerability: {assessment.vulnerability_type} ({assessment.cwe_id})\n"
        f"Target File: {assessment.slice.file_path}\n\n"
        f"Vulnerable Code:\n```python\n{assessment.slice.function_body}\n```\n\n"
        f"Red-Team Exploit Test:\n```python\n{exploit.test_code}\n```\n\n"
        f"Tavily Mitigation Guidance:\n{intelligence.mitigation_pattern}\n"
    )

    if failed_patch_error:
        user_content += (
            f"\n[SELF-HEALING RETRY NOTICE]\n"
            f"Your previous patch attempt failed verification with the following error/traceback:\n"
            f"```\n{failed_patch_error}\n```\n"
            "Analyze why the previous patch failed or caused a regression and produce a corrected patch."
        )

    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_content},
    ]
