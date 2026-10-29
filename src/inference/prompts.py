"""Prompt templates for triage, Red-Team exploitation, and Blue-Team patching."""

from __future__ import annotations

from src.common.models import (
    EXPLOIT_FAILURE_MARKER,
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
        "(e.g., SQL injection, command injection, path traversal, buffer overflow, RCE, network flaw). "
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
        f"Target Language: {slice_obj.target_language}\n"
        f"Attack Vector: {slice_obj.attack_vector}\n"
        f"File Path: {slice_obj.file_path}\n"
        f"Function Name: {slice_obj.function_name}\n"
        f"Sink Type: {slice_obj.sink_type}\n"
        f"Entry Point: {slice_obj.entry_point}\n"
        f"Imports: {', '.join(slice_obj.imports)}\n\n"
        f"Function Body:\n```{slice_obj.target_language}\n{slice_obj.function_body}\n```\n\n"
        f"Caller Context:\n```{slice_obj.target_language}\n{slice_obj.caller_context}\n```"
    )

    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_content},
    ]


def build_red_team_messages(
    assessment: VulnAssessment,
    intelligence: TavilyIntelligence,
) -> list[dict[str, str]]:
    """Build messages for Red-Team exploit test or harness generation."""
    lang = assessment.slice.target_language.lower()
    vector = assessment.slice.attack_vector.lower()

    if vector == "rce_shell":
        test_filename_hint = "exploit_rce.py"
        runner_hint = "python3 exploit_rce.py"
        lang_instructions = (
            "Write a standalone Python exploit script (exploit_rce.py) that injects shell commands "
            "(e.g., '; id' or command substitution) into the target function/endpoint and verifies execution. "
            f"The failure message must include '{EXPLOIT_FAILURE_MARKER}'."
        )
    elif vector == "network_socket":
        test_filename_hint = "exploit_net.py"
        runner_hint = "python3 exploit_net.py"
        lang_instructions = (
            "Write a network socket / HTTP fuzzing exploit script (exploit_net.py) using requests or socket "
            "that sends malformed payloads or triggers protocol vulnerabilities against localhost. "
            f"The failure message must include '{EXPLOIT_FAILURE_MARKER}'."
        )
    elif vector == "privesc_endpoint":
        test_filename_hint = "exploit_sec.sh"
        runner_hint = "bash exploit_sec.sh"
        lang_instructions = (
            "Write an endpoint security test script (exploit_sec.sh) that validates insecure file permissions, "
            "missing systemd hardening flags, or weak capability assignments. "
            f"The failure message must include '{EXPLOIT_FAILURE_MARKER}'."
        )
    elif lang in ("c", "cpp"):
        test_filename_hint = "exploit.c"
        runner_hint = "gcc -o exploit exploit.c && ./exploit"
        lang_instructions = (
            "Write a standalone C/C++ exploit program (exploit.c) that compiles with gcc/g++ "
            "and actively triggers memory corruption or buffer overflow. "
            f"The failure message must include '{EXPLOIT_FAILURE_MARKER}'."
        )
    elif lang == "go":
        test_filename_hint = "exploit_test.go"
        runner_hint = "go test -v"
        lang_instructions = (
            "Write a Go unit test file (*_test.go) that triggers the vulnerability. "
            f"The failure message must include '{EXPLOIT_FAILURE_MARKER}'."
        )
    else:
        test_filename_hint = "test_exploit.py"
        runner_hint = "pytest"
        lang_instructions = (
            "write exactly one standalone pytest test function that fails on the unpatched code "
            "only because its vulnerability-specific assertion fails. The assertion message for that "
            f"expected failure must begin with '{EXPLOIT_FAILURE_MARKER}'. "
            "The same test must pass after the vulnerability is fixed. "
            "Do not use crashes, import errors, or setup failures as evidence of exploitability."
        )

    system_prompt = (
        "You are an adversarial Red-Team penetration testing agent. "
        f"Given a vulnerable code slice and live threat intelligence (CVE/advisory context), {lang_instructions} "
        "You must respond with valid JSON matching this schema:\n"
        "{\n"
        f'  "test_code": string (valid exploit code/test harness),\n'
        f'  "test_filename": string (e.g., "{test_filename_hint}"),\n'
        f'  "runner_command": string (e.g., "{runner_hint}"),\n'
        '  "exploit_description": string\n'
        "}\n"
        "The test file is copied into the repository workspace root before execution. "
        "Import the target application using repository-relative imports (for the demo app, "
        "use `from app.main import app`); do not assume the original absolute path or add "
        "an examples/ prefix. Use only the fixed pytest runner supplied by the verifier."
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
        "Set the `diff` field to a valid unified diff accepted by `git apply`; do not use search/replace blocks. "
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
