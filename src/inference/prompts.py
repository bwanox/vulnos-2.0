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
            "(e.g., '; id' or command substitution) into the target function/endpoint and verifies execution."
        )
    elif vector == "network_socket":
        test_filename_hint = "exploit_net.py"
        runner_hint = "python3 exploit_net.py"
        lang_instructions = (
            "Write a network socket / HTTP fuzzing exploit script (exploit_net.py) using requests or socket "
            "that sends malformed payloads or triggers protocol vulnerabilities against localhost."
        )
    elif vector == "privesc_endpoint":
        test_filename_hint = "exploit_sec.sh"
        runner_hint = "bash exploit_sec.sh"
        lang_instructions = (
            "Write an endpoint security test script (exploit_sec.sh) that validates insecure file permissions, "
            "missing systemd hardening flags, or weak capability assignments."
        )
    elif lang in ("c", "cpp"):
        test_filename_hint = "exploit.c"
        runner_hint = "gcc -o exploit exploit.c && ./exploit"
        lang_instructions = (
            "Write a standalone C/C++ exploit program (exploit.c) that compiles with gcc/g++ "
            "and actively triggers memory corruption or buffer overflow."
        )
    elif lang == "go":
        test_filename_hint = "exploit_test.go"
        runner_hint = "go test -v"
        lang_instructions = "Write a Go unit test file (*_test.go) that triggers the vulnerability."
    else:
        test_filename_hint = "test_exploit.py"
        runner_hint = "pytest"
        lang_instructions = "Write a standalone pytest test function that actively exploits the vulnerability."

    system_prompt = (
        f"You are an adversarial Red-Team penetration testing agent. "
        f"Attack Vector: {vector.upper()}, Language: {lang.upper()}. {lang_instructions} "
        "You must respond with valid JSON matching this schema:\n"
        "{\n"
        f'  "test_code": string (valid exploit code/test harness),\n'
        f'  "test_filename": string (e.g., "{test_filename_hint}"),\n'
        f'  "runner_command": string (e.g., "{runner_hint}"),\n'
        '  "exploit_description": string\n'
        "}"
    )

    user_content = (
        f"Target Language: {lang}\n"
        f"Attack Vector: {vector}\n"
        f"Vulnerability Type: {assessment.vulnerability_type} ({assessment.cwe_id})\n"
        f"File: {assessment.slice.file_path}, Function: {assessment.slice.function_name}\n\n"
        f"Code Body:\n```{lang}\n{assessment.slice.function_body}\n```\n\n"
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
    lang = assessment.slice.target_language.lower()
    vector = assessment.slice.attack_vector.lower()

    hardening_hint = ""
    if vector == "rce_shell":
        hardening_hint = "Ensure all subprocess/shell execution uses shell=False with argument lists, or strict input allowlisting."
    elif vector == "network_socket":
        hardening_hint = "Ensure strict input validation, bounds checking, and protocol deserialization safety."
    elif vector == "privesc_endpoint":
        hardening_hint = "Ensure secure file permissions (chmod 600/700) and systemd security directives."

    system_prompt = (
        f"You are a Blue-Team defensive security engineer specializing in {lang.upper()} systems. "
        f"{hardening_hint} "
        "Given a vulnerable code slice, live threat intelligence, and a Red-Team exploit harness, "
        "synthesize a minimal surgical git unified diff or patch that neutralizes the vulnerability "
        "while ensuring all normal execution and tests continue to pass. "
        "You must respond with valid JSON matching this schema:\n"
        "{\n"
        '  "diff": string (unified diff format),\n'
        '  "patch_description": string,\n'
        '  "files_modified": array of strings\n'
        "}"
    )

    user_content = (
        f"Target Language: {lang}\n"
        f"Attack Vector: {vector}\n"
        f"Vulnerability: {assessment.vulnerability_type} ({assessment.cwe_id})\n"
        f"Target File: {assessment.slice.file_path}\n\n"
        f"Vulnerable Code:\n```{lang}\n{assessment.slice.function_body}\n```\n\n"
        f"Red-Team Exploit Harness ({exploit.test_filename}):\n```{lang}\n{exploit.test_code}\n```\n\n"
        f"Tavily Mitigation Guidance:\n{intelligence.mitigation_pattern}\n"
    )

    if failed_patch_error:
        user_content += (
            f"\n[SELF-HEALING RETRY NOTICE]\n"
            f"Your previous patch attempt failed verification with the following error:\n"
            f"```\n{failed_patch_error}\n```\n"
            "Analyze why the previous patch failed or caused a test regression and produce a corrected patch."
        )

    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_content},
    ]
