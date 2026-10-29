"""Tests for systems-security and network attack generation."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock

from src.common.models import CodeSlice, ExploitTest, TavilyIntelligence, VulnAssessment
from src.inference.client import NebisResponse
from src.inference.red_team import generate_exploit


@pytest.fixture
def rce_assessment():
    s = CodeSlice(
        file_path="server.py",
        function_name="run_cmd",
        function_body="os.system(user_input)",
        target_language="python",
        attack_vector="rce_shell",
        sink_type="subprocess",
    )
    return VulnAssessment(slice=s, is_vulnerable=True, confidence=0.99, vulnerability_type="Remote Code Execution", cwe_id="CWE-78")


@pytest.fixture
def net_assessment():
    s = CodeSlice(
        file_path="api.py",
        function_name="handle_packet",
        function_body="pickle.loads(net_data)",
        target_language="python",
        attack_vector="network_socket",
        sink_type="deserializer",
    )
    return VulnAssessment(slice=s, is_vulnerable=True, confidence=0.95, vulnerability_type="Insecure Deserialization", cwe_id="CWE-502")


@pytest.fixture
def sample_intel():
    return TavilyIntelligence(cve_ids=["CVE-2022-9999"], mitigation_pattern="Avoid shell=True and pickle deserialization.")


@pytest.mark.asyncio
async def test_generates_rce_exploit_script(rce_assessment, sample_intel):
    client = AsyncMock()
    client.complete_ultra.return_value = NebisResponse(
        content='{"test_code": "import requests; print(requests.get(\\"http://localhost:8000/cmd?q=id\\").text)", "test_filename": "exploit_rce.py", "runner_command": "python3 exploit_rce.py", "exploit_description": "RCE exploit payload"}',
        model="ultra",
        prompt_tokens=110,
        completion_tokens=55,
        latency_ms=210.0,
        cost=0.0011,
    )

    exploit = await generate_exploit(client, rce_assessment, sample_intel)
    assert isinstance(exploit, ExploitTest)
    assert "requests" in exploit.test_code
    assert exploit.test_filename == "exploit_rce.py"
    assert exploit.attack_vector == "rce_shell"
    assert "python3" in exploit.runner_command


@pytest.mark.asyncio
async def test_generates_network_fuzz_harness(net_assessment, sample_intel):
    client = AsyncMock()
    client.complete_ultra.return_value = NebisResponse(
        content='{"test_code": "import socket, pickle; s = socket.socket(); s.connect((\\"127.0.0.1\\", 9000)); s.send(pickle.dumps(RCE()))", "test_filename": "exploit_net.py", "runner_command": "python3 exploit_net.py", "exploit_description": "Network deserialization fuzzer"}',
        model="ultra",
        prompt_tokens=120,
        completion_tokens=60,
        latency_ms=230.0,
        cost=0.0012,
    )

    exploit = await generate_exploit(client, net_assessment, sample_intel)
    assert isinstance(exploit, ExploitTest)
    assert "socket" in exploit.test_code
    assert exploit.test_filename == "exploit_net.py"
    assert exploit.attack_vector == "network_socket"
