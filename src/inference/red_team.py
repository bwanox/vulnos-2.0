"""Red-Team PoC exploit test generator using Nemotron-Ultra."""

from __future__ import annotations

import json

from src.common.models import (
    AgentState,
    ExploitTest,
    TavilyIntelligence,
    VulnAssessment,
)
from src.inference.client import NebisClient
from src.inference.exceptions import ModelResponseError
from src.inference.prompts import build_red_team_messages
from src.inference.schemas import ExploitResponseSchema


async def generate_exploit(
    client: NebisClient,
    assessment: VulnAssessment,
    intelligence: TavilyIntelligence,
) -> ExploitTest:
    """Generate a Red-Team PoC exploit test using Nemotron-Ultra."""
    messages = build_red_team_messages(assessment, intelligence)
    response = await client.complete_ultra(
        messages=messages,
        response_format={"type": "json_object"},
        state=AgentState.RED_TEAM_EXPLOIT,
    )

    try:
        data = json.loads(response.content)
        parsed = ExploitResponseSchema(**data)
    except (json.JSONDecodeError, Exception) as initial_error:
        repair_messages = list(messages) + [
            {"role": "assistant", "content": response.content},
            {
                "role": "user",
                "content": f"Response was not valid JSON. Error: {initial_error}. Output valid JSON matching schema.",
            },
        ]
        response = await client.complete_ultra(
            messages=repair_messages,
            response_format={"type": "json_object"},
            state=AgentState.RED_TEAM_EXPLOIT,
        )
        try:
            data = json.loads(response.content)
            parsed = ExploitResponseSchema(**data)
        except Exception as retry_error:
            raise ModelResponseError(
                f"Failed to parse exploit response as JSON: {retry_error}",
                details={"raw_content": response.content},
            ) from retry_error

    return ExploitTest(
        test_code=parsed.test_code,
        test_filename=parsed.test_filename or "test_exploit.py",
        exploit_description=parsed.exploit_description,
    )
