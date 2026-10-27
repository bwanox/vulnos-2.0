"""Blue-Team patch synthesizer using Nemotron-Ultra with self-healing retry support."""

from __future__ import annotations

import json

from src.common.models import (
    AgentState,
    ExploitTest,
    PatchDiff,
    TavilyIntelligence,
    VulnAssessment,
)
from src.inference.client import NebisClient
from src.inference.exceptions import ModelResponseError
from src.inference.prompts import build_blue_team_messages
from src.inference.schemas import PatchResponseSchema


async def generate_patch(
    client: NebisClient,
    assessment: VulnAssessment,
    intelligence: TavilyIntelligence,
    exploit: ExploitTest,
    failed_patch_error: str | None = None,
) -> PatchDiff:
    """Generate a Blue-Team patch diff using Nemotron-Ultra."""
    messages = build_blue_team_messages(
        assessment, intelligence, exploit, failed_patch_error
    )
    response = await client.complete_ultra(
        messages=messages,
        response_format={"type": "json_object"},
        state=AgentState.BLUE_TEAM_PATCH,
    )

    try:
        data = json.loads(response.content)
        parsed = PatchResponseSchema(**data)
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
            state=AgentState.BLUE_TEAM_PATCH,
        )
        try:
            data = json.loads(response.content)
            parsed = PatchResponseSchema(**data)
        except Exception as retry_error:
            raise ModelResponseError(
                f"Failed to parse patch response as JSON: {retry_error}",
                details={"raw_content": response.content},
            ) from retry_error

    return PatchDiff(
        diff=parsed.diff,
        patch_description=parsed.patch_description,
        files_modified=parsed.files_modified,
    )
