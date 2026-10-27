"""Nemotron-Nano triage module with JSON repair and validation."""

from __future__ import annotations

import json

from src.common.models import CodeSlice, VulnAssessment
from src.inference.client import NebisClient
from src.inference.exceptions import ModelResponseError
from src.inference.prompts import build_triage_messages
from src.inference.schemas import TriageResponseSchema


async def triage_slice(client: NebisClient, slice_obj: CodeSlice) -> VulnAssessment:
    """Analyze a CodeSlice using Nemotron-Nano and return a VulnAssessment."""
    messages = build_triage_messages(slice_obj)
    response = await client.complete_nano(
        messages=messages,
        response_format={"type": "json_object"},
    )

    try:
        data = json.loads(response.content)
        parsed = TriageResponseSchema(**data)
    except (json.JSONDecodeError, Exception) as initial_error:
        # Retry once asking model to fix JSON
        repair_messages = list(messages) + [
            {"role": "assistant", "content": response.content},
            {
                "role": "user",
                "content": f"Your response was not valid JSON matching the required schema. Error: {initial_error}. Please output valid JSON only.",
            },
        ]
        response = await client.complete_nano(
            messages=repair_messages,
            response_format={"type": "json_object"},
        )
        try:
            data = json.loads(response.content)
            parsed = TriageResponseSchema(**data)
        except Exception as retry_error:
            raise ModelResponseError(
                f"Failed to parse triage response as JSON after retry: {retry_error}",
                details={"raw_content": response.content},
            ) from retry_error

    return VulnAssessment(
        slice=slice_obj,
        is_vulnerable=parsed.is_vulnerable,
        confidence=parsed.confidence,
        vulnerability_type=parsed.vulnerability_type,
        cwe_id=parsed.cwe_id,
        reasoning=parsed.reasoning,
    )
