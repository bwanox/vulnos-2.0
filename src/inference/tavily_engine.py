"""Tavily threat intelligence pipeline for CVE and advisory grounding."""

from __future__ import annotations

import asyncio
import re
from typing import Any

from tavily import TavilyClient

from src.common.config import TavilyConfig
from src.common.models import (
    AgentState,
    DependencyInfo,
    TavilyIntelligence,
    VulnAssessment,
)
from src.inference.exceptions import ConfigError, ThreatIntelError
from src.inference.telemetry import TelemetryEmitter


class TavilyThreatEngine:
    """Performs live threat intelligence search and extraction using Tavily."""

    def __init__(
        self,
        config: TavilyConfig,
        emitter: TelemetryEmitter | None = None,
    ) -> None:
        if not config.api_key:
            raise ConfigError("Tavily API key is required (TAVILY_API_KEY)")
        self.config = config
        self.emitter = emitter or TelemetryEmitter()
        self._tavily = TavilyClient(api_key=config.api_key)

    def _build_queries(
        self,
        assessment: VulnAssessment,
        dependencies: list[DependencyInfo] | None = None,
    ) -> list[str]:
        queries = []
        if assessment.cwe_id and assessment.vulnerability_type:
            queries.append(
                f"{assessment.cwe_id} {assessment.vulnerability_type} mitigation CVE security advisory"
            )
        elif assessment.vulnerability_type:
            queries.append(
                f"{assessment.vulnerability_type} vulnerability patch CVE"
            )

        if dependencies:
            for dep in dependencies:
                queries.append(
                    f"{dep.name} {dep.current_version} vulnerability CVE security advisory"
                )

        if not queries:
            queries.append("software vulnerability CVE mitigation pattern")

        return queries

    async def search_threat_intel(
        self,
        assessment: VulnAssessment,
        dependencies: list[DependencyInfo] | None = None,
    ) -> TavilyIntelligence:
        """Query Tavily search and extract APIs for live threat intelligence."""
        queries = self._build_queries(assessment, dependencies)
        fetched_urls: list[str] = []
        all_content: list[str] = []

        try:
            for query in queries:
                search_response = await asyncio.to_thread(
                    self._tavily.search,
                    query=query,
                    search_depth="advanced",
                    max_results=3,
                    include_domains=[
                        "nvd.nist.gov",
                        "github.com",
                        "cve.org",
                        "osv.dev",
                    ],
                )
                results = search_response.get("results", [])
                for r in results:
                    url = r.get("url")
                    content = r.get("content")
                    if url and url not in fetched_urls:
                        fetched_urls.append(url)
                    if content:
                        all_content.append(content)

            # Extract full content from top URLs if any found
            if fetched_urls:
                top_urls = fetched_urls[:3]
                extract_response = await asyncio.to_thread(
                    self._tavily.extract,
                    urls=top_urls,
                )
                extract_results = extract_response.get("results", [])
                for er in extract_results:
                    raw = er.get("raw_content")
                    if raw:
                        all_content.append(raw)

            # Include URLs in text searchable corpus so CVE IDs in URLs are captured
            combined_text = "\n".join(all_content + fetched_urls)

            # Parse CVE IDs via regex
            cve_ids = list(
                set(re.findall(r"CVE-\d{4}-\d{4,}", combined_text, re.IGNORECASE))
            )
            # Normalize to uppercase
            cve_ids = [c.upper() for c in cve_ids]

            # Look for safe version patterns
            safe_version = ""
            version_match = re.search(
                r"(?:fixed in|upgrade to|safe version[:\s]+)([v\d\.]+)",
                combined_text,
                re.IGNORECASE,
            )
            if version_match:
                safe_version = version_match.group(1)

            # Emit telemetry
            self.emitter.emit(
                state=AgentState.TAVILY_ENRICH,
                model_used="tavily-search-extract",
                tokens_used=0,
                latency_ms=0.0,
                cost_estimate=0.0,
                tavily_urls=fetched_urls,
            )

            return TavilyIntelligence(
                cve_ids=cve_ids,
                advisory_urls=fetched_urls,
                safe_version=safe_version,
                mitigation_pattern=combined_text[:1000],  # summary snippet
                raw_context=combined_text,
            )

        except Exception as e:
            # Graceful degradation: log/return empty intel rather than crashing pipeline
            return TavilyIntelligence(
                raw_context=f"Tavily threat intel fetch encountered error: {e}"
            )
