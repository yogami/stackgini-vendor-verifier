"""Fallback chain combining primary LLM/search adapters with zero-key public intelligence."""

from __future__ import annotations

from src.domain.assessment import VendorInput, WebIntelligence
from src.domain.models import ProbeOutcome, ProbeStatus
from src.ports.research import WebResearchPort


class FallbackResearchAdapter:
    """Try WebResearchPort providers in priority order until one returns OBSERVED."""

    def __init__(self, providers: tuple[WebResearchPort, ...]) -> None:
        self._providers = providers

    async def research_vendor(self, item: VendorInput, dom_excerpt: str) -> ProbeOutcome[WebIntelligence]:
        """Return first OBSERVED outcome across providers, or last unavailable outcome."""
        last: ProbeOutcome[WebIntelligence] = ProbeOutcome.unavailable("https://news.google.com/", "no_providers")
        for provider in self._providers:
            outcome = await provider.research_vendor(item, dom_excerpt)
            if outcome.status == ProbeStatus.OBSERVED:
                return outcome
            last = outcome
        return last
