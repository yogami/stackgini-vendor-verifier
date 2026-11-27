"""ISP-compliant secondary ports for rendered page forensics and web research."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from src.domain.assessment import DomForensics, VendorInput, WebIntelligence
from src.domain.models import ProbeOutcome


class RenderedPagePort(Protocol):
    """Port for headless browser DOM inspection."""

    async def inspect_page(self, url: str) -> ProbeOutcome[DomForensics]:
        """Render url and extract DOM forensics."""
        ...


class WebResearchPort(Protocol):
    """Port for off-site grounded vendor research."""

    async def research_vendor(self, item: VendorInput, dom_excerpt: str) -> ProbeOutcome[WebIntelligence]:
        """Run grounded web research for vendor and return cited findings."""
        ...


@dataclass(frozen=True)
class ResearchGateway:
    """Browser and web research ports injected into AssessVendorUseCase."""

    page: RenderedPagePort
    research: WebResearchPort
