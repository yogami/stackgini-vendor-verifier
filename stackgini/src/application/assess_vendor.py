"""Application use case orchestrating probes, Playwright DOM, and web intelligence."""

from __future__ import annotations

import asyncio

from src.application.verify_vendor import VerifyVendorUseCase
from src.domain.assessment import (
    DomForensics,
    StackginiAssessment,
    VendorInput,
    assess_from_evidence,
    extract_domain_from_url,
)
from src.domain.models import ProbeOutcome, ProbeStatus, VendorClaim
from src.ports.research import ResearchGateway

MAX_DOM_EXCERPT_CHARS = 3000


def _format_dom_excerpt(dom: ProbeOutcome[DomForensics]) -> str:
    if dom.status != ProbeStatus.OBSERVED or dom.value is None:
        return f"DOM unavailable: {dom.reason}"
    info = dom.value
    excerpt = info.visible_text[:MAX_DOM_EXCERPT_CHARS]
    return (
        f"final_url={info.final_url} | title={info.title} | dead_social_links={info.dead_social_links} "
        f"| legal_docs={info.legal_doc_urls} | spa={info.is_js_spa_shell()} | text={excerpt}"
    )


class AssessVendorUseCase:
    """Coordinate infrastructure probes, rendered DOM checks, and grounded web research."""

    def __init__(self, verify_use_case: VerifyVendorUseCase, gateway: ResearchGateway) -> None:
        self._verify = verify_use_case
        self._gateway = gateway

    async def execute(self, item: VendorInput, current_year: int) -> StackginiAssessment:
        """Assess a vendor row across all technical and off-site signals."""
        domain = extract_domain_from_url(item.url)
        claim = VendorClaim(domain=domain, current_year=current_year)
        ledger, dom = await asyncio.gather(
            self._verify.execute(claim),
            self._gateway.page.inspect_page(item.url),
        )
        research = await self._gateway.research.research_vendor(item, _format_dom_excerpt(dom))
        return assess_from_evidence(item, ledger, dom, research)
