"""FastAPI entrypoint exposing health, verification, assessment, and OpenAPI endpoints."""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from src.application.assess_vendor import AssessVendorUseCase
from src.application.verify_vendor import VerifyVendorUseCase
from src.domain.assessment import StackginiAssessment, VendorInput
from src.domain.models import EvidenceLedger, VendorClaim, VerifiedFinding
from src.domain.rules import default_vendor_rules
from src.infrastructure.composite_research import FallbackResearchAdapter
from src.infrastructure.dns_subprocessor import CuratedSubprocessorAdapter, DnsResolverAdapter
from src.infrastructure.gemini_research import GeminiWebResearchAdapter
from src.infrastructure.http_probes import CrtShHttpAdapter, RdapHttpAdapter, WaybackHttpAdapter
from src.infrastructure.openrouter_research import OpenRouterWebResearchAdapter
from src.infrastructure.playwright_dom import PlaywrightDomAdapter
from src.infrastructure.public_research import PublicSignalsResearchAdapter
from src.infrastructure.ssrf import normalize_public_domain
from src.ports.probes import VendorProbeGateway
from src.ports.research import ResearchGateway


class VerifyVendorRequest(BaseModel):
    """Inbound payload for 5-signal domain verification."""

    domain: str
    claimed_since_year: int | None = None


class FindingPayload(BaseModel):
    """Serialized URL-backed finding."""

    rule_id: str
    claim: str
    source_url: str
    observed_fact: str
    impact: int


class VerifyVendorResponse(BaseModel):
    """Deterministic verification report."""

    domain: str
    trust_score: int
    verdict: str
    findings: list[FindingPayload]
    abstained_signals: list[str]


class AssessVendorRequest(BaseModel):
    """Inbound payload for full Stackgini vendor assessment."""

    url: str
    product: str
    vendor: str
    row_id: str = "1"


class AssessVendorResponse(BaseModel):
    """Full Stackgini assessment response with cited sources."""

    id: str
    url: str
    product: str
    vendor: str
    overall: str
    green_flags: list[str]
    yellow_flags: list[str]
    red_flags: list[str]
    reasoning: str
    source_urls: list[str]


def _serialize_finding(finding: VerifiedFinding) -> FindingPayload:
    return FindingPayload(
        rule_id=finding.rule_id,
        claim=finding.claim,
        source_url=finding.source_url,
        observed_fact=finding.observed_fact,
        impact=finding.impact,
    )


def _serialize_ledger(domain: str, ledger: EvidenceLedger) -> VerifyVendorResponse:
    return VerifyVendorResponse(
        domain=domain,
        trust_score=ledger.trust_score(),
        verdict=ledger.verdict().value,
        findings=[_serialize_finding(item) for item in ledger.findings],
        abstained_signals=list(ledger.abstained),
    )


def _serialize_assessment(assessment: StackginiAssessment) -> AssessVendorResponse:
    return AssessVendorResponse(
        id=assessment.item.row_id,
        url=assessment.item.url,
        product=assessment.item.product,
        vendor=assessment.item.vendor,
        overall=assessment.overall.value,
        green_flags=list(assessment.green_flags),
        yellow_flags=list(assessment.yellow_flags),
        red_flags=list(assessment.red_flags),
        reasoning=assessment.reasoning,
        source_urls=list(assessment.source_urls),
    )


def _default_use_case(current_year: int) -> VerifyVendorUseCase:
    transport = httpx.AsyncHTTPTransport(local_address=str(ipaddress.IPv4Address(0)))
    client = httpx.AsyncClient(transport=transport, headers={"User-Agent": "StackginiVerifier/0.2"})
    gateway = VendorProbeGateway(
        rdap=RdapHttpAdapter(client, current_year=current_year),
        certs=CrtShHttpAdapter(client),
        dns=DnsResolverAdapter(),
        subprocessor=CuratedSubprocessorAdapter({}),
        wayback=WaybackHttpAdapter(client),
    )
    return VerifyVendorUseCase(gateway=gateway, rules=default_vendor_rules())


def build_default_assess_use_case(current_year: int, api_key: str | None = None) -> AssessVendorUseCase:
    """Wire full Stackgini assessment use case with live adapters."""
    verify_use_case = _default_use_case(current_year)
    research_chain = FallbackResearchAdapter(
        (
            OpenRouterWebResearchAdapter(),
            GeminiWebResearchAdapter(api_key=api_key),
            PublicSignalsResearchAdapter(),
        )
    )
    research_gateway = ResearchGateway(
        page=PlaywrightDomAdapter(),
        research=research_chain,
    )
    return AssessVendorUseCase(verify_use_case=verify_use_case, gateway=research_gateway)


def _safe_domain_or_422(raw_domain: str) -> str:
    try:
        return normalize_public_domain(raw_domain)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def _register_verify_route(app: FastAPI, use_case: VerifyVendorUseCase | None) -> None:
    @app.post("/api/v1/verify", response_model=VerifyVendorResponse)
    async def verify_vendor(payload: VerifyVendorRequest) -> VerifyVendorResponse:
        domain = _safe_domain_or_422(payload.domain)
        year = datetime.now(tz=UTC).year
        active_use_case = use_case or _default_use_case(year)
        claim = VendorClaim(domain=domain, current_year=year, claimed_since_year=payload.claimed_since_year)
        ledger = await active_use_case.execute(claim)
        return _serialize_ledger(domain, ledger)


def _register_assess_route(app: FastAPI, assess_use_case: AssessVendorUseCase | None) -> None:
    @app.post("/api/v1/assess", response_model=AssessVendorResponse)
    async def assess_vendor(payload: AssessVendorRequest) -> AssessVendorResponse:
        _safe_domain_or_422(payload.url)
        year = datetime.now(tz=UTC).year
        active_assess = assess_use_case or build_default_assess_use_case(year)
        item = VendorInput(payload.row_id, payload.url, payload.product, payload.vendor)
        assessment = await active_assess.execute(item, current_year=year)
        return _serialize_assessment(assessment)


def create_app(
    use_case: VerifyVendorUseCase | None = None,
    assess_use_case: AssessVendorUseCase | None = None,
) -> FastAPI:
    """Construct the Stackgini Vendor Verifier FastAPI application."""
    app = FastAPI(
        title="Stackgini Vendor Verifier",
        version="0.2.0",
        openapi_url="/api/openapi.json",
        docs_url="/api/docs",
    )

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    _register_verify_route(app, use_case)
    _register_assess_route(app, assess_use_case)
    return app


app = create_app()
