"""FastAPI entrypoint exposing dashboard UI, health, verification, assessment, and OpenAPI."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from src.api.dashboard import render_dashboard_html
from src.application.assess_vendor import AssessVendorUseCase
from src.application.verify_vendor import VerifyVendorUseCase
from src.domain.assessment import StackginiAssessment, VendorInput
from src.domain.models import EvidenceLedger, VendorClaim, VerifiedFinding
from src.domain.rules import default_vendor_rules
from src.infrastructure.composite_research import FallbackResearchAdapter
from src.infrastructure.dns_subprocessor import DnsResolverAdapter, PublicSubprocessorAdapter
from src.infrastructure.gemini_research import GeminiWebResearchAdapter
from src.infrastructure.http_probes import (
    CrtShHttpAdapter,
    RdapHttpAdapter,
    RdapWithWhoisAdapter,
    WaybackHttpAdapter,
    make_resilient_async_client,
)
from src.infrastructure.openrouter_research import OpenRouterWebResearchAdapter
from src.infrastructure.playwright_dom import PlaywrightDomAdapter
from src.infrastructure.public_research import PublicSignalsResearchAdapter
from src.infrastructure.ssrf import normalize_public_domain
from src.ports.probes import VendorProbeGateway
from src.ports.research import ResearchGateway

CLIENT_TIMEOUT_SECONDS = 45.0


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
    """Deterministic EvidenceLedger response."""

    domain: str
    trust_score: int
    verdict: str
    findings: list[FindingPayload]
    abstained_signals: list[str]


class AssessVendorRequest(BaseModel):
    """Inbound payload for full Stackgini vendor assessment."""

    row_id: str = "1"
    url: str
    product: str
    vendor: str


class AssessVendorResponse(BaseModel):
    """Full Stackgini vendor verdict with URL citations and technical probe breakdown."""

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
    trust_score: int = 70
    infra_verdict: str = "verified"
    findings: list[FindingPayload] = Field(default_factory=list)
    abstained_signals: list[str] = Field(default_factory=list)
    dom_summary: str = ""


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
    ledger = assessment.ledger
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
        trust_score=ledger.trust_score(),
        infra_verdict=ledger.verdict().value,
        findings=[_serialize_finding(f) for f in ledger.findings],
        abstained_signals=list(ledger.abstained),
        dom_summary=assessment.dom_summary,
    )


def build_verify_use_case(current_year: int, client: httpx.AsyncClient) -> VerifyVendorUseCase:
    """Wire five live infrastructure probes using the caller-managed AsyncClient."""
    rdap = RdapWithWhoisAdapter(RdapHttpAdapter(client, current_year=current_year), current_year=current_year)
    gateway = VendorProbeGateway(
        rdap=rdap,
        certs=CrtShHttpAdapter(client),
        dns=DnsResolverAdapter(),
        subprocessor=PublicSubprocessorAdapter(client),
        wayback=WaybackHttpAdapter(client),
    )
    return VerifyVendorUseCase(gateway=gateway, rules=default_vendor_rules())


def build_default_assess_use_case(
    current_year: int,
    client: httpx.AsyncClient,
    api_key: str | None = None,
) -> AssessVendorUseCase:
    """Wire full Stackgini assessment use case using a managed AsyncClient."""
    verify_use_case = build_verify_use_case(current_year, client)
    research_chain = FallbackResearchAdapter(
        (
            OpenRouterWebResearchAdapter(client=client),
            GeminiWebResearchAdapter(api_key=api_key),
            PublicSignalsResearchAdapter(client=client),
        )
    )
    research_gateway = ResearchGateway(page=PlaywrightDomAdapter(), research=research_chain)
    return AssessVendorUseCase(verify_use_case=verify_use_case, gateway=research_gateway)


def _safe_domain_or_422(raw_domain: str) -> str:
    try:
        return normalize_public_domain(raw_domain)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


async def _run_with_verify_client(
    client: httpx.AsyncClient,
    claim: VendorClaim,
    injected: VerifyVendorUseCase | None,
) -> VerifyVendorResponse:
    uc = injected or build_verify_use_case(claim.current_year, client)
    return _serialize_ledger(claim.domain, await uc.execute(claim))


async def _execute_verify(
    request: Request,
    claim: VendorClaim,
    injected: VerifyVendorUseCase | None,
) -> VerifyVendorResponse:
    shared_client = getattr(request.app.state, "http_client", None)
    if isinstance(shared_client, httpx.AsyncClient):
        return await _run_with_verify_client(shared_client, claim, injected)
    async with make_resilient_async_client(CLIENT_TIMEOUT_SECONDS) as temp_client:
        return await _run_with_verify_client(temp_client, claim, injected)


async def _run_with_assess_client(
    client: httpx.AsyncClient,
    item: VendorInput,
    year: int,
    injected: AssessVendorUseCase | None,
) -> AssessVendorResponse:
    uc = injected or build_default_assess_use_case(year, client)
    return _serialize_assessment(await uc.execute(item, year))


async def _execute_assess(
    request: Request,
    item: VendorInput,
    year: int,
    injected: AssessVendorUseCase | None,
) -> AssessVendorResponse:
    shared_client = getattr(request.app.state, "http_client", None)
    if isinstance(shared_client, httpx.AsyncClient):
        return await _run_with_assess_client(shared_client, item, year, injected)
    async with make_resilient_async_client(CLIENT_TIMEOUT_SECONDS) as temp_client:
        return await _run_with_assess_client(temp_client, item, year, injected)


def _register_ui_and_health(app: FastAPI) -> None:
    @app.get("/", response_class=HTMLResponse)
    async def dashboard() -> HTMLResponse:
        return HTMLResponse(content=render_dashboard_html())

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}


def _register_verify(app: FastAPI, use_case: VerifyVendorUseCase | None) -> None:
    @app.post("/api/v1/verify", response_model=VerifyVendorResponse)
    async def verify_vendor(request: Request, payload: VerifyVendorRequest) -> VerifyVendorResponse:
        domain = _safe_domain_or_422(payload.domain)
        year = datetime.now(tz=UTC).year
        claim = VendorClaim(domain=domain, current_year=year, claimed_since_year=payload.claimed_since_year)
        return await _execute_verify(request, claim, use_case)


def _register_assess(app: FastAPI, assess_use_case: AssessVendorUseCase | None) -> None:
    @app.post("/api/v1/assess", response_model=AssessVendorResponse)
    async def assess_vendor(request: Request, payload: AssessVendorRequest) -> AssessVendorResponse:
        _safe_domain_or_422(payload.url)
        year = datetime.now(tz=UTC).year
        item = VendorInput(payload.row_id, payload.url, payload.product, payload.vendor)
        return await _execute_assess(request, item, year, assess_use_case)


@asynccontextmanager
async def _app_lifespan(fastapi_app: FastAPI) -> AsyncIterator[None]:
    client = make_resilient_async_client(CLIENT_TIMEOUT_SECONDS)
    fastapi_app.state.http_client = client
    try:
        yield
    finally:
        await client.aclose()


def create_app(
    use_case: VerifyVendorUseCase | None = None,
    assess_use_case: AssessVendorUseCase | None = None,
) -> FastAPI:
    """Construct the Stackgini Vendor Verifier FastAPI application."""
    app = FastAPI(
        title="Stackgini Vendor Verifier",
        version="0.3.0",
        openapi_url="/api/openapi.json",
        docs_url="/api/docs",
        lifespan=_app_lifespan,
    )
    _register_ui_and_health(app)
    _register_verify(app, use_case)
    _register_assess(app, assess_use_case)
    return app


app = create_app()
