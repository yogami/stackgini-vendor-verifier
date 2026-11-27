"""FastAPI entrypoint exposing health, verification, and OpenAPI schema endpoints."""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from src.application.verify_vendor import VerifyVendorUseCase
from src.domain.models import EvidenceLedger, VendorClaim, VerifiedFinding
from src.domain.rules import default_vendor_rules
from src.infrastructure.dns_subprocessor import CuratedSubprocessorAdapter, DnsResolverAdapter
from src.infrastructure.http_probes import CrtShHttpAdapter, RdapHttpAdapter, WaybackHttpAdapter
from src.infrastructure.ssrf import normalize_public_domain
from src.ports.probes import VendorProbeGateway


class VerifyVendorRequest(BaseModel):
    """Inbound payload for vendor verification."""

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


def _default_use_case(current_year: int) -> VerifyVendorUseCase:
    client = httpx.AsyncClient(headers={"User-Agent": "StackginiVerifier/0.1"})
    gateway = VendorProbeGateway(
        rdap=RdapHttpAdapter(client, current_year=current_year),
        certs=CrtShHttpAdapter(client),
        dns=DnsResolverAdapter(),
        subprocessor=CuratedSubprocessorAdapter({}),
        wayback=WaybackHttpAdapter(client),
    )
    return VerifyVendorUseCase(gateway=gateway, rules=default_vendor_rules())


def _safe_domain_or_422(raw_domain: str) -> str:
    try:
        return normalize_public_domain(raw_domain)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def create_app(use_case: VerifyVendorUseCase | None = None) -> FastAPI:
    """Construct the Stackgini Vendor Verifier FastAPI application."""
    app = FastAPI(
        title="Stackgini Vendor Verifier",
        version="0.1.0",
        openapi_url="/api/openapi.json",
        docs_url="/api/docs",
    )

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/v1/verify", response_model=VerifyVendorResponse)
    async def verify_vendor(payload: VerifyVendorRequest) -> VerifyVendorResponse:
        domain = _safe_domain_or_422(payload.domain)
        year = datetime.now(tz=UTC).year
        active_use_case = use_case or _default_use_case(year)
        claim = VendorClaim(domain=domain, current_year=year, claimed_since_year=payload.claimed_since_year)
        ledger = await active_use_case.execute(claim)
        return _serialize_ledger(domain, ledger)

    return app


app = create_app()
