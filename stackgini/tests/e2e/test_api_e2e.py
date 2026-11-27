"""End-to-end API smoke test against FastAPI routes and OpenAPI manifest."""

from __future__ import annotations

from fastapi.testclient import TestClient

from src.api.app import create_app
from src.application.assess_vendor import AssessVendorUseCase
from src.application.verify_vendor import VerifyVendorUseCase
from src.domain.assessment import DomForensics, StackginiVerdict, VendorInput, WebCitation, WebIntelligence
from src.domain.models import (
    CertFootprint,
    DnsProfile,
    DomainAgeRecord,
    ProbeOutcome,
    SubprocessorMatch,
    WaybackTimeline,
)
from src.domain.rules import default_vendor_rules
from src.ports.probes import VendorProbeGateway
from src.ports.research import ResearchGateway


class StubRdap:
    async def fetch_domain_age(self, domain: str) -> ProbeOutcome[DomainAgeRecord]:
        return ProbeOutcome.observed(f"https://rdap.org/domain/{domain}", DomainAgeRecord(2020, 2200))


class StubCerts:
    async def fetch_cert_history(self, domain: str) -> ProbeOutcome[CertFootprint]:
        return ProbeOutcome.observed(f"https://crt.sh/?q={domain}", CertFootprint(8, 2020))


class StubDns:
    async def fetch_dns_profile(self, domain: str) -> ProbeOutcome[DnsProfile]:
        return ProbeOutcome.observed(
            f"https://dns.google/resolve?name={domain}",
            DnsProfile(("mx.vendor.de",), "v=spf1 ~all", "v=DMARC1; p=reject"),
        )


class StubSubprocessor:
    async def lookup_subprocessor(self, domain: str) -> ProbeOutcome[SubprocessorMatch]:
        return ProbeOutcome.observed("https://trust.vendor.de/subprocessors", SubprocessorMatch(("enterprise-a",)))


class StubWayback:
    async def fetch_timeline(self, domain: str) -> ProbeOutcome[WaybackTimeline]:
        return ProbeOutcome.observed(f"https://web.archive.org/cdx/search/cdx?url={domain}", WaybackTimeline(20, 2020))


def test_api_health_openapi_and_verify_endpoint() -> None:
    gateway = VendorProbeGateway(
        rdap=StubRdap(),
        certs=StubCerts(),
        dns=StubDns(),
        subprocessor=StubSubprocessor(),
        wayback=StubWayback(),
    )
    app = create_app(use_case=VerifyVendorUseCase(gateway=gateway, rules=default_vendor_rules()))
    client = TestClient(app)

    health = client.get("/health")
    assert health.status_code == 200
    assert health.json() == {"status": "ok"}

    openapi = client.get("/api/openapi.json")
    assert openapi.status_code == 200
    assert "/api/v1/verify" in openapi.json()["paths"]

    verified = client.post("/api/v1/verify", json={"domain": "https://vendor.de", "claimed_since_year": 2020})
    assert verified.status_code == 200
    body = verified.json()
    assert body["domain"] == "vendor.de"
    assert body["verdict"] == "verified"
    assert body["trust_score"] == 95

    rejected = client.post("/api/v1/verify", json={"domain": "http://127.0.0.1:8000"})
    assert rejected.status_code == 422


class StubPagePort:
    async def inspect_page(self, url: str) -> ProbeOutcome[DomForensics]:
        return ProbeOutcome.observed(url, DomForensics(url, "Vendor", "Enterprise SaaS", 0, (), 800))


class StubResearchPort:
    async def research_vendor(self, item: VendorInput, dom_excerpt: str) -> ProbeOutcome[WebIntelligence]:
        return ProbeOutcome.observed(
            "https://www.google.com/search",
            WebIntelligence(
                suggested_overall=StackginiVerdict.GREEN,
                summary="Established SaaS vendor.",
                citations=(WebCitation("Vendor", "https://vendor.de/about"),),
                green_signals=("Enterprise adoption",),
                yellow_signals=(),
                red_signals=(),
            ),
        )


def test_api_assess_endpoint_returns_stackgini_verdict() -> None:
    probes = VendorProbeGateway(
        rdap=StubRdap(),
        certs=StubCerts(),
        dns=StubDns(),
        subprocessor=StubSubprocessor(),
        wayback=StubWayback(),
    )
    verify_uc = VerifyVendorUseCase(gateway=probes, rules=default_vendor_rules())
    assess_uc = AssessVendorUseCase(verify_uc, ResearchGateway(StubPagePort(), StubResearchPort()))
    client = TestClient(create_app(use_case=verify_uc, assess_use_case=assess_uc))
    resp = client.post(
        "/api/v1/assess",
        json={"row_id": "1", "url": "https://vendor.de", "product": "VendorSuite", "vendor": "Vendor GmbH"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["overall"] == "Green"
    assert "https://vendor.de/about" in data["source_urls"]
