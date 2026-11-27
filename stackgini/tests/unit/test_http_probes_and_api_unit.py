"""Unit tests for HTTP probe mappers, MockTransport adapters, SSRF, and API serialization."""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest
from fastapi.testclient import TestClient

from src.api.app import _default_use_case, create_app
from src.domain.models import (
    CertFootprint,
    DnsProfile,
    DomainAgeRecord,
    ProbeOutcome,
    ProbeStatus,
    SubprocessorMatch,
    VendorClaim,
    VendorSignals,
    VendorSnapshot,
    WaybackTimeline,
)
from src.domain.rules import (
    CertificateHistoryRule,
    DnsAuthSignalRule,
    DomainAgeMismatchRule,
    SubprocessorCorroborationRule,
    evaluate_vendor,
)
from src.infrastructure.http_probes import CrtShHttpAdapter, RdapHttpAdapter, WaybackHttpAdapter
from src.infrastructure.ssrf import normalize_public_domain


def _route_handler(routes: dict[str, httpx.Response]) -> Callable[[httpx.Request], httpx.Response]:
    def _handle(request: httpx.Request) -> httpx.Response:
        return routes.get(request.url.host, httpx.Response(404))

    return _handle


def _timeout_handler(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectTimeout("timeout")


async def test_http_adapters_handle_invalid_json_and_missing_events() -> None:
    transport = httpx.MockTransport(
        _route_handler(
            {
                "rdap.org": httpx.Response(200, json={"events": [{"eventAction": "last changed"}]}),
                "crt.sh": httpx.Response(200, content=b"{not-json"),
                "web.archive.org": httpx.Response(404),
            }
        )
    )
    async with httpx.AsyncClient(transport=transport) as client:
        rdap = await RdapHttpAdapter(client, current_year=2026).fetch_domain_age("x.de")
        crt = await CrtShHttpAdapter(client).fetch_cert_history("x.de")
        wb = await WaybackHttpAdapter(client).fetch_timeline("x.de")

    assert rdap.status == ProbeStatus.NOT_FOUND
    assert crt.status == ProbeStatus.UNAVAILABLE
    assert crt.reason == "invalid_json"
    assert wb.status == ProbeStatus.NOT_FOUND


async def test_http_adapters_handle_transport_errors_and_bad_rdap_json() -> None:
    bad_json_transport = httpx.MockTransport(
        _route_handler(
            {
                "rdap.org": httpx.Response(200, content=b"bad"),
                "web.archive.org": httpx.Response(200, content=b"bad"),
            }
        )
    )
    async with httpx.AsyncClient(transport=bad_json_transport) as client:
        rdap = await RdapHttpAdapter(client, current_year=2026).fetch_domain_age("x.de")
        wb = await WaybackHttpAdapter(client).fetch_timeline("x.de")
    async with httpx.AsyncClient(transport=httpx.MockTransport(_timeout_handler)) as client:
        crt = await CrtShHttpAdapter(client).fetch_cert_history("x.de")

    assert rdap.status == ProbeStatus.UNAVAILABLE
    assert crt.status == ProbeStatus.UNAVAILABLE
    assert wb.status == ProbeStatus.UNAVAILABLE


async def test_rdap_wayback_observed_via_mock_transport() -> None:
    transport = httpx.MockTransport(
        _route_handler(
            {
                "rdap.org": httpx.Response(
                    200, json={"events": [{"eventAction": "registration", "eventDate": "2020-05-01Z"}]}
                ),
                "crt.sh": httpx.Response(200, json=[{"not_before": "2020-05-01"}]),
                "web.archive.org": httpx.Response(200, json=[["timestamp"], ["20200101000000"]]),
            }
        )
    )
    async with httpx.AsyncClient(transport=transport) as client:
        rdap = await RdapHttpAdapter(client, current_year=2026).fetch_domain_age("ok.de")
        crt = await CrtShHttpAdapter(client).fetch_cert_history("ok.de")
        wb = await WaybackHttpAdapter(client).fetch_timeline("ok.de")

    assert rdap.status == ProbeStatus.OBSERVED
    assert crt.status == ProbeStatus.OBSERVED
    assert wb.status == ProbeStatus.OBSERVED


def test_rules_edge_branches_and_ssrf_global_ip() -> None:
    with pytest.raises(ValueError, match="Invalid public domain"):
        normalize_public_domain("8.8.8.8")

    signals = VendorSignals(
        rdap=ProbeOutcome.observed("https://rdap.org/domain/x.de", DomainAgeRecord(2025, 400)),
        certs=ProbeOutcome(status=ProbeStatus.OBSERVED, source_url="https://crt.sh/?q=x.de", value=None),
        dns=ProbeOutcome(status=ProbeStatus.OBSERVED, source_url="https://dns.google/resolve", value=None),
        subprocessor=ProbeOutcome.observed("https://subprocessors.local/x.de", SubprocessorMatch(())),
        wayback=ProbeOutcome.observed("https://web.archive.org/cdx", WaybackTimeline(50, None)),
    )
    snap = VendorSnapshot(claim=VendorClaim("x.de", 2026, claimed_since_year=2025), signals=signals)
    ledger = evaluate_vendor(
        snap,
        (
            DomainAgeMismatchRule(),
            CertificateHistoryRule(),
            DnsAuthSignalRule(),
            SubprocessorCorroborationRule(),
        ),
    )
    assert ledger.trust_score() == 70


def test_api_default_factory_and_health_route() -> None:
    use_case = _default_use_case(2026)
    client = TestClient(create_app(use_case=use_case))
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}
    bad = client.post("/api/v1/verify", json={"domain": "localhost"})
    assert bad.status_code == 422


def test_dns_profile_and_cert_footprint_helpers() -> None:
    profile = DnsProfile((), "v=spf1 ~all", "")
    assert profile.has_auth_txt() is True
    assert profile.has_full_auth() is False
    assert CertFootprint(3, 2024).earliest_year == 2024
