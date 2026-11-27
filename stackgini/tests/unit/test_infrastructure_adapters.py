"""Unit tests for DNS, subprocessor, and SSRF edge-case behavior."""

from __future__ import annotations

from dataclasses import dataclass

import dns.exception
import dns.resolver
import httpx
import pytest

from src.domain.models import ProbeStatus
from src.infrastructure.dns_subprocessor import (
    CuratedSubprocessorAdapter,
    DnsResolverAdapter,
    PublicSubprocessorAdapter,
    extract_saas_verifications,
)
from src.infrastructure.ssrf import normalize_public_domain, normalize_public_url, verify_public_url_with_dns


@dataclass(frozen=True)
class FakeMxRecord:
    """Minimal MX rdata stub."""

    exchange: str


@dataclass(frozen=True)
class FakeTxtRecord:
    """Minimal TXT rdata stub."""

    strings: tuple[bytes, ...]


_DNS_FIXTURES: dict[tuple[str, str], list[object]] = {
    ("vendor.de", "MX"): [FakeMxRecord("mx1.vendor.de.")],
    ("_dmarc.vendor.de", "TXT"): [FakeTxtRecord((b"v=DMARC1; p=reject",))],
    ("vendor.de", "TXT"): [
        FakeTxtRecord((b"v=spf1 include:_spf.vendor.de ~all",)),
        FakeTxtRecord((b"google-site-verification=abc",)),
        FakeTxtRecord((b"docusign=123",)),
        FakeTxtRecord((b"stripe-verification=xyz",)),
    ],
}


def _fake_resolve(qname: str, rdtype: str, lifetime: float = 4.0) -> list[object]:
    return _DNS_FIXTURES.get((qname, rdtype), [])


def _raise_timeout(qname: str, rdtype: str, lifetime: float = 4.0) -> list[object]:
    raise dns.exception.Timeout


def _raise_no_answer(qname: str, rdtype: str, lifetime: float = 4.0) -> list[object]:
    raise dns.resolver.NoAnswer


async def test_curated_subprocessor_adapter_observed_and_not_found() -> None:
    adapter = CuratedSubprocessorAdapter({"linear.app": ("acme-corp", "globex")})
    found = await adapter.lookup_subprocessor("Linear.App")
    missing = await adapter.lookup_subprocessor("unknown.test")
    assert found.status == ProbeStatus.OBSERVED
    assert found.value is not None
    assert found.value.enterprise_refs == ("acme-corp", "globex")
    assert missing.status == ProbeStatus.NOT_FOUND


async def test_dns_resolver_adapter_observed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dns.resolver, "resolve", _fake_resolve)
    outcome = await DnsResolverAdapter().fetch_dns_profile("vendor.de")
    assert outcome.status == ProbeStatus.OBSERVED
    assert outcome.value is not None
    assert outcome.value.mx_hosts == ("mx1.vendor.de",)
    assert outcome.value.has_full_auth() is True
    assert outcome.value.saas_verifications == ("docusign", "google", "stripe")


def _subprocessor_route(req: httpx.Request) -> httpx.Response:
    routes: dict[tuple[str, str], httpx.Response] = {
        ("vendor.de", "/subprocessors"): httpx.Response(200, text="GDPR Subprocessors: AWS, Stripe"),
        ("spa.de", "/subprocessors"): httpx.Response(
            200, text="<html><body><div id='root'>Loading</div></body></html>"
        ),
    }
    if req.url.host == "api.github.com":
        return httpx.Response(200, json={"items": [{"html_url": "https://github.com/acme/trust"}]})
    return routes.get((req.url.host, req.url.path), httpx.Response(404))


async def test_public_subprocessor_adapter_and_ssrf_dns_rebinding(monkeypatch: pytest.MonkeyPatch) -> None:
    async with httpx.AsyncClient(transport=httpx.MockTransport(_subprocessor_route)) as client:
        res = await PublicSubprocessorAdapter(client).lookup_subprocessor("vendor.de")
    assert res.status == ProbeStatus.OBSERVED
    assert res.value is not None
    assert res.value.dpa_url == "https://vendor.de/subprocessors"
    assert "https://github.com/acme/trust" in res.value.enterprise_refs

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda r: httpx.Response(200, text="<div>Loading</div>") if r.url.host == "spa.de" else httpx.Response(404)
        )
    ) as spa_client:
        spa_res = await PublicSubprocessorAdapter(spa_client).lookup_subprocessor("spa.de")
        assert spa_res.status == ProbeStatus.UNAVAILABLE

    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _r: httpx.Response(503))) as err_client:
        unavail = await PublicSubprocessorAdapter(err_client).lookup_subprocessor("down.de")
    assert unavail.status == ProbeStatus.UNAVAILABLE

    assert extract_saas_verifications(["atlassian-domain-verification=x", "MS=ms1"]) == ("atlassian", "microsoft-365")
    assert normalize_public_url("vendor.de") == "https://vendor.de"

    monkeypatch.setattr("socket.getaddrinfo", lambda _h, _p: [(2, 1, 6, "", ("127.0.0.1", 0))])
    with pytest.raises(ValueError, match="non-global"):
        verify_public_url_with_dns("https://rebind.example/")


async def test_dns_resolver_adapter_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dns.resolver, "resolve", _raise_timeout)
    failed = await DnsResolverAdapter().fetch_dns_profile("vendor.de")
    assert failed.status == ProbeStatus.UNAVAILABLE


async def test_dns_resolver_handles_no_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dns.resolver, "resolve", _raise_no_answer)
    outcome = await DnsResolverAdapter().fetch_dns_profile("empty.de")
    assert outcome.status == ProbeStatus.OBSERVED
    assert outcome.value is not None
    assert outcome.value.mx_hosts == ()
    assert outcome.value.has_auth_txt() is False


def test_ssrf_guard_rejects_bad_format_and_empty_host() -> None:
    with pytest.raises(ValueError, match="Invalid public domain"):
        normalize_public_domain("not_a_domain")
    with pytest.raises(ValueError, match="Invalid empty hostname"):
        normalize_public_domain("https:///only-path")
