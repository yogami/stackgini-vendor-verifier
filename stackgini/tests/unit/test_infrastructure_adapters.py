"""Unit tests for DNS, subprocessor, and SSRF edge-case behavior."""

from __future__ import annotations

from dataclasses import dataclass

import dns.exception
import dns.resolver
import pytest

from src.domain.models import ProbeStatus
from src.infrastructure.dns_subprocessor import CuratedSubprocessorAdapter, DnsResolverAdapter
from src.infrastructure.ssrf import normalize_public_domain


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
    ("vendor.de", "TXT"): [FakeTxtRecord((b"v=spf1 include:_spf.vendor.de ~all",))],
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
