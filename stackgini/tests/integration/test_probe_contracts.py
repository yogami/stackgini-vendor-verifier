"""Fowler Port Contract Tests verifying real adapters and in-memory fakes share tri-state behavior."""

from __future__ import annotations

import httpx
import pytest
import respx

from src.domain.models import (
    CertFootprint,
    DomainAgeRecord,
    ProbeOutcome,
    ProbeStatus,
    SubprocessorMatch,
    WaybackTimeline,
)
from src.infrastructure.dns_subprocessor import PublicSubprocessorAdapter
from src.infrastructure.http_probes import CrtShHttpAdapter, RdapHttpAdapter, WaybackHttpAdapter
from src.ports.probes import CertHistoryPort, RdapProbePort, SubprocessorPort, WaybackTimelinePort


class FakeRdapContract:
    """In-memory fake obeying the tri-state RdapProbePort contract."""

    def __init__(self, mode: ProbeStatus) -> None:
        self._mode = mode

    async def fetch_domain_age(self, domain: str) -> ProbeOutcome[DomainAgeRecord]:
        url = f"https://rdap.org/domain/{domain}"
        if self._mode == ProbeStatus.OBSERVED:
            return ProbeOutcome.observed(url, DomainAgeRecord(2020, 2200))
        return (
            ProbeOutcome.not_found(url) if self._mode == ProbeStatus.NOT_FOUND else ProbeOutcome.unavailable(url, "429")
        )


class FakeCertContract:
    """In-memory fake obeying the tri-state CertHistoryPort contract."""

    def __init__(self, mode: ProbeStatus) -> None:
        self._mode = mode

    async def fetch_cert_history(self, domain: str) -> ProbeOutcome[CertFootprint]:
        url = f"https://crt.sh/?q={domain}&output=json"
        if self._mode == ProbeStatus.OBSERVED:
            return ProbeOutcome.observed(url, CertFootprint(2, 2021, 2023, ("api",)))
        return (
            ProbeOutcome.not_found(url) if self._mode == ProbeStatus.NOT_FOUND else ProbeOutcome.unavailable(url, "to")
        )


class FakeSubprocessorContract:
    """In-memory fake obeying the tri-state SubprocessorPort contract."""

    def __init__(self, mode: ProbeStatus) -> None:
        self._mode = mode

    async def lookup_subprocessor(self, domain: str) -> ProbeOutcome[SubprocessorMatch]:
        url = f"https://api.github.com/search/repositories?q=%22{domain}%22+subprocessors&per_page=3"
        if self._mode == ProbeStatus.OBSERVED:
            return ProbeOutcome.observed(url, SubprocessorMatch(("https://github.com/acme/trust",)))
        return (
            ProbeOutcome.not_found(url) if self._mode == ProbeStatus.NOT_FOUND else ProbeOutcome.unavailable(url, "503")
        )


class FakeWaybackContract:
    """In-memory fake obeying the tri-state WaybackTimelinePort contract."""

    def __init__(self, mode: ProbeStatus) -> None:
        self._mode = mode

    async def fetch_timeline(self, domain: str) -> ProbeOutcome[WaybackTimeline]:
        url = "https://web.archive.org/cdx/search/cdx"
        if self._mode == ProbeStatus.OBSERVED:
            return ProbeOutcome.observed(url, WaybackTimeline(2, 2020))
        return (
            ProbeOutcome.not_found(url) if self._mode == ProbeStatus.NOT_FOUND else ProbeOutcome.unavailable(url, "503")
        )


async def _assert_rdap_contract(port: RdapProbePort, expected: ProbeStatus) -> None:
    outcome = await port.fetch_domain_age("vendor.de")
    assert outcome.status == expected
    if expected == ProbeStatus.OBSERVED:
        assert outcome.value is not None
        assert outcome.value.registered_year == 2020


async def _assert_cert_contract(port: CertHistoryPort, expected: ProbeStatus) -> None:
    outcome = await port.fetch_cert_history("vendor.de")
    assert outcome.status == expected
    if expected == ProbeStatus.OBSERVED:
        assert outcome.value is not None
        assert outcome.value.cert_count == 2


async def _assert_subprocessor_contract(port: SubprocessorPort, expected: ProbeStatus) -> None:
    outcome = await port.lookup_subprocessor("vendor.de")
    assert outcome.status == expected
    if expected == ProbeStatus.OBSERVED:
        assert outcome.value is not None
        assert outcome.value.enterprise_refs or outcome.value.dpa_url


async def _assert_wayback_contract(port: WaybackTimelinePort, expected: ProbeStatus) -> None:
    outcome = await port.fetch_timeline("vendor.de")
    assert outcome.status == expected
    if expected == ProbeStatus.OBSERVED:
        assert outcome.value is not None
        assert outcome.value.earliest_year == 2020


@pytest.mark.asyncio
async def test_rdap_contract_symmetric_http_and_fake() -> None:
    url = "https://rdap.org/domain/vendor.de"
    cases = [
        (
            ProbeStatus.OBSERVED,
            httpx.Response(
                200, json={"events": [{"eventAction": "registration", "eventDate": "2020-01-15T00:00:00Z"}]}
            ),
        ),
        (ProbeStatus.NOT_FOUND, httpx.Response(404)),
        (ProbeStatus.UNAVAILABLE, httpx.Response(429)),
    ]
    for status, response in cases:
        await _assert_rdap_contract(FakeRdapContract(status), status)
        with respx.mock(assert_all_called=True) as mock:
            mock.get(url).mock(return_value=response)
            async with httpx.AsyncClient() as client:
                await _assert_rdap_contract(RdapHttpAdapter(client, current_year=2026), status)
    assert len(cases) == 3


@pytest.mark.asyncio
async def test_crtsh_contract_symmetric_http_and_fake() -> None:
    url = "https://crt.sh/?q=vendor.de&output=json"
    cases = [
        (
            ProbeStatus.OBSERVED,
            httpx.Response(200, json=[{"not_before": "2021-05-01T00:00:00"}, {"not_before": "2023-05-01T00:00:00"}]),
        ),
        (ProbeStatus.NOT_FOUND, httpx.Response(200, json=[])),
        (ProbeStatus.UNAVAILABLE, httpx.Response(503)),
    ]
    for status, response in cases:
        await _assert_cert_contract(FakeCertContract(status), status)
        with respx.mock(assert_all_called=True) as mock:
            mock.get(url).mock(return_value=response)
            async with httpx.AsyncClient() as client:
                await _assert_cert_contract(CrtShHttpAdapter(client), status)
    assert len(cases) == 3


@pytest.mark.asyncio
async def test_subprocessor_and_wayback_contracts_symmetric() -> None:
    for status in (ProbeStatus.OBSERVED, ProbeStatus.NOT_FOUND, ProbeStatus.UNAVAILABLE):
        await _assert_subprocessor_contract(FakeSubprocessorContract(status), status)
        await _assert_wayback_contract(FakeWaybackContract(status), status)

    wb_url = "https://web.archive.org/cdx/search/cdx"
    with respx.mock(assert_all_called=True) as mock:
        mock.get(wb_url).mock(
            return_value=httpx.Response(200, json=[["timestamp"], ["20200412000000"], ["20220601000000"]])
        )
        async with httpx.AsyncClient() as client:
            await _assert_wayback_contract(WaybackHttpAdapter(client), ProbeStatus.OBSERVED)

    with respx.mock(assert_all_called=True) as mock:
        mock.get("https://vendor.de/subprocessors").mock(return_value=httpx.Response(404))
        mock.get("https://vendor.de/dpa").mock(return_value=httpx.Response(404))
        mock.get("https://api.github.com/search/repositories?q=%22vendor.de%22%20subprocessors&per_page=3").mock(
            return_value=httpx.Response(200, json={"items": [{"html_url": "https://github.com/acme/trust"}]})
        )
        async with httpx.AsyncClient() as client:
            res = await PublicSubprocessorAdapter(client).lookup_subprocessor("vendor.de")
            assert res.status == ProbeStatus.OBSERVED
