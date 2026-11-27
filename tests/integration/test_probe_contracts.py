"""Fowler Port Contract Tests ensuring fake and respx HTTP adapters share identical tri-state behavior."""

from __future__ import annotations

import httpx
import pytest
import respx

from src.domain.models import ProbeStatus
from src.infrastructure.http_probes import CrtShHttpAdapter, RdapHttpAdapter, WaybackHttpAdapter


@pytest.mark.asyncio
async def test_rdap_adapter_contract_observed_not_found_and_unavailable() -> None:
    url = "https://rdap.org/domain/vendor.de"
    with respx.mock(assert_all_called=True) as mock:
        mock.get(url).mock(
            return_value=httpx.Response(
                200,
                json={"events": [{"eventAction": "registration", "eventDate": "2020-01-15T00:00:00Z"}]},
            )
        )
        async with httpx.AsyncClient() as client:
            outcome = await RdapHttpAdapter(client, current_year=2026).fetch_domain_age("vendor.de")
            assert outcome.status == ProbeStatus.OBSERVED
            assert outcome.value is not None
            assert outcome.value.registered_year == 2020

    with respx.mock(assert_all_called=True) as mock:
        mock.get(url).mock(return_value=httpx.Response(404))
        async with httpx.AsyncClient() as client:
            outcome = await RdapHttpAdapter(client, current_year=2026).fetch_domain_age("vendor.de")
            assert outcome.status == ProbeStatus.NOT_FOUND

    with respx.mock(assert_all_called=True) as mock:
        mock.get(url).mock(return_value=httpx.Response(429))
        async with httpx.AsyncClient() as client:
            outcome = await RdapHttpAdapter(client, current_year=2026).fetch_domain_age("vendor.de")
            assert outcome.status == ProbeStatus.UNAVAILABLE


@pytest.mark.asyncio
async def test_crtsh_adapter_contract_observed_not_found_and_unavailable() -> None:
    url = "https://crt.sh/?q=vendor.de&output=json"
    with respx.mock(assert_all_called=True) as mock:
        mock.get(url).mock(
            return_value=httpx.Response(
                200,
                json=[{"not_before": "2021-05-01T00:00:00"}, {"not_before": "2023-05-01T00:00:00"}],
            )
        )
        async with httpx.AsyncClient() as client:
            outcome = await CrtShHttpAdapter(client).fetch_cert_history("vendor.de")
            assert outcome.status == ProbeStatus.OBSERVED
            assert outcome.value is not None
            assert outcome.value.cert_count == 2
            assert outcome.value.earliest_year == 2021

    with respx.mock(assert_all_called=True) as mock:
        mock.get(url).mock(return_value=httpx.Response(200, json=[]))
        async with httpx.AsyncClient() as client:
            outcome = await CrtShHttpAdapter(client).fetch_cert_history("vendor.de")
            assert outcome.status == ProbeStatus.NOT_FOUND

    with respx.mock(assert_all_called=True) as mock:
        mock.get(url).mock(side_effect=httpx.ConnectTimeout("timed out"))
        async with httpx.AsyncClient() as client:
            outcome = await CrtShHttpAdapter(client).fetch_cert_history("vendor.de")
            assert outcome.status == ProbeStatus.UNAVAILABLE


@pytest.mark.asyncio
async def test_wayback_adapter_contract_observed_not_found_and_unavailable() -> None:
    url = "https://web.archive.org/cdx/search/cdx"
    with respx.mock(assert_all_called=True) as mock:
        mock.get(url).mock(
            return_value=httpx.Response(
                200,
                json=[["timestamp"], ["20200412000000"], ["20220601000000"]],
            )
        )
        async with httpx.AsyncClient() as client:
            outcome = await WaybackHttpAdapter(client).fetch_timeline("vendor.de")
            assert outcome.status == ProbeStatus.OBSERVED
            assert outcome.value is not None
            assert outcome.value.snapshot_count == 2
            assert outcome.value.earliest_year == 2020

    with respx.mock(assert_all_called=True) as mock:
        mock.get(url).mock(return_value=httpx.Response(200, json=[]))
        async with httpx.AsyncClient() as client:
            outcome = await WaybackHttpAdapter(client).fetch_timeline("vendor.de")
            assert outcome.status == ProbeStatus.NOT_FOUND

    with respx.mock(assert_all_called=True) as mock:
        mock.get(url).mock(return_value=httpx.Response(503))
        async with httpx.AsyncClient() as client:
            outcome = await WaybackHttpAdapter(client).fetch_timeline("vendor.de")
            assert outcome.status == ProbeStatus.UNAVAILABLE
