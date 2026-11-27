"""Unit tests for zero-key public intelligence adapter (News RSS, Wikipedia, Statuspage, DOM text)."""

from __future__ import annotations

from collections.abc import Callable

import httpx

from src.domain.assessment import StackginiVerdict, VendorInput
from src.domain.models import ProbeStatus
from src.infrastructure.composite_research import FallbackResearchAdapter
from src.infrastructure.gemini_research import GeminiWebResearchAdapter
from src.infrastructure.public_research import (
    PublicSignalsResearchAdapter,
    parse_news_rss_items,
    scan_dom_text_signals,
)


def _mock_handler(routes: dict[str, httpx.Response]) -> Callable[[httpx.Request], httpx.Response]:
    def _handle(request: httpx.Request) -> httpx.Response:
        return routes.get(request.url.host, httpx.Response(404))

    return _handle


def test_parse_news_rss_items_extracts_titles_and_links() -> None:
    rss_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <rss version="2.0"><channel>
      <item><title>FTC orders Avast to pay $16.5M over browsing data</title>
            <link>https://www.ftc.gov/news-events/avast</link></item>
      <item><title>Avast Czech DPA fine</title>
            <link>https://example.org/avast-fine</link></item>
    </channel></rss>"""
    hits = parse_news_rss_items(rss_xml)
    assert len(hits) == 2
    assert hits[0].url == "https://www.ftc.gov/news-events/avast"
    assert "FTC" in hits[0].title


def test_scan_dom_text_signals_flags_eol_and_placeholders() -> None:
    reds, yellows = scan_dom_text_signals("Software is discontinued. Click Run Anyway on Defender. {{PRICE_TIER}}")
    assert len(reds) >= 1
    assert len(yellows) >= 1


async def test_public_signals_returns_unavailable_on_all_errors_and_not_found_on_empty_probes() -> None:
    err_transport = httpx.MockTransport(lambda _req: httpx.Response(429))
    async with httpx.AsyncClient(transport=err_transport) as client:
        res = await PublicSignalsResearchAdapter(client=client).research_vendor(
            VendorInput("50", "https://unknown.example/", "App", "Vendor"),
            "Standard marketing text",
        )
    assert res.status == ProbeStatus.UNAVAILABLE
    assert res.reason == "upstream_probes_unavailable"

    empty_transport = httpx.MockTransport(
        _mock_handler(
            {
                "news.google.com": httpx.Response(200, text="<rss><channel></channel></rss>"),
                "en.wikipedia.org": httpx.Response(200, json={"query": {"search": []}}),
                "api.github.com": httpx.Response(200, json={"items": []}),
                "status.unknown.example": httpx.Response(404),
            }
        )
    )
    async with httpx.AsyncClient(transport=empty_transport) as client:
        not_found_res = await PublicSignalsResearchAdapter(client=client).research_vendor(
            VendorInput("51", "https://unknown.example/", "App", "Vendor"),
            "Standard marketing text",
        )
    assert not_found_res.status == ProbeStatus.NOT_FOUND


async def test_public_signals_ignores_stock_ticker_and_non_software_homonyms() -> None:
    rss_xml = (
        "<rss><channel>"
        "<item><title>Broadcom Inc. $AVGO Stock Acquired by Fund LLC</title><link>https://ex.com/1</link></item>"
        "<item><title>NutriBullet Blender Lawsuit Exploding Container</title><link>https://ex.com/2</link></item>"
        "</channel></rss>"
    )
    transport = httpx.MockTransport(
        _mock_handler(
            {
                "news.google.com": httpx.Response(200, text=rss_xml),
                "en.wikipedia.org": httpx.Response(200, json={"query": {"search": [{"title": "Blender (software)"}]}}),
                "api.github.com": httpx.Response(200, json={"items": []}),
            }
        )
    )
    async with httpx.AsyncClient(transport=transport) as client:
        res = await PublicSignalsResearchAdapter(client=client).research_vendor(
            VendorInput("6", "https://www.blender.org/", "Blender", "Blender Foundation"),
            "Open source 3D creation suite",
        )
    assert res.status == ProbeStatus.OBSERVED
    assert res.value is not None
    assert res.value.suggested_overall == StackginiVerdict.GREEN
    assert res.value.red_signals == ()


async def test_public_signals_adapter_detects_red_ftc_and_green_wiki() -> None:
    rss_body = (
        "<rss><channel><item><title>FTC fines Avast $16.5M for selling browsing data</title>"
        "<link>https://www.ftc.gov/avast</link></item></channel></rss>"
    )
    wiki_body = {"query": {"search": [{"title": "Avast", "snippet": "Czech cybersecurity software company"}]}}
    transport = httpx.MockTransport(
        _mock_handler(
            {
                "news.google.com": httpx.Response(200, text=rss_body),
                "en.wikipedia.org": httpx.Response(200, json=wiki_body),
            }
        )
    )
    async with httpx.AsyncClient(transport=transport) as client:
        adapter = PublicSignalsResearchAdapter(client=client)
        res = await adapter.research_vendor(
            VendorInput("40", "https://www.avast.com/", "Avast", "Avast"),
            "Free antivirus and VPN",
        )

    assert res.status == ProbeStatus.OBSERVED
    assert res.value is not None
    assert res.value.suggested_overall == StackginiVerdict.RED
    assert any("FTC" in s for s in res.value.red_signals)


async def test_public_signals_adapter_detects_statuspage_incident_yellow() -> None:
    status_json = {
        "incidents": [
            {
                "name": "Web Experimentation unauthorized JavaScript injection incident",
                "shortlink": "https://stspg.io/abc123",
            }
        ]
    }
    transport = httpx.MockTransport(
        _mock_handler(
            {
                "status.optimizely.com": httpx.Response(200, json=status_json),
                "en.wikipedia.org": httpx.Response(200, json={"query": {"search": [{"title": "Optimizely"}]}}),
                "news.google.com": httpx.Response(200, text="<rss><channel></channel></rss>"),
            }
        )
    )
    async with httpx.AsyncClient(transport=transport) as client:
        adapter = PublicSignalsResearchAdapter(client=client)
        res = await adapter.research_vendor(
            VendorInput("25", "https://www.optimizely.com/", "Optimizely", "Optimizely"),
            "Enterprise experimentation platform",
        )

    assert res.status == ProbeStatus.OBSERVED
    assert res.value is not None
    assert res.value.suggested_overall == StackginiVerdict.YELLOW
    assert any("incident" in s.lower() for s in res.value.yellow_signals)


async def test_fallback_research_adapter_falls_back_from_missing_gemini_to_public() -> None:
    transport = httpx.MockTransport(
        _mock_handler(
            {
                "en.wikipedia.org": httpx.Response(200, json={"query": {"search": [{"title": "Postfix"}]}}),
                "news.google.com": httpx.Response(200, text="<rss><channel></channel></rss>"),
                "api.github.com": httpx.Response(
                    200,
                    json={
                        "items": [
                            {
                                "full_name": "vdukhovni/postfix",
                                "stargazers_count": 500,
                                "html_url": "https://github.com/vdukhovni/postfix",
                            }
                        ]
                    },
                ),
            }
        )
    )
    async with httpx.AsyncClient(transport=transport) as client:
        chain = FallbackResearchAdapter(
            (GeminiWebResearchAdapter(api_key=""), PublicSignalsResearchAdapter(client=client))
        )
        res = await chain.research_vendor(VendorInput("6", "https://www.postfix.org/", "Postfix", "Wietse"), "MTA")

    assert res.status == ProbeStatus.OBSERVED
    assert res.value is not None
    assert res.value.suggested_overall == StackginiVerdict.GREEN
