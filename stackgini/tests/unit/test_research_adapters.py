"""Unit tests for Playwright DOM adapter, Gemini web research adapter, and CSV batch runner."""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from google.genai import errors as genai_errors
from playwright.async_api import Route, async_playwright

from src.application.assess_vendor import AssessVendorUseCase
from src.application.verify_vendor import VerifyVendorUseCase
from src.domain.assessment import DomForensics, StackginiAssessment, StackginiVerdict, VendorInput, WebIntelligence
from src.domain.models import (
    CertFootprint,
    DnsProfile,
    DomainAgeRecord,
    EvidenceLedger,
    ProbeOutcome,
    ProbeStatus,
    SubprocessorMatch,
    VendorClaim,
    WaybackTimeline,
)
from src.domain.rules import default_vendor_rules
from src.infrastructure.csv_batch import read_vendor_csv, run_csv_batch, write_assessment_outputs
from src.infrastructure.gemini_research import (
    GeminiWebResearchAdapter,
    extract_citations_from_steps,
    parse_gemini_assessment_json,
)
from src.infrastructure.playwright_dom import (
    PlaywrightDomAdapter,
    _dom_outcome,
    _extract_from_page,
    _ssrf_route_guard,
    build_dom_forensics,
    is_waf_blocked_dom,
)
from src.ports.probes import VendorProbeGateway
from src.ports.research import ResearchGateway


@dataclass(frozen=True)
class FakeCitation:
    type: str
    url: str
    title: str


@dataclass(frozen=True)
class FakeContentBlock:
    type: str
    annotations: list[FakeCitation]


@dataclass(frozen=True)
class FakeStep:
    type: str
    content: list[FakeContentBlock]


class _ExplodingVerify(VerifyVendorUseCase):
    async def execute(self, claim: VendorClaim) -> EvidenceLedger:
        raise ValueError(f"simulated_error:{claim.domain}")


class _NoopPage:
    async def inspect_page(self, url: str) -> ProbeOutcome[DomForensics]:
        return ProbeOutcome.unavailable(url, "skip")


class _NoopResearch:
    async def research_vendor(self, item: VendorInput, dom_excerpt: str) -> ProbeOutcome[WebIntelligence]:
        return ProbeOutcome.not_found("https://news.google.com/")


class _NoopAge:
    async def fetch_domain_age(self, domain: str) -> ProbeOutcome[DomainAgeRecord]:
        return ProbeOutcome.not_found(f"https://rdap.org/domain/{domain}")


class _NoopCert:
    async def fetch_cert_history(self, domain: str) -> ProbeOutcome[CertFootprint]:
        return ProbeOutcome.not_found(f"https://crt.sh/?q={domain}")


class _NoopDns:
    async def fetch_dns_profile(self, domain: str) -> ProbeOutcome[DnsProfile]:
        return ProbeOutcome.not_found(f"https://dns.google/resolve?name={domain}")


class _NoopSub:
    async def lookup_subprocessor(self, domain: str) -> ProbeOutcome[SubprocessorMatch]:
        return ProbeOutcome.not_found(f"https://github.com/search?q={domain}")


class _NoopWb:
    async def fetch_timeline(self, domain: str) -> ProbeOutcome[WaybackTimeline]:
        return ProbeOutcome.not_found("https://web.archive.org/cdx")


def test_build_dom_forensics_extracts_fields() -> None:
    raw_payload: dict[str, object] = {
        "title": "PBM Platform",
        "visible_text": "Campaign platform",
        "dead_social_links": 4,
        "legal_doc_urls": ["https://pbm.com/privacy", "https://pbm.com/privacy"],
    }
    dom = build_dom_forensics("https://pbm.com/en/", raw_payload, raw_html_len=1500)
    assert isinstance(dom, DomForensics)
    assert dom.dead_social_links == 4
    assert dom.legal_doc_urls == ("https://pbm.com/privacy",)
    assert dom.raw_text_len == 1500
    assert is_waf_blocked_dom(DomForensics("https://x.com", "Access Denied", "Access Denied", 0, (), 50)) is True
    assert is_waf_blocked_dom(dom) is False


async def test_playwright_dom_adapter_rejects_ssrf_before_launch() -> None:
    outcome = await PlaywrightDomAdapter().inspect_page("http://127.0.0.1/admin")
    assert outcome.status == ProbeStatus.UNAVAILABLE
    assert "Invalid" in outcome.reason


def test_parse_gemini_assessment_json_and_citations() -> None:
    steps = [
        FakeStep(
            type="model_output",
            content=[
                FakeContentBlock(
                    type="text",
                    annotations=[
                        FakeCitation("url_citation", "https://www.ftc.gov/news", "FTC Order"),
                        FakeCitation("other", "ftp://ignored", "Ignored"),
                    ],
                )
            ],
        )
    ]
    citations = extract_citations_from_steps(steps)
    assert len(citations) == 1
    assert citations[0].url == "https://www.ftc.gov/news"

    payload = json.dumps(
        {
            "suggested_overall": "Red",
            "green_signals": ["Popular brand"],
            "yellow_signals": [],
            "red_signals": ["FTC fined company $16.5M for selling user browsing data"],
            "reasoning": "Regulator fine contradicts privacy marketing.",
        }
    )
    intel = parse_gemini_assessment_json(payload, citations)
    assert intel.suggested_overall == StackginiVerdict.RED
    assert "FTC fined" in intel.red_signals[0]


async def test_gemini_adapter_returns_unavailable_without_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    adapter = GeminiWebResearchAdapter(api_key="")
    outcome = await adapter.research_vendor(VendorInput("1", "https://example.com", "Ex", "Ex Inc"), "text")
    assert outcome.status == ProbeStatus.UNAVAILABLE
    assert outcome.reason == "missing_api_key"


def test_csv_batch_read_and_write_roundtrip(tmp_path: Path) -> None:
    input_csv = tmp_path / "in.csv"
    input_csv.write_text(
        '"id","url","product","vendor"\n"1","https://www.postfix.org/","Postfix","Wietse Venema"\n',
        encoding="utf-8",
    )
    items = read_vendor_csv(input_csv)
    assert len(items) == 1
    assessment = StackginiAssessment(
        item=items[0],
        overall=StackginiVerdict.GREEN,
        green_flags=("Global MTA standard",),
        yellow_flags=(),
        red_flags=(),
        reasoning="Widely deployed and actively maintained.",
        source_urls=("https://www.postfix.org/",),
    )
    out_csv = tmp_path / "out.csv"
    write_assessment_outputs(out_csv, [assessment])

    with out_csv.open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["overall"] == "Green"
    assert "[Sources: https://www.postfix.org/]" in rows[0]["reasoning"]
    parsed_sources = json.loads((tmp_path / "out_sources.json").read_text(encoding="utf-8"))
    assert parsed_sources[0]["id"] == "1"
    assert parsed_sources[0]["technical_probes"]["trust_score"] == 70
    assert parsed_sources[0]["technical_probes"]["verdict"] == "verified"


def test_csv_batch_validates_required_columns(tmp_path: Path) -> None:
    bad_csv = tmp_path / "bad.csv"
    bad_csv.write_text('"id","url","product"\n"1","https://vendor.de","App"\n', encoding="utf-8")
    with pytest.raises(ValueError, match="Missing required CSV columns: vendor"):
        read_vendor_csv(bad_csv)


async def test_run_csv_batch_isolates_row_errors_and_writes_outputs(tmp_path: Path) -> None:
    in_csv = tmp_path / "in.csv"
    in_csv.write_text('"id","url","product","vendor"\n"7","bad://row","Prod","Vend"\n', encoding="utf-8")
    out_csv = tmp_path / "out.csv"
    gateway = VendorProbeGateway(_NoopAge(), _NoopCert(), _NoopDns(), _NoopSub(), _NoopWb())
    verify = _ExplodingVerify(gateway, default_vendor_rules())
    assess = AssessVendorUseCase(verify, ResearchGateway(_NoopPage(), _NoopResearch()))
    results = await run_csv_batch(assess, in_csv, out_csv, concurrency=2)
    assert len(results) == 1
    assert results[0].overall == StackginiVerdict.YELLOW
    assert out_csv.is_file()


async def test_playwright_real_chromium_extracts_claims_and_imprint() -> None:
    html = (
        "<html><head><title>Acme SaaS</title></head><body>"
        "<main><p>Acme GmbH HRB 9999 Berlin</p></main>"
        "<footer><span>© 2018 Acme GmbH</span>"
        '<a href="/login">Sign In</a><a href="/privacy">Privacy Policy</a>'
        '<a href="#" aria-label="LinkedIn">LinkedIn</a></footer></body></html>'
    )
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.route(
            "https://vendor.example/**", lambda r: r.fulfill(status=200, content_type="text/html", body=html)
        )
        await page.goto("https://vendor.example/home")
        dom = await _extract_from_page(page)
        await browser.close()
    assert dom.claimed_year == 2018
    assert dom.imprint_hits >= 2
    assert dom.login_targets == ("/login",)
    assert dom.dead_social_links == 1
    assert "https://vendor.example/privacy" in dom.legal_doc_urls

    waf = DomForensics("https://x.com", "Access Denied", "Access Denied", 0, (), 50)
    assert _dom_outcome(waf).status == ProbeStatus.UNAVAILABLE
    assert _dom_outcome(dom).status == ProbeStatus.OBSERVED


async def test_playwright_route_guard_aborts_local_redirect() -> None:
    events: list[str] = []

    class _FakeRoute:
        request = SimpleNamespace(is_navigation_request=lambda: False, url="http://169.254.169.254/latest")

        async def abort(self) -> None:
            events.append("aborted")

        async def continue_(self) -> None:
            events.append("continued")

    await _ssrf_route_guard(cast(Route, _FakeRoute()))
    assert events == ["aborted"]


async def test_gemini_invoke_sync_and_api_error_handling(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_payload = json.dumps(
        {
            "suggested_overall": "Green",
            "green_signals": ["Mature platform"],
            "yellow_signals": [],
            "red_signals": [],
            "reasoning": "Verified via Google Search.",
        }
    )
    ok_res = SimpleNamespace(
        steps=[
            FakeStep(
                "model_output",
                [FakeContentBlock("text", [FakeCitation("url_citation", "https://example.org/news", "News")])],
            )
        ],
        output_text=fake_payload,
    )
    monkeypatch.setattr(
        "src.infrastructure.gemini_research.genai.Client",
        lambda **kw: SimpleNamespace(interactions=SimpleNamespace(create=lambda **_k: ok_res)),
    )
    res = await GeminiWebResearchAdapter(api_key="gem-key").research_vendor(
        VendorInput("1", "https://vendor.example", "App", "Vendor"), "excerpt"
    )
    assert res.status == ProbeStatus.OBSERVED
    assert res.value is not None
    assert res.value.suggested_overall == StackginiVerdict.GREEN

    def _raise_api(**_kw: object) -> object:
        raise genai_errors.APIError(429, {"error": {"message": "quota"}}, None)

    monkeypatch.setattr(
        "src.infrastructure.gemini_research.genai.Client",
        lambda **kw: SimpleNamespace(interactions=SimpleNamespace(create=_raise_api)),
    )
    err = await GeminiWebResearchAdapter(api_key="gem-key").research_vendor(
        VendorInput("1", "https://vendor.example", "App", "Vendor"), "excerpt"
    )
    assert err.status == ProbeStatus.UNAVAILABLE
    assert err.reason == "APIError"
