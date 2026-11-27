"""Unit tests for Playwright DOM adapter, Gemini web research adapter, and CSV batch runner."""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path

import pytest

from src.domain.assessment import DomForensics, StackginiAssessment, StackginiVerdict, VendorInput
from src.domain.models import ProbeOutcome, ProbeStatus
from src.infrastructure.csv_batch import read_vendor_csv, write_assessment_outputs
from src.infrastructure.gemini_research import (
    GeminiWebResearchAdapter,
    extract_citations_from_steps,
    parse_gemini_assessment_json,
)
from src.infrastructure.playwright_dom import PlaywrightDomAdapter, build_dom_forensics, is_waf_blocked_dom


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


def test_build_dom_forensics_extracts_fields() -> None:
    raw_payload: dict[str, object] = {
        "title": "PBM Platform",
        "visible_text": "Campaign platform coming soon",
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
    assert items[0].vendor == "Wietse Venema"

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
    assert rows[0]["red_flags"] == "None identified."
    sources_json = tmp_path / "out_sources.json"
    assert json.loads(sources_json.read_text(encoding="utf-8"))[0]["id"] == "1"
    assert isinstance(ProbeOutcome.not_found("https://example.com").status, ProbeStatus)
