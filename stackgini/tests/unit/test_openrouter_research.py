"""Unit tests for OpenRouter two-stage web research adapter and .env loader."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest

from src.domain.assessment import StackginiVerdict, VendorInput, WebCitation
from src.domain.models import ProbeStatus
from src.infrastructure.openrouter_research import (
    OpenRouterWebResearchAdapter,
    load_dotenv_if_present,
    parse_openrouter_response,
)


def _mock_transport(fn: Callable[[httpx.Request], httpx.Response]) -> httpx.MockTransport:
    return httpx.MockTransport(fn)


def _two_stage_handler(request: httpx.Request) -> httpx.Response:
    payload = json.loads(request.content.decode("utf-8"))
    if "plugins" in payload:
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": "Omnissa serves 26,000+ customers under KKR with a 2026 CEO transition.",
                            "annotations": [
                                {
                                    "type": "url_citation",
                                    "url_citation": {"url": "https://www.omnissa.com/news", "title": "Omnissa PR"},
                                }
                            ],
                        }
                    }
                ]
            },
        )
    return httpx.Response(
        200,
        json={
            "choices": [
                {
                    "message": {
                        "content": json.dumps(
                            {
                                "suggested_overall": "Green",
                                "green_signals": ["26,000+ enterprise customers"],
                                "yellow_signals": ["KKR carve-out from Broadcom/VMware"],
                                "red_signals": [],
                                "reasoning": "Solid enterprise vendor.",
                                "citations": [{"title": "Omnissa", "url": "https://www.omnissa.com/"}],
                            }
                        )
                    }
                }
            ]
        },
    )


def test_load_dotenv_if_present_sets_unset_vars(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text('# comment\nOPENROUTER_API_KEY="test-secret"\nEMPTY_KEY=\n', encoding="utf-8")
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    load_dotenv_if_present(env_file)
    assert os.environ.get("OPENROUTER_API_KEY") == "test-secret"


async def test_openrouter_adapter_returns_unavailable_without_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    adapter = OpenRouterWebResearchAdapter(api_key="")
    res = await adapter.research_vendor(VendorInput("1", "https://omnissa.com", "Workspace ONE", "Omnissa"), "dom")
    assert res.status == ProbeStatus.UNAVAILABLE
    assert res.reason == "missing_api_key"


def test_parse_openrouter_response_parses_fenced_json_and_nested_citations() -> None:
    body = {
        "choices": [
            {
                "message": {
                    "content": '```json\n{"suggested_overall":"Yellow","green_signals":["Mature"],'
                    '"yellow_signals":["Nov 2026 breach on status page"],'
                    '"red_signals":[],"reasoning":"Status page breach.",'
                    '"citations":[{"title":"Advisory","url":"https://status.optimizely.com/"}]}\n```',
                    "annotations": [
                        {
                            "type": "url_citation",
                            "url_citation": {"url": "https://bleepingcomputer.com/x", "title": "News"},
                        }
                    ],
                }
            }
        ]
    }
    intel = parse_openrouter_response(body, allowed_host="optimizely.com")
    assert intel.suggested_overall == StackginiVerdict.YELLOW
    assert len(intel.citations) == 2
    assert intel.citations[1].url == "https://bleepingcomputer.com/x"


async def test_openrouter_adapter_two_stage_200_and_429() -> None:
    async with httpx.AsyncClient(transport=_mock_transport(_two_stage_handler)) as client:
        adapter = OpenRouterWebResearchAdapter(api_key="test-key", client=client)
        res = await adapter.research_vendor(VendorInput("1", "https://www.omnissa.com/", "WS1", "Omnissa"), "dom")
    assert res.status == ProbeStatus.OBSERVED
    assert res.value is not None
    assert res.value.suggested_overall == StackginiVerdict.GREEN
    assert any(c.url == "https://www.omnissa.com/news" for c in res.value.citations)

    async with httpx.AsyncClient(transport=_mock_transport(lambda _r: httpx.Response(429))) as client:
        err_adapter = OpenRouterWebResearchAdapter(api_key="test-key", client=client)
        err_res = await err_adapter.research_vendor(
            VendorInput("1", "https://www.omnissa.com/", "WS1", "Omnissa"), "dom"
        )
    assert err_res.status == ProbeStatus.UNAVAILABLE
    assert err_res.reason == "http_429"


def test_parse_openrouter_response_filters_ungrounded_stage2_citations() -> None:
    payload = {
        "choices": [
            {
                "message": {
                    "content": json.dumps(
                        {
                            "suggested_overall": "Green",
                            "green_signals": ["Active vendor"],
                            "yellow_signals": [],
                            "red_signals": [],
                            "reasoning": "Verified.",
                            "citations": [
                                {"title": "Hallucinated", "url": "https://fake-source.invalid/report"},
                                {"title": "Vendor Legal", "url": "https://vendor.de/imprint"},
                            ],
                        }
                    )
                }
            }
        ]
    }
    stage1_cites = [WebCitation("Real News", "https://reuters.com/vendor")]
    intel = parse_openrouter_response(payload, extra_citations=stage1_cites, allowed_host="vendor.de")
    urls = {c.url for c in intel.citations}
    assert "https://fake-source.invalid/report" not in urls
    assert "https://vendor.de/imprint" in urls
    assert "https://reuters.com/vendor" in urls

    empty_stage1_intel = parse_openrouter_response(payload, extra_citations=[], allowed_host="vendor.de")
    assert {c.url for c in empty_stage1_intel.citations} == {"https://vendor.de/imprint"}


def _partial_response(calls: list[str], body: dict[str, object]) -> httpx.Response:
    if "plugins" not in body:
        return httpx.Response(500)
    ok_msg = {"choices": [{"message": {"content": "Offsite report ok", "annotations": []}}]}
    return httpx.Response(503) if len(calls) == 1 else httpx.Response(200, json=ok_msg)


def _make_partial_handler(calls: list[str]) -> Callable[[httpx.Request], httpx.Response]:
    def _handle(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode("utf-8"))
        calls.append(str(body.get("model", "")))
        return _partial_response(calls, body)

    return _handle


async def test_openrouter_adapter_handles_partial_stage1_error_and_stage2_500() -> None:
    calls: list[str] = []
    async with httpx.AsyncClient(transport=_mock_transport(_make_partial_handler(calls))) as client:
        adapter = OpenRouterWebResearchAdapter(api_key="test-key", client=client)
        res = await adapter.research_vendor(VendorInput("2", "https://vendor.de", "App", "Vendor"), "excerpt")
    assert res.status == ProbeStatus.UNAVAILABLE
    assert res.reason == "http_500"
    assert len(calls) == 3
