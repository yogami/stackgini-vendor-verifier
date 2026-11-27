"""Unit tests for OpenRouter web-grounded research adapter and .env loader."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest

from src.domain.assessment import StackginiVerdict, VendorInput
from src.domain.models import ProbeStatus
from src.infrastructure.openrouter_research import (
    OpenRouterWebResearchAdapter,
    load_dotenv_if_present,
    parse_openrouter_response,
)


def _mock_transport(fn: Callable[[httpx.Request], httpx.Response]) -> httpx.MockTransport:
    return httpx.MockTransport(fn)


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


def test_parse_openrouter_response_parses_fenced_json_and_citations() -> None:
    body = {
        "choices": [
            {
                "message": {
                    "content": '```json\n{"suggested_overall":"Yellow","green_signals":["Mature"],'
                    '"yellow_signals":["Nov 2026 breach on status page"],'
                    '"red_signals":[],"reasoning":"Status page breach.",'
                    '"citations":[{"title":"Advisory","url":"https://status.optimizely.com/"}]}\n```',
                    "annotations": [{"type": "url_citation", "url": "https://bleepingcomputer.com/x", "title": "News"}],
                }
            }
        ]
    }
    intel = parse_openrouter_response(body)
    assert intel.suggested_overall == StackginiVerdict.YELLOW
    assert len(intel.citations) == 2
    assert intel.citations[0].url == "https://status.optimizely.com/"


async def test_openrouter_adapter_handles_200_and_429() -> None:
    ok_payload = {
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
    }

    async with httpx.AsyncClient(transport=_mock_transport(lambda _r: httpx.Response(200, json=ok_payload))) as client:
        adapter = OpenRouterWebResearchAdapter(api_key="test-key", client=client)
        res = await adapter.research_vendor(VendorInput("1", "https://www.omnissa.com/", "WS1", "Omnissa"), "dom")
    assert res.status == ProbeStatus.OBSERVED
    assert res.value is not None
    assert res.value.suggested_overall == StackginiVerdict.GREEN

    async with httpx.AsyncClient(transport=_mock_transport(lambda _r: httpx.Response(429))) as client:
        err_adapter = OpenRouterWebResearchAdapter(api_key="test-key", client=client)
        err_res = await err_adapter.research_vendor(
            VendorInput("1", "https://www.omnissa.com/", "WS1", "Omnissa"), "dom"
        )
    assert err_res.status == ProbeStatus.UNAVAILABLE
    assert err_res.reason == "http_429"
