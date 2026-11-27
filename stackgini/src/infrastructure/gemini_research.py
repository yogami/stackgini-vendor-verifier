"""Gemini Interactions API adapter with Google Search grounding for off-site vendor intelligence."""

from __future__ import annotations

import asyncio
import ipaddress
import os

import httpx
from google import genai
from google.genai import types
from pydantic import BaseModel, Field

from src.domain.assessment import StackginiVerdict, VendorInput, WebCitation, WebIntelligence
from src.domain.models import ProbeOutcome

DEFAULT_GEMINI_MODEL = "gemini-4-hydrogen"
GROUNDING_SOURCE_URL = "https://generativelanguage.googleapis.com/"

_CALIBRATION_PROMPT = """You are a senior software procurement due-diligence analyst evaluating a vendor for Stackgini.
Use Google Search extensively to check off-site facts that are NOT on the vendor marketing page.

Target:
- URL: {url}
- Product: {product}
- Vendor: {vendor}
- Rendered DOM Excerpt: {dom_excerpt}

Check these off-site dimensions:
1. Regulatory fines, DPA/GDPR rulings, FTC orders, lawsuits, or geopolitical exposure (e.g. Russia ops).
2. Security breaches and disclosure transparency (Mandiant post-mortem vs silent status-page-only notice).
3. M&A, private equity carve-outs, ownership flips, renames/licensing confusion, or roadmap stalls.
4. Community adoption, recent releases, third-party ecosystems, and company size vs claimed traction.

CRITICAL CALIBRATION RULES:
- Do NOT downgrade an ugly or 1990s/2000s site if release history, foundation backing, or adoption is active.
- Rate GREEN when the product is solid and active, even with minor M&A context or transparent incident disclosure.
- Rate YELLOW for confusing multi-product naming/licensing traps, PE roadmap squeezes, or status-page breaches.
- Rate RED for regulator fines, undisclosed sanctions risk, fake logos/metrics, missing entity, or AV-bypass EOL.

Keep each bullet concise and factual. Cite external evidence in reasoning."""


class _GeminiAssessmentSchema(BaseModel):
    """Structured JSON schema returned by Gemini Google Search grounding."""

    suggested_overall: StackginiVerdict = Field(description="Green, Yellow, or Red")
    green_signals: list[str] = Field(default_factory=list)
    yellow_signals: list[str] = Field(default_factory=list)
    red_signals: list[str] = Field(default_factory=list)
    reasoning: str = Field(description="Balanced 2-4 sentence summary citing key evidence.")


def _citation_from_annotation(ann: object) -> WebCitation | None:
    if getattr(ann, "type", "") != "url_citation":
        return None
    url = str(getattr(ann, "url", ""))
    return (
        WebCitation(title=str(getattr(ann, "title", "")), url=url) if url.startswith(("http://", "https://")) else None
    )


def _collect_valid_citations(annotations: object) -> list[WebCitation]:
    if not isinstance(annotations, list):
        return []
    items = [_citation_from_annotation(ann) for ann in annotations]
    return [c for c in items if c is not None]


def _block_citations(block: object) -> list[WebCitation]:
    if getattr(block, "type", "") != "text":
        return []
    return _collect_valid_citations(getattr(block, "annotations", None))


def _step_citations(step: object) -> list[WebCitation]:
    if getattr(step, "type", "") != "model_output":
        return []
    content = getattr(step, "content", None)
    return [c for block in content for c in _block_citations(block)] if isinstance(content, list) else []


def extract_citations_from_steps(steps: object) -> tuple[WebCitation, ...]:
    """Extract unique HTTP(S) WebCitations from Gemini interaction steps."""
    if not isinstance(steps, list):
        return ()
    all_citations = [c for step in steps for c in _step_citations(step)]
    return tuple({c.url: c for c in all_citations}.values())


def parse_gemini_assessment_json(raw_json: str, citations: tuple[WebCitation, ...]) -> WebIntelligence:
    """Validate structured JSON output into immutable WebIntelligence."""
    parsed = _GeminiAssessmentSchema.model_validate_json(raw_json)
    return WebIntelligence(
        suggested_overall=parsed.suggested_overall,
        summary=parsed.reasoning.strip(),
        citations=citations,
        green_signals=tuple(parsed.green_signals),
        yellow_signals=tuple(parsed.yellow_signals),
        red_signals=tuple(parsed.red_signals),
    )


def _resolve_api_key(explicit_key: str | None) -> str:
    if explicit_key is not None:
        return explicit_key.strip()
    env_key = os.environ.get("GEMINI_API_KEY")
    return (env_key if env_key else os.environ.get("GOOGLE_API_KEY", "")).strip()


def _invoke_gemini_sync(api_key: str, model: str, prompt: str) -> WebIntelligence:
    ipv4_any = str(ipaddress.IPv4Address(0))
    http_client = httpx.Client(transport=httpx.HTTPTransport(local_address=ipv4_any), timeout=15.0)
    client = genai.Client(
        api_key=api_key,
        http_options=types.HttpOptions(httpx_client=http_client, retry_options=types.HttpRetryOptions(attempts=1)),
    )
    interaction = client.interactions.create(
        model=model,
        input=prompt,
        tools=[{"type": "google_search"}],
        response_format={
            "type": "text",
            "mime_type": "application/json",
            "schema": _GeminiAssessmentSchema.model_json_schema(),
        },
    )
    citations = extract_citations_from_steps(getattr(interaction, "steps", None))
    output_text = str(getattr(interaction, "output_text", "") or "")
    return parse_gemini_assessment_json(output_text, citations)


class GeminiWebResearchAdapter:
    """WebResearchPort backed by Gemini Interactions API + Google Search Grounding."""

    def __init__(self, api_key: str | None = None, model: str = DEFAULT_GEMINI_MODEL) -> None:
        self._api_key = _resolve_api_key(api_key)
        self._model = model

    async def research_vendor(self, item: VendorInput, dom_excerpt: str) -> ProbeOutcome[WebIntelligence]:
        """Run grounded web search for item and return cited WebIntelligence."""
        if not self._api_key:
            return ProbeOutcome.unavailable(GROUNDING_SOURCE_URL, "missing_api_key")
        prompt = _CALIBRATION_PROMPT.format(
            url=item.url,
            product=item.product,
            vendor=item.vendor,
            dom_excerpt=dom_excerpt,
        )
        return await self._safe_query(prompt)

    async def _safe_query(self, prompt: str) -> ProbeOutcome[WebIntelligence]:
        try:
            intel = await asyncio.to_thread(_invoke_gemini_sync, self._api_key, self._model, prompt)
        except Exception as exc:
            return ProbeOutcome.unavailable(GROUNDING_SOURCE_URL, type(exc).__name__)
        return ProbeOutcome.observed(GROUNDING_SOURCE_URL, intel)
