"""OpenRouter two-stage web-grounded research adapter for Stackgini due diligence."""

from __future__ import annotations

import asyncio
import ipaddress
import os
import re
from pathlib import Path

import httpx
from pydantic import BaseModel, Field

from src.domain.assessment import (
    StackginiVerdict,
    VendorInput,
    WebCitation,
    WebIntelligence,
    extract_domain_from_url,
)
from src.domain.models import ProbeOutcome

OPENROUTER_CHAT_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_SEARCH_MODEL = "openai/gpt-4o-mini"
DEFAULT_SYNTHESIS_MODEL = "anthropic/claude-sonnet-4.5"
TIMEOUT_SECONDS = 45.0
MAX_WEB_RESULTS = 5
MAX_DOSSIER_TOKENS = 950
HTTP_OK = 200

_PRODUCT_SEARCH_PROMPT = """Research this software product and vendor using web search:
- URL: {url}
- Product: {product}
- Vendor: {vendor}
- Rendered DOM Excerpt: {dom_excerpt}

Report factual evidence with dates, numbers, and exact URLs for:
1. Ownership & M&A history: how many times sold/acquired, PE roll-ups, post-M&A layoffs or roadmap stalls,
   or whether product is hidden/sunsetted in parent navigation.
2. Product naming, SKU, or licensing confusion (e.g. overlapping names, frequent renames, token pricing).
3. Real adoption & maintenance: customer count, employee count, latest release dates, GitHub/community ecosystem,
   3rd-party workshops/training, and whether maintainer is a full-time hobbyist vs established creator/YC startup."""

_OFFSITE_SEARCH_PROMPT = """Search strictly OFF-SITE third-party sources (exclude {domain}) for:
- Product: {product}
- Vendor: {vendor}
Query guidance: check regulatory actions (FTC, GDPR DPA, ICO, noyb), lawsuits, sanctions/Russia trackers
(e.g. Yale CELI), data breaches/CVEs (including status page incidents), and paid/fake review scandals.

Provide exact dates, fine amounts, affected counts, and exact external URLs. Never cite unverified
paywall directory stubs as sanctions matches unless confirmed by official EU/OFAC/UK/gov/reputable news."""

_SYNTHESIS_PROMPT = """You are Stackgini's senior procurement verifier. Grade the vendor strictly on verified facts.

Target: {product} by {vendor} ({url})
Rendered DOM Excerpt: {dom_excerpt}
Product & Ownership Dossier:
{product_dossier}

Off-Site Enforcement, Breach & Risk Dossier:
{offsite_dossier}

CALIBRATION RULES (FOLLOW CAREFULLY):
1. LEGACY / SINGLE-DEV / STARTUP CALIBRATION -> GREEN (with caveats in yellow_signals):
   - NEVER downgrade ugly, 1990s/2000s, or minimal websites if active releases, paid workshops, or adoption exist.
   - Established single-developer tools with multi-year/decade adoption or current 2025-2026 releases are GREEN
     (note bus-factor/commercial-license nuance in yellow_signals; ONLY Yellow if recent supply-chain hijack
     or developer explicitly states day-job hobbyist with tiny traction).
   - Valid YC-backed or early-stage startups with clear working self-serve pricing are GREEN.
   - Solid enterprise leaders with ONE carve-out/acquisition or a transparently remediated past incident
     with published external forensics (e.g. Mandiant) are GREEN (list M&A/CEO/incident notes in yellow_signals).
2. YELLOW (Moderate / Portfolio / Governance Risk):
   - Chronic M&A churn (>= 3 owners or repeated renames), PE roll-up known for layoffs/roadmap freezes,
     or acquired product hidden/unclear in parent navigation.
   - Severe product naming/SKU/licensing/token confusion across a large portfolio.
   - Recent supply-chain/customer-impacting security breach absent from main site (only on status page/press).
   - Missing ISO 27001/SOC 2 on enterprise compliance pitch alongside unfinished site / dead '#' social links.
3. RED (Disqualifying Trust, Legal, or Substance Risk):
   - Regulator-confirmed violations/fines (FTC, GDPR DPA) or major ongoing biometric/deception enforcement.
   - Undisclosed geopolitical/sanctions risk from credible research (e.g. Yale CELI Russia list) - ignore
     random directory/paywall stubs like registercheck.de.
   - Fake/contradictory user numbers, partner badges styled as customers, missing legal entity,
     privacy policy downloading a .docx, or EOL product telling users to disable/bypass antivirus.

Only put verified disqualifying facts in `red_signals` (leave `red_signals` empty for Green/Yellow).
Return strict JSON:
{{
  "suggested_overall": "Green" | "Yellow" | "Red",
  "green_signals": [string],
  "yellow_signals": [string],
  "red_signals": [string],
  "reasoning": "2-4 balanced sentences citing the key verified facts and sources.",
  "citations": [{{"title": string, "url": "https://..."}}]
}}"""


class _CitationItem(BaseModel):
    title: str = ""
    url: str = ""


class _OpenRouterSchema(BaseModel):
    suggested_overall: StackginiVerdict = StackginiVerdict.YELLOW
    green_signals: list[str] = Field(default_factory=list)
    yellow_signals: list[str] = Field(default_factory=list)
    red_signals: list[str] = Field(default_factory=list)
    reasoning: str = ""
    citations: list[_CitationItem] = Field(default_factory=list)


def _strip_quotes(raw: str) -> str:
    return raw.strip().strip('"').strip("'")


def _is_env_assignment(cleaned: str) -> bool:
    return bool(cleaned) and not cleaned.startswith("#") and "=" in cleaned


def _parse_env_line(line: str) -> tuple[str, str]:
    cleaned = line.strip()
    if not _is_env_assignment(cleaned):
        return "", ""
    key, val = cleaned.split("=", 1)
    return key.strip(), _strip_quotes(val)


def _apply_env_line(line: str) -> None:
    key, val = _parse_env_line(line)
    if key and val:
        os.environ.setdefault(key, val)


def _load_env_file(target: Path) -> None:
    if not target.is_file():
        return
    for line in target.read_text(encoding="utf-8").splitlines():
        _apply_env_line(line)


def load_dotenv_if_present(env_path: Path | None = None) -> None:
    """Load key=value pairs from .env into os.environ when not already set."""
    _load_env_file(Path(".env") if env_path is None else env_path)


def _strip_json_fences(raw_text: str) -> str:
    cleaned = raw_text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", cleaned, flags=re.DOTALL)
    return cleaned.strip()


def _valid_citation(title: str, url: str) -> WebCitation | None:
    cleaned_url = url.strip()
    if not cleaned_url.startswith(("http://", "https://")):
        return None
    return WebCitation(title=title.strip() or cleaned_url, url=cleaned_url)


def _parse_one_annotation(ann: object) -> WebCitation | None:
    entry = _as_dict(ann)
    if entry.get("type") != "url_citation":
        return None
    nested = entry.get("url_citation")
    source = nested if isinstance(nested, dict) else entry
    return _valid_citation(str(source.get("title", "")), str(source.get("url", "")))


def _annotation_citations(message: dict[str, object]) -> list[WebCitation]:
    raw_anns = message.get("annotations")
    if not isinstance(raw_anns, list):
        return []
    parsed = [_parse_one_annotation(ann) for ann in raw_anns]
    return [c for c in parsed if c is not None]


def _merge_citations(parsed: _OpenRouterSchema, extra: list[WebCitation]) -> tuple[WebCitation, ...]:
    body_cites = [c for c in (_valid_citation(i.title, i.url) for i in parsed.citations) if c is not None]
    combined = [*body_cites, *extra]
    return tuple({c.url: c for c in combined}.values())


def _as_dict(obj: object) -> dict[str, object]:
    return obj if isinstance(obj, dict) else {}


def _index0_dict(items: object) -> dict[str, object]:
    if not isinstance(items, list):
        return {}
    return _as_dict(items[0]) if items else {}


def _extract_message(payload: object) -> dict[str, object]:
    choices = payload.get("choices") if isinstance(payload, dict) else None
    msg = _index0_dict(choices).get("message")
    return msg if isinstance(msg, dict) else {}


def parse_openrouter_response(payload: object, extra_citations: list[WebCitation] | None = None) -> WebIntelligence:
    """Validate OpenRouter chat completion payload into immutable WebIntelligence."""
    message = _extract_message(payload)
    content = _strip_json_fences(str(message.get("content", "")))
    if not content:
        raise ValueError("Empty OpenRouter completion content")
    parsed = _OpenRouterSchema.model_validate_json(content)
    all_extra = [*_annotation_citations(message), *(extra_citations or [])]
    return WebIntelligence(
        suggested_overall=parsed.suggested_overall,
        summary=parsed.reasoning.strip(),
        citations=_merge_citations(parsed, all_extra),
        green_signals=tuple(parsed.green_signals),
        yellow_signals=tuple(parsed.yellow_signals),
        red_signals=tuple(parsed.red_signals),
    )


def _default_ipv4_async_client() -> httpx.AsyncClient:
    ipv4_any = str(ipaddress.IPv4Address(0))
    return httpx.AsyncClient(
        transport=httpx.AsyncHTTPTransport(local_address=ipv4_any),
        timeout=TIMEOUT_SECONDS,
    )


def _resolve_openrouter_key(explicit_key: str | None) -> str:
    if explicit_key is not None:
        return explicit_key.strip()
    load_dotenv_if_present(Path(".env"))
    return os.environ.get("OPENROUTER_API_KEY", "").strip()


async def _close_if_owned(client: httpx.AsyncClient, external: httpx.AsyncClient | None) -> None:
    if external is None:
        await client.aclose()


class OpenRouterWebResearchAdapter:
    """Two-stage OpenRouter WebResearchPort: dual web search + frontier calibrated synthesis."""

    def __init__(
        self,
        api_key: str | None = None,
        search_model: str = DEFAULT_SEARCH_MODEL,
        synthesis_model: str = DEFAULT_SYNTHESIS_MODEL,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._api_key = _resolve_openrouter_key(api_key)
        self._search_model = search_model
        self._synthesis_model = synthesis_model
        self._client = client

    async def research_vendor(self, item: VendorInput, dom_excerpt: str) -> ProbeOutcome[WebIntelligence]:
        """Run dual web retrieval and Stage 2 calibrated verdict synthesis."""
        if not self._api_key:
            return ProbeOutcome.unavailable(OPENROUTER_CHAT_URL, "missing_api_key")
        return await self._execute_with_client(item, dom_excerpt)

    async def _execute_with_client(self, item: VendorInput, dom_excerpt: str) -> ProbeOutcome[WebIntelligence]:
        client = self._client or _default_ipv4_async_client()
        try:
            return await self._run_two_stage(client, item, dom_excerpt)
        except (httpx.HTTPError, ValueError) as exc:
            return ProbeOutcome.unavailable(OPENROUTER_CHAT_URL, type(exc).__name__)
        finally:
            await _close_if_owned(client, self._client)

    async def _run_two_stage(
        self,
        client: httpx.AsyncClient,
        item: VendorInput,
        dom_excerpt: str,
    ) -> ProbeOutcome[WebIntelligence]:
        domain = extract_domain_from_url(item.url)
        p1 = _PRODUCT_SEARCH_PROMPT.format(
            url=item.url, product=item.product, vendor=item.vendor, dom_excerpt=dom_excerpt
        )
        p2 = _OFFSITE_SEARCH_PROMPT.format(domain=domain, product=item.product, vendor=item.vendor)
        (prod_txt, prod_cites, err1), (off_txt, off_cites, err2) = await asyncio.gather(
            self._search_call(client, p1),
            self._search_call(client, p2),
        )
        if err1 and err2:
            return ProbeOutcome.unavailable(OPENROUTER_CHAT_URL, err1)
        return await self._stage2_synthesize(client, item, dom_excerpt, (prod_txt, off_txt, [*prod_cites, *off_cites]))

    async def _search_call(self, client: httpx.AsyncClient, prompt: str) -> tuple[str, list[WebCitation], str]:
        body = {
            "model": self._search_model,
            "plugins": [{"id": "web", "max_results": MAX_WEB_RESULTS}],
            "max_tokens": MAX_DOSSIER_TOKENS,
            "messages": [{"role": "user", "content": prompt}],
        }
        resp = await self._post_json(client, body)
        if resp.status_code != HTTP_OK:
            return "", [], f"http_{resp.status_code}"
        msg = _extract_message(resp.json())
        return str(msg.get("content", "")), _annotation_citations(msg), ""

    async def _stage2_synthesize(
        self,
        client: httpx.AsyncClient,
        item: VendorInput,
        dom_excerpt: str,
        stage1: tuple[str, str, list[WebCitation]],
    ) -> ProbeOutcome[WebIntelligence]:
        prompt = _SYNTHESIS_PROMPT.format(
            url=item.url,
            product=item.product,
            vendor=item.vendor,
            dom_excerpt=dom_excerpt,
            product_dossier=stage1[0],
            offsite_dossier=stage1[1],
        )
        body = {
            "model": self._synthesis_model,
            "response_format": {"type": "json_object"},
            "max_tokens": MAX_DOSSIER_TOKENS,
            "messages": [{"role": "user", "content": prompt}],
        }
        resp = await self._post_json(client, body)
        if resp.status_code != HTTP_OK:
            return ProbeOutcome.unavailable(OPENROUTER_CHAT_URL, f"http_{resp.status_code}")
        intel = parse_openrouter_response(resp.json(), extra_citations=stage1[2])
        return ProbeOutcome.observed(OPENROUTER_CHAT_URL, intel)

    async def _post_json(self, client: httpx.AsyncClient, body: dict[str, object]) -> httpx.Response:
        return await client.post(
            OPENROUTER_CHAT_URL,
            headers={"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"},
            json=body,
            timeout=TIMEOUT_SECONDS,
        )
