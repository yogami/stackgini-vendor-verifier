"""OpenRouter web-grounded research adapter for nuanced procurement due diligence."""

from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path

import httpx
from pydantic import BaseModel, Field

from src.domain.assessment import StackginiVerdict, VendorInput, WebCitation, WebIntelligence
from src.domain.models import ProbeOutcome

OPENROUTER_CHAT_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_OPENROUTER_MODEL = "anthropic/claude-sonnet-4.5"
TIMEOUT_SECONDS = 45.0
MAX_WEB_RESULTS = 8
HTTP_OK = 200

_STACKGINI_PROMPT = """You are a senior software procurement due-diligence analyst for Stackgini.
Use web search thoroughly to investigate off-site facts NOT on the vendor's marketing page.

Target:
- URL: {url}
- Product: {product}
- Vendor: {vendor}
- Rendered DOM Excerpt: {dom_excerpt}

Investigate these 5 dimensions via web search:
1. Regulatory & legal accountability: FTC orders, GDPR/DPA fines or unlawful rulings, class actions,
   sanctions/Russia exit trackers (e.g. Yale CELI), or missing legal entity/Impressum.
2. Security posture & disclosure transparency: Recent breaches or CVEs. Distinguish transparent
   disclosure with external forensics (Green with yellow_signals) vs silent/status-page-only
   incidents (Yellow).
3. Ownership, M&A & naming/licensing traps: Private equity carve-outs, frequent owner flips,
   post-acquisition layoffs/roadmap freezes, or multi-product naming/SKU/token confusion.
   Distinguish solid market leaders with M&A/CEO context (Green + yellow_signals) from confusing
   licensing mazes or PE asset-squeezing (Yellow).
4. Legacy-site calibration: NEVER downgrade ugly, 1990s/2000s, or minimal sites when recent
   releases, foundation backing, community forks, or 3rd-party training prove active adoption (Green).
   Conversely, check if a clean site is a single-hobbyist side project (Yellow), EOL with AV-bypass
   instructions (Red), or displays fake user counts / partner badges styled as customers (Red).
5. Always cite exact external URLs found via search in `citations`.

Return strict JSON with keys:
- "suggested_overall": "Green" | "Yellow" | "Red"
- "green_signals": [string]
- "yellow_signals": [string]
- "red_signals": [string]
- "reasoning": string (concise 2-4 sentence procurement summary citing verified sources)
- "citations": [{{"title": string, "url": "https://..."}}]"""


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
    if not isinstance(ann, dict) or ann.get("type") != "url_citation":
        return None
    return _valid_citation(str(ann.get("title", "")), str(ann.get("url", "")))


def _annotation_citations(message: dict[str, object]) -> list[WebCitation]:
    raw_anns = message.get("annotations")
    if not isinstance(raw_anns, list):
        return []
    parsed = [_parse_one_annotation(ann) for ann in raw_anns]
    return [c for c in parsed if c is not None]


def _merge_citations(parsed: _OpenRouterSchema, message: dict[str, object]) -> tuple[WebCitation, ...]:
    body_cites = [c for c in (_valid_citation(i.title, i.url) for i in parsed.citations) if c is not None]
    combined = [*body_cites, *_annotation_citations(message)]
    return tuple({c.url: c for c in combined}.values())


def _as_dict(obj: object) -> dict[str, object]:
    return obj if isinstance(obj, dict) else {}


def _index0_dict(items: object) -> dict[str, object]:
    if not isinstance(items, list):
        return {}
    return _as_dict(items[0]) if items else {}


def _first_choice(payload: object) -> dict[str, object]:
    choices = payload.get("choices") if isinstance(payload, dict) else None
    return _index0_dict(choices)


def _extract_message(payload: object) -> dict[str, object]:
    msg = _first_choice(payload).get("message")
    return msg if isinstance(msg, dict) else {}


def parse_openrouter_response(payload: object) -> WebIntelligence:
    """Validate OpenRouter chat completion payload into immutable WebIntelligence."""
    message = _extract_message(payload)
    content = _strip_json_fences(str(message.get("content", "")))
    if not content:
        raise ValueError("Empty OpenRouter completion content")
    parsed = _OpenRouterSchema.model_validate_json(content)
    citations = _merge_citations(parsed, message)
    return WebIntelligence(
        suggested_overall=parsed.suggested_overall,
        summary=parsed.reasoning.strip(),
        citations=citations,
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
    """WebResearchPort powered by OpenRouter frontier models + live web search plugin."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = DEFAULT_OPENROUTER_MODEL,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._api_key = _resolve_openrouter_key(api_key)
        self._model = model
        self._client = client

    async def research_vendor(self, item: VendorInput, dom_excerpt: str) -> ProbeOutcome[WebIntelligence]:
        """Run OpenRouter web-grounded research and return cited WebIntelligence."""
        if not self._api_key:
            return ProbeOutcome.unavailable(OPENROUTER_CHAT_URL, "missing_api_key")
        prompt = _STACKGINI_PROMPT.format(
            url=item.url,
            product=item.product,
            vendor=item.vendor,
            dom_excerpt=dom_excerpt,
        )
        return await self._post_chat(prompt)

    async def _post_chat(self, prompt: str) -> ProbeOutcome[WebIntelligence]:
        client = self._client or _default_ipv4_async_client()
        try:
            resp = await client.post(
                OPENROUTER_CHAT_URL,
                headers={"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"},
                json=self._request_body(prompt),
                timeout=TIMEOUT_SECONDS,
            )
            return self._map_response(resp)
        except (httpx.HTTPError, ValueError) as exc:
            return ProbeOutcome.unavailable(OPENROUTER_CHAT_URL, type(exc).__name__)
        finally:
            await _close_if_owned(client, self._client)

    def _request_body(self, prompt: str) -> dict[str, object]:
        return {
            "model": self._model,
            "plugins": [{"id": "web", "max_results": MAX_WEB_RESULTS}],
            "response_format": {"type": "json_object"},
            "messages": [{"role": "user", "content": prompt}],
        }

    def _map_response(self, resp: httpx.Response) -> ProbeOutcome[WebIntelligence]:
        if resp.status_code != HTTP_OK:
            return ProbeOutcome.unavailable(OPENROUTER_CHAT_URL, f"http_{resp.status_code}")
        return _decode_openrouter_json(resp)


def _decode_openrouter_json(resp: httpx.Response) -> ProbeOutcome[WebIntelligence]:
    try:
        intel = parse_openrouter_response(resp.json())
    except ValueError as exc:
        return ProbeOutcome.unavailable(OPENROUTER_CHAT_URL, type(exc).__name__)
    return ProbeOutcome.observed(OPENROUTER_CHAT_URL, intel)
