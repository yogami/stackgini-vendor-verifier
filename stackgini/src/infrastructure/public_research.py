"""Zero-key public web intelligence adapter using News RSS, Wikipedia, Statuspage, and GitHub."""

from __future__ import annotations

import asyncio
import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import quote

import httpx
from bs4 import BeautifulSoup, Tag

from src.domain.assessment import (
    StackginiVerdict,
    VendorInput,
    WebCitation,
    WebIntelligence,
    extract_domain_from_url,
)
from src.domain.models import ProbeOutcome

TIMEOUT_SECONDS = 8.0
MAX_RSS_HITS = 5
MIN_ENTITY_LEN = 3
HTTP_OK = 200
HIGH_STARS_THRESHOLD = 100
RED_KEYWORDS = (
    "ftc",
    "fined",
    "fine ",
    "penalty",
    "unlawful",
    "lawsuit",
    "class action",
    "ordered to pay",
    "banned from selling",
    "russia",
)
YELLOW_KEYWORDS = (
    "breach",
    "incident",
    "injection",
    "compromise",
    "hijack",
    "layoff",
    "private equity",
    "acquired",
    "carve-out",
    "renamed",
)
EOL_MARKERS = ("letzte jahr", "trotzdem ausführen", "discontinued", "end of life", "end-of-life")
YELLOW_DOM_MARKERS = ("{{price}}", "coming soon")
INCIDENT_TERMS = ("incident", "security", "injection", "breach", "unauthorized", "compromise")


@dataclass(frozen=True)
class _SignalBundle:
    news_hits: tuple[WebCitation, ...]
    wiki_res: tuple[WebCitation | None, str]
    sp_res: tuple[tuple[str, ...], tuple[WebCitation, ...]]
    gh_res: tuple[WebCitation | None, str]


def _as_dict(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


def _first_dict(items: object) -> dict[str, object]:
    if not isinstance(items, list) or not items:
        return {}
    return _as_dict(items[0])


def _str_field(mapping: dict[str, object], key: str) -> str:
    val = mapping.get(key)
    return val if isinstance(val, str) else ""


def _tag_text(parent: Tag, name: str) -> str:
    child = parent.find(name)
    return child.get_text(strip=True) if isinstance(child, Tag) else ""


def _is_http_link(url: str) -> bool:
    return url.startswith(("http://", "https://"))


def _is_valid_rss_pair(title: str, url: str) -> bool:
    return bool(title) and _is_http_link(url)


def _parse_single_rss_item(item: object) -> WebCitation | None:
    if not isinstance(item, Tag):
        return None
    title = _tag_text(item, "title")
    url = _tag_text(item, "link")
    return WebCitation(title=title, url=url) if _is_valid_rss_pair(title, url) else None


def parse_news_rss_items(xml_text: str) -> tuple[WebCitation, ...]:
    """Parse Google News RSS XML into verified WebCitation entries."""
    soup = BeautifulSoup(xml_text, "xml")
    parsed = [_parse_single_rss_item(node) for node in soup.find_all("item")[:MAX_RSS_HITS]]
    return tuple(c for c in parsed if c is not None)


def scan_dom_text_signals(dom_excerpt: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Detect deterministic EOL/security-bypass and placeholder signals in DOM text."""
    low = dom_excerpt.lower()
    reds = tuple(f"DOM text contains discontinuation/bypass marker: '{m}'" for m in EOL_MARKERS if m in low)
    yellows = tuple(f"DOM text contains unfinished/placeholder marker: '{m}'" for m in YELLOW_DOM_MARKERS if m in low)
    return reds, yellows


def _short_name(raw_name: str, fallback_domain: str) -> str:
    cleaned = re.split(r"[\(\/:,-]", raw_name, maxsplit=1)[0].strip()
    words = cleaned.split()[:3]
    short = " ".join(words)
    return short if len(short) >= MIN_ENTITY_LEN else fallback_domain.split(".", 1)[0]


def _word_hit(text: str, kw: str) -> bool:
    return bool(re.search(rf"\b{re.escape(kw.strip())}", text))


def _match_headline_tone(hit: WebCitation) -> tuple[str, str]:
    low = hit.title.lower().replace("breachguard", "")
    if any(_word_hit(low, kw) for kw in RED_KEYWORDS):
        return f"News/regulatory signal: {hit.title} ({hit.url})", ""
    yellow = f"News/ownership/security signal: {hit.title} ({hit.url})"
    return ("", yellow) if any(_word_hit(low, kw) for kw in YELLOW_KEYWORDS) else ("", "")


def _classify_news_hit(hit: WebCitation, entity: str) -> tuple[str, str]:
    if entity.lower() not in hit.title.lower():
        return "", ""
    return _match_headline_tone(hit)


def _non_empty_at(pairs: list[tuple[str, str]], index: int) -> tuple[str, ...]:
    return tuple(pair[index] for pair in pairs if pair[index])


def _classify_news_hits(
    hits: tuple[WebCitation, ...],
    entity: str,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    pairs = [_classify_news_hit(hit, entity) for hit in hits]
    return _non_empty_at(pairs, 0), _non_empty_at(pairs, 1)


async def _safe_get_json(client: httpx.AsyncClient, url: str, params: dict[str, str] | None = None) -> object:
    try:
        resp = await client.get(url, params=params, timeout=TIMEOUT_SECONDS)
        return resp.json() if resp.status_code == HTTP_OK else {}
    except (httpx.HTTPError, ValueError):
        return {}


async def _fetch_news_rss(client: httpx.AsyncClient, query: str) -> tuple[WebCitation, ...]:
    url = "https://news.google.com/rss/search"
    params = {"q": query, "hl": "en-US", "gl": "US", "ceid": "US:en"}
    try:
        resp = await client.get(url, params=params, timeout=TIMEOUT_SECONDS)
    except httpx.HTTPError:
        return ()
    return parse_news_rss_items(resp.text) if resp.status_code == HTTP_OK else ()


def _extract_wiki_hit(data: object, entity: str) -> tuple[WebCitation | None, str]:
    query_obj = _as_dict(_as_dict(data).get("query"))
    title = _str_field(_first_dict(query_obj.get("search")), "title")
    if not title or entity.lower() not in title.lower():
        return None, ""
    wiki_url = f"https://en.wikipedia.org/wiki/{quote(title.replace(' ', '_'))}"
    return WebCitation(title=f"Wikipedia: {title}", url=wiki_url), f"Established Wikipedia entry: {title} ({wiki_url})"


async def _fetch_wikipedia_signal(client: httpx.AsyncClient, entity: str) -> tuple[WebCitation | None, str]:
    data = await _safe_get_json(
        client,
        "https://en.wikipedia.org/w/api.php",
        {"action": "query", "list": "search", "srsearch": entity, "format": "json"},
    )
    return _extract_wiki_hit(data, entity)


def _is_incident_title(name: str) -> bool:
    return bool(name) and any(kw in name.lower() for kw in INCIDENT_TERMS)


def _incident_signal(inc: object, base_url: str) -> tuple[str, WebCitation] | None:
    entry = _as_dict(inc)
    name = _str_field(entry, "name")
    if not _is_incident_title(name):
        return None
    link = _str_field(entry, "shortlink")
    cite_url = link if _is_http_link(link) else base_url
    return f"Statuspage security/incident report: {name} ({cite_url})", WebCitation(title=name, url=cite_url)


def _unzip_incidents(pairs: list[tuple[str, WebCitation]]) -> tuple[tuple[str, ...], tuple[WebCitation, ...]]:
    return tuple(p[0] for p in pairs), tuple(p[1] for p in pairs)


def _collect_incidents(incidents: list[object], base_url: str) -> tuple[tuple[str, ...], tuple[WebCitation, ...]]:
    parsed = [_incident_signal(inc, base_url) for inc in incidents[:MAX_RSS_HITS]]
    return _unzip_incidents([p for p in parsed if p is not None])


async def _fetch_statuspage_incidents(
    client: httpx.AsyncClient,
    domain: str,
) -> tuple[tuple[str, ...], tuple[WebCitation, ...]]:
    url = f"https://status.{domain}/api/v2/incidents.json"
    data = await _safe_get_json(client, url)
    incidents = _as_dict(data).get("incidents")
    return _collect_incidents(incidents, url) if isinstance(incidents, list) else ((), ())


def _is_notable_repo(stars: object, repo_url: str) -> bool:
    return isinstance(stars, int) and stars >= HIGH_STARS_THRESHOLD and _is_http_link(repo_url)


def _extract_github_hit(data: object, entity: str) -> tuple[WebCitation | None, str]:
    first = _first_dict(_as_dict(data).get("items"))
    stars = first.get("stargazers_count", 0)
    repo_url = _str_field(first, "html_url")
    full_name = _str_field(first, "full_name")
    if entity.lower() not in full_name.lower() or not _is_notable_repo(stars, repo_url):
        return None, ""
    return WebCitation(title=f"GitHub: {full_name}", url=repo_url), f"Active GitHub repo ({stars} stars): {repo_url}"


async def _fetch_github_signal(client: httpx.AsyncClient, entity: str) -> tuple[WebCitation | None, str]:
    data = await _safe_get_json(
        client,
        "https://api.github.com/search/repositories",
        {"q": f"{entity} in:name", "sort": "stars", "per_page": "1"},
    )
    return _extract_github_hit(data, entity)


def _pick_verdict(reds: tuple[str, ...], yellows: tuple[str, ...]) -> StackginiVerdict:
    if reds:
        return StackginiVerdict.RED
    return StackginiVerdict.YELLOW if yellows else StackginiVerdict.GREEN


def _build_summary(item: VendorInput, overall: StackginiVerdict, counts: tuple[int, int, int]) -> str:
    return (
        f"Public intelligence verdict for {item.product} ({item.vendor}) is {overall.value}: "
        f"{counts[0]} positive, {counts[1]} caution, and {counts[2]} risk signals verified."
    )


def _default_ipv4_client() -> httpx.AsyncClient:
    ipv4_any = str(ipaddress.IPv4Address(0))
    return httpx.AsyncClient(
        transport=httpx.AsyncHTTPTransport(local_address=ipv4_any),
        follow_redirects=True,
        headers={"User-Agent": "StackginiVerifier/0.2"},
    )


class PublicSignalsResearchAdapter:
    """Zero-key WebResearchPort combining News RSS, Wikipedia, Statuspage, GitHub, and DOM signals."""

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client

    async def research_vendor(self, item: VendorInput, dom_excerpt: str) -> ProbeOutcome[WebIntelligence]:
        """Gather zero-key off-site evidence and synthesize a cited WebIntelligence report."""
        client = self._client or _default_ipv4_client()
        try:
            intel = await self._gather(client, item, dom_excerpt)
        finally:
            if self._client is None:
                await client.aclose()
        return ProbeOutcome.observed("https://news.google.com/", intel)

    async def _gather(self, client: httpx.AsyncClient, item: VendorInput, dom_excerpt: str) -> WebIntelligence:
        domain = extract_domain_from_url(item.url)
        entity = _short_name(item.product, domain)
        vendor_entity = _short_name(item.vendor, domain)
        reg_hits, ma_hits, wiki_res, sp_res, gh_res = await asyncio.gather(
            _fetch_news_rss(client, f'"{vendor_entity}" (FTC OR GDPR OR fine OR lawsuit OR breach OR Russia)'),
            _fetch_news_rss(client, f'"{vendor_entity}" (acquired OR "private equity" OR renamed OR layoffs)'),
            _fetch_wikipedia_signal(client, entity),
            _fetch_statuspage_incidents(client, domain),
            _fetch_github_signal(client, entity),
        )
        bundle = _SignalBundle(reg_hits + ma_hits, wiki_res, sp_res, gh_res)
        return self._assemble(item, vendor_entity, dom_excerpt, bundle)

    def _assemble(
        self,
        item: VendorInput,
        entity: str,
        dom_excerpt: str,
        bundle: _SignalBundle,
    ) -> WebIntelligence:
        news_reds, news_yellows = _classify_news_hits(bundle.news_hits, entity)
        dom_reds, dom_yellows = scan_dom_text_signals(dom_excerpt)
        greens = tuple(s for s in (bundle.wiki_res[1], bundle.gh_res[1]) if s)
        yellows = (*news_yellows, *bundle.sp_res[0], *dom_yellows)
        reds = (*news_reds, *dom_reds)
        citations = tuple(
            c for c in (*bundle.news_hits, *bundle.sp_res[1], bundle.wiki_res[0], bundle.gh_res[0]) if c is not None
        )
        overall = _pick_verdict(reds, yellows)
        counts = (len(greens), len(yellows), len(reds))
        return WebIntelligence(
            suggested_overall=overall,
            summary=_build_summary(item, overall, counts),
            citations=citations,
            green_signals=greens,
            yellow_signals=yellows,
            red_signals=reds,
        )
