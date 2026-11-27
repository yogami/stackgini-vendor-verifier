"""Zero-key public web intelligence adapter using News RSS, Wikipedia, Statuspage, and GitHub."""

from __future__ import annotations

import asyncio
import contextlib
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
from src.infrastructure.ssrf import verify_public_url_with_dns, verify_resolved_public_ips

TIMEOUT_SECONDS = 8.0
MAX_RSS_HITS = 5
MIN_ENTITY_LEN = 3
HTTP_OK = 200
HIGH_STARS_THRESHOLD = 100
ENTITY_STOPWORDS = frozenset({"and", "the", "of", "for", "by"})
RED_KEYWORDS = (
    "ftc",
    "fined",
    "penalty",
    "unlawful",
    "lawsuit",
    "class action",
    "ordered to pay",
    "banned from selling",
    "sanctions",
    "russia",
)
YELLOW_KEYWORDS = (
    "breach",
    "incident",
    "compromise",
    "hijack",
    "layoff",
    "private equity",
    "acquired",
    "carve-out",
    "renamed",
)
EOL_TERMS = ("discontinued", "end of life", "end-of-life", "no longer maintained", "final release")
BYPASS_TERMS = ("run anyway", "ignore warning", "disable antivirus", "smartscreen", "defender warning")
TEMPLATE_PLACEHOLDER_RE = re.compile(r"\{\{[A-Z0-9_]{2,20}\}\}|\[placeholder\]", re.ASCII)
INCIDENT_TERMS = ("incident", "security", "breach", "unauthorized", "compromise", "vulnerability")
FINANCIAL_WIRE_NOISE = (
    "stock acquired",
    "shares acquired",
    "shares purchased",
    "price target",
    "earnings call",
)
SOFTWARE_CONTEXT_TERMS = (
    "software",
    "saas",
    "platform",
    "cloud",
    "security",
    "breach",
    "cyber",
    "data",
    "privacy",
    "app",
    "vendor",
    "ftc",
    "gdpr",
    "dpa",
    "cve",
)


@dataclass(frozen=True)
class _RssProbeResult:
    hits: tuple[WebCitation, ...]
    ok: int


@dataclass(frozen=True)
class _TextSignalResult:
    citation: WebCitation | None
    signal: str
    ok: int


@dataclass(frozen=True)
class _StatusProbeResult:
    signals: tuple[str, ...]
    citations: tuple[WebCitation, ...]
    ok: int


@dataclass(frozen=True)
class _SignalBundle:
    news_hits: tuple[WebCitation, ...]
    wiki_res: _TextSignalResult
    sp_res: _StatusProbeResult
    gh_res: _TextSignalResult
    ok_probes: int
    err_probes: int


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


def _build_rss_citation(title: str, url: str) -> WebCitation | None:
    return WebCitation(title=title, url=url) if bool(title) and _is_http_link(url) else None


def _parse_single_rss_item(item: object) -> WebCitation | None:
    if not isinstance(item, Tag):
        return None
    return _build_rss_citation(_tag_text(item, "title"), _tag_text(item, "link"))


def parse_news_rss_items(xml_text: str) -> tuple[WebCitation, ...]:
    """Parse Google News RSS XML into verified WebCitation entries."""
    soup = BeautifulSoup(xml_text, "xml")
    parsed = [_parse_single_rss_item(node) for node in soup.find_all("item")[:MAX_RSS_HITS]]
    return tuple(c for c in parsed if c is not None)


def _has_eol_and_bypass(low: str) -> bool:
    return any(term in low for term in EOL_TERMS) and any(term in low for term in BYPASS_TERMS)


def scan_dom_text_signals(dom_excerpt: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Detect general EOL security-bypass risks and unfilled template placeholders."""
    low = dom_excerpt.lower()
    red_msg = ("DOM indicates product discontinuation combined with security-warning bypass guidance.",)
    yel_msg = ("DOM contains unfilled template placeholder markup.",)
    reds = red_msg if _has_eol_and_bypass(low) else ()
    yellows = yel_msg if TEMPLATE_PLACEHOLDER_RE.search(dom_excerpt) else ()
    return reds, yellows


def _clean_entity_words(raw_name: str) -> list[str]:
    cleaned = re.split(r"[\(\/:,-]", raw_name, maxsplit=1)[0].strip()
    return [w for w in cleaned.split()[:3] if w.lower() not in ENTITY_STOPWORDS]


def _short_name(raw_name: str, fallback_domain: str) -> str:
    words = _clean_entity_words(raw_name)
    short = " ".join(words[:2])
    return short if len(short) >= MIN_ENTITY_LEN else fallback_domain.split(".", 1)[0]


def _word_hit(text: str, kw: str) -> bool:
    return bool(re.search(rf"\b{re.escape(kw.strip())}\b", text))


def _match_headline_tone(hit: WebCitation) -> tuple[str, str]:
    low = hit.title.lower()
    if any(_word_hit(low, kw) for kw in RED_KEYWORDS):
        return f"News/regulatory signal: {hit.title} ({hit.url})", ""
    yellow = f"News/ownership/security signal: {hit.title} ({hit.url})"
    return ("", yellow) if any(_word_hit(low, kw) for kw in YELLOW_KEYWORDS) else ("", "")


def _is_noisy_headline(lowered_title: str) -> bool:
    normalized = lowered_title.replace("\u2019", "'")
    return any(noise in normalized for noise in FINANCIAL_WIRE_NOISE)


def _has_domain_or_vendor(lowered_title: str, domain: str, vendor_ent: str) -> bool:
    if domain.lower() in lowered_title:
        return True
    return bool(vendor_ent) and vendor_ent.lower() in lowered_title


def _has_software_context(lowered_title: str) -> bool:
    return any(term in lowered_title for term in SOFTWARE_CONTEXT_TERMS)


def _matches_product_context(lowered_title: str, prod_ent: str) -> bool:
    return bool(prod_ent) and prod_ent.lower() in lowered_title and _has_software_context(lowered_title)


def _is_relevant_news(lowered_title: str, entities: tuple[str, str, str]) -> bool:
    if _is_noisy_headline(lowered_title):
        return False
    vendor_ent, prod_ent, domain = entities
    return _has_domain_or_vendor(lowered_title, domain, vendor_ent) or _matches_product_context(lowered_title, prod_ent)


def _classify_news_hit(hit: WebCitation, entities: tuple[str, str, str]) -> tuple[str, str]:
    lowered_title = hit.title.lower()
    return _match_headline_tone(hit) if _is_relevant_news(lowered_title, entities) else ("", "")


def _non_empty_at(pairs: list[tuple[str, str]], index: int) -> tuple[str, ...]:
    return tuple(pair[index] for pair in pairs if pair[index])


def _classify_news_hits(
    hits: tuple[WebCitation, ...],
    entities: tuple[str, str, str],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    pairs = [_classify_news_hit(hit, entities) for hit in hits]
    return _non_empty_at(pairs, 0), _non_empty_at(pairs, 1)


def _parse_json_or_empty(resp: httpx.Response) -> tuple[object, int]:
    data: object = {}
    ok = 0
    if resp.status_code == HTTP_OK:
        with contextlib.suppress(ValueError):
            data, ok = resp.json(), 1
    return data, ok


async def _safe_get_json(
    client: httpx.AsyncClient, url: str, params: dict[str, str] | None = None
) -> tuple[object, int]:
    try:
        resp = await client.get(url, params=params, timeout=TIMEOUT_SECONDS)
    except httpx.HTTPError:
        return {}, 0
    return _parse_json_or_empty(resp)


async def _fetch_news_rss(client: httpx.AsyncClient, query: str) -> _RssProbeResult:
    url = "https://news.google.com/rss/search"
    params = {"q": query, "hl": "en-US", "gl": "US", "ceid": "US:en"}
    try:
        resp = await client.get(url, params=params, timeout=TIMEOUT_SECONDS)
    except httpx.HTTPError:
        return _RssProbeResult((), 0)
    return (
        _RssProbeResult(parse_news_rss_items(resp.text), 1) if resp.status_code == HTTP_OK else _RssProbeResult((), 0)
    )


def _extract_wiki_hit(data: object, entity: str, ok: int) -> _TextSignalResult:
    query_obj = _as_dict(_as_dict(data).get("query"))
    title = _str_field(_first_dict(query_obj.get("search")), "title")
    if not title or entity.lower() not in title.lower():
        return _TextSignalResult(None, "", ok)
    wiki_url = f"https://en.wikipedia.org/wiki/{quote(title.replace(' ', '_'))}"
    return _TextSignalResult(
        WebCitation(title=f"Wikipedia: {title}", url=wiki_url),
        f"Established Wikipedia entry: {title} ({wiki_url})",
        ok,
    )


async def _fetch_wikipedia_signal(client: httpx.AsyncClient, entity: str, query: str = "") -> _TextSignalResult:
    data, ok = await _safe_get_json(
        client,
        "https://en.wikipedia.org/w/api.php",
        {"action": "query", "list": "search", "srsearch": query or entity, "format": "json"},
    )
    return _extract_wiki_hit(data, entity, ok)


def _is_incident_title(name: str) -> bool:
    lowered = name.lower()
    return bool(name) and any(kw in lowered for kw in INCIDENT_TERMS)


def _incident_signal(inc: object, base_url: str) -> tuple[str, WebCitation] | None:
    entry = _as_dict(inc)
    name = _str_field(entry, "name")
    if not _is_incident_title(name):
        return None
    link = _str_field(entry, "shortlink")
    cite_url = link if _is_http_link(link) else base_url
    return f"Statuspage security/incident report: {name} ({cite_url})", WebCitation(title=name, url=cite_url)


def _collect_incidents(incidents: list[object], base_url: str, ok: int) -> _StatusProbeResult:
    parsed = [res for inc in incidents[:MAX_RSS_HITS] if (res := _incident_signal(inc, base_url)) is not None]
    return _StatusProbeResult(tuple(p[0] for p in parsed), tuple(p[1] for p in parsed), ok)


async def _fetch_statuspage_incidents(client: httpx.AsyncClient, domain: str) -> _StatusProbeResult:
    url = f"https://status.{domain}/api/v2/incidents.json"
    try:
        await asyncio.to_thread(verify_resolved_public_ips, f"status.{domain}")
        await asyncio.to_thread(verify_public_url_with_dns, url)
    except ValueError:
        return _StatusProbeResult((), (), 0)
    data, ok = await _safe_get_json(client, url)
    incidents = _as_dict(data).get("incidents")
    return _collect_incidents(incidents, url, ok) if isinstance(incidents, list) else _StatusProbeResult((), (), ok)


def _is_notable_repo(stars: object, repo_url: str) -> bool:
    return isinstance(stars, int) and stars >= HIGH_STARS_THRESHOLD and _is_http_link(repo_url)


def _extract_github_hit(data: object, entity: str, ok: int) -> _TextSignalResult:
    first = _first_dict(_as_dict(data).get("items"))
    stars = first.get("stargazers_count", 0)
    repo_url = _str_field(first, "html_url")
    full_name = _str_field(first, "full_name")
    if entity.lower() not in full_name.lower() or not _is_notable_repo(stars, repo_url):
        return _TextSignalResult(None, "", ok)
    return _TextSignalResult(
        WebCitation(title=f"GitHub: {full_name}", url=repo_url),
        f"Active GitHub repo ({stars} stars): {repo_url}",
        ok,
    )


async def _fetch_github_signal(client: httpx.AsyncClient, entity: str) -> _TextSignalResult:
    data, ok = await _safe_get_json(
        client,
        "https://api.github.com/search/repositories",
        {"q": f"{entity} in:name", "sort": "stars", "per_page": "1"},
    )
    return _extract_github_hit(data, entity, ok)


def _pick_verdict(reds: tuple[str, ...], yellows: tuple[str, ...]) -> StackginiVerdict:
    if reds:
        return StackginiVerdict.RED
    return StackginiVerdict.YELLOW if yellows else StackginiVerdict.GREEN


def _build_summary(item: VendorInput, overall: StackginiVerdict, counts: tuple[int, int, int]) -> str:
    return (
        f"Public intelligence verdict for {item.product} ({item.vendor}) is {overall.value}: "
        f"{counts[0]} positive, {counts[1]} caution, and {counts[2]} risk signals verified."
    )


def _default_http_client() -> httpx.AsyncClient:
    headers = {"User-Agent": "StackginiVerifier/0.3"}
    try:
        transport = httpx.AsyncHTTPTransport(local_address=str(ipaddress.IPv4Address(0)))
        return httpx.AsyncClient(transport=transport, follow_redirects=True, headers=headers)
    except OSError:
        return httpx.AsyncClient(follow_redirects=True, headers=headers)


class PublicSignalsResearchAdapter:
    """Zero-key WebResearchPort combining News RSS, Wikipedia, Statuspage, GitHub, and DOM signals."""

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client

    async def research_vendor(self, item: VendorInput, dom_excerpt: str) -> ProbeOutcome[WebIntelligence]:
        """Gather zero-key off-site evidence and avoid false Green on failed/empty probes."""
        client = self._client or _default_http_client()
        try:
            bundle, intel = await self._gather(client, item, dom_excerpt)
        finally:
            if self._client is None:
                await client.aclose()
        return self._to_outcome(bundle, intel)

    async def _gather(
        self,
        client: httpx.AsyncClient,
        item: VendorInput,
        dom_excerpt: str,
    ) -> tuple[_SignalBundle, WebIntelligence]:
        domain = extract_domain_from_url(item.url)
        prod_ent = _short_name(item.product, domain)
        vend_ent = _short_name(item.vendor, domain)
        reg_res, ma_res, wiki_res, sp_res, gh_res = await asyncio.gather(
            _fetch_news_rss(
                client, f'("{domain}" OR ("{vend_ent}" software)) (FTC OR GDPR OR fine OR lawsuit OR breach)'
            ),
            _fetch_news_rss(
                client, f'("{domain}" OR ("{vend_ent}" software)) (acquired OR "private equity" OR renamed)'
            ),
            _fetch_wikipedia_signal(client, prod_ent, query=f'"{prod_ent}" software'),
            _fetch_statuspage_incidents(client, domain),
            _fetch_github_signal(client, prod_ent),
        )
        ok_count = reg_res.ok + ma_res.ok + wiki_res.ok + sp_res.ok + gh_res.ok
        bundle = _SignalBundle(reg_res.hits + ma_res.hits, wiki_res, sp_res, gh_res, ok_count, 5 - ok_count)
        return bundle, self._assemble(item, (vend_ent, prod_ent, domain), dom_excerpt, bundle)

    def _assemble(
        self,
        item: VendorInput,
        entities: tuple[str, str, str],
        dom_excerpt: str,
        bundle: _SignalBundle,
    ) -> WebIntelligence:
        news_reds, news_yellows = _classify_news_hits(bundle.news_hits, entities)
        dom_reds, dom_yellows = scan_dom_text_signals(dom_excerpt)
        greens = tuple(s for s in (bundle.wiki_res.signal, bundle.gh_res.signal) if s)
        yellows = (*news_yellows, *bundle.sp_res.signals, *dom_yellows)
        reds = (*news_reds, *dom_reds)
        citations = tuple(
            c
            for c in (*bundle.news_hits, *bundle.sp_res.citations, bundle.wiki_res.citation, bundle.gh_res.citation)
            if c
        )
        overall = _pick_verdict(reds, yellows)
        return WebIntelligence(
            suggested_overall=overall,
            summary=_build_summary(item, overall, (len(greens), len(yellows), len(reds))),
            citations=citations,
            green_signals=greens,
            yellow_signals=yellows,
            red_signals=reds,
        )

    def _empty_fallback(self, bundle: _SignalBundle) -> ProbeOutcome[WebIntelligence]:
        if bundle.ok_probes == 0 and bundle.err_probes > 0:
            return ProbeOutcome.unavailable("https://news.google.com/", "upstream_probes_unavailable")
        return ProbeOutcome.not_found("https://news.google.com/", "no_public_signals")

    def _to_outcome(self, bundle: _SignalBundle, intel: WebIntelligence) -> ProbeOutcome[WebIntelligence]:
        if any((intel.green_signals, intel.yellow_signals, intel.red_signals)):
            return ProbeOutcome.observed("https://news.google.com/", intel)
        return self._empty_fallback(bundle)
