"""DNS TXT SaaS fingerprinting and public GDPR subprocessor lookup adapters."""

from __future__ import annotations

import asyncio
from urllib.parse import quote

import dns.exception
import dns.resolver
import httpx

from src.domain.models import DnsProfile, ProbeOutcome, SubprocessorMatch
from src.infrastructure.ssrf import verify_public_url_with_dns, verify_resolved_public_ips

DNS_TIMEOUT_SECONDS = 4.0
PROBE_TIMEOUT_SECONDS = 5.0
HTTP_OK = 200
DPA_BODY_MARKERS = ("subprocessor", "data processing", "auftragsverarbeiter", "gdpr", "privacy")
SAAS_TXT_PREFIXES: dict[str, str] = {
    "google-site-verification=": "google",
    "atlassian-domain-verification=": "atlassian",
    "docusign=": "docusign",
    "stripe-verification=": "stripe",
    "slack-domain-verification=": "slack",
    "hubspot-domain-verification=": "hubspot",
    "apple-domain-verification=": "apple",
    "notion-domain-verification=": "notion",
    "notion_verify_": "notion",
    "openai-domain-verification=": "openai",
    "anthropic-domain-verification": "anthropic",
    "zoom-domain-verification=": "zoom",
    "zoom_verify_": "zoom",
    "1password-site-verification=": "1password",
    "airtable-verification=": "airtable",
    "miro-verification=": "miro",
    "vercel-domain-verification": "vercel",
    "ms=": "microsoft-365",
}


def _resolve_mx(domain: str) -> tuple[str, ...]:
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=DNS_TIMEOUT_SECONDS)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return ()
    return tuple(sorted(str(rdata.exchange).rstrip(".") for rdata in answers))


def _query_txt_strings(domain: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=DNS_TIMEOUT_SECONDS)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    return ["".join(part.decode("utf-8", errors="ignore") for part in rdata.strings) for rdata in answers]


def _match_prefix_record(records: list[str], prefix: str) -> str:
    lowered = prefix.lower()
    return next((rec for rec in records if rec.lower().startswith(lowered)), "")


def _detect_saas_token(record: str) -> str:
    lowered = record.lower()
    for marker, vendor_name in SAAS_TXT_PREFIXES.items():
        if lowered.startswith(marker):
            return vendor_name
    return ""


def extract_saas_verifications(records: list[str]) -> tuple[str, ...]:
    """Extract sorted unique third-party SaaS tools evidenced by TXT verifications."""
    found = {token for rec in records if (token := _detect_saas_token(rec))}
    return tuple(sorted(found))


def _resolve_dns_sync(domain: str) -> DnsProfile:
    mx_hosts = _resolve_mx(domain)
    root_txts = _query_txt_strings(domain)
    dmarc_txts = _query_txt_strings(f"_dmarc.{domain}")
    return DnsProfile(
        mx_hosts=mx_hosts,
        spf_record=_match_prefix_record(root_txts, "v=spf1"),
        dmarc_record=_match_prefix_record(dmarc_txts, "v=dmarc1"),
        saas_verifications=extract_saas_verifications(root_txts),
    )


class DnsResolverAdapter:
    """Async wrapper around dnspython for MX, SPF, DMARC, and SaaS TXT fingerprinting."""

    async def fetch_dns_profile(self, domain: str) -> ProbeOutcome[DnsProfile]:
        """Resolve MX, SPF, DMARC, and TXT verification tokens safely."""
        source_url = f"https://dns.google/resolve?name={domain}"
        try:
            profile = await asyncio.to_thread(_resolve_dns_sync, domain)
        except dns.exception.DNSException as exc:
            return ProbeOutcome.unavailable(source_url, type(exc).__name__)
        return ProbeOutcome.observed(source_url, profile)


def _entry_html_url(entry: object) -> str:
    if not isinstance(entry, dict):
        return ""
    return str(entry.get("html_url", "")).strip()


def _extract_repo_urls(payload: object) -> tuple[str, ...]:
    items = payload.get("items", []) if isinstance(payload, dict) else []
    urls = [_entry_html_url(entry) for entry in items]
    return tuple(url for url in urls if url)


def _has_dpa_markers(resp: httpx.Response) -> bool:
    if resp.status_code != HTTP_OK:
        return False
    body_head = resp.text[:6000].lower()
    return any(marker in body_head for marker in DPA_BODY_MARKERS)


def _valid_dpa_response(resp: httpx.Response) -> str:
    safe_url = ""
    if _has_dpa_markers(resp):
        try:
            safe_url = verify_public_url_with_dns(str(resp.url))
        except ValueError:
            safe_url = ""
    return safe_url


async def _try_dpa_path(client: httpx.AsyncClient, path: str) -> str:
    try:
        safe_url = await asyncio.to_thread(verify_public_url_with_dns, path)
        resp = await client.get(safe_url, timeout=PROBE_TIMEOUT_SECONDS, follow_redirects=True)
    except (httpx.HTTPError, ValueError):
        return ""
    return _valid_dpa_response(resp)


async def _probe_first_dpa_url(client: httpx.AsyncClient, domain: str) -> str:
    try:
        await asyncio.to_thread(verify_resolved_public_ips, domain)
    except ValueError:
        return ""
    urls = await asyncio.gather(
        _try_dpa_path(client, f"https://{domain}/subprocessors"),
        _try_dpa_path(client, f"https://{domain}/dpa"),
    )
    return next((u for u in urls if u), "")


def _decode_github_items(resp: httpx.Response) -> tuple[tuple[str, ...], bool]:
    result: tuple[tuple[str, ...], bool] = ((), False)
    if resp.status_code == HTTP_OK:
        try:
            result = _extract_repo_urls(resp.json()), True
        except ValueError:
            result = (), False
    return result


async def _search_github_subprocessor_refs(client: httpx.AsyncClient, domain: str) -> tuple[tuple[str, ...], str, bool]:
    query = quote(f'"{domain}" subprocessors')
    url = f"https://api.github.com/search/repositories?q={query}&per_page=3"
    try:
        resp = await client.get(url, timeout=PROBE_TIMEOUT_SECONDS)
    except httpx.HTTPError:
        return (), url, False
    refs, ok = _decode_github_items(resp)
    return refs, url, ok


def _negative_subprocessor_outcome(query_url: str, ok: bool) -> ProbeOutcome[SubprocessorMatch]:
    return ProbeOutcome.not_found(query_url) if ok else ProbeOutcome.unavailable(query_url, "subprocessor_unavailable")


def _build_subprocessor_outcome(
    refs: tuple[str, ...],
    dpa_url: str,
    query_url: str,
    ok: bool,
) -> ProbeOutcome[SubprocessorMatch]:
    if not any((refs, dpa_url)):
        return _negative_subprocessor_outcome(query_url, ok)
    return ProbeOutcome.observed(dpa_url or query_url, SubprocessorMatch(enterprise_refs=refs, dpa_url=dpa_url))


class PublicSubprocessorAdapter:
    """Live GDPR subprocessor & DPA endpoint lookup replacing fake .local stubs."""

    def __init__(self, client: httpx.AsyncClient, registry: dict[str, tuple[str, ...]] | None = None) -> None:
        self._client = client
        self._registry = registry or {}

    async def lookup_subprocessor(self, domain: str) -> ProbeOutcome[SubprocessorMatch]:
        """Check vendor DPA endpoints, curated refs, and public repository mentions."""
        normalized = domain.lower()
        dpa_url, (gh_refs, query_url, ok) = await asyncio.gather(
            _probe_first_dpa_url(self._client, normalized),
            _search_github_subprocessor_refs(self._client, normalized),
        )
        refs = tuple(dict.fromkeys((*self._registry.get(normalized, ()), *gh_refs)))
        return _build_subprocessor_outcome(refs, dpa_url, query_url, ok)


class CuratedSubprocessorAdapter:
    """Deterministic registry reverse-index adapter using verifiable HTTP query URLs."""

    def __init__(self, registry: dict[str, tuple[str, ...]]) -> None:
        self._registry = registry

    async def lookup_subprocessor(self, domain: str) -> ProbeOutcome[SubprocessorMatch]:
        """Lookup verified enterprise subprocessor references for domain."""
        normalized = domain.lower()
        source_url = f"https://github.com/search?q={quote(normalized)}+subprocessors&type=repositories"
        refs = self._registry.get(normalized, ())
        if not refs:
            return ProbeOutcome.not_found(source_url)
        return ProbeOutcome.observed(source_url, SubprocessorMatch(enterprise_refs=refs))
