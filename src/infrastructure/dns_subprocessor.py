"""DNS and GDPR subprocessor infrastructure adapters."""

from __future__ import annotations

import asyncio

import dns.exception
import dns.resolver

from src.domain.models import DnsProfile, ProbeOutcome, SubprocessorMatch

DNS_TIMEOUT_SECONDS = 4.0


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


def _resolve_txt_prefix(domain: str, prefix: str) -> str:
    lowered = prefix.lower()
    records = _query_txt_strings(domain)
    return next((rec for rec in records if rec.lower().startswith(lowered)), "")


def _resolve_dns_sync(domain: str) -> DnsProfile:
    mx_hosts = _resolve_mx(domain)
    spf = _resolve_txt_prefix(domain, "v=spf1")
    dmarc = _resolve_txt_prefix(f"_dmarc.{domain}", "v=dmarc1")
    return DnsProfile(mx_hosts=mx_hosts, spf_record=spf, dmarc_record=dmarc)


class DnsResolverAdapter:
    """Async wrapper around dnspython for MX, SPF, and DMARC lookup."""

    async def fetch_dns_profile(self, domain: str) -> ProbeOutcome[DnsProfile]:
        """Resolve MX, SPF, and DMARC records safely."""
        source_url = f"https://dns.google/resolve?name={domain}"
        try:
            profile = await asyncio.to_thread(_resolve_dns_sync, domain)
        except dns.exception.DNSException as exc:
            return ProbeOutcome.unavailable(source_url, type(exc).__name__)
        return ProbeOutcome.observed(source_url, profile)


class CuratedSubprocessorAdapter:
    """Deterministic local reverse-index adapter for known SaaS subprocessors."""

    def __init__(self, registry: dict[str, tuple[str, ...]]) -> None:
        self._registry = registry

    async def lookup_subprocessor(self, domain: str) -> ProbeOutcome[SubprocessorMatch]:
        """Lookup verified enterprise subprocessor references for domain."""
        source_url = f"https://subprocessors.stackgini.local/lookup/{domain}"
        refs = self._registry.get(domain.lower(), ())
        if not refs:
            return ProbeOutcome.not_found(source_url)
        return ProbeOutcome.observed(source_url, SubprocessorMatch(enterprise_refs=refs))
