"""ISP-compliant secondary port protocols for the five verification signals."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from src.domain.models import (
    CertFootprint,
    DnsProfile,
    DomainAgeRecord,
    ProbeOutcome,
    SubprocessorMatch,
    WaybackTimeline,
)


class RdapProbePort(Protocol):
    """Port for RDAP/WHOIS domain registration age lookup."""

    async def fetch_domain_age(self, domain: str) -> ProbeOutcome[DomainAgeRecord]:
        """Fetch domain age record or return tri-state unavailable/not-found outcome."""
        ...


class CertHistoryPort(Protocol):
    """Port for Certificate Transparency log history lookup."""

    async def fetch_cert_history(self, domain: str) -> ProbeOutcome[CertFootprint]:
        """Fetch certificate count and earliest issuance year."""
        ...


class DnsRecordPort(Protocol):
    """Port for MX, SPF, and DMARC DNS lookup."""

    async def fetch_dns_profile(self, domain: str) -> ProbeOutcome[DnsProfile]:
        """Fetch MX hosts and authentication TXT records."""
        ...


class SubprocessorPort(Protocol):
    """Port for GDPR enterprise subprocessor reverse lookup."""

    async def lookup_subprocessor(self, domain: str) -> ProbeOutcome[SubprocessorMatch]:
        """Lookup verified enterprise subprocessor citations."""
        ...


class WaybackTimelinePort(Protocol):
    """Port for Wayback Machine CDX timeline lookup."""

    async def fetch_timeline(self, domain: str) -> ProbeOutcome[WaybackTimeline]:
        """Fetch archived snapshot count and earliest capture year."""
        ...


@dataclass(frozen=True)
class VendorProbeGateway:
    """Aggregated secondary ports injected into the verification use case."""

    rdap: RdapProbePort
    certs: CertHistoryPort
    dns: DnsRecordPort
    subprocessor: SubprocessorPort
    wayback: WaybackTimelinePort
