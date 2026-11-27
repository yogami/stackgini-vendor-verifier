"""Immutable domain value objects, tri-state probe outcomes, and EvidenceLedger."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

BASE_TRUST_SCORE = 70
MIN_TRUST_SCORE = 0
MAX_TRUST_SCORE = 100
VERIFIED_THRESHOLD = 70
SUSPICIOUS_THRESHOLD = 40
HTTP_SCHEMES = ("http://", "https://")


def _require_http_url(url: str) -> None:
    if not url.startswith(HTTP_SCHEMES):
        raise ValueError(f"Expected HTTP(S) source_url, got: {url!r}")


class ProbeStatus(StrEnum):
    """Tri-state status preventing timeouts from masquerading as negative evidence."""

    OBSERVED = "observed"
    NOT_FOUND = "not_found"
    UNAVAILABLE = "unavailable"


class Verdict(StrEnum):
    """Deterministic risk verdict derived from EvidenceLedger score."""

    VERIFIED = "verified"
    SUSPICIOUS = "suspicious"
    FRAUD_RISK = "fraud_risk"


@dataclass(frozen=True)
class ProbeOutcome[T]:
    """Immutable Null-Object wrapper around external registry probe responses."""

    status: ProbeStatus
    source_url: str
    value: T | None = None
    reason: str = ""

    def __post_init__(self) -> None:
        if self.status != ProbeStatus.UNAVAILABLE:
            _require_http_url(self.source_url)

    @classmethod
    def observed(cls, source_url: str, value: T) -> ProbeOutcome[T]:
        """Construct an observed outcome backed by a verifiable source URL."""
        return cls(status=ProbeStatus.OBSERVED, source_url=source_url, value=value)

    @classmethod
    def not_found(cls, source_url: str, reason: str = "not_found") -> ProbeOutcome[T]:
        """Construct an authoritative negative outcome (e.g., HTTP 404 or empty registry)."""
        return cls(status=ProbeStatus.NOT_FOUND, source_url=source_url, reason=reason)

    @classmethod
    def unavailable(cls, source_url: str, reason: str) -> ProbeOutcome[T]:
        """Construct an abstaining outcome for transient rate limits or timeouts."""
        return cls(status=ProbeStatus.UNAVAILABLE, source_url=source_url, reason=reason)


@dataclass(frozen=True)
class DomainAgeRecord:
    """RDAP or WHOIS domain registration age metadata."""

    registered_year: int
    age_days: int


@dataclass(frozen=True)
class CertFootprint:
    """Certificate Transparency footprint from crt.sh."""

    cert_count: int
    earliest_year: int | None


@dataclass(frozen=True)
class DnsProfile:
    """MX and authentication TXT records for a vendor domain."""

    mx_hosts: tuple[str, ...]
    spf_record: str
    dmarc_record: str

    def has_auth_txt(self) -> bool:
        """Return True when either SPF or DMARC policy is published."""
        return bool(self.spf_record or self.dmarc_record)

    def has_full_auth(self) -> bool:
        """Return True when both MX delivery and DMARC enforcement are present."""
        return bool(self.mx_hosts and self.dmarc_record)


@dataclass(frozen=True)
class SubprocessorMatch:
    """Reverse lookup result across public enterprise GDPR subprocessor lists."""

    enterprise_refs: tuple[str, ...]


@dataclass(frozen=True)
class WaybackTimeline:
    """Wayback Machine CDX snapshot summary."""

    snapshot_count: int
    earliest_year: int | None


@dataclass(frozen=True)
class VendorClaim:
    """Target domain and optional claimed establishment year."""

    domain: str
    current_year: int
    claimed_since_year: int | None = None


@dataclass(frozen=True)
class VendorSignals:
    """Bundle of all five external probe outcomes for a vendor domain."""

    rdap: ProbeOutcome[DomainAgeRecord]
    certs: ProbeOutcome[CertFootprint]
    dns: ProbeOutcome[DnsProfile]
    subprocessor: ProbeOutcome[SubprocessorMatch]
    wayback: ProbeOutcome[WaybackTimeline]


@dataclass(frozen=True)
class VendorSnapshot:
    """Complete immutable input snapshot evaluated by VendorRule specifications."""

    claim: VendorClaim
    signals: VendorSignals


@dataclass(frozen=True)
class VerifiedFinding:
    """Single URL-backed forensic finding emitted by a VendorRule."""

    rule_id: str
    claim: str
    source_url: str
    observed_fact: str
    impact: int

    def __post_init__(self) -> None:
        _require_http_url(self.source_url)


@dataclass(frozen=True)
class EvidenceLedger:
    """Immutable Collecting Parameter accumulating findings and abstained signals."""

    findings: tuple[VerifiedFinding, ...] = ()
    abstained: tuple[str, ...] = ()

    def with_finding(self, finding: VerifiedFinding) -> EvidenceLedger:
        """Return a new ledger with the verified finding appended."""
        return EvidenceLedger(findings=(*self.findings, finding), abstained=self.abstained)

    def with_abstained(self, signal_name: str) -> EvidenceLedger:
        """Return a new ledger recording an abstained unavailable probe."""
        return EvidenceLedger(findings=self.findings, abstained=(*self.abstained, signal_name))

    def trust_score(self) -> int:
        """Compute clamped trust score in [0, 100]."""
        raw = BASE_TRUST_SCORE + sum(item.impact for item in self.findings)
        return max(MIN_TRUST_SCORE, min(MAX_TRUST_SCORE, raw))

    def verdict(self) -> Verdict:
        """Map numeric trust score into deterministic risk verdict."""
        score = self.trust_score()
        if score >= VERIFIED_THRESHOLD:
            return Verdict.VERIFIED
        return Verdict.SUSPICIOUS if score >= SUSPICIOUS_THRESHOLD else Verdict.FRAUD_RISK
