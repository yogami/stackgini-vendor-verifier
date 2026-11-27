"""Composable Kerievsky VendorRule specifications for all five verification signals."""

from __future__ import annotations

from typing import Protocol

from src.domain.models import (
    CertFootprint,
    DnsProfile,
    DomainAgeRecord,
    EvidenceLedger,
    ProbeOutcome,
    ProbeStatus,
    SubprocessorMatch,
    VendorClaim,
    VendorSnapshot,
    VerifiedFinding,
    WaybackTimeline,
)

MIN_ESTABLISHED_DAYS = 180
YOUNG_DOMAIN_PENALTY = -30
BACKDATE_GAP_YEARS = 2
BACKDATE_PENALTY = -25
MISSING_CERTS_PENALTY = -25
SINGLE_CERT_PENALTY = -10
ESTABLISHED_CERT_COUNT = 5
ESTABLISHED_CERT_BONUS = 5
NO_DNS_AUTH_PENALTY = -20
FULL_DNS_AUTH_BONUS = 5
SUBPROCESSOR_BONUS = 10
MISSING_WAYBACK_PENALTY = -20
ESTABLISHED_WAYBACK_SNAPSHOTS = 10
ESTABLISHED_WAYBACK_YEARS = 2
ESTABLISHED_WAYBACK_BONUS = 5


class VendorRule(Protocol):
    """Composable specification evaluating one verification signal into an EvidenceLedger."""

    def evaluate(self, snapshot: VendorSnapshot, ledger: EvidenceLedger) -> EvidenceLedger:
        """Evaluate snapshot and return updated EvidenceLedger."""
        ...


def _check_young_domain(source_url: str, record: DomainAgeRecord, ledger: EvidenceLedger) -> EvidenceLedger:
    if record.age_days >= MIN_ESTABLISHED_DAYS:
        return ledger
    finding = VerifiedFinding(
        rule_id="rdap_young_domain",
        claim="Domain registration age",
        source_url=source_url,
        observed_fact=f"age_days={record.age_days}",
        impact=YOUNG_DOMAIN_PENALTY,
    )
    return ledger.with_finding(finding)


def _compare_claim_year(
    claimed_year: int,
    probe: ProbeOutcome[DomainAgeRecord],
    ledger: EvidenceLedger,
) -> EvidenceLedger:
    record = probe.value
    if record is None or (record.registered_year - claimed_year) < BACKDATE_GAP_YEARS:
        return ledger
    finding = VerifiedFinding(
        rule_id="rdap_backdated_claim",
        claim=f"Claimed heritage since {claimed_year}",
        source_url=probe.source_url,
        observed_fact=f"registered_year={record.registered_year}",
        impact=BACKDATE_PENALTY,
    )
    return ledger.with_finding(finding)


def _check_backdated_claim(
    claim: VendorClaim,
    probe: ProbeOutcome[DomainAgeRecord],
    ledger: EvidenceLedger,
) -> EvidenceLedger:
    if claim.claimed_since_year is None:
        return ledger
    return _compare_claim_year(claim.claimed_since_year, probe, ledger)


class DomainAgeMismatchRule:
    """Evaluate RDAP registration age and claimed founding-year contradictions."""

    def evaluate(self, snapshot: VendorSnapshot, ledger: EvidenceLedger) -> EvidenceLedger:
        """Score domain age and backdating mismatch against RDAP evidence."""
        probe = snapshot.signals.rdap
        if probe.status != ProbeStatus.OBSERVED or probe.value is None:
            return ledger.with_abstained("rdap")
        updated = _check_young_domain(probe.source_url, probe.value, ledger)
        return _check_backdated_claim(snapshot.claim, probe, updated)


def _single_cert_finding(source_url: str, footprint: CertFootprint) -> VerifiedFinding | None:
    if footprint.cert_count > 1:
        return None
    return VerifiedFinding(
        rule_id="cert_single",
        claim="Certificate Transparency footprint",
        source_url=source_url,
        observed_fact=f"cert_count={footprint.cert_count}",
        impact=SINGLE_CERT_PENALTY,
    )


def _established_cert_finding(source_url: str, footprint: CertFootprint) -> VerifiedFinding | None:
    if footprint.cert_count < ESTABLISHED_CERT_COUNT:
        return None
    return VerifiedFinding(
        rule_id="cert_established",
        claim="Certificate Transparency footprint",
        source_url=source_url,
        observed_fact=f"cert_count={footprint.cert_count}",
        impact=ESTABLISHED_CERT_BONUS,
    )


def _append_if_present(ledger: EvidenceLedger, finding: VerifiedFinding | None) -> EvidenceLedger:
    return ledger.with_finding(finding) if finding is not None else ledger


def _evaluate_observed_certs(
    source_url: str, footprint: CertFootprint | None, ledger: EvidenceLedger
) -> EvidenceLedger:
    if footprint is None:
        return ledger
    finding = _single_cert_finding(source_url, footprint) or _established_cert_finding(source_url, footprint)
    return _append_if_present(ledger, finding)


def _evaluate_cert_probe(probe: ProbeOutcome[CertFootprint], ledger: EvidenceLedger) -> EvidenceLedger:
    if probe.status == ProbeStatus.NOT_FOUND:
        return ledger.with_finding(
            VerifiedFinding(
                rule_id="cert_not_found",
                claim="Certificate Transparency footprint",
                source_url=probe.source_url,
                observed_fact="cert_count=0",
                impact=MISSING_CERTS_PENALTY,
            )
        )
    return _evaluate_observed_certs(probe.source_url, probe.value, ledger)


class CertificateHistoryRule:
    """Evaluate crt.sh certificate issuance depth."""

    def evaluate(self, snapshot: VendorSnapshot, ledger: EvidenceLedger) -> EvidenceLedger:
        """Score crt.sh certificate count, abstaining on transient unavailability."""
        probe = snapshot.signals.certs
        if probe.status == ProbeStatus.UNAVAILABLE:
            return ledger.with_abstained("certs")
        return _evaluate_cert_probe(probe, ledger)


def _missing_dns_finding(source_url: str, profile: DnsProfile) -> VerifiedFinding | None:
    if profile.mx_hosts or profile.has_auth_txt():
        return None
    return VerifiedFinding(
        rule_id="dns_missing_auth",
        claim="Mail and sender authentication DNS records",
        source_url=source_url,
        observed_fact="mx_count=0,spf=absent,dmarc=absent",
        impact=NO_DNS_AUTH_PENALTY,
    )


def _full_dns_finding(source_url: str, profile: DnsProfile) -> VerifiedFinding | None:
    if not profile.has_full_auth():
        return None
    return VerifiedFinding(
        rule_id="dns_full_auth",
        claim="Mail and sender authentication DNS records",
        source_url=source_url,
        observed_fact=f"mx_count={len(profile.mx_hosts)},dmarc=present",
        impact=FULL_DNS_AUTH_BONUS,
    )


def _evaluate_observed_dns(source_url: str, profile: DnsProfile | None, ledger: EvidenceLedger) -> EvidenceLedger:
    if profile is None:
        return ledger
    finding = _missing_dns_finding(source_url, profile) or _full_dns_finding(source_url, profile)
    return _append_if_present(ledger, finding)


class DnsAuthSignalRule:
    """Evaluate MX, SPF, and DMARC DNS authentication posture."""

    def evaluate(self, snapshot: VendorSnapshot, ledger: EvidenceLedger) -> EvidenceLedger:
        """Score DNS infrastructure maturity from observed MX/TXT records."""
        probe = snapshot.signals.dns
        if probe.status != ProbeStatus.OBSERVED:
            return ledger.with_abstained("dns")
        return _evaluate_observed_dns(probe.source_url, probe.value, ledger)


def _evaluate_observed_subprocessor(
    source_url: str,
    match: SubprocessorMatch | None,
    ledger: EvidenceLedger,
) -> EvidenceLedger:
    if match is None or not match.enterprise_refs:
        return ledger
    return ledger.with_finding(
        VerifiedFinding(
            rule_id="subprocessor_corroborated",
            claim="Enterprise GDPR subprocessor reverse lookup",
            source_url=source_url,
            observed_fact=f"enterprise_refs={len(match.enterprise_refs)}",
            impact=SUBPROCESSOR_BONUS,
        )
    )


def _evaluate_subprocessor_probe(probe: ProbeOutcome[SubprocessorMatch], ledger: EvidenceLedger) -> EvidenceLedger:
    if probe.status == ProbeStatus.NOT_FOUND:
        return ledger.with_finding(
            VerifiedFinding(
                rule_id="subprocessor_unlisted",
                claim="Enterprise GDPR subprocessor reverse lookup",
                source_url=probe.source_url,
                observed_fact="enterprise_refs=0",
                impact=0,
            )
        )
    return _evaluate_observed_subprocessor(probe.source_url, probe.value, ledger)


class SubprocessorCorroborationRule:
    """Evaluate corroboration from third-party enterprise GDPR subprocessor registries."""

    def evaluate(self, snapshot: VendorSnapshot, ledger: EvidenceLedger) -> EvidenceLedger:
        """Award corroboration when enterprise subprocessor records reference vendor."""
        probe = snapshot.signals.subprocessor
        if probe.status == ProbeStatus.UNAVAILABLE:
            return ledger.with_abstained("subprocessor")
        return _evaluate_subprocessor_probe(probe, ledger)


def _is_established_wayback(timeline: WaybackTimeline, current_year: int) -> bool:
    if timeline.snapshot_count < ESTABLISHED_WAYBACK_SNAPSHOTS:
        return False
    cutoff_year = current_year - ESTABLISHED_WAYBACK_YEARS
    return timeline.earliest_year is not None and timeline.earliest_year <= cutoff_year


def _evaluate_observed_wayback(
    probe: ProbeOutcome[WaybackTimeline],
    current_year: int,
    ledger: EvidenceLedger,
) -> EvidenceLedger:
    timeline = probe.value
    if timeline is None or not _is_established_wayback(timeline, current_year):
        return ledger
    finding = VerifiedFinding(
        rule_id="wayback_established",
        claim="Wayback CDX archive longevity",
        source_url=probe.source_url,
        observed_fact=f"snapshots={timeline.snapshot_count},earliest_year={timeline.earliest_year}",
        impact=ESTABLISHED_WAYBACK_BONUS,
    )
    return ledger.with_finding(finding)


def _evaluate_wayback_probe(
    probe: ProbeOutcome[WaybackTimeline],
    current_year: int,
    ledger: EvidenceLedger,
) -> EvidenceLedger:
    if probe.status == ProbeStatus.NOT_FOUND:
        return ledger.with_finding(
            VerifiedFinding(
                rule_id="wayback_not_found",
                claim="Wayback CDX archive longevity",
                source_url=probe.source_url,
                observed_fact="snapshots=0",
                impact=MISSING_WAYBACK_PENALTY,
            )
        )
    return _evaluate_observed_wayback(probe, current_year, ledger)


class WaybackTimelineRule:
    """Evaluate Wayback Machine CDX snapshot longevity."""

    def evaluate(self, snapshot: VendorSnapshot, ledger: EvidenceLedger) -> EvidenceLedger:
        """Score archived web presence from Wayback CDX timeline."""
        probe = snapshot.signals.wayback
        if probe.status == ProbeStatus.UNAVAILABLE:
            return ledger.with_abstained("wayback")
        return _evaluate_wayback_probe(probe, snapshot.claim.current_year, ledger)


def default_vendor_rules() -> tuple[VendorRule, ...]:
    """Return the canonical five-signal verification rule suite."""
    return (
        DomainAgeMismatchRule(),
        CertificateHistoryRule(),
        DnsAuthSignalRule(),
        SubprocessorCorroborationRule(),
        WaybackTimelineRule(),
    )


def evaluate_vendor(snapshot: VendorSnapshot, rules: tuple[VendorRule, ...]) -> EvidenceLedger:
    """Run all VendorRule specifications against snapshot into an EvidenceLedger."""
    ledger = EvidenceLedger()
    for rule in rules:
        ledger = rule.evaluate(snapshot, ledger)
    return ledger
