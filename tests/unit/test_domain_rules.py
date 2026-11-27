"""Unit tests for domain invariants, Kerievsky specifications, and EvidenceLedger scoring."""

from __future__ import annotations

import pytest

from src.domain.models import (
    CertFootprint,
    DnsProfile,
    DomainAgeRecord,
    EvidenceLedger,
    ProbeOutcome,
    ProbeStatus,
    SubprocessorMatch,
    VendorClaim,
    VendorSignals,
    VendorSnapshot,
    Verdict,
    VerifiedFinding,
    WaybackTimeline,
)
from src.domain.rules import (
    CertificateHistoryRule,
    DnsAuthSignalRule,
    DomainAgeMismatchRule,
    SubprocessorCorroborationRule,
    WaybackTimelineRule,
    default_vendor_rules,
    evaluate_vendor,
)


def _established_signals() -> VendorSignals:
    return VendorSignals(
        rdap=ProbeOutcome.observed("https://rdap.org/domain/linear.app", DomainAgeRecord(2019, 2500)),
        certs=ProbeOutcome.observed("https://crt.sh/?q=linear.app", CertFootprint(24, 2019)),
        dns=ProbeOutcome.observed(
            "https://dns.google/resolve?name=linear.app",
            DnsProfile(("aspmx.l.google.com",), "v=spf1 include:_spf.google.com ~all", "v=DMARC1; p=reject"),
        ),
        subprocessor=ProbeOutcome.observed(
            "https://trust.example.com/subprocessors",
            SubprocessorMatch(("acme-corp", "globex")),
        ),
        wayback=ProbeOutcome.observed(
            "https://web.archive.org/cdx/search/cdx?url=linear.app",
            WaybackTimeline(120, 2019),
        ),
    )


def _unavailable_signals() -> VendorSignals:
    return VendorSignals(
        rdap=ProbeOutcome.unavailable("https://rdap.org/domain/down.test", "http_429"),
        certs=ProbeOutcome.unavailable("https://crt.sh/?q=down.test", "timeout"),
        dns=ProbeOutcome.unavailable("https://dns.google/resolve?name=down.test", "timeout"),
        subprocessor=ProbeOutcome.unavailable("https://trust.example.com", "http_503"),
        wayback=ProbeOutcome.unavailable("https://web.archive.org/cdx/search/cdx", "http_429"),
    )


def test_verified_finding_requires_http_source_url() -> None:
    with pytest.raises(ValueError, match="source_url"):
        VerifiedFinding(
            rule_id="rdap_age",
            claim="Young domain",
            source_url="",
            observed_fact="age_days=12",
            impact=-30,
        )


def test_probe_outcome_observed_requires_http_source_url() -> None:
    with pytest.raises(ValueError, match="source_url"):
        ProbeOutcome(status=ProbeStatus.OBSERVED, source_url="ftp://bad.test", value=None)


def test_established_vendor_scores_verified() -> None:
    snapshot = VendorSnapshot(
        claim=VendorClaim(domain="linear.app", current_year=2026, claimed_since_year=2019),
        signals=_established_signals(),
    )
    ledger = evaluate_vendor(snapshot, default_vendor_rules())
    assert ledger.trust_score() == 95
    assert ledger.verdict() == Verdict.VERIFIED
    assert ledger.abstained == ()
    assert len(ledger.findings) == 4


def test_unavailable_signals_abstain_without_penalty() -> None:
    snapshot = VendorSnapshot(
        claim=VendorClaim(domain="down.test", current_year=2026, claimed_since_year=2020),
        signals=_unavailable_signals(),
    )
    ledger = evaluate_vendor(snapshot, default_vendor_rules())
    assert ledger.trust_score() == 70
    assert ledger.verdict() == Verdict.VERIFIED
    assert len(ledger.abstained) == 5
    assert ledger.findings == ()


def test_backdated_young_clone_scores_fraud_risk() -> None:
    signals = VendorSignals(
        rdap=ProbeOutcome.observed("https://rdap.org/domain/clone.ai", DomainAgeRecord(2026, 20)),
        certs=ProbeOutcome.not_found("https://crt.sh/?q=clone.ai"),
        dns=ProbeOutcome.observed("https://dns.google/resolve?name=clone.ai", DnsProfile((), "", "")),
        subprocessor=ProbeOutcome.not_found("https://trust.example.com/subprocessors"),
        wayback=ProbeOutcome.not_found("https://web.archive.org/cdx/search/cdx?url=clone.ai"),
    )
    snapshot = VendorSnapshot(
        claim=VendorClaim(domain="clone.ai", current_year=2026, claimed_since_year=2018),
        signals=signals,
    )
    ledger = evaluate_vendor(snapshot, default_vendor_rules())
    assert ledger.trust_score() == 0
    assert ledger.verdict() == Verdict.FRAUD_RISK
    assert len(ledger.findings) == 6


def test_single_cert_triggers_minor_penalty() -> None:
    signals = _unavailable_signals()
    single_cert = ProbeOutcome.observed("https://crt.sh/?q=new.io", CertFootprint(1, 2026))
    snapshot = VendorSnapshot(
        claim=VendorClaim(domain="new.io", current_year=2026, claimed_since_year=None),
        signals=VendorSignals(
            rdap=signals.rdap,
            certs=single_cert,
            dns=signals.dns,
            subprocessor=signals.subprocessor,
            wayback=signals.wayback,
        ),
    )
    ledger = CertificateHistoryRule().evaluate(snapshot, EvidenceLedger())
    assert ledger.trust_score() == 60
    assert ledger.verdict() == Verdict.SUSPICIOUS
    assert ledger.findings[0].rule_id == "cert_single"


def test_individual_rules_handle_neutral_observed_outcomes() -> None:
    signals = VendorSignals(
        rdap=ProbeOutcome.observed("https://rdap.org/domain/mid.io", DomainAgeRecord(2025, 300)),
        certs=ProbeOutcome.observed("https://crt.sh/?q=mid.io", CertFootprint(3, 2025)),
        dns=ProbeOutcome.observed("https://dns.google/resolve?name=mid.io", DnsProfile(("mx.mid.io",), "", "")),
        subprocessor=ProbeOutcome.not_found("https://trust.example.com"),
        wayback=ProbeOutcome.observed("https://web.archive.org/cdx/search/cdx", WaybackTimeline(4, 2025)),
    )
    snapshot = VendorSnapshot(
        claim=VendorClaim(domain="mid.io", current_year=2026, claimed_since_year=2025),
        signals=signals,
    )
    for rule in (
        DomainAgeMismatchRule(),
        CertificateHistoryRule(),
        DnsAuthSignalRule(),
        SubprocessorCorroborationRule(),
        WaybackTimelineRule(),
    ):
        result = rule.evaluate(snapshot, EvidenceLedger())
        assert result.trust_score() == 70
