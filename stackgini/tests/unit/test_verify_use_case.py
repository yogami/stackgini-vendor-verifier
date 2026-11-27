"""Unit tests for VerifyVendorUseCase and SSRF domain validation."""

from __future__ import annotations

import pytest

from src.application.verify_vendor import VerifyVendorUseCase
from src.domain.models import (
    CertFootprint,
    DnsProfile,
    DomainAgeRecord,
    ProbeOutcome,
    SubprocessorMatch,
    VendorClaim,
    Verdict,
    WaybackTimeline,
)
from src.domain.rules import default_vendor_rules
from src.infrastructure.ssrf import normalize_public_domain
from src.ports.probes import VendorProbeGateway


class FakeRdapProbe:
    """In-memory fake RDAP port."""

    async def fetch_domain_age(self, domain: str) -> ProbeOutcome[DomainAgeRecord]:
        return ProbeOutcome.observed(f"https://rdap.org/domain/{domain}", DomainAgeRecord(2020, 2200))


class FakeCertProbe:
    """In-memory fake crt.sh port."""

    async def fetch_cert_history(self, domain: str) -> ProbeOutcome[CertFootprint]:
        return ProbeOutcome.observed(f"https://crt.sh/?q={domain}", CertFootprint(10, 2020))


class FakeDnsProbe:
    """In-memory fake DNS port."""

    async def fetch_dns_profile(self, domain: str) -> ProbeOutcome[DnsProfile]:
        return ProbeOutcome.observed(
            f"https://dns.google/resolve?name={domain}",
            DnsProfile((f"mail.{domain}",), "v=spf1 ~all", "v=DMARC1; p=quarantine"),
        )


class FakeSubprocessorProbe:
    """In-memory fake GDPR subprocessor port."""

    async def lookup_subprocessor(self, domain: str) -> ProbeOutcome[SubprocessorMatch]:
        return ProbeOutcome.not_found(f"https://github.com/search?q={domain}")


class FakeWaybackProbe:
    """In-memory fake Wayback CDX port."""

    async def fetch_timeline(self, domain: str) -> ProbeOutcome[WaybackTimeline]:
        return ProbeOutcome.observed(
            f"https://web.archive.org/cdx/search/cdx?url={domain}",
            WaybackTimeline(30, 2021),
        )


async def test_verify_vendor_use_case_aggregates_five_signals() -> None:
    gateway = VendorProbeGateway(
        rdap=FakeRdapProbe(),
        certs=FakeCertProbe(),
        dns=FakeDnsProbe(),
        subprocessor=FakeSubprocessorProbe(),
        wayback=FakeWaybackProbe(),
    )
    use_case = VerifyVendorUseCase(gateway=gateway, rules=default_vendor_rules())
    ledger = await use_case.execute(VendorClaim(domain="stackgini.de", current_year=2026, claimed_since_year=2021))
    assert ledger.verdict() == Verdict.VERIFIED
    assert ledger.trust_score() == 85
    assert ledger.abstained == ()


@pytest.mark.parametrize(
    "raw_domain",
    [
        "localhost",
        "127.0.0.1",
        "http://169.254.169.254/latest/meta-data",
        "http://10.0.0.1/admin",
        "ftp://vendor.de",
        "internal.local",
        "",
    ],
)
def test_ssrf_guard_rejects_unsafe_targets(raw_domain: str) -> None:
    with pytest.raises(ValueError, match="Invalid"):
        normalize_public_domain(raw_domain)


def test_ssrf_guard_normalizes_https_url_to_domain() -> None:
    assert normalize_public_domain("HTTPS://Stackgini.DE/pricing?utm=1") == "stackgini.de"
