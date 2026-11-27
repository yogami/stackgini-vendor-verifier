"""Unit tests for Stackgini assessment domain, DOM forensics, and AssessVendorUseCase."""

from __future__ import annotations

import pytest

from src.application.assess_vendor import AssessVendorUseCase
from src.application.verify_vendor import VerifyVendorUseCase
from src.domain.assessment import (
    DomForensics,
    StackginiVerdict,
    VendorInput,
    WebCitation,
    WebIntelligence,
    assess_from_evidence,
)
from src.domain.models import (
    CertFootprint,
    DnsProfile,
    DomainAgeRecord,
    EvidenceLedger,
    ProbeOutcome,
    SubprocessorMatch,
    VendorClaim,
    VendorSignals,
    VendorSnapshot,
    WaybackTimeline,
)
from src.domain.rules import default_vendor_rules, evaluate_vendor
from src.ports.probes import VendorProbeGateway
from src.ports.research import ResearchGateway


class StubRdap:
    async def fetch_domain_age(self, domain: str) -> ProbeOutcome[DomainAgeRecord]:
        return ProbeOutcome.observed(f"https://rdap.org/domain/{domain}", DomainAgeRecord(2015, 4000))


class StubCerts:
    async def fetch_cert_history(self, domain: str) -> ProbeOutcome[CertFootprint]:
        return ProbeOutcome.observed(f"https://crt.sh/?q={domain}", CertFootprint(12, 2015))


class StubDns:
    async def fetch_dns_profile(self, domain: str) -> ProbeOutcome[DnsProfile]:
        return ProbeOutcome.observed(
            f"https://dns.google/resolve?name={domain}",
            DnsProfile((f"mx.{domain}",), "v=spf1 ~all", "v=DMARC1; p=reject"),
        )


class StubSubprocessor:
    async def lookup_subprocessor(self, domain: str) -> ProbeOutcome[SubprocessorMatch]:
        return ProbeOutcome.not_found(f"https://github.com/search?q={domain}")


class StubWayback:
    async def fetch_timeline(self, domain: str) -> ProbeOutcome[WaybackTimeline]:
        return ProbeOutcome.observed(f"https://web.archive.org/cdx/search/cdx?url={domain}", WaybackTimeline(80, 2015))


class StubPagePort:
    def __init__(self, outcome: ProbeOutcome[DomForensics]) -> None:
        self._outcome = outcome

    async def inspect_page(self, url: str) -> ProbeOutcome[DomForensics]:
        return self._outcome


class StubResearchPort:
    def __init__(self, outcome: ProbeOutcome[WebIntelligence]) -> None:
        self._outcome = outcome

    async def research_vendor(self, item: VendorInput, dom_excerpt: str) -> ProbeOutcome[WebIntelligence]:
        return self._outcome


def test_web_citation_rejects_non_http_url() -> None:
    with pytest.raises(ValueError, match="source_url"):
        WebCitation(title="Bad", url="javascript:alert(1)")


def test_dom_forensics_detects_docx_privacy_and_js_spa() -> None:
    dom = DomForensics(
        final_url="https://auditalign.io/",
        title="AuditAlign",
        visible_text="x" * 600,
        dead_social_links=3,
        legal_doc_urls=("https://auditalign.io/privacy.docx",),
        raw_text_len=50,
    )
    assert dom.has_docx_privacy() is True
    assert dom.is_js_spa_shell() is True


def test_assess_from_evidence_overrides_to_red_on_docx_privacy() -> None:
    item = VendorInput("10", "https://www.auditalign.io/", "AuditAlign", "AuditAlign")
    dom = ProbeOutcome.observed(
        "https://www.auditalign.io/",
        DomForensics(
            final_url="https://www.auditalign.io/",
            title="AuditAlign",
            visible_text="AI governance for financial institutions",
            dead_social_links=0,
            legal_doc_urls=("https://www.auditalign.io/privacy.docx",),
            raw_text_len=800,
        ),
    )
    web: ProbeOutcome[WebIntelligence] = ProbeOutcome.unavailable("https://search.google.com", "no_key")
    result = assess_from_evidence(item, EvidenceLedger(), dom, web)
    assert result.overall == StackginiVerdict.RED
    assert any(".docx" in flag for flag in result.red_flags)
    assert "https://www.auditalign.io/privacy.docx" in result.source_urls


def test_assess_from_evidence_preserves_green_with_yellow_context() -> None:
    item = VendorInput("1", "https://www.omnissa.com/", "Workspace ONE", "Omnissa")
    dom = ProbeOutcome.observed(
        "https://www.omnissa.com/",
        DomForensics("https://www.omnissa.com/", "Omnissa", "Enterprise workspace", 0, (), 2000),
    )
    web = ProbeOutcome.observed(
        "https://www.google.com/search?q=omnissa",
        WebIntelligence(
            suggested_overall=StackginiVerdict.GREEN,
            summary="Solid enterprise product carved out from VMware under KKR with recent CEO transition.",
            citations=(WebCitation("Omnissa Press", "https://www.omnissa.com/news"),),
            green_signals=("26,000+ enterprise customers and active trust center",),
            yellow_signals=("Carved out from Broadcom/VMware to KKR with CEO transition in 2026",),
            red_signals=(),
        ),
    )
    result = assess_from_evidence(item, EvidenceLedger(), dom, web)
    assert result.overall == StackginiVerdict.GREEN
    assert len(result.yellow_flags) == 1
    assert result.red_flags == ()
    assert "https://www.omnissa.com/news" in result.source_urls


async def test_assess_vendor_use_case_combines_probes_dom_and_research() -> None:
    probes = VendorProbeGateway(
        rdap=StubRdap(),
        certs=StubCerts(),
        dns=StubDns(),
        subprocessor=StubSubprocessor(),
        wayback=StubWayback(),
    )
    dom_outcome = ProbeOutcome.observed(
        "https://www.postfix.org/",
        DomForensics("https://www.postfix.org/", "Postfix", "The Postfix Home Page", 0, (), 900),
    )
    web_outcome = ProbeOutcome.observed(
        "https://www.google.com/search?q=postfix",
        WebIntelligence(
            suggested_overall=StackginiVerdict.GREEN,
            summary="Category-standard mail transfer agent actively maintained despite dated site design.",
            citations=(WebCitation("Postfix Announcements", "https://www.postfix.org/announcements.html"),),
            green_signals=("Widespread global mail infrastructure and recent releases",),
            yellow_signals=("Website design is dated",),
            red_signals=(),
        ),
    )
    verify_use_case = VerifyVendorUseCase(probes, default_vendor_rules())
    gateway = ResearchGateway(
        page=StubPagePort(dom_outcome),
        research=StubResearchPort(web_outcome),
    )
    assessment = await AssessVendorUseCase(verify_use_case, gateway).execute(
        VendorInput("6", "https://www.postfix.org/", "Postfix", "Wietse Venema"),
        current_year=2026,
    )
    assert assessment.overall == StackginiVerdict.GREEN
    assert "mail transfer agent" in assessment.reasoning
    assert "https://www.postfix.org/announcements.html" in assessment.source_urls


def test_assess_from_evidence_fallback_yellow_and_green() -> None:
    item = VendorInput("28", "https://www.cadkas.com/index.php", "CAD-KAS", "Kassler GbR")
    dom = ProbeOutcome.observed(
        "https://www.cadkas.com/index.php",
        DomForensics("https://www.cadkas.com/index.php", "CAD-KAS", "PDF editor", 2, (), 500),
    )
    web: ProbeOutcome[WebIntelligence] = ProbeOutcome.unavailable("https://search.google.com", "no_key")
    yellow_res = assess_from_evidence(item, EvidenceLedger(), dom, web)
    assert yellow_res.overall == StackginiVerdict.YELLOW

    clean_dom: ProbeOutcome[DomForensics] = ProbeOutcome.unavailable("https://www.cadkas.com/index.php", "timeout")
    green_res = assess_from_evidence(item, EvidenceLedger(), clean_dom, web)
    assert green_res.overall == StackginiVerdict.GREEN


def test_resolve_overall_never_overrides_fraud_risk_or_web_reds_with_green() -> None:
    item = VendorInput("99", "https://shady.example/", "ShadyApp", "Shady LLC")
    dom = ProbeOutcome.observed(
        "https://shady.example/",
        DomForensics("https://shady.example/", "Shady", "Enterprise tool", 0, (), 900, claimed_year=2015),
    )
    bad_signals = VendorSignals(
        rdap=ProbeOutcome.observed("https://rdap.org/domain/shady.example", DomainAgeRecord(2026, 20)),
        certs=ProbeOutcome.not_found("https://crt.sh/?q=shady.example"),
        dns=ProbeOutcome.observed("https://dns.google/resolve?name=shady.example", DnsProfile((), "", "")),
        subprocessor=ProbeOutcome.not_found("https://github.com/search?q=shady.example"),
        wayback=ProbeOutcome.not_found("https://web.archive.org/cdx"),
    )

    fraud_ledger = evaluate_vendor(
        VendorSnapshot(VendorClaim("shady.example", 2026, claimed_since_year=2015), bad_signals),
        default_vendor_rules(),
    )
    optimistic_web = ProbeOutcome.observed(
        "https://news.google.com/",
        WebIntelligence(StackginiVerdict.GREEN, "Looks ok", (), (), (), ()),
    )
    result = assess_from_evidence(item, fraud_ledger, dom, optimistic_web)
    assert result.overall == StackginiVerdict.RED
    assert result.red_flags


async def test_assess_vendor_wires_dom_claimed_year_into_rdap_backdate_check() -> None:
    probes = VendorProbeGateway(
        rdap=StubRdap(),
        certs=StubCerts(),
        dns=StubDns(),
        subprocessor=StubSubprocessor(),
        wayback=StubWayback(),
    )
    dom_outcome = ProbeOutcome.observed(
        "https://backdated.example/",
        DomForensics("https://backdated.example/", "App", "Copyright 2005", 0, (), 800, claimed_year=2005),
    )
    web_outcome: ProbeOutcome[WebIntelligence] = ProbeOutcome.not_found("https://news.google.com/", "none")
    verify_use_case = VerifyVendorUseCase(probes, default_vendor_rules())
    gateway = ResearchGateway(page=StubPagePort(dom_outcome), research=StubResearchPort(web_outcome))
    assessment = await AssessVendorUseCase(verify_use_case, gateway).execute(
        VendorInput("101", "https://backdated.example/", "Backdated", "Test Co"),
        current_year=2026,
    )
    assert any("2005" in flag for flag in assessment.yellow_flags)
    assert any(f.rule_id == "rdap_backdated_claim" for f in assessment.ledger.findings)


def test_assess_from_evidence_all_abstained_returns_yellow_not_green_and_picks_docx_url() -> None:
    item = VendorInput("102", "https://blind.example/", "Blind", "Blind Co")
    blind_ledger = EvidenceLedger(abstained=("rdap", "certs", "wayback"))
    res = assess_from_evidence(
        item,
        blind_ledger,
        ProbeOutcome.unavailable("https://blind.example/", "timeout"),
        ProbeOutcome.unavailable("https://news.google.com/", "upstream_probes_unavailable"),
    )
    assert res.overall == StackginiVerdict.YELLOW

    docx_dom = ProbeOutcome.observed(
        "https://blind.example/",
        DomForensics(
            "https://blind.example/",
            "Blind",
            "App",
            0,
            ("https://blind.example/imprint", "https://blind.example/terms.docx"),
            800,
        ),
    )
    docx_res = assess_from_evidence(
        item, EvidenceLedger(), docx_dom, ProbeOutcome.not_found("https://news.google.com/")
    )
    assert docx_res.overall == StackginiVerdict.RED
    assert "terms.docx" in docx_res.red_flags[0]
