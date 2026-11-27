"""Domain models and calibrated verdict synthesis for Stackgini vendor assessments."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from urllib.parse import urlparse

from src.domain.models import EvidenceLedger, ProbeOutcome, ProbeStatus, Verdict

HTTP_SCHEMES = ("http://", "https://")
JS_SPA_RAW_THRESHOLD = 200
JS_SPA_RENDERED_THRESHOLD = 500
DEAD_SOCIAL_YELLOW_THRESHOLD = 2
MIN_TRUST_FOR_GREEN = 70
MIN_ABSTAINED_FOR_CAUTION = 3
DOCX_EXTENSIONS = (".doc", ".docx")


class StackginiVerdict(StrEnum):
    """Official Stackgini assessment ratings."""

    GREEN = "Green"
    YELLOW = "Yellow"
    RED = "Red"


@dataclass(frozen=True)
class VendorInput:
    """Single vendor evaluation target matching Stackgini CSV schema."""

    row_id: str
    url: str
    product: str
    vendor: str


@dataclass(frozen=True)
class DomForensics:
    """Headless browser DOM snapshot and structural claim signals."""

    final_url: str
    title: str
    visible_text: str
    dead_social_links: int
    legal_doc_urls: tuple[str, ...]
    raw_text_len: int
    claimed_year: int | None = None
    login_targets: tuple[str, ...] = ()
    imprint_hits: int = 0

    def has_docx_privacy(self) -> bool:
        """Return True when a privacy or legal link points to a Word document."""
        return any(link.lower().split("?", 1)[0].endswith(DOCX_EXTENSIONS) for link in self.legal_doc_urls)

    def is_js_spa_shell(self) -> bool:
        """Return True when rendered text is rich while raw HTML lacks body text."""
        return self.raw_text_len < JS_SPA_RAW_THRESHOLD and len(self.visible_text) > JS_SPA_RENDERED_THRESHOLD


@dataclass(frozen=True)
class WebCitation:
    """Verified web citation backing off-site research."""

    title: str
    url: str

    def __post_init__(self) -> None:
        if not self.url.startswith(HTTP_SCHEMES):
            raise ValueError(f"Expected HTTP(S) source_url, got: {self.url!r}")


@dataclass(frozen=True)
class WebIntelligence:
    """Grounded off-site intelligence synthesized from live search."""

    suggested_overall: StackginiVerdict
    summary: str
    citations: tuple[WebCitation, ...]
    green_signals: tuple[str, ...]
    yellow_signals: tuple[str, ...]
    red_signals: tuple[str, ...]


@dataclass(frozen=True)
class StackginiAssessment:
    """Complete URL-cited Stackgini assessment output."""

    item: VendorInput
    overall: StackginiVerdict
    green_flags: tuple[str, ...]
    yellow_flags: tuple[str, ...]
    red_flags: tuple[str, ...]
    reasoning: str
    source_urls: tuple[str, ...]
    ledger: EvidenceLedger = field(default_factory=EvidenceLedger)
    dom_summary: str = ""


def extract_domain_from_url(raw_url: str) -> str:
    """Extract lowercase hostname from a URL or bare domain string."""
    candidate = raw_url.strip() if "://" in raw_url else f"https://{raw_url.strip()}"
    host = (urlparse(candidate).hostname or "").strip(".").lower()
    return host.removeprefix("www.")


def _dedupe(items: tuple[str, ...]) -> tuple[str, ...]:
    seen: dict[str, None] = {}
    for item in items:
        cleaned = item.strip()
        if cleaned:
            seen[cleaned] = None
    return tuple(seen.keys())


def _first_docx_url(urls: tuple[str, ...]) -> str:
    return next((link for link in urls if link.lower().split("?", 1)[0].endswith(DOCX_EXTENSIONS)), "")


def _dom_red_flags(dom: ProbeOutcome[DomForensics]) -> tuple[str, ...]:
    if dom.value is None:
        return ()
    docx_url = _first_docx_url(dom.value.legal_doc_urls)
    return (f"Privacy or legal link downloads a Word document ({docx_url}).",) if docx_url else ()


def _observed_dom_yellow_flags(info: DomForensics) -> tuple[str, ...]:
    flags: list[str] = []
    if info.dead_social_links >= DEAD_SOCIAL_YELLOW_THRESHOLD:
        flags.append(f"Footer has {info.dead_social_links} dead '#' social links.")
    if info.is_js_spa_shell():
        flags.append("Site is client-side JS rendered; plain HTML fetch misses body content.")
    return tuple(flags)


def _dom_yellow_flags(dom: ProbeOutcome[DomForensics]) -> tuple[str, ...]:
    return _observed_dom_yellow_flags(dom.value) if dom.value is not None else ()


def _ledger_green_flags(ledger: EvidenceLedger) -> tuple[str, ...]:
    return tuple(f"{f.claim}: {f.observed_fact} ({f.source_url})" for f in ledger.findings if f.impact > 0)


def _infra_caution_flags(ledger: EvidenceLedger) -> tuple[str, ...]:
    return tuple(f"{f.claim}: {f.observed_fact} ({f.source_url})" for f in ledger.findings if f.impact < 0)


def _infra_red_flags(ledger: EvidenceLedger) -> tuple[str, ...]:
    if ledger.verdict() != Verdict.FRAUD_RISK:
        return ()
    return _infra_caution_flags(ledger)


def _infra_yellow_flags(ledger: EvidenceLedger) -> tuple[str, ...]:
    if ledger.verdict() == Verdict.FRAUD_RISK:
        return ()
    return _infra_caution_flags(ledger)


def _dom_sources(dom: ProbeOutcome[DomForensics]) -> tuple[str, ...]:
    if dom.value is None:
        return ()
    return (dom.source_url, *dom.value.legal_doc_urls)


def _web_sources(web: ProbeOutcome[WebIntelligence]) -> tuple[str, ...]:
    if web.value is None:
        return ()
    return tuple(c.url for c in web.value.citations)


def _collect_sources(
    ledger: EvidenceLedger,
    dom: ProbeOutcome[DomForensics],
    web: ProbeOutcome[WebIntelligence],
) -> tuple[str, ...]:
    ledger_urls = tuple(f.source_url for f in ledger.findings)
    return _dedupe((*ledger_urls, *_dom_sources(dom), *_web_sources(web)))


def _is_red_fallback(ledger: EvidenceLedger, red_flags: tuple[str, ...]) -> bool:
    return bool(red_flags) or ledger.verdict() == Verdict.FRAUD_RISK


def _is_yellow_fallback(ledger: EvidenceLedger, yellow_flags: tuple[str, ...]) -> bool:
    too_blind = len(ledger.abstained) >= MIN_ABSTAINED_FOR_CAUTION and not ledger.findings
    return any((yellow_flags, ledger.trust_score() < MIN_TRUST_FOR_GREEN, too_blind))


def _fallback_verdict(
    ledger: EvidenceLedger, red_flags: tuple[str, ...], yellow_flags: tuple[str, ...]
) -> StackginiVerdict:
    if _is_red_fallback(ledger, red_flags):
        return StackginiVerdict.RED
    return StackginiVerdict.YELLOW if _is_yellow_fallback(ledger, yellow_flags) else StackginiVerdict.GREEN


def _observed_web(web: ProbeOutcome[WebIntelligence]) -> WebIntelligence | None:
    return web.value if web.status == ProbeStatus.OBSERVED and web.value is not None else None


def _has_hard_red(
    ledger: EvidenceLedger,
    dom_reds: tuple[str, ...],
    observed: WebIntelligence | None,
) -> bool:
    web_reds = observed.red_signals if observed is not None else ()
    return any((dom_reds, web_reds, _infra_red_flags(ledger)))


def _calibrated_web_verdict(ledger: EvidenceLedger, observed: WebIntelligence) -> StackginiVerdict:
    if ledger.verdict() == Verdict.SUSPICIOUS and observed.suggested_overall == StackginiVerdict.GREEN:
        return StackginiVerdict.YELLOW
    return observed.suggested_overall


def _non_red_verdict(
    ledger: EvidenceLedger,
    yellow_flags: tuple[str, ...],
    observed: WebIntelligence | None,
) -> StackginiVerdict:
    if observed is not None:
        return _calibrated_web_verdict(ledger, observed)
    return _fallback_verdict(ledger, _infra_red_flags(ledger), yellow_flags)


def _resolve_overall(
    ledger: EvidenceLedger,
    dom_reds: tuple[str, ...],
    yellow_flags: tuple[str, ...],
    web: ProbeOutcome[WebIntelligence],
) -> StackginiVerdict:
    observed = _observed_web(web)
    if _has_hard_red(ledger, dom_reds, observed):
        return StackginiVerdict.RED
    return _non_red_verdict(ledger, yellow_flags, observed)


def _build_reasoning(
    ledger: EvidenceLedger,
    web: ProbeOutcome[WebIntelligence],
    overall: StackginiVerdict,
) -> str:
    observed = _observed_web(web)
    if observed is not None:
        return observed.summary
    return (
        f"Technical verification fallback verdict {overall.value} "
        f"(trust_score={ledger.trust_score()}, findings={len(ledger.findings)})."
    )


def _dom_summary_text(dom: ProbeOutcome[DomForensics]) -> str:
    if dom.status != ProbeStatus.OBSERVED or dom.value is None:
        return f"DOM {dom.status.value}: {dom.reason}"
    info = dom.value
    return (
        f"final_url={info.final_url}, claimed_year={info.claimed_year}, "
        f"dead_social={info.dead_social_links}, legal_docs={len(info.legal_doc_urls)}, "
        f"imprint_hits={info.imprint_hits}"
    )


def _build_flag_groups(
    observed: WebIntelligence | None,
    ledger: EvidenceLedger,
    dom: ProbeOutcome[DomForensics],
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    dom_reds = _dom_red_flags(dom)
    if observed is None:
        return (
            _dedupe(_ledger_green_flags(ledger)),
            _dedupe((*_dom_yellow_flags(dom), *_infra_yellow_flags(ledger))),
            _dedupe((*dom_reds, *_infra_red_flags(ledger))),
        )
    return (
        _dedupe((*observed.green_signals, *_ledger_green_flags(ledger))),
        _dedupe((*observed.yellow_signals, *_dom_yellow_flags(dom), *_infra_yellow_flags(ledger))),
        _dedupe((*observed.red_signals, *dom_reds, *_infra_red_flags(ledger))),
    )


def assess_from_evidence(
    item: VendorInput,
    ledger: EvidenceLedger,
    dom: ProbeOutcome[DomForensics],
    web: ProbeOutcome[WebIntelligence],
) -> StackginiAssessment:
    """Combine technical probes, Playwright DOM forensics, and web research into a verdict."""
    observed = _observed_web(web)
    green_flags, yellow_flags, red_flags = _build_flag_groups(observed, ledger, dom)
    overall = _resolve_overall(ledger, _dom_red_flags(dom), yellow_flags, web)
    return StackginiAssessment(
        item=item,
        overall=overall,
        green_flags=green_flags,
        yellow_flags=yellow_flags,
        red_flags=red_flags,
        reasoning=_build_reasoning(ledger, web, overall),
        source_urls=_collect_sources(ledger, dom, web),
        ledger=ledger,
        dom_summary=_dom_summary_text(dom),
    )
