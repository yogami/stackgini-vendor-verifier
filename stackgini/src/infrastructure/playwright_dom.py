"""Headless Playwright DOM forensics adapter with SSRF redirect guard."""

from __future__ import annotations

import asyncio
import re

from playwright.async_api import Error as PlaywrightError
from playwright.async_api import Page, Route, async_playwright

from src.domain.assessment import DomForensics
from src.domain.models import ProbeOutcome
from src.infrastructure.ssrf import verify_public_url_with_dns

PAGE_TIMEOUT_MS = 12000
MAX_VISIBLE_TEXT_CHARS = 8000
WAF_SHORT_LEN = 500
WAF_MARKERS = (
    "access denied",
    "you don't have permission to access",
    "attention required! | cloudflare",
    "just a moment...",
)
USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
IMPRINT_MARKERS = (
    "gmbh",
    "inc.",
    "ltd",
    "llc",
    "b.v.",
    "hrb ",
    "ust-id",
    "vat ",
    "impressum",
    "imprint",
    "privacy policy",
    "datenschutz",
)
CLAIM_YEAR_RE = re.compile(r"(?:©|\(c\)|copyright|since|founded)\s*(19[89]\d|20[0-2]\d)", re.IGNORECASE)

_DOM_EXTRACTION_JS = """() => {
    const title = document.title || "";
    const text = document.body ? (document.body.innerText || "") : "";
    const anchors = Array.from(document.querySelectorAll("a"));
    const socialHints = ["linkedin", "twitter", "facebook", "instagram", "youtube", "x.com"];
    const legalHints = ["privacy", "datenschutz", "imprint", "impressum", "legal", "trust", "terms", "security"];
    const loginHints = ["sign in", "log in", "login", "portal", "dashboard"];
    let deadSocial = 0;
    const legalDocs = [];
    const loginTargets = [];
    const logoAlts = [];
    for (const a of anchors) {
        const rawHref = (a.getAttribute("href") || "").trim();
        const label = ((a.getAttribute("aria-label") || "") + " " + (a.innerText || "")).trim().toLowerCase();
        const blob = (rawHref + " " + label).toLowerCase();
        if (rawHref === "#" && socialHints.some((k) => blob.includes(k))) {
            deadSocial += 1;
        }
        if (a.href && legalHints.some((k) => blob.includes(k)) && legalDocs.length < 15) {
            legalDocs.push(a.href);
        }
        if (loginHints.some((k) => label === k || label.includes(k)) && loginTargets.length < 5) {
            loginTargets.push(rawHref || a.href || "#");
        }
    }
    for (const img of Array.from(document.querySelectorAll("img[alt]"))) {
        const alt = (img.getAttribute("alt") || "").trim();
        if (alt.length >= 2 && alt.length <= 60 && logoAlts.length < 20) {
            logoAlts.push(alt);
        }
    }
    const altBlock = logoAlts.length ? "\\n[IMG_ALTS]: " + logoAlts.join(" | ") : "";
    return {
        title,
        visible_text: (text.slice(0, 7200) + altBlock).slice(0, 8000),
        dead_social_links: deadSocial,
        legal_doc_urls: legalDocs,
        login_targets: loginTargets,
    };
}"""


def _strip_tags_len(raw_html: str) -> int:
    cleaned = re.sub(r"<[^>]+>", " ", raw_html)
    return len(" ".join(cleaned.split()))


def _is_http_url(item: object) -> bool:
    return isinstance(item, str) and item.startswith(("http://", "https://"))


def _unique_urls(raw_urls: object) -> tuple[str, ...]:
    if not isinstance(raw_urls, list):
        return ()
    return tuple(dict.fromkeys(item for item in raw_urls if _is_http_url(item)))


def _unique_strings(raw_values: object) -> tuple[str, ...]:
    if not isinstance(raw_values, list):
        return ()
    return tuple(dict.fromkeys(str(item).strip() for item in raw_values if str(item).strip()))


def extract_claimed_year(text: str) -> int | None:
    """Extract earliest copyright or founding year claimed in visible text."""
    matches = [int(year) for year in CLAIM_YEAR_RE.findall(text)]
    return min(matches) if matches else None


def count_imprint_markers(text: str) -> int:
    """Count legal entity, registration, and imprint markers in rendered page text."""
    lowered = text.lower()
    return sum(1 for marker in IMPRINT_MARKERS if marker in lowered)


def build_dom_forensics(final_url: str, payload: dict[str, object], raw_html_len: int) -> DomForensics:
    """Convert raw browser evaluation dictionary into immutable DomForensics."""
    raw_dead = payload.get("dead_social_links", 0)
    dead_count = raw_dead if isinstance(raw_dead, int) else 0
    visible = str(payload.get("visible_text", ""))[:MAX_VISIBLE_TEXT_CHARS]
    return DomForensics(
        final_url=final_url,
        title=str(payload.get("title", "")),
        visible_text=visible,
        dead_social_links=dead_count,
        legal_doc_urls=_unique_urls(payload.get("legal_doc_urls")),
        raw_text_len=raw_html_len,
        claimed_year=extract_claimed_year(visible),
        login_targets=_unique_strings(payload.get("login_targets")),
        imprint_hits=count_imprint_markers(visible),
    )


async def _ssrf_route_guard(route: Route) -> None:
    req = route.request
    if req.url.startswith(("http://", "https://")):
        try:
            await asyncio.to_thread(verify_public_url_with_dns, req.url)
        except ValueError:
            await route.abort()
            return
    await route.continue_()


async def _extract_from_page(page: Page) -> DomForensics:
    await asyncio.to_thread(verify_public_url_with_dns, page.url)
    raw_html = await page.content()
    eval_result = await page.evaluate(_DOM_EXTRACTION_JS)
    payload = eval_result if isinstance(eval_result, dict) else {}
    return build_dom_forensics(page.url, payload, _strip_tags_len(raw_html))


async def _run_playwright_inspection(safe_url: str) -> DomForensics:
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        try:
            context = await browser.new_context(user_agent=USER_AGENT)
            await context.route("**/*", _ssrf_route_guard)
            page = await context.new_page()
            await page.goto(safe_url, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS)
            await page.wait_for_timeout(400)
            return await _extract_from_page(page)
        finally:
            await browser.close()


def is_waf_blocked_dom(dom: DomForensics) -> bool:
    """Return True when page text looks like a short WAF/bot-protection challenge."""
    text = dom.visible_text.strip().lower()
    if len(text) > WAF_SHORT_LEN:
        return False
    combined = f"{dom.title.lower()} {text}"
    return any(marker in combined for marker in WAF_MARKERS)


def _dom_outcome(forensics: DomForensics) -> ProbeOutcome[DomForensics]:
    if is_waf_blocked_dom(forensics):
        return ProbeOutcome.unavailable(forensics.final_url, "waf_blocked")
    return ProbeOutcome.observed(forensics.final_url, forensics)


class PlaywrightDomAdapter:
    """Async headless Chromium adapter implementing RenderedPagePort."""

    async def inspect_page(self, url: str) -> ProbeOutcome[DomForensics]:
        """Validate SSRF safety, render page in Chromium, and extract DOM forensics."""
        try:
            safe_url = verify_public_url_with_dns(url)
        except ValueError as exc:
            return ProbeOutcome.unavailable(url, str(exc))
        return await self._safe_render(safe_url)

    async def _safe_render(self, url: str) -> ProbeOutcome[DomForensics]:
        try:
            forensics = await _run_playwright_inspection(url)
        except (PlaywrightError, TimeoutError, ValueError, OSError) as exc:
            return ProbeOutcome.unavailable(url, type(exc).__name__)
        return _dom_outcome(forensics)
