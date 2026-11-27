"""Headless Playwright DOM forensics adapter for Stackgini vendor inspection."""

from __future__ import annotations

import re

from playwright.async_api import Error as PlaywrightError
from playwright.async_api import Page, async_playwright

from src.domain.assessment import DomForensics
from src.domain.models import ProbeOutcome
from src.infrastructure.ssrf import normalize_public_domain

PAGE_TIMEOUT_MS = 12000
MAX_VISIBLE_TEXT_CHARS = 8000
USER_AGENT = "StackginiVendorVerifier/0.2 (+https://stackgini.de)"

_DOM_EXTRACTION_JS = """() => {
    const title = document.title || "";
    const text = document.body ? (document.body.innerText || "") : "";
    const anchors = Array.from(document.querySelectorAll("a"));
    const socialHints = ["linkedin", "twitter", "facebook", "instagram", "youtube", "x.com"];
    const legalHints = ["privacy", "datenschutz", "imprint", "impressum", "legal", "trust", "terms", "security"];
    let deadSocial = 0;
    const legalDocs = [];
    for (const a of anchors) {
        const rawHref = (a.getAttribute("href") || "").trim();
        const blob = (rawHref + " " + (a.getAttribute("aria-label") || "") + " " + (a.innerText || "")).toLowerCase();
        if (rawHref === "#" && socialHints.some((k) => blob.includes(k))) {
            deadSocial += 1;
        }
        if (a.href && legalHints.some((k) => blob.includes(k)) && legalDocs.length < 15) {
            legalDocs.push(a.href);
        }
    }
    return { title, visible_text: text.slice(0, 8000), dead_social_links: deadSocial, legal_doc_urls: legalDocs };
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


def build_dom_forensics(final_url: str, payload: dict[str, object], raw_html_len: int) -> DomForensics:
    """Convert raw browser evaluation dictionary into immutable DomForensics."""
    raw_dead = payload.get("dead_social_links", 0)
    dead_count = raw_dead if isinstance(raw_dead, int) else 0
    return DomForensics(
        final_url=final_url,
        title=str(payload.get("title", "")),
        visible_text=str(payload.get("visible_text", ""))[:MAX_VISIBLE_TEXT_CHARS],
        dead_social_links=dead_count,
        legal_doc_urls=_unique_urls(payload.get("legal_doc_urls")),
        raw_text_len=raw_html_len,
    )


async def _extract_from_page(page: Page) -> DomForensics:
    raw_html = await page.content()
    eval_result = await page.evaluate(_DOM_EXTRACTION_JS)
    payload = eval_result if isinstance(eval_result, dict) else {}
    return build_dom_forensics(page.url, payload, _strip_tags_len(raw_html))


async def _run_playwright_inspection(url: str) -> DomForensics:
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        try:
            context = await browser.new_context(user_agent=USER_AGENT)
            page = await context.new_page()
            await page.goto(url, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS)
            await page.wait_for_timeout(500)
            return await _extract_from_page(page)
        finally:
            await browser.close()


class PlaywrightDomAdapter:
    """Async headless Chromium adapter implementing RenderedPagePort."""

    async def inspect_page(self, url: str) -> ProbeOutcome[DomForensics]:
        """Validate SSRF safety, render page in Chromium, and extract DOM forensics."""
        try:
            normalize_public_domain(url)
        except ValueError as exc:
            return ProbeOutcome.unavailable(url, str(exc))
        return await self._safe_render(url)

    async def _safe_render(self, url: str) -> ProbeOutcome[DomForensics]:
        try:
            forensics = await _run_playwright_inspection(url)
        except (PlaywrightError, TimeoutError, OSError) as exc:
            return ProbeOutcome.unavailable(url, type(exc).__name__)
        return ProbeOutcome.observed(forensics.final_url, forensics)
