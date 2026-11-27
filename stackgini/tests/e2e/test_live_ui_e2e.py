"""Live HTTP + headless Chromium Playwright E2E substance tests (local uvicorn or --base-url)."""

from __future__ import annotations

import multiprocessing
import os
import socket
import time
from collections.abc import Iterator

import httpx
import pytest
import uvicorn
from playwright.sync_api import Page, expect


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _probe_health(base_url: str) -> bool:
    try:
        return httpx.get(f"{base_url}/health", timeout=2.0).status_code == 200
    except httpx.HTTPError:
        return False


def _wait_for_health(base_url: str, timeout_seconds: float = 20.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if _probe_health(base_url):
            return
        time.sleep(0.3)
    raise RuntimeError(f"Live server failed health check at {base_url}")


def _serve_uvicorn(port: int) -> None:
    os.environ["OPENROUTER_API_KEY"] = ""
    os.environ["GEMINI_API_KEY"] = ""
    os.environ["GOOGLE_API_KEY"] = ""
    uvicorn.run("src.api.app:app", host="127.0.0.1", port=port, log_level="warning")


@pytest.fixture(scope="module")
def target_base_url(request: pytest.FixtureRequest) -> Iterator[str]:
    """Use --base-url (e.g. live Railway URL) if provided, else launch real local uvicorn."""
    cli_url = str(request.config.getoption("--base-url") or "").strip().rstrip("/")
    if cli_url:
        _wait_for_health(cli_url)
        yield cli_url
        return

    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    ctx = multiprocessing.get_context("spawn")
    proc = ctx.Process(target=_serve_uvicorn, args=(port,), daemon=True)
    proc.start()
    try:
        _wait_for_health(base_url)
        yield base_url
    finally:
        proc.terminate()
        proc.join(timeout=5)


def test_live_health_openapi_and_ssrf_guard(target_base_url: str) -> None:
    health = httpx.get(f"{target_base_url}/health", timeout=10.0)
    assert health.status_code == 200
    assert health.json() == {"status": "ok"}

    openapi = httpx.get(f"{target_base_url}/api/openapi.json", timeout=10.0)
    assert openapi.status_code == 200
    paths = openapi.json()["paths"]
    assert "/api/v1/verify" in paths
    assert "/api/v1/assess" in paths

    ssrf = httpx.post(f"{target_base_url}/api/v1/verify", json={"domain": "http://127.0.0.1:8000"}, timeout=10.0)
    assert ssrf.status_code == 422


def test_live_dashboard_browser_substance_assessment(page: Page, target_base_url: str) -> None:
    page.goto(f"{target_base_url}/", wait_until="domcontentloaded")
    expect(page.locator("h1")).to_contain_text("Stackgini Vendor Verifier")

    page.get_by_role("button", name="Sample: Postfix").click()
    page.get_by_role("button", name="Run Full Verification").click()

    expect(page.locator("#result")).to_be_visible(timeout=60000)
    verdict_text = (page.locator("#res-verdict").text_content() or "").strip()
    assert verdict_text in {"Green", "Yellow", "Red"}
    assert "/100" in (page.locator("#res-score").text_content() or "")
    assert page.locator("#res-findings tr").count() >= 1
    assert page.locator("#res-sources a").count() >= 1


def test_live_dashboard_rejects_ssrf_in_browser(page: Page, target_base_url: str) -> None:
    page.goto(f"{target_base_url}/", wait_until="domcontentloaded")
    page.fill("#vendor-url", "http://127.0.0.1:8000")
    page.fill("#vendor-product", "Internal")
    page.fill("#vendor-company", "Internal")
    page.get_by_role("button", name="Run Full Verification").click()

    expect(page.locator("#error-box")).to_be_visible(timeout=10000)
    assert "Invalid" in (page.locator("#error-box").text_content() or "")


def test_live_openapi_docs_render_in_browser(page: Page, target_base_url: str) -> None:
    page.goto(f"{target_base_url}/api/docs", wait_until="domcontentloaded")
    expect(page).to_have_title("Stackgini Vendor Verifier - Swagger UI")
    assert "Stackgini Vendor Verifier" in page.title()
