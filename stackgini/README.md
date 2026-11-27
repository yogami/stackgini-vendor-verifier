# Stackgini Vendor Verifier

Deterministic + web-grounded SaaS vendor verification engine built under Hexagonal DDD, TDD, and strict AST craftsmanship rules.

## Verification Pipeline
1. **5 Infrastructure & Registry Probes** (`src/infrastructure/http_probes.py`, `src/infrastructure/dns_subprocessor.py`):
   - RDAP registration age (`rdap.org`)
   - Certificate Transparency footprint (`crt.sh`)
   - DNS MX, SPF, and DMARC posture (`dnspython`)
   - GDPR subprocessor reverse lookup
   - Wayback Machine CDX timeline (`web.archive.org`)
2. **Headless Playwright DOM Forensics** (`src/infrastructure/playwright_dom.py`):
   - SSRF-guarded Chromium rendering (`normalize_public_domain`), JS SPA shell detection, `.docx` legal-link trap detection, dead `#` footer social links, and `[IMG_ALTS]` logo inspection.
3. **Layered Off-Site Research Chain** (`src/infrastructure/composite_research.py`):
   - Primary: `OpenRouterWebResearchAdapter` (`openai/gpt-4o-mini` dual product + off-site `-site:<domain>` web search -> `anthropic/claude-sonnet-4.5` calibrated JSON synthesis).
   - Secondary: `GeminiWebResearchAdapter` (`google-genai` Google Search grounding).
   - Zero-key fallback: `PublicSignalsResearchAdapter` (Google News RSS, Wikipedia API, Statuspage v2 incidents, GitHub Search API, and DOM text markers).

## Run on Blind Drop CSV (`19:00 CET`)
```bash
cd stackgini
uv run python -m scripts.assess_csv path/to/blind_drop_10.csv path/to/verdicts_submission.csv --concurrency 5
```
Produces:
- `verdicts_submission.csv` (`id,url,product,vendor,overall,green_flags,yellow_flags,red_flags,reasoning` with inline `[Sources: ...]` citations)
- `verdicts_submission_sources.json` (complete `source_urls[]` audit trail per row)

## Run Live FastAPI Demo (`20:00 CET`)
```bash
cd stackgini
uv run uvicorn src.api.app:app --host 127.0.0.1 --port 8000
```
- Swagger UI: `http://127.0.0.1:8000/api/docs`
- OpenAPI spec: `http://127.0.0.1:8000/api/openapi.json`
- Single assessment: `POST /api/v1/assess`

## Craftsmanship Gates
```bash
cd stackgini
uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy --strict src tests
uv run xenon --max-absolute A --max-modules A --max-average A src
uv run lint-imports
uv run python scripts/craftsmanship_gate.py --require-ddd-dirs --require-specs
uv run bandit -r src -ll -ii
uv run pytest tests/unit tests/integration tests/e2e --cov=src --cov-branch --cov-fail-under=85 -q
```
