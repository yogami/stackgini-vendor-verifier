# Stackgini Vendor Verifier (Berlin AI Labs)

Automated SaaS vendor verification engine built for the **Stackgini · Agents with Taste** challenge at AI Agents Berlin Hackathon (`Team: Berlin AI Labs` | `Yami Gopal <gopal.yami@gmail.com>`).

## Top-Level Deliverables
- [stackgini-verdicts.csv](stackgini-verdicts.csv): Agent verdict file matching Stackgini's exact CSV schema (`id,url,product,vendor,overall,green_flags,yellow_flags,red_flags,reasoning`), including inline URLs behind reasons. (Pre-19:00 sample baseline currently committed; will be replaced with the official 10-product blind drop after `19:00 CET` and updated before `19:45 CET`.)
- [stackgini-verdicts_sources.json](stackgini-verdicts_sources.json): Complete per-row audit trail with `source_urls[]` and `technical_probes` (`trust_score`, `verdict`, `abstained`, `findings`, `dom_summary`).
- **Live Demo Web App:** https://stackgini-verifier-production.up.railway.app

## Source Code & Architecture (`stackgini/`)
- **Hexagonal DDD Core:** [stackgini/src/](stackgini/src) (`domain/`, `ports/`, `application/`, `infrastructure/`, `api/`)
  - **5 Deterministic Signals:** RDAP + WHOIS domain age, Certificate Transparency history & operational subdomain profiling (`crt.sh`), DNS mail auth + third-party SaaS TXT verification tokens (`dnspython`), live GDPR DPA/subprocessor lookup, and Wayback Machine CDX timeline.
  - **SSRF-Guarded Headless Playwright DOM Forensics:** Extracts footer copyright/founding claims (cross-checked against RDAP age), legal imprint markers, login targets, `.docx` privacy traps, and dead `#` social links while blocking DNS-rebinding and private-IP redirects.
  - **Two-Stage Off-Site Intelligence:** Dual search dossiers (`openai/gpt-4o-mini` web plugin) synthesized into calibrated verdicts (`anthropic/claude-sonnet-4.5`) with grounded citation verification and zero-key fallback (`PublicSignalsResearchAdapter`).

## Run Locally or on Blind Drop CSV
```bash
cd stackgini
uv run python -m scripts.assess_csv path/to/input.csv ../stackgini-verdicts.csv --concurrency 4
```

## How to Read `stackgini-verdicts.csv`
- `overall`: `Green`, `Yellow`, or `Red` (enforces hard-fail invariants on regulatory/DOM/fraud risks without penalizing dated legacy websites that prove active maintenance).
- `green_flags`, `yellow_flags`, `red_flags`: semicolon-separated factual findings with inline source links.
- `reasoning`: concise buyer synthesis citing verifying `[Sources: ...]` URLs, backed by full probe logs in `stackgini-verdicts_sources.json`.
