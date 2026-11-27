# Stackgini Vendor Verifier: Living Specification

## 1. Goal & Scope
Deterministic plus live web-grounded SaaS vendor verification engine built under Hexagonal DDD, TDD, and AST craftsmanship governance.
Evaluates `(id, url, product, vendor)` inputs using:
1. Five infrastructure/registry signals:
   - RDAP domain registration age with `python-whois` fallback (`rdap.org`).
   - Certificate Transparency history & operational subdomain profiling (`crt.sh`, extracting SAN/CN subdomains such as `api`, `app`, `auth`, `sso`, `docs`, `status` plus renewal span).
   - DNS mail posture (MX, SPF, DMARC) plus third-party SaaS domain verification TXT tokens.
   - GDPR subprocessor & vendor DPA lookup (`<domain>/dpa`, `<domain>/subprocessors`, public enterprise citations; zero synthetic `.local` URLs).
   - Wayback Machine CDX archive timeline (`web.archive.org`).
2. Headless Playwright DOM forensics guarded against SSRF redirects and DNS rebinding (`normalize_public_domain` + global IP verification):
   - Claim decomposition (`AVeriTeC`): copyright/founding year passed to RDAP age verification, login portal targets, corporate imprint markers, dead `#` footer links, `.docx` privacy link traps, and client-side SPA detection.
3. Off-site web intelligence with prompt-injection delimiters, grounded citation filtering, and zero benchmark memorization.
4. Calibrated Stackgini verdict synthesis (`Green`, `Yellow`, `Red`) preserving hard-fail invariants (`FRAUD_RISK` or verified red flags NEVER yield `Green`), plus interactive dashboard UI at `/`.

## 2. Tri-State Probe Outcome Contract (`ProbeOutcome[T]`)
Every external probe port returns an immutable `ProbeOutcome[T]`:
- `OBSERVED`: Registry, browser, or search returned usable data with verified HTTP(S) `source_url`.
- `NOT_FOUND`: Authoritative negative result (HTTP 404 or empty authoritative dataset with `source_url`).
- `UNAVAILABLE`: Transient failure (HTTP 429, 5xx, timeout, missing credentials). Rules MUST abstain on `UNAVAILABLE`, and web fallback MUST NOT hallucinate `Green` when upstream probes fail.

## 3. Stackgini Calibration & Verdict Rules
- **Hard Invariant:** Any active `red_flags`, DOM `.docx` trap, or infrastructure `FRAUD_RISK` verdict forces `overall = "Red"`.
- **Legacy design calibration:** Old or minimal websites MUST NOT be penalized when release history, community adoption, or verified infrastructure confirms active maintenance.
- **Green with context:** Mature vendors with M&A/PE history or transparently disclosed incidents remain `Green` while surfacing those items in `yellow_flags`.
- **Yellow:** Serial M&A naming/licensing churn, PE roll-ups with stalled roadmaps, silent status-page-only breaches, backdated claims, or single-hobbyist maintainer risks.
- **Red:** Regulator enforcement (FTC, DPA/GDPR), unlawful data practices, undisclosed sanctions exposure, fake traction or logo misrepresentation, missing legal entity, or EOL with security-bypass instructions.

## 4. Input / Output, UI & API Contract
- **CSV Input Schema:** Required columns `id,url,product,vendor` (validated on load).
- **CSV Output Schema:** `id,url,product,vendor,overall,green_flags,yellow_flags,red_flags,reasoning`
- **Audit Companion:** `<output>_sources.json` recording `source_urls[]` and `technical_probes` (`trust_score`, `verdict`, `abstained`, `findings`, `dom_summary`) per row.
- **HTTP Endpoints:**
  - `GET /` -> Interactive Stackgini Verification Dashboard HTML UI
  - `GET /health` -> `{"status": "ok"}`
  - `POST /api/v1/verify` -> single domain 5-signal check
  - `POST /api/v1/assess` -> full Stackgini `(url, product, vendor)` assessment
  - Exposes `/api/openapi.json` and `/api/docs`.
