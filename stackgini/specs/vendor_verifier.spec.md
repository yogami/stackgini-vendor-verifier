# Stackgini Vendor Verifier: Living Specification

## 1. Goal & Scope
Deterministic plus live web-grounded SaaS vendor verification engine built under Hexagonal DDD, TDD, and AST craftsmanship governance.
Evaluates `(id, url, product, vendor)` inputs using:
1. Five infrastructure/registry signals (RDAP/WHOIS age, crt.sh history, DNS MX/SPF/DMARC, GDPR subprocessor reverse lookup, Wayback CDX timeline).
2. Headless Playwright DOM forensics (redirect resolution, dead `#` footer links, `.docx` privacy policy traps, client-side SPA detection, copyright and EOL/release markers).
3. Off-site web intelligence (regulatory fines, data breaches and disclosure quality, M&A/PE ownership history, naming churn, and independent adoption).
4. Calibrated Stackgini verdict synthesis (`Green`, `Yellow`, `Red`) with URL-cited flags.

## 2. Tri-State Probe Outcome Contract (`ProbeOutcome[T]`)
Every external probe port returns an immutable `ProbeOutcome[T]`:
- `OBSERVED`: Registry, browser, or search returned usable data with `source_url`.
- `NOT_FOUND`: Authoritative negative result (HTTP 404 or empty authoritative dataset with `source_url`).
- `UNAVAILABLE`: Transient failure (HTTP 429, 5xx, timeout, missing credentials). Rules MUST abstain on `UNAVAILABLE`.

## 3. Stackgini Calibration & Verdict Rules
- **Overall ratings:** `Green`, `Yellow`, `Red`.
- **Legacy design calibration:** Old or minimal websites MUST NOT be penalized when release cadence, community forks, or third-party ecosystems confirm active maintenance.
- **Green with context:** Mature vendors with M&A/PE history or transparently disclosed incidents remain `Green` while surfacing those items in `yellow_flags`.
- **Yellow:** Naming/licensing traps across product portfolios, PE roll-ups with layoff/roadmap freezes, silent status-page-only breaches, or single-hobbyist maintainer continuity risks.
- **Red:** Regulator enforcement (FTC, DPA/GDPR), unlawful data practices, undisclosed geopolitical/sanctions risk, fake/contradictory traction or partner-as-customer logos, missing legal entity, or EOL with security-bypass instructions.

## 4. Input / Output & API Contract
- **CSV Input Schema:** `id,url,product,vendor`
- **CSV Output Schema:** `id,url,product,vendor,overall,green_flags,yellow_flags,red_flags,reasoning`
- **Audit Companion:** `<output>_sources.json` recording `source_urls[]` and technical probe summaries per row.
- **HTTP Endpoints:**
  - `GET /health` -> `{"status": "ok"}`
  - `POST /api/v1/verify` -> single domain 5-signal check
  - `POST /api/v1/assess` -> full Stackgini `(url, product, vendor)` assessment
  - Exposes `/api/openapi.json` and `/api/docs`.
