# Stackgini Vendor Verifier: Living Specification

## 1. Goal & Scope
Deterministic 5-signal SaaS vendor verifier built under Hexagonal DDD, TDD, and strict AST craftsmanship governance.
Given a candidate vendor domain (and optional site-claimed founding or copyright year), the system probes five independent external signals, records only URL-backed findings, and produces a transparent trust score and verdict.

## 2. Tri-State Probe Outcome Contract (`ProbeOutcome[T]`)
Every external probe port returns an immutable `ProbeOutcome[T]`:
- `OBSERVED`: Registry or archive returned usable data with `source_url`.
- `NOT_FOUND`: Registry or archive responded authoritatively with HTTP 404 or empty authoritative dataset with `source_url`.
- `UNAVAILABLE`: Transient failure (HTTP 429, 5xx, DNS timeout, network error). Rules MUST abstain on `UNAVAILABLE` and never emit negative trust penalties for rate-limited or offline registries.

## 3. Five Verification Signals
1. **RDAP / WHOIS Domain Age (`DomainAgeMismatchRule`)**:
   - Penalizes domains registered fewer than `MIN_ESTABLISHED_DAYS` (180 days) (`-30` points) and penalizes explicit copyright or founding year backdating where `claimed_since_year` precedes RDAP registration year by at least `BACKDATE_GAP_YEARS` (2 years) (`-25` points).
2. **crt.sh Certificate History (`CertificateHistoryRule`)**:
   - Authoritative `NOT_FOUND` (zero certs) triggers `-25` points.
   - `OBSERVED` with single certificate (`cert_count <= 1`) triggers `-10` points; established footprint (`cert_count >= 5`) adds `+5` corroboration.
3. **DNS TXT / MX Authentication (`DnsAuthSignalRule`)**:
   - Missing both MX and SPF/DMARC TXT records triggers `-20` points; having both MX and DMARC adds `+5` corroboration.
4. **GDPR Subprocessor Reverse Lookup (`SubprocessorCorroborationRule`)**:
   - `OBSERVED` verified enterprise subprocessor listing adds `+10` corroboration; `NOT_FOUND` records neutral observation (`0` impact).
5. **Wayback CDX Timeline (`WaybackTimelineRule`)**:
   - Authoritative `NOT_FOUND` (zero snapshots) triggers `-20` points; established history (`snapshot_count >= 10` and `earliest_year <= current_year - 2`) adds `+5` corroboration.

## 4. Evidence & Scoring Invariants
- `VerifiedFinding` rejects empty or non-HTTP(S) `source_url` in `__post_init__` (zero unlinked claims).
- `EvidenceLedger` starts from `BASE_TRUST_SCORE = 70` and clamps final `trust_score` to `[0, 100]`.
- Verdicts:
  - `VERIFIED`: `trust_score >= 70`
  - `SUSPICIOUS`: `40 <= trust_score < 70`
  - `FRAUD_RISK`: `trust_score < 40`

## 5. API & SSRF Safety Contract
- `GET /health` -> `200 OK` `{"status": "ok"}`
- `POST /api/v1/verify` -> accepts `{"domain": str, "claimed_since_year": int | null}` and returns `trust_score`, `verdict`, `findings[]`, and `abstained_signals[]`.
- Rejects localhost, private/loopback/link-local IP literals, and non-HTTP(S) schemes with `422 Unprocessable Entity`.
- Exposes `/api/openapi.json` and `/api/docs`.
