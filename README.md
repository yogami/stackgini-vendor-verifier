# Stackgini Vendor Verifier

Deterministic 5-signal SaaS vendor verification engine built under Hexagonal DDD, TDD, and strict AST craftsmanship rules.

## Signals
1. **RDAP / WHOIS Domain Age** (`RdapHttpAdapter` + `DomainAgeMismatchRule`)
2. **crt.sh Certificate Transparency History** (`CrtShHttpAdapter` + `CertificateHistoryRule`)
3. **DNS MX / SPF / DMARC Posture** (`DnsResolverAdapter` + `DnsAuthSignalRule`)
4. **GDPR Subprocessor Reverse Lookup** (`CuratedSubprocessorAdapter` + `SubprocessorCorroborationRule`)
5. **Wayback CDX Archive Timeline** (`WaybackHttpAdapter` + `WaybackTimelineRule`)

## Architecture
- `src/domain/`: Immutable `@dataclass(frozen=True)` models, tri-state `ProbeOutcome[T]`, `VendorRule` specifications, and `EvidenceLedger`.
- `src/ports/`: ISP-compliant secondary protocols (`<= 3` methods per port).
- `src/application/`: `VerifyVendorUseCase` orchestration with zero infrastructure imports.
- `src/infrastructure/`: SSRF domain normalizer, async `httpx` adapters, and `dnspython` resolver.
- `src/api/`: FastAPI service exposing `/health`, `/api/v1/verify`, `/api/openapi.json`, and `/api/docs`.

## Verification Gates
```bash
uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy --strict src tests
uv run xenon --max-absolute A --max-modules A --max-average A src
uv run lint-imports
uv run python scripts/craftsmanship_gate.py --require-ddd-dirs --require-specs
uv run bandit -r src -ll -ii
uv run pytest tests/unit tests/integration tests/e2e --cov=src --cov-branch --cov-fail-under=85 -q
```
