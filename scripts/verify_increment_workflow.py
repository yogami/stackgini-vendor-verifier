"""Parallel multi-agent increment verification workflow enforcing Fowler, Kerievsky, and Uncle Bob rules."""

GATE_SCHEMA = {
    "type": "object",
    "properties": {
        "gate": {"type": "string"},
        "passed": {"type": "boolean"},
        "commands_run": {"type": "array", "items": {"type": "string"}},
        "blocking_issues": {"type": "array", "items": {"type": "string"}},
        "evidence_summary": {"type": "string"},
    },
    "required": ["gate", "passed", "commands_run", "blocking_issues", "evidence_summary"],
}

READONLY_RULE = (
    "CRITICAL: You are a read-only verification agent. NEVER edit, create, or delete repository files. "
    "Even if commands fail, ALWAYS call `finish` with passed=false and exact command output in blocking_issues."
)

phase("1. Parallel Quality, Security, Contract TDD & Local E2E Gates")

lint_prompt = f"""{READONLY_RULE}
Run the full Clean Code, Fowler Refactoring, and Clean Architecture static gates in the workspace:
1. `uv run ruff check src tests`
2. `uv run ruff format --check src tests`
3. `uv run mypy --strict src tests`
4. `uv run xenon --max-absolute A --max-modules A --max-average A src`
5. `uv run lint-imports` (verifies concentric Dependency Rule: api -> infrastructure -> application -> ports -> domain)
6. `uv run python scripts/craftsmanship_gate.py --require-ddd-dirs --require-specs`
   (enforces CC <= 3, src method <= 30 lines, params <= 4, ISP port methods <= 3, frozen domain dataclasses, zero Any in domain/ports, zero boolean flag args, zero magic numbers, non-anemic domain, and substance assertions)
Report every failure verbatim in blocking_issues. Set gate="Linter, Smell & Clean Architecture Gate"."""

security_prompt = f"""{READONLY_RULE}
Run security, dependency, secret-leak, and SSRF / polite-crawler checks in the workspace:
1. `uv run bandit -r src -ll -ii`
2. Try `uv run pip-audit --offline` (if offline cache lacks vulnerability DB, run `uv run pip-audit`).
3. Inspect `git diff` and `src/` for hardcoded API keys, unsafe `shell=True`, `eval`, missing URL scheme/private-IP SSRF guards, or missing HTTP timeouts and polite rate-limiting on vendor probes.
Report any critical or medium issue in blocking_issues. Set gate="Security & SSRF Gate"."""

substance_prompt = f"""{READONLY_RULE}
Run Uncle Bob TDD branch coverage, Fowler Port Contract Tests, and OpenAPI parity checks in the workspace:
1. `uv run pytest tests/unit tests/integration --cov=src --cov-branch --cov-fail-under=85 -q`
2. Verify Fowler Port Contract Tests exist and pass for active ports (testing both in-memory fakes and respx HTTP adapters on 200, 404, and timeout/429 Unavailable outcomes).
3. Verify FastAPI exports `/api/openapi.json` and `/api/docs` cleanly and matches `specs/`.
Set gate="Branch-Covered TDD & Port Contract Gate"."""

local_e2e_prompt = f"""{READONLY_RULE}
Run end-to-end Playwright substance tests against a live local uvicorn server:
1. Pick a free local port via Python socket bind to port 0 and start `uv run uvicorn ...` in the background, redirecting logs to `/tmp/e2e_uvicorn.log`.
2. Wait for HTTP 200 on `/health` (or `/api/docs`), then run `uv run pytest tests/e2e --base-url http://127.0.0.1:<port> -q`.
3. Always terminate the uvicorn process in a trap/finally block after tests complete.
Report pass/fail and exact test output. Set gate="Local Playwright E2E Gate"."""

phase1_results = await parallel(
    [
        ("Linter, Smell & Clean Architecture Gate", lint_prompt),
        ("Security & SSRF Gate", security_prompt),
        ("Branch-Covered TDD & Port Contract Gate", substance_prompt),
        ("Local Playwright E2E Gate", local_e2e_prompt),
    ],
    lambda item: agent(
        item[1],
        schema=GATE_SCHEMA,
        role=item[0],
        workspace="inherit",
        model="flash",
    ),
)

for r in phase1_results:
    log(f"[{r['gate']}] passed={r['passed']} | {r['evidence_summary']}")

phase("2. Blind Skeptical Peer Review (Fowler / Kerievsky / Uncle Bob Audit)")

peer_prompt = f"""{READONLY_RULE}
Act as a Skeptical Peer Reviewer per Studio RULES.md Section 7, grading against Martin Fowler, Joshua Kerievsky, and Uncle Bob:
1. Inspect `specs/`, `git log -n 6 --oneline`, `git status`, and `git diff main...HEAD` (or `git diff HEAD`).
2. Uncle Bob Check: Verify Three Laws of TDD / Red-Green-Refactor discipline, Command-Query Separation (CQS), ISP on `src/ports/`, DIP on `src/application/`, and Compose Method single-abstraction-level functions (`<= 30` lines, `CC <= 3`).
3. Martin Fowler Check: Reject Primitive Obsession, Feature Envy (`a.b.c` train wrecks), Data Clumps, Anemic Domain Models, or drifted test doubles lacking Contract Tests.
4. Joshua Kerievsky Check: Verify signal rules use Composable Specifications + Collecting Parameter (`EvidenceLedger`) and `Introduce Null Object` (`UNAVAILABLE` vs `NOT_FOUND` tri-state outcomes so network timeouts never trigger false-positive fraud flags), without speculative unused abstractions.
Set gate="Blind Skeptical Peer Review"."""

peer_result = await agent(
    peer_prompt,
    schema=GATE_SCHEMA,
    role="Skeptical Peer Reviewer",
    workspace="inherit",
    model="inherit",
)
log(f"[{peer_result['gate']}] passed={peer_result['passed']} | {peer_result['evidence_summary']}")

all_results = [*phase1_results, peer_result]

railway_url = args.get("railway_url")
if railway_url:
    phase("3. Railway Production Deploy & Live Playwright E2E")
    prod_prompt = f"""{READONLY_RULE}
Verify live Railway production deployment and run the Playwright E2E suite against `{railway_url}`:
1. Run `railway deployment list --json` and confirm the newest deployment status is `SUCCESS`.
2. Run `curl -fsS {railway_url}/api/openapi.json >/dev/null` and `uv run pytest tests/e2e --base-url {railway_url} -q`.
3. Do NOT pass if deployment status is not SUCCESS or if any Playwright assertion fails.
Set gate="Production Playwright E2E Gate"."""

    prod_result = await agent(
        prod_prompt,
        schema=GATE_SCHEMA,
        role="Production Playwright E2E Gate",
        workspace="inherit",
        model="flash",
    )
    log(f"[{prod_result['gate']}] passed={prod_result['passed']} | {prod_result['evidence_summary']}")
    all_results.append(prod_result)

failures = [r for r in all_results if not r["passed"]]
if failures:
    details = "; ".join(f"{f['gate']}: {f['blocking_issues']}" for f in failures)
    raise RuntimeError(f"Verification gates failed: {details}")

log("ALL_VERIFICATION_GATES_PASSED")
