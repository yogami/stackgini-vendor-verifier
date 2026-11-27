"""CSV batch reader, bounded-concurrency runner, and Stackgini verdict writer."""

from __future__ import annotations

import asyncio
import csv
import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

import httpx
import whois

from src.application.assess_vendor import AssessVendorUseCase
from src.domain.assessment import StackginiAssessment, StackginiVerdict, VendorInput

REQUIRED_COLUMNS = ("id", "url", "product", "vendor")
OUTPUT_COLUMNS = [
    "id",
    "url",
    "product",
    "vendor",
    "overall",
    "green_flags",
    "yellow_flags",
    "red_flags",
    "reasoning",
]
MAX_INLINE_SOURCES = 5
POLITE_HOST_GAP_SECONDS = 0.25


def _missing_columns(present: set[str]) -> list[str]:
    return [col for col in REQUIRED_COLUMNS if col not in present]


def _validate_headers(fieldnames: Sequence[str] | None) -> None:
    present = set(fieldnames or ())
    missing = _missing_columns(present)
    if missing:
        raise ValueError(f"Missing required CSV columns: {', '.join(missing)}")


def _row_to_vendor_input(row: dict[str, str]) -> VendorInput:
    return VendorInput(
        row_id=str(row.get("id", "")).strip(),
        url=str(row.get("url", "")).strip(),
        product=str(row.get("product", "")).strip(),
        vendor=str(row.get("vendor", "")).strip(),
    )


def _load_validated_rows(csv_path: Path) -> list[VendorInput]:
    with csv_path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        _validate_headers(reader.fieldnames)
        return [_row_to_vendor_input(row) for row in reader]


def read_vendor_csv(csv_path: Path) -> list[VendorInput]:
    """Load and validate id,url,product,vendor rows from a Stackgini CSV file."""
    return [item for item in _load_validated_rows(csv_path) if any((item.row_id, item.url))]


def _format_flags(flags: tuple[str, ...]) -> str:
    return "; ".join(flags) if flags else "None identified."


def _format_reasoning(assessment: StackginiAssessment) -> str:
    base = assessment.reasoning.strip()
    if not assessment.source_urls:
        return base
    top_urls = ", ".join(assessment.source_urls[:MAX_INLINE_SOURCES])
    return f"{base} [Sources: {top_urls}]"


def _assessment_to_row(assessment: StackginiAssessment) -> dict[str, str]:
    return {
        "id": assessment.item.row_id,
        "url": assessment.item.url,
        "product": assessment.item.product,
        "vendor": assessment.item.vendor,
        "overall": assessment.overall.value,
        "green_flags": _format_flags(assessment.green_flags),
        "yellow_flags": _format_flags(assessment.yellow_flags),
        "red_flags": _format_flags(assessment.red_flags),
        "reasoning": _format_reasoning(assessment),
    }


def _probe_summary_payload(assessment: StackginiAssessment) -> dict[str, object]:
    ledger = assessment.ledger
    return {
        "trust_score": ledger.trust_score(),
        "verdict": ledger.verdict().value,
        "abstained": list(ledger.abstained),
        "findings": [
            {
                "rule_id": f.rule_id,
                "claim": f.claim,
                "observed_fact": f.observed_fact,
                "impact": f.impact,
                "source_url": f.source_url,
            }
            for f in ledger.findings
        ],
        "dom_summary": assessment.dom_summary,
    }


def _sources_payload(assessments: list[StackginiAssessment]) -> list[dict[str, object]]:
    return [
        {
            "id": a.item.row_id,
            "url": a.item.url,
            "overall": a.overall.value,
            "source_urls": list(a.source_urls),
            "technical_probes": _probe_summary_payload(a),
        }
        for a in assessments
    ]


def write_assessment_outputs(output_csv: Path, assessments: list[StackginiAssessment]) -> Path:
    """Write Stackgini verdict CSV plus companion <stem>_sources.json audit file."""
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with output_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=OUTPUT_COLUMNS, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        for item in assessments:
            writer.writerow(_assessment_to_row(item))

    sources_path = output_csv.with_name(f"{output_csv.stem}_sources.json")
    sources_path.write_text(json.dumps(_sources_payload(assessments), indent=2), encoding="utf-8")
    return sources_path


def _row_error_fallback(item: VendorInput, exc: Exception) -> StackginiAssessment:
    return StackginiAssessment(
        item=item,
        overall=StackginiVerdict.YELLOW,
        green_flags=(),
        yellow_flags=(f"Assessment skipped due to row validation or runtime error: {type(exc).__name__}",),
        red_flags=(),
        reasoning=f"Row could not be assessed automatically ({type(exc).__name__}: {exc}).",
        source_urls=(),
    )


async def _assess_with_limit(
    sem: asyncio.Semaphore,
    use_case: AssessVendorUseCase,
    item: VendorInput,
    current_year: int,
) -> StackginiAssessment:
    async with sem:
        await asyncio.sleep(POLITE_HOST_GAP_SECONDS)
        try:
            return await use_case.execute(item, current_year=current_year)
        except (httpx.HTTPError, whois.WhoisError, ValueError, RuntimeError, OSError) as exc:
            return _row_error_fallback(item, exc)


async def run_csv_batch(
    use_case: AssessVendorUseCase,
    input_csv: Path,
    output_csv: Path,
    concurrency: int = 4,
) -> list[StackginiAssessment]:
    """Assess all rows in input_csv concurrently and write Stackgini outputs."""
    items = read_vendor_csv(input_csv)
    sem = asyncio.Semaphore(max(1, concurrency))
    year = datetime.now(tz=UTC).year
    results = await asyncio.gather(*(_assess_with_limit(sem, use_case, item, year) for item in items))
    write_assessment_outputs(output_csv, list(results))
    return list(results)
