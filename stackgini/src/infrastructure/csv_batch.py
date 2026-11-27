"""CSV batch reader, bounded-concurrency runner, and Stackgini verdict writer."""

from __future__ import annotations

import asyncio
import csv
import json
from datetime import UTC, datetime
from pathlib import Path

from src.application.assess_vendor import AssessVendorUseCase
from src.domain.assessment import StackginiAssessment, VendorInput

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


def read_vendor_csv(csv_path: Path) -> list[VendorInput]:
    """Load id,url,product,vendor rows from a Stackgini CSV file."""
    with csv_path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        return [
            VendorInput(
                row_id=str(row.get("id", "")).strip(),
                url=str(row.get("url", "")).strip(),
                product=str(row.get("product", "")).strip(),
                vendor=str(row.get("vendor", "")).strip(),
            )
            for row in reader
        ]


def _format_flags(flags: tuple[str, ...]) -> str:
    return "; ".join(flags) if flags else "None identified."


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
        "reasoning": assessment.reasoning,
    }


def _sources_payload(assessments: list[StackginiAssessment]) -> list[dict[str, object]]:
    return [
        {
            "id": a.item.row_id,
            "url": a.item.url,
            "overall": a.overall.value,
            "source_urls": list(a.source_urls),
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


async def _assess_with_limit(
    sem: asyncio.Semaphore,
    use_case: AssessVendorUseCase,
    item: VendorInput,
    current_year: int,
) -> StackginiAssessment:
    async with sem:
        return await use_case.execute(item, current_year=current_year)


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
