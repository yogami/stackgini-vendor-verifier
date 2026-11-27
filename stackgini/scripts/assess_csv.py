"""CLI runner for evaluating a Stackgini input CSV (id,url,product,vendor)."""

from __future__ import annotations

import argparse
import asyncio
from datetime import UTC, datetime
from pathlib import Path

from src.api.app import build_default_assess_use_case
from src.infrastructure.csv_batch import run_csv_batch
from src.infrastructure.http_probes import make_resilient_async_client


async def _run(input_csv: Path, output_csv: Path, concurrency: int) -> None:
    year = datetime.now(tz=UTC).year
    async with make_resilient_async_client(timeout_seconds=45.0) as client:
        use_case = build_default_assess_use_case(current_year=year, client=client)
        results = await run_csv_batch(use_case, input_csv, output_csv, concurrency=concurrency)
    counts: dict[str, int] = {"Green": 0, "Yellow": 0, "Red": 0}
    for res in results:
        counts[res.overall.value] = counts.get(res.overall.value, 0) + 1
    print(f"ASSESSED {len(results)} ROWS -> {output_csv} | {counts}")


def main() -> int:
    """Parse CLI arguments and run batch assessment."""
    parser = argparse.ArgumentParser(description="Run Stackgini vendor assessment over a CSV.")
    parser.add_argument("input_csv", type=Path)
    parser.add_argument("output_csv", type=Path)
    parser.add_argument("--concurrency", type=int, default=4)
    args = parser.parse_args()
    asyncio.run(_run(args.input_csv, args.output_csv, args.concurrency))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
