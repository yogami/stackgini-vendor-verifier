"""Polite async HTTP adapters for RDAP, crt.sh, and Wayback CDX probes."""

from __future__ import annotations

from datetime import UTC, datetime

import httpx

from src.domain.models import CertFootprint, DomainAgeRecord, ProbeOutcome, WaybackTimeline

DEFAULT_TIMEOUT_SECONDS = 8.0
HTTP_OK = 200
HTTP_NOT_FOUND = 404
YEAR_PREFIX_LEN = 4


def _parse_iso_datetime(raw_date: object) -> datetime | None:
    if not isinstance(raw_date, str):
        return None
    return datetime.fromisoformat(raw_date.replace("Z", "+00:00"))


def _parse_registration_event(event: object) -> datetime | None:
    if not isinstance(event, dict) or event.get("eventAction") != "registration":
        return None
    return _parse_iso_datetime(event.get("eventDate"))


def _first_registration_dt(events: list[object]) -> datetime | None:
    for event in events:
        dt = _parse_registration_event(event)
        if dt is not None:
            return dt
    return None


def _parse_rdap_date(payload: object) -> datetime | None:
    if not isinstance(payload, dict):
        return None
    events = payload.get("events")
    return _first_registration_dt(events) if isinstance(events, list) else None


def _build_age_record(reg_dt: datetime, current_year: int) -> DomainAgeRecord:
    ref_dt = datetime(current_year, 12, 31, tzinfo=UTC)
    age_days = max(0, (ref_dt - reg_dt.astimezone(UTC)).days)
    return DomainAgeRecord(registered_year=reg_dt.year, age_days=age_days)


def _digits_to_int(prefix: str) -> int | None:
    return int(prefix) if prefix.isdigit() else None


def _year_from_prefix(raw: object) -> int | None:
    if not isinstance(raw, str) or len(raw) < YEAR_PREFIX_LEN:
        return None
    return _digits_to_int(raw[:YEAR_PREFIX_LEN])


def _cert_row_year(row: object) -> int | None:
    return _year_from_prefix(row.get("not_before")) if isinstance(row, dict) else None


def _cdx_row_year(row: object) -> int | None:
    return _year_from_prefix(row[0]) if isinstance(row, list) and row else None


def _min_year(candidates: list[int | None]) -> int | None:
    years = [y for y in candidates if y is not None]
    return min(years) if years else None


async def _fetch_http_response(
    client: httpx.AsyncClient,
    url: str,
    params: dict[str, str] | None = None,
) -> tuple[httpx.Response | None, str]:
    try:
        resp = await client.get(url, params=params, timeout=DEFAULT_TIMEOUT_SECONDS)
    except httpx.HTTPError as exc:
        return None, type(exc).__name__
    return resp, ""


def _decode_json_body(resp: httpx.Response) -> tuple[object | None, str]:
    try:
        return resp.json(), ""
    except ValueError:
        return None, "invalid_json"


def _unavailable_or_not_found[T](url: str, status_code: int) -> ProbeOutcome[T]:
    if status_code == HTTP_NOT_FOUND:
        return ProbeOutcome.not_found(url)
    return ProbeOutcome.unavailable(url, f"http_{status_code}")


def _decode_ok_response[T](url: str, resp: httpx.Response) -> tuple[object, None] | tuple[None, ProbeOutcome[T]]:
    if resp.status_code != HTTP_OK:
        return None, _unavailable_or_not_found(url, resp.status_code)
    data, err = _decode_json_body(resp)
    return (None, ProbeOutcome.unavailable(url, err)) if err else (data, None)


async def _get_json_or_error[T](
    client: httpx.AsyncClient,
    url: str,
    params: dict[str, str] | None = None,
) -> tuple[object, None] | tuple[None, ProbeOutcome[T]]:
    resp, err = await _fetch_http_response(client, url, params)
    if resp is None:
        return None, ProbeOutcome.unavailable(url, err)
    return _decode_ok_response(url, resp)


def _map_rdap_payload(url: str, data: object, current_year: int) -> ProbeOutcome[DomainAgeRecord]:
    reg_dt = _parse_rdap_date(data)
    if reg_dt is None:
        return ProbeOutcome.not_found(url, "missing_registration_event")
    return ProbeOutcome.observed(url, _build_age_record(reg_dt, current_year))


def _map_crtsh_rows(url: str, rows: object) -> ProbeOutcome[CertFootprint]:
    if not isinstance(rows, list) or not rows:
        return ProbeOutcome.not_found(url)
    earliest = _min_year([_cert_row_year(row) for row in rows])
    return ProbeOutcome.observed(url, CertFootprint(cert_count=len(rows), earliest_year=earliest))


def _map_cdx_rows(url: str, rows: object) -> ProbeOutcome[WaybackTimeline]:
    if not isinstance(rows, list) or len(rows) <= 1:
        return ProbeOutcome.not_found(url)
    earliest = _min_year([_cdx_row_year(row) for row in rows[1:]])
    return ProbeOutcome.observed(url, WaybackTimeline(snapshot_count=len(rows) - 1, earliest_year=earliest))


class RdapHttpAdapter:
    """Async httpx adapter querying rdap.org for domain registration dates."""

    def __init__(self, client: httpx.AsyncClient, current_year: int) -> None:
        self._client = client
        self._current_year = current_year

    async def fetch_domain_age(self, domain: str) -> ProbeOutcome[DomainAgeRecord]:
        """Fetch RDAP registration record with tri-state error handling."""
        url = f"https://rdap.org/domain/{domain}"
        data, failure = await _get_json_or_error(self._client, url)
        return failure if failure is not None else _map_rdap_payload(url, data, self._current_year)


class CrtShHttpAdapter:
    """Async httpx adapter querying crt.sh JSON API."""

    def __init__(self, client: httpx.AsyncClient) -> None:
        self._client = client

    async def fetch_cert_history(self, domain: str) -> ProbeOutcome[CertFootprint]:
        """Fetch Certificate Transparency footprint with tri-state mapping."""
        url = f"https://crt.sh/?q={domain}&output=json"
        rows, failure = await _get_json_or_error(self._client, url)
        return failure if failure is not None else _map_crtsh_rows(url, rows)


class WaybackHttpAdapter:
    """Async httpx adapter querying Wayback Machine CDX JSON API."""

    def __init__(self, client: httpx.AsyncClient) -> None:
        self._client = client

    async def fetch_timeline(self, domain: str) -> ProbeOutcome[WaybackTimeline]:
        """Fetch Wayback CDX capture timeline with tri-state mapping."""
        url = "https://web.archive.org/cdx/search/cdx"
        params = {"url": domain, "output": "json", "fl": "timestamp", "collapse": "timestamp:6"}
        rows, failure = await _get_json_or_error(self._client, url, params=params)
        return failure if failure is not None else _map_cdx_rows(url, rows)
