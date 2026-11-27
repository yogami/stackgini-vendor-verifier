"""SSRF protection, DNS-rebinding guards, and domain normalization for vendor inputs."""

from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlparse

DOMAIN_PATTERN = re.compile(r"^(?=.{3,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
FORBIDDEN_SUFFIXES = (".local", ".internal", ".localhost", ".arpa")
ALLOWED_SCHEMES = frozenset({"http", "https"})


def _prepare_candidate_url(raw_input: str) -> str:
    cleaned = raw_input.strip()
    if not cleaned:
        raise ValueError("Invalid empty domain")
    return cleaned if "://" in cleaned else f"https://{cleaned}"


def _require_hostname(hostname: str | None) -> str:
    host = (hostname or "").strip(".").lower()
    if not host:
        raise ValueError("Invalid empty hostname")
    return host


def _extract_host(raw_input: str) -> str:
    parsed = urlparse(_prepare_candidate_url(raw_input))
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise ValueError(f"Invalid URL scheme: {parsed.scheme}")
    return _require_hostname(parsed.hostname)


def _reject_local_name(host: str) -> None:
    if host == "localhost" or host.endswith(FORBIDDEN_SUFFIXES):
        raise ValueError(f"Invalid private or local host: {host}")


def _reject_non_global_ip(host: str) -> None:
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return
    if not addr.is_global:
        raise ValueError(f"Invalid non-global IP literal: {host}")


def normalize_public_domain(raw_input: str) -> str:
    """Validate and normalize a public vendor URL or hostname into a lowercase domain."""
    host = _extract_host(raw_input)
    _reject_local_name(host)
    _reject_non_global_ip(host)
    if not DOMAIN_PATTERN.match(host):
        raise ValueError(f"Invalid public domain format: {host}")
    return host


def normalize_public_url(raw_input: str) -> str:
    """Ensure raw_input resolves to a valid public HTTP(S) URL string."""
    candidate = _prepare_candidate_url(raw_input)
    normalize_public_domain(candidate)
    return candidate


def _resolved_ip_strings(host: str) -> tuple[str, ...]:
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return ()
    return tuple(str(entry[4][0]).split("%", 1)[0] for entry in infos if entry[4])


def verify_resolved_public_ips(host: str) -> None:
    """Reject hostnames resolving via DNS to private, loopback, or link-local IPs."""
    for ip_str in _resolved_ip_strings(host):
        _reject_non_global_ip(ip_str)


def verify_public_url_with_dns(raw_input: str) -> str:
    """Validate URL syntax and enforce DNS global-IP check against rebinding."""
    normalized = normalize_public_url(raw_input)
    verify_resolved_public_ips(normalize_public_domain(normalized))
    return normalized
