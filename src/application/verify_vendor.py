"""Application use case orchestrating all five verification probes."""

from __future__ import annotations

import asyncio

from src.domain.models import EvidenceLedger, VendorClaim, VendorSignals, VendorSnapshot
from src.domain.rules import VendorRule, evaluate_vendor
from src.ports.probes import VendorProbeGateway


class VerifyVendorUseCase:
    """Coordinate concurrent probe execution and deterministic rule evaluation."""

    def __init__(self, gateway: VendorProbeGateway, rules: tuple[VendorRule, ...]) -> None:
        self._gateway = gateway
        self._rules = rules

    async def execute(self, claim: VendorClaim) -> EvidenceLedger:
        """Probe all five signals for claim.domain and evaluate domain rules."""
        rdap, certs, dns, subprocessor, wayback = await asyncio.gather(
            self._gateway.rdap.fetch_domain_age(claim.domain),
            self._gateway.certs.fetch_cert_history(claim.domain),
            self._gateway.dns.fetch_dns_profile(claim.domain),
            self._gateway.subprocessor.lookup_subprocessor(claim.domain),
            self._gateway.wayback.fetch_timeline(claim.domain),
        )
        signals = VendorSignals(
            rdap=rdap,
            certs=certs,
            dns=dns,
            subprocessor=subprocessor,
            wayback=wayback,
        )
        return evaluate_vendor(VendorSnapshot(claim=claim, signals=signals), self._rules)
