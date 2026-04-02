#!/usr/bin/env python3
from __future__ import annotations

from typing import Any, Dict, List, Optional

import oci
from ocinferno.core.utils.service_runtime import _init_client


def build_dns_client(session, region: Optional[str] = None):
    """Initialize a DNS client with shared signer/proxy/session behavior."""
    client = _init_client(
        oci.dns.DnsClient,
        session=session,
        service_name="DNS",
    )
    target_region = region or getattr(session, "region", None)
    if target_region:
        try:
            client.base_client.set_region(target_region)
        except Exception:
            pass
    return client


class DnsZonesResource:
    TABLE_NAME = "dns_zones"
    COLUMNS = ["id", "name", "scope", "zone_type", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_dns_client(session=session, region=region)

    # List both GLOBAL and PRIVATE zones in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        global_resp = oci.pagination.list_call_get_all_results(self.client.list_zones, compartment_id=compartment_id, scope="GLOBAL")
        private_resp = oci.pagination.list_call_get_all_results(self.client.list_zones, compartment_id=compartment_id, scope="PRIVATE")
        global_rows = oci.util.to_dict(global_resp.data) or []
        private_rows = oci.util.to_dict(private_resp.data) or []
        return global_rows + private_rows

    # Get one zone by name or OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_zone(zone_name_or_id=resource_id).data) or {}

    # Save zone rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for zone rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:  # pragma: no cover - placeholder
        _ = (resource_id, out_path)
        return False


class DnsZoneRecordsResource:
    TABLE_NAME = "dns_zone_records"
    COLUMNS = ["zone_id", "domain", "rtype", "_rdata_display"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_dns_client(session=session, region=region)

    # List zones (helper used by enum flow for per-zone record enumeration).
    def list_zones(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        return DnsZonesResource(self.session).list(compartment_id=compartment_id)

    # List record sets in one zone.
    def list(self, *, zone_name_or_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.get_zone_records, zone_name_or_id=zone_name_or_id)
        payload = oci.util.to_dict(resp.data) or {}
        if isinstance(payload, dict) and "items" in payload:
            return payload.get("items") or []
        return payload if isinstance(payload, list) else []

    # Get zone metadata by name or OCID.
    def get_zone(self, *, zone_name_or_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_zone(zone_name_or_id=zone_name_or_id).data) or {}

    # No direct single-record endpoint in this enum flow.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        _ = resource_id
        return {}

    # Save zone-record rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for record rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:  # pragma: no cover - placeholder
        _ = (resource_id, out_path)
        return False


class DnsPrivateResolversResource:
    TABLE_NAME = "dns_private_resolvers"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_dns_client(session=session, region=region)

    # List private resolvers in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_resolvers, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one private resolver by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_resolver(resolver_id=resource_id).data) or {}

    # Save resolver rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for resolver rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:  # pragma: no cover - placeholder
        _ = (resource_id, out_path)
        return False
