#!/usr/bin/env python3
from __future__ import annotations

from typing import Any, Dict, List, Optional

import oci
from ocinferno.core.console import UtilityTools
from ocinferno.core.resource import OciListResource
from ocinferno.core.utils.service_runtime import _init_client
from ocinferno.core.utils.service_runtime import ResourceBase


def build_dns_client(session, region: Optional[str] = None):
    """Initialize a DNS client with shared signer/proxy/session behavior."""
    return _init_client(
        oci.dns.DnsClient,
        session=session,
        service_name="DNS",
        region=region,
    )


class DnsZonesResource(ResourceBase):
    TABLE_NAME = "dns_zones"
    COLUMNS = ["id", "name", "scope", "zone_type", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_dns_client(session=session, region=region)

    # List both GLOBAL and PRIVATE zones in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        debug = bool(getattr(self.session, "individual_run_debug", False) or getattr(self.session, "debug", False))
        global_rows: List[Dict[str, Any]] = []
        try:
            global_resp = oci.pagination.list_call_get_all_results(self.client.list_zones, compartment_id=compartment_id, scope="GLOBAL")
            global_rows = oci.util.to_dict(global_resp.data) or []
        except Exception as err:
            UtilityTools.dlog(debug, "list_zones failed", scope="GLOBAL", err=f"{type(err).__name__}: {err}")

        private_rows: List[Dict[str, Any]] = []
        try:
            private_resp = oci.pagination.list_call_get_all_results(self.client.list_zones, compartment_id=compartment_id, scope="PRIVATE")
            private_rows = oci.util.to_dict(private_resp.data) or []
        except Exception as err:
            UtilityTools.dlog(debug, "list_zones failed", scope="PRIVATE", err=f"{type(err).__name__}: {err}")

        return global_rows + private_rows

    # Get one zone by name or OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_zone(zone_name_or_id=resource_id).data) or {}

    # No binary download endpoint for zone rows.

class DnsZoneRecordsResource(ResourceBase):
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

    # No binary download endpoint for record rows.

class DnsPrivateResolversResource(OciListResource):
    CLIENT_CLS = oci.dns.DnsClient
    SERVICE_NAME = "DNS"
    TABLE_NAME = "dns_private_resolvers"
    LIST_METHOD = "list_resolvers"
    GET_METHOD = "get_resolver"
    GET_ID_PARAM = "resolver_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]
