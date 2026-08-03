#!/usr/bin/env python3
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

import oci
from ocinferno.core.utils.service_runtime import _init_client
from ocinferno.core.utils.service_runtime import ResourceBase


def build_audit_client(session, region: Optional[str] = None):
    """Initialize an Audit client with shared signer/proxy/session behavior."""
    return _init_client(
        oci.audit.AuditClient,
        session=session,
        service_name="Audit",
        region=region,
    )


class AuditEventsResource(ResourceBase):
    TABLE_NAME = "audit_events"
    COLUMNS = [
        "event_id",
        "event_time",
        "event_name",
        "event_type",
        "principal_name",
        "principal_id",
        "source_ip",
        "user_agent",
        "request_action",
        "resource_name",
        "compartment_id",
    ]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_audit_client(session=session, region=region)

    # List audit events over a time window and flatten each event's nested
    # ``data`` payload into a flat row. Audit events have no single OCID and no
    # get-by-id endpoint, so this is the only read path.
    def list(self, *, compartment_id: str, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(
            self.client.list_events,
            compartment_id=compartment_id,
            start_time=start_time,
            end_time=end_time,
        )
        rows: List[Dict[str, Any]] = []
        for evt in resp.data or []:
            envelope = oci.util.to_dict(evt) or {}
            data = envelope.get("data") or {}
            identity = data.get("identity") or {}
            request = data.get("request") or {}
            rows.append({
                "event_id": envelope.get("event_id"),
                "event_time": envelope.get("event_time"),
                "event_name": data.get("event_name"),
                "event_type": envelope.get("event_type"),
                "principal_name": identity.get("principal_name"),
                "principal_id": identity.get("principal_id"),
                "source_ip": identity.get("ip_address"),
                "user_agent": identity.get("user_agent"),
                "request_action": request.get("action"),
                "resource_name": data.get("resource_name"),
                "compartment_id": data.get("compartment_id") or compartment_id,
            })
        return rows

    # No get-by-id endpoint for audit events.
    def get(self, *, resource_id: str) -> Dict[str, Any]:  # pragma: no cover - placeholder
        _ = resource_id
        return {}

    # No binary download endpoint for audit event rows.
