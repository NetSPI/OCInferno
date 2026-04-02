#!/usr/bin/env python3
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

import oci
from ocinferno.core.utils.service_runtime import _init_client


def build_notification_clients(session, region: Optional[str] = None) -> Tuple[Any, Any]:
    """Initialize Notification control/data plane clients with shared behavior."""
    cp = _init_client(
        oci.ons.NotificationControlPlaneClient,
        session=session,
        service_name="Notifications",
    )
    dp = _init_client(
        oci.ons.NotificationDataPlaneClient,
        session=session,
        service_name="Notifications",
    )

    target_region = region or getattr(session, "region", None)
    if target_region:
        for client in (cp, dp):
            try:
                client.base_client.set_region(target_region)
            except Exception:
                pass
    return cp, dp


class NotificationTopicsResource:
    TABLE_NAME = "notification_topics"
    COLUMNS = ["topic_id", "name", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.cp, _ = build_notification_clients(session=session, region=region)

    # List topics in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.cp.list_topics, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one topic by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.cp.get_topic(topic_id=resource_id).data) or {}

    # Save topic rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for topic rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:  # pragma: no cover - placeholder
        _ = (resource_id, out_path)
        return False


class NotificationSubscriptionsResource:
    TABLE_NAME = "notification_subscriptions"
    COLUMNS = ["id", "topic_id", "protocol", "endpoint", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        _, self.dp = build_notification_clients(session=session, region=region)

    # List subscriptions in a compartment (optionally scoped to one topic).
    def list(self, *, compartment_id: str, topic_id: Optional[str] = None) -> List[Dict[str, Any]]:
        if topic_id:
            resp = oci.pagination.list_call_get_all_results(
                self.dp.list_subscriptions,
                compartment_id=compartment_id,
                topic_id=topic_id,
            )
        else:
            resp = oci.pagination.list_call_get_all_results(self.dp.list_subscriptions, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one subscription by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.dp.get_subscription(subscription_id=resource_id).data) or {}

    # Save subscription rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for subscription rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:  # pragma: no cover - placeholder
        _ = (resource_id, out_path)
        return False
