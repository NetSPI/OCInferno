from __future__ import annotations

from typing import Any, Dict, List, Optional

import oci
from ocinferno.core.utils.service_runtime import _init_client


def build_resource_scheduler_client(session, region: Optional[str] = None):
    """Initialize a Resource Scheduler client with shared signer/proxy/session behavior."""
    client = _init_client(
        oci.resource_scheduler.ScheduleClient,
        session=session,
        service_name="ResourceScheduler",
    )
    target_region = region or getattr(session, "region", None)
    if target_region:
        try:
            client.base_client.set_region(target_region)
        except Exception:
            pass
    return client


class ResourceSchedulesResource:
    TABLE_NAME = "resource_schedules"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_resource_scheduler_client(session=session, region=region)

    # List schedules in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_schedules, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one schedule by OCID.
    def get(self, *, schedule_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_schedule(schedule_id=schedule_id).data) or {}

    # Save schedule rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for schedule rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:  # pragma: no cover - placeholder
        _ = (resource_id, out_path)
        return False
