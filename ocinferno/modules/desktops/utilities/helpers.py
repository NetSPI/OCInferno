from __future__ import annotations

import hashlib
import json
from argparse import Namespace
from typing import Any, Dict, List

import oci
from ocinferno.core.console import UtilityTools
from ocinferno.core.resource import OciListResource
from ocinferno.core.utils.module_helpers import dedupe_strs, ids_from_db, parse_csv_args


class DesktopsDesktopsResource(OciListResource):
    CLIENT_CLS = oci.desktops.DesktopServiceClient
    SERVICE_NAME = "Desktops"
    TABLE_NAME = "desktops_desktops"
    LIST_METHOD = "list_desktops"
    GET_METHOD = "get_desktop"
    GET_ID_PARAM = "desktop_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "desktop_pool_id", "time_created"]

class DesktopsPoolsResource(OciListResource):
    CLIENT_CLS = oci.desktops.DesktopServiceClient
    SERVICE_NAME = "Desktops"
    TABLE_NAME = "desktops_pools"
    LIST_METHOD = "list_desktop_pools"
    GET_METHOD = "get_desktop_pool"
    GET_ID_PARAM = "desktop_pool_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]


def resolve_desktop_pool_ids(session, args: Namespace, *, comp_id: str, debug: bool = False) -> List[str]:
    """Resolve desktop pool IDs from CLI, DB cache, or a live list.

    Shared by the pool_desktops/pool_volumes nested fan-out components in
    enum_desktops.py -- resolved ONCE per run_module call (not independently per
    component) and passed to both via ``nested_list_fn(manual_parent_ids=...)``.
    """
    cli_ids = parse_csv_args(getattr(args, "pool_ids", []))
    if cli_ids:
        return cli_ids

    db_ids = ids_from_db(session, table_name=DesktopsPoolsResource.TABLE_NAME, compartment_id=comp_id)
    if db_ids:
        return db_ids

    try:
        rows = DesktopsPoolsResource(session).list(compartment_id=comp_id) or []
        out = [row.get("id") for row in rows if isinstance(row, dict) and isinstance(row.get("id"), str)]
        return dedupe_strs(out)
    except Exception as err:
        UtilityTools.dlog(debug, "desktop pool bootstrap failed", err=f"{type(err).__name__}: {err}")
        return []


class DesktopsPoolDesktopsResource(OciListResource):
    # Nested under a desktop pool: list_desktop_pool_desktops takes BOTH compartment_id
    # and desktop_pool_id (child_takes_compartment=True in enum_desktops.py's nested_list_fn).
    CLIENT_CLS = oci.desktops.DesktopServiceClient
    SERVICE_NAME = "Desktops"
    TABLE_NAME = "desktops_pool_desktops"
    LIST_METHOD = "list_desktop_pool_desktops"
    GET_METHOD = "get_desktop"
    GET_ID_PARAM = "desktop_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "desktop_pool_id", "time_created"]

class DesktopsPoolVolumesResource(OciListResource):
    # Nested under a desktop pool (compartment_id + desktop_pool_id, like pool desktops
    # above); volume rows are list-only (no meaningful get) in this enum flow.
    CLIENT_CLS = oci.desktops.DesktopServiceClient
    SERVICE_NAME = "Desktops"
    TABLE_NAME = "desktops_pool_volumes"
    LIST_METHOD = "list_desktop_pool_volumes"
    COLUMNS = ["desktop_pool_id", "id", "display_name", "lifecycle_state", "time_created"]

    # Pool-volume rows are list-only in this enum flow.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        _ = resource_id
        return {}

    # Stable hash helper for list-only volume rows.
    def record_hash(self, row: Dict[str, Any], *, prefix: str = "") -> str:
        raw = json.dumps(row or {}, sort_keys=True, default=str, separators=(",", ":"))
        return hashlib.sha1((prefix + raw).encode("utf-8", errors="ignore")).hexdigest()

    # No binary download endpoint for pool-volume rows.

class DesktopsWorkRequestsResource(OciListResource):
    CLIENT_CLS = oci.desktops.DesktopServiceClient
    SERVICE_NAME = "Desktops"
    TABLE_NAME = "desktops_work_requests"
    LIST_METHOD = "list_work_requests"
    GET_METHOD = "get_work_request"
    GET_ID_PARAM = "work_request_id"
    COLUMNS = ["id", "operation_type", "status", "time_accepted", "time_finished"]
