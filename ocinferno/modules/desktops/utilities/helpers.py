from __future__ import annotations

import hashlib
import json
from argparse import Namespace
from typing import Any, Dict, List, Optional

import oci
from ocinferno.core.console import UtilityTools
from ocinferno.core.utils.module_helpers import dedupe_strs, ids_from_db, parse_csv_args
from ocinferno.core.utils.service_runtime import _init_client


def build_desktops_client(session, region: Optional[str] = None):
    """Initialize a Desktops client with shared signer/proxy/session behavior."""
    client = _init_client(
        oci.desktops.DesktopServiceClient,
        session=session,
        service_name="Desktops",
    )
    target_region = region or getattr(session, "region", None)
    if target_region:
        try:
            client.base_client.set_region(target_region)
        except Exception:
            pass
    return client


class DesktopsDesktopsResource:
    TABLE_NAME = "desktops_desktops"
    COLUMNS = ["id", "display_name", "lifecycle_state", "desktop_pool_id", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.debug = bool(getattr(session, "individual_run_debug", False) or getattr(session, "debug", False))
        self.client = build_desktops_client(session=session, region=region)

    # List desktops in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_desktops, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one desktop by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_desktop(desktop_id=resource_id).data) or {}

    # Save desktop rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for desktop rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:  # pragma: no cover - placeholder
        _ = (resource_id, out_path)
        return False


class DesktopsPoolsResource:
    TABLE_NAME = "desktops_pools"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.debug = bool(getattr(session, "individual_run_debug", False) or getattr(session, "debug", False))
        self.client = build_desktops_client(session=session, region=region)

    # List desktop pools in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_desktop_pools, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one desktop pool by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_desktop_pool(desktop_pool_id=resource_id).data) or {}

    # Save desktop-pool rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for desktop-pool rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:  # pragma: no cover - placeholder
        _ = (resource_id, out_path)
        return False


class DesktopsPoolDesktopsResource:
    TABLE_NAME = "desktops_pool_desktops"
    TABLE_POOLS = "desktops_pools"
    COLUMNS = ["id", "display_name", "lifecycle_state", "desktop_pool_id", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.debug = bool(getattr(session, "individual_run_debug", False) or getattr(session, "debug", False))
        self.client = build_desktops_client(session=session, region=region)

    # Resolve pool IDs from CLI, cache, or live listing.
    def resolve_pool_ids(self, args: Namespace, *, comp_id: str) -> List[str]:
        cli_ids = parse_csv_args(getattr(args, "pool_ids", []))
        if cli_ids:
            return cli_ids

        db_ids = ids_from_db(self.session, table_name=self.TABLE_POOLS, compartment_id=comp_id)
        if db_ids:
            return db_ids

        try:
            rows = DesktopsPoolsResource(self.session).list(compartment_id=comp_id) or []
            out = [row.get("id") for row in rows if isinstance(row, dict) and isinstance(row.get("id"), str)]
            return dedupe_strs(out)
        except Exception as err:
            UtilityTools.dlog(self.debug, "desktop pool bootstrap failed", err=f"{type(err).__name__}: {err}")
            return []

    # List desktops under one pool.
    def list(self, *, compartment_id: str, desktop_pool_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(
            self.client.list_desktop_pool_desktops,
            compartment_id=compartment_id,
            desktop_pool_id=desktop_pool_id,
        )
        return oci.util.to_dict(resp.data) or []

    # Get one desktop by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_desktop(desktop_id=resource_id).data) or {}

    # Save pool-desktop rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for pool-desktop rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:  # pragma: no cover - placeholder
        _ = (resource_id, out_path)
        return False


class DesktopsPoolVolumesResource:
    TABLE_NAME = "desktops_pool_volumes"
    TABLE_POOLS = "desktops_pools"
    COLUMNS = ["desktop_pool_id", "id", "display_name", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.debug = bool(getattr(session, "individual_run_debug", False) or getattr(session, "debug", False))
        self.client = build_desktops_client(session=session, region=region)

    # Resolve pool IDs from CLI, cache, or live listing.
    def resolve_pool_ids(self, args: Namespace, *, comp_id: str) -> List[str]:
        cli_ids = parse_csv_args(getattr(args, "pool_ids", []))
        if cli_ids:
            return cli_ids

        db_ids = ids_from_db(self.session, table_name=self.TABLE_POOLS, compartment_id=comp_id)
        if db_ids:
            return db_ids

        try:
            rows = DesktopsPoolsResource(self.session).list(compartment_id=comp_id) or []
            out = [row.get("id") for row in rows if isinstance(row, dict) and isinstance(row.get("id"), str)]
            return dedupe_strs(out)
        except Exception as err:
            UtilityTools.dlog(self.debug, "desktop pool bootstrap failed", err=f"{type(err).__name__}: {err}")
            return []

    # List volumes under one desktop pool.
    def list(self, *, desktop_pool_id: str, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(
            self.client.list_desktop_pool_volumes,
            desktop_pool_id=desktop_pool_id,
            compartment_id=compartment_id,
        )
        return oci.util.to_dict(resp.data) or []

    # Pool-volume rows are list-only in this enum flow.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        _ = resource_id
        return {}

    # Stable hash helper for list-only volume rows.
    def record_hash(self, row: Dict[str, Any], *, prefix: str = "") -> str:
        raw = json.dumps(row or {}, sort_keys=True, default=str, separators=(",", ":"))
        return hashlib.sha1((prefix + raw).encode("utf-8", errors="ignore")).hexdigest()

    # Save pool-volume rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for pool-volume rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:  # pragma: no cover - placeholder
        _ = (resource_id, out_path)
        return False


class DesktopsWorkRequestsResource:
    TABLE_NAME = "desktops_work_requests"
    COLUMNS = ["id", "operation_type", "status", "time_accepted", "time_finished"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_desktops_client(session=session, region=region)

    # List work requests in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_work_requests, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one work request by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_work_request(work_request_id=resource_id).data) or {}

    # Save work-request rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for work-request rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:  # pragma: no cover - placeholder
        _ = (resource_id, out_path)
        return False
