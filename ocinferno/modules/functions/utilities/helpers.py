from __future__ import annotations

from argparse import Namespace
from typing import Any, Dict, List, Optional

import oci
from ocinferno.core.utils.module_helpers import ids_from_db, parse_csv_args
from ocinferno.core.utils.service_runtime import _init_client


def build_functions_client(session, region: Optional[str] = None):
    """Initialize a Functions client with shared signer/proxy/session behavior."""
    client = _init_client(
        oci.functions.FunctionsManagementClient,
        session=session,
        service_name="Functions",
    )
    target_region = region or getattr(session, "region", None)
    if target_region:
        try:
            client.base_client.set_region(target_region)
        except Exception:
            pass
    return client


class FunctionsAppsResource:
    TABLE_NAME = "functions_apps"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_functions_client(session=session, region=region)

    # List applications in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_applications, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one application by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_application(application_id=resource_id).data) or {}

    # Save application rows to cache table.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)


class FunctionsFunctionsResource:
    TABLE_NAME = "functions_functions"
    APPS_TABLE = "functions_apps"
    COLUMNS = ["id", "display_name", "lifecycle_state", "application_id", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_functions_client(session=session, region=region)

    # Resolve application IDs from CLI, cached DB rows, or live app listing.
    def list_app_ids(self, *, compartment_id: Optional[str], args: Namespace) -> List[str]:
        cli_ids = parse_csv_args(list(getattr(args, "app_ids", []) or []))
        if cli_ids:
            return cli_ids

        db_ids = ids_from_db(self.session, table_name=self.APPS_TABLE, compartment_id=compartment_id)
        if db_ids:
            return db_ids

        if not compartment_id:
            return []
        try:
            resp = oci.pagination.list_call_get_all_results(self.client.list_applications, compartment_id=compartment_id)
            apps = oci.util.to_dict(resp.data) or []
            return parse_csv_args([row.get("id") for row in apps if isinstance(row, dict) and row.get("id")])
        except Exception:
            return []

    # List functions under one application.
    def list(self, *, application_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_functions, application_id=application_id)
        return oci.util.to_dict(resp.data) or []

    # Get one function by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_function(function_id=resource_id).data) or {}

    # Save function rows to cache table.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)
