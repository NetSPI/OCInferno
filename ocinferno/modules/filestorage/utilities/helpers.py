from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

import oci

from ocinferno.core.utils.module_helpers import dedupe_strs
from ocinferno.core.utils.service_runtime import _init_client


def build_file_storage_clients(session, region: Optional[str] = None):
    """Initialize File Storage + Identity clients with shared signer/proxy/session behavior."""
    fs_client = _init_client(
        oci.file_storage.FileStorageClient,
        session=session,
        service_name="FileStorage",
    )
    id_client = _init_client(
        oci.identity.IdentityClient,
        session=session,
        service_name="Identity",
    )

    target_region = region or getattr(session, "region", None)
    if target_region:
        for client in (fs_client, id_client):
            try:
                client.base_client.set_region(target_region)
            except Exception:
                pass

    return fs_client, id_client


class FileStorageFileSystemsResource:
    TABLE_NAME = "file_storage_file_systems"
    COLUMNS = ["id", "display_name", "availability_domain", "lifecycle_state", "metered_bytes", "region"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.fs_client, self.id_client = build_file_storage_clients(session=session, region=region)

    # Resolve AD names for cross-AD list loops.
    def list_availability_domains(self) -> List[str]:
        tenancy_id = (
            getattr(self.session, "tenant_id", None)
            or getattr(self.session, "tenancy_id", None)
            or getattr(self.session, "compartment_id", None)
        )
        if not tenancy_id:
            raise ValueError("No tenancy_id/tenant_id available on session")

        resp = oci.pagination.list_call_get_all_results(
            self.id_client.list_availability_domains,
            tenancy_id,
        )
        out: List[str] = []
        for ad in (resp.data or []):
            name = getattr(ad, "name", None)
            if name:
                out.append(name)
        return out

    # List file systems in one AD.
    def _list_file_systems_in_ad(self, *, compartment_id: str, availability_domain: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(
            self.fs_client.list_file_systems,
            compartment_id=compartment_id,
            availability_domain=availability_domain,
        )
        rows = oci.util.to_dict(resp.data) or []
        return rows if isinstance(rows, list) else [rows]

    # List file systems across ADs.
    def list(self, *, compartment_id: str, availability_domains: List[str], limit: int = 0, region: str = "") -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for ad in availability_domains:
            chunk = self._list_file_systems_in_ad(compartment_id=compartment_id, availability_domain=ad) or []
            for row in chunk:
                if not isinstance(row, dict):
                    continue
                row.setdefault("compartment_id", compartment_id)
                row.setdefault("availability_domain", ad)
                row.setdefault("region", region)
                rows.append(row)
                if limit and len(rows) >= limit:
                    return rows
        return rows

    # Get one file system by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.fs_client.get_file_system(file_system_id=resource_id).data) or {}

    # Save file-system rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for file-system rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False


class FileStorageMountTargetsResource:
    TABLE_NAME = "file_storage_mount_targets"
    COLUMNS = ["id", "display_name", "availability_domain", "lifecycle_state", "subnet_id", "region"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.fs_client, self.id_client = build_file_storage_clients(session=session, region=region)

    # List mount targets in one AD.
    def _list_mount_targets_in_ad(self, *, compartment_id: str, availability_domain: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(
            self.fs_client.list_mount_targets,
            compartment_id=compartment_id,
            availability_domain=availability_domain,
        )
        rows = oci.util.to_dict(resp.data) or []
        return rows if isinstance(rows, list) else [rows]

    # List mount targets across ADs.
    def list(self, *, compartment_id: str, availability_domains: List[str], limit: int = 0, region: str = "") -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for ad in availability_domains:
            chunk = self._list_mount_targets_in_ad(compartment_id=compartment_id, availability_domain=ad) or []
            for row in chunk:
                if not isinstance(row, dict):
                    continue
                row.setdefault("compartment_id", compartment_id)
                row.setdefault("availability_domain", ad)
                row.setdefault("region", region)
                rows.append(row)
                if limit and len(rows) >= limit:
                    return rows
        return rows

    # Get one mount target by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.fs_client.get_mount_target(mount_target_id=resource_id).data) or {}

    # Save mount-target rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for mount-target rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False


class FileStorageExportSetsResource:
    TABLE_NAME = "file_storage_export_sets"
    COLUMNS = ["id", "display_name", "availability_domain", "lifecycle_state", "region"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.fs_client, self.id_client = build_file_storage_clients(session=session, region=region)

    # List export sets in one AD.
    def _list_export_sets_in_ad(self, *, compartment_id: str, availability_domain: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(
            self.fs_client.list_export_sets,
            compartment_id=compartment_id,
            availability_domain=availability_domain,
        )
        rows = oci.util.to_dict(resp.data) or []
        return rows if isinstance(rows, list) else [rows]

    # List export sets across ADs.
    def list(self, *, compartment_id: str, availability_domains: List[str], limit: int = 0, region: str = "") -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for ad in availability_domains:
            chunk = self._list_export_sets_in_ad(compartment_id=compartment_id, availability_domain=ad) or []
            for row in chunk:
                if not isinstance(row, dict):
                    continue
                row.setdefault("compartment_id", compartment_id)
                row.setdefault("availability_domain", ad)
                row.setdefault("region", region)
                rows.append(row)
                if limit and len(rows) >= limit:
                    return rows
        return rows

    # Get one export set by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.fs_client.get_export_set(export_set_id=resource_id).data) or {}

    # Save export-set rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for export-set rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False


class FileStorageExportsResource:
    TABLE_NAME = "file_storage_exports"
    COLUMNS = ["id", "path", "export_set_id", "file_system_id", "lifecycle_state", "region"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.fs_client, self.id_client = build_file_storage_clients(session=session, region=region)

    # Resolve export-set IDs for export enumeration.
    def resolve_export_sets(
        self,
        *,
        compartment_id: str,
        availability_domains: List[str],
        export_set_id: str = "",
        region: str = "",
    ) -> Tuple[List[str], Dict[str, Dict[str, Any]]]:
        if export_set_id:
            return [export_set_id], {}

        ids: List[str] = []
        meta: Dict[str, Dict[str, Any]] = {}
        for ad in availability_domains:
            resp = oci.pagination.list_call_get_all_results(
                self.fs_client.list_export_sets,
                compartment_id=compartment_id,
                availability_domain=ad,
            )
            rows = oci.util.to_dict(resp.data) or []
            rows = rows if isinstance(rows, list) else [rows]
            for row in rows:
                if not isinstance(row, dict):
                    continue
                rid = row.get("id")
                if not rid:
                    continue
                ids.append(rid)
                row.setdefault("compartment_id", compartment_id)
                row.setdefault("availability_domain", ad)
                row.setdefault("region", region)
                meta[rid] = row

        return dedupe_strs(ids), meta

    # List exports across one or more export sets.
    def list(
        self,
        *,
        compartment_id: str,
        export_set_ids: List[str],
        export_set_meta: Dict[str, Dict[str, Any]],
        limit: int = 0,
        region: str = "",
    ) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for export_set_id in export_set_ids:
            resp = oci.pagination.list_call_get_all_results(self.fs_client.list_exports, export_set_id=export_set_id)
            ex_rows = oci.util.to_dict(resp.data) or []
            ex_rows = ex_rows if isinstance(ex_rows, list) else [ex_rows]
            meta = export_set_meta.get(export_set_id) or {}
            for row in ex_rows:
                if not isinstance(row, dict):
                    continue
                row.setdefault("export_set_id", export_set_id)
                row.setdefault("compartment_id", meta.get("compartment_id", compartment_id))
                row.setdefault("availability_domain", meta.get("availability_domain", ""))
                row.setdefault("region", meta.get("region", region))
                rows.append(row)
                if limit and len(rows) >= limit:
                    return rows
        return rows

    # Get one export by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.fs_client.get_export(export_id=resource_id).data) or {}

    # Save export rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for export rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False


class FileStorageSnapshotsResource:
    TABLE_NAME = "file_storage_snapshots"
    COLUMNS = ["id", "name", "file_system_id", "lifecycle_state", "region", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.fs_client, self.id_client = build_file_storage_clients(session=session, region=region)

    # Resolve file-system IDs for snapshot enumeration.
    def resolve_file_systems(
        self,
        *,
        compartment_id: str,
        availability_domains: List[str],
        file_system_id: str = "",
        region: str = "",
    ) -> Tuple[List[str], Dict[str, Dict[str, Any]]]:
        if file_system_id:
            return [file_system_id], {}

        ids: List[str] = []
        meta: Dict[str, Dict[str, Any]] = {}
        for ad in availability_domains:
            resp = oci.pagination.list_call_get_all_results(
                self.fs_client.list_file_systems,
                compartment_id=compartment_id,
                availability_domain=ad,
            )
            rows = oci.util.to_dict(resp.data) or []
            rows = rows if isinstance(rows, list) else [rows]
            for row in rows:
                if not isinstance(row, dict):
                    continue
                rid = row.get("id")
                if not rid:
                    continue
                ids.append(rid)
                row.setdefault("compartment_id", compartment_id)
                row.setdefault("availability_domain", ad)
                row.setdefault("region", region)
                meta[rid] = row

        return dedupe_strs(ids), meta

    # List snapshots across one or more file systems.
    def list(
        self,
        *,
        compartment_id: str,
        file_system_ids: List[str],
        file_system_meta: Dict[str, Dict[str, Any]],
        limit: int = 0,
        region: str = "",
    ) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for file_system_id in file_system_ids:
            resp = oci.pagination.list_call_get_all_results(self.fs_client.list_snapshots, file_system_id=file_system_id)
            snap_rows = oci.util.to_dict(resp.data) or []
            snap_rows = snap_rows if isinstance(snap_rows, list) else [snap_rows]
            meta = file_system_meta.get(file_system_id) or {}
            for row in snap_rows:
                if not isinstance(row, dict):
                    continue
                row.setdefault("file_system_id", file_system_id)
                row.setdefault("compartment_id", meta.get("compartment_id", compartment_id))
                row.setdefault("availability_domain", meta.get("availability_domain", ""))
                row.setdefault("region", meta.get("region", region))
                rows.append(row)
                if limit and len(rows) >= limit:
                    return rows
        return rows

    # Get one snapshot by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.fs_client.get_snapshot(snapshot_id=resource_id).data) or {}

    # Save snapshot rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for snapshot rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False
