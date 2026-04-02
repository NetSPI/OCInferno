#!/usr/bin/env python3
from __future__ import annotations

from typing import Any, Dict, List, Optional

import oci
from ocinferno.core.utils.module_helpers import fill_missing_fields
from ocinferno.core.utils.service_runtime import _init_client


class BlockStorageResourceClient:
    """
    Reusable wrapper for OCI Block Storage via oci.core.BlockstorageClient.

    Pattern:
      - list_* returns list[dict]
      - get_* returns dict
      - enum modules decide what to store
    """

    TABLE_VOLUMES = "blockstorage_volumes"
    TABLE_BOOT_VOLUMES = "blockstorage_boot_volumes"
    TABLE_VOLUME_BACKUPS = "blockstorage_volume_backups"
    TABLE_BOOT_VOLUME_BACKUPS = "blockstorage_boot_volume_backups"

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = _init_client(
            oci.core.BlockstorageClient,
            session=session,
            service_name="Block Storage",
        )

        if region:
            try:
                self.client.base_client.set_region(region)
            except Exception:
                pass
        elif getattr(session, "region", None):
            try:
                self.client.base_client.set_region(session.region)
            except Exception:
                pass

    # --------------------
    # Volumes
    # --------------------
    def list_volumes(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(
            self.client.list_volumes,
            compartment_id=compartment_id,
        )
        return oci.util.to_dict(resp.data) or []

    def get_volume(self, *, volume_id: str) -> Dict[str, Any]:
        resp = self.client.get_volume(volume_id=volume_id)
        return oci.util.to_dict(resp.data) or {}

    # --------------------
    # Boot Volumes
    # --------------------
    def list_boot_volumes(self, *, compartment_id: str, availability_domain: Optional[str] = None) -> List[Dict[str, Any]]:
        kwargs: Dict[str, Any] = {"compartment_id": compartment_id}
        if availability_domain:
            kwargs["availability_domain"] = availability_domain
        resp = oci.pagination.list_call_get_all_results(
            self.client.list_boot_volumes,
            **kwargs,
        )
        return oci.util.to_dict(resp.data) or []

    def get_boot_volume(self, *, boot_volume_id: str) -> Dict[str, Any]:
        resp = self.client.get_boot_volume(boot_volume_id=boot_volume_id)
        return oci.util.to_dict(resp.data) or {}

    # --------------------
    # Volume Backups
    # --------------------
    def list_volume_backups(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(
            self.client.list_volume_backups,
            compartment_id=compartment_id,
        )
        return oci.util.to_dict(resp.data) or []

    def get_volume_backup(self, *, backup_id: str) -> Dict[str, Any]:
        resp = self.client.get_volume_backup(volume_backup_id=backup_id)
        return oci.util.to_dict(resp.data) or {}

    # --------------------
    # Boot Volume Backups
    # --------------------
    def list_boot_volume_backups(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(
            self.client.list_boot_volume_backups,
            compartment_id=compartment_id,
        )
        return oci.util.to_dict(resp.data) or []

    def get_boot_volume_backup(self, *, backup_id: str) -> Dict[str, Any]:
        resp = self.client.get_boot_volume_backup(boot_volume_backup_id=backup_id)
        return oci.util.to_dict(resp.data) or {}


fill_missing = fill_missing_fields


class BlockVolumesResource:
    TABLE_NAME = BlockStorageResourceClient.TABLE_VOLUMES
    COLUMNS = ["id", "display_name", "lifecycle_state", "size_in_gbs", "availability_domain"]

    def __init__(self, ops: BlockStorageResourceClient):
        self.ops = ops

    def list(self, *, compartment_id: str, **_kwargs) -> List[Dict[str, Any]]:
        return self.ops.list_volumes(compartment_id=compartment_id)

    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return self.ops.get_volume(volume_id=resource_id)

    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.ops.session.save_resources(rows or [], self.TABLE_NAME)


class BlockBootVolumesResource:
    TABLE_NAME = BlockStorageResourceClient.TABLE_BOOT_VOLUMES
    COLUMNS = ["id", "display_name", "lifecycle_state", "size_in_gbs", "availability_domain"]

    def __init__(self, ops: BlockStorageResourceClient):
        self.ops = ops

    def list(self, *, compartment_id: str, availability_domain: Optional[str] = None, **_kwargs) -> List[Dict[str, Any]]:
        return self.ops.list_boot_volumes(compartment_id=compartment_id, availability_domain=availability_domain)

    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return self.ops.get_boot_volume(boot_volume_id=resource_id)

    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.ops.session.save_resources(rows or [], self.TABLE_NAME)


class BlockVolumeBackupsResource:
    TABLE_NAME = BlockStorageResourceClient.TABLE_VOLUME_BACKUPS
    COLUMNS = ["id", "display_name", "lifecycle_state", "size_in_gbs", "volume_id"]

    def __init__(self, ops: BlockStorageResourceClient):
        self.ops = ops

    def list(self, *, compartment_id: str, **_kwargs) -> List[Dict[str, Any]]:
        return self.ops.list_volume_backups(compartment_id=compartment_id)

    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return self.ops.get_volume_backup(backup_id=resource_id)

    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.ops.session.save_resources(rows or [], self.TABLE_NAME)


class BlockBootVolumeBackupsResource:
    TABLE_NAME = BlockStorageResourceClient.TABLE_BOOT_VOLUME_BACKUPS
    COLUMNS = ["id", "display_name", "lifecycle_state", "size_in_gbs", "boot_volume_id"]

    def __init__(self, ops: BlockStorageResourceClient):
        self.ops = ops

    def list(self, *, compartment_id: str, **_kwargs) -> List[Dict[str, Any]]:
        return self.ops.list_boot_volume_backups(compartment_id=compartment_id)

    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return self.ops.get_boot_volume_backup(backup_id=resource_id)

    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.ops.session.save_resources(rows or [], self.TABLE_NAME)
