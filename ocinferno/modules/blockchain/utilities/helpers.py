from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional

import oci
from ocinferno.core.utils.service_runtime import _init_client


def build_blockchain_client(session, region: Optional[str] = None):
    """Initialize a Blockchain client with shared signer/proxy/session behavior."""
    client = _init_client(
        oci.blockchain.BlockchainPlatformClient,
        session=session,
        service_name="Blockchain",
    )
    target_region = region or getattr(session, "region", None)
    if target_region:
        try:
            client.base_client.set_region(target_region)
        except Exception:
            pass
    return client


class BlockchainPlatformsResource:
    TABLE_NAME = "blockchain_platforms"
    COLUMNS = ["id", "display_name", "lifecycle_state", "compartment_id", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_blockchain_client(session=session, region=region)

    # List blockchain platforms in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_blockchain_platforms, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one blockchain platform by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_blockchain_platform(blockchain_platform_id=resource_id).data) or {}

    # Save platform rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for platform rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:  # pragma: no cover - placeholder
        _ = (resource_id, out_path)
        return False


class BlockchainPeersResource:
    TABLE_NAME = "blockchain_peers"
    COLUMNS = ["id", "display_name", "lifecycle_state", "blockchain_platform_id", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_blockchain_client(session=session, region=region)

    # List peers under a blockchain platform.
    def list(self, *, blockchain_platform_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_peers, blockchain_platform_id=blockchain_platform_id)
        return oci.util.to_dict(resp.data) or []

    # Get one peer under its platform.
    def get(self, *, resource_id: str, blockchain_platform_id: str) -> Dict[str, Any]:
        resp = self.client.get_peer(blockchain_platform_id=blockchain_platform_id, peer_id=resource_id)
        return oci.util.to_dict(resp.data) or {}

    # Save peer rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for peer rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:  # pragma: no cover - placeholder
        _ = (resource_id, out_path)
        return False


class BlockchainOsnsResource:
    TABLE_NAME = "blockchain_osns"
    COLUMNS = ["id", "display_name", "lifecycle_state", "blockchain_platform_id", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_blockchain_client(session=session, region=region)

    # List orderer service nodes under a blockchain platform.
    def list(self, *, blockchain_platform_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_osns, blockchain_platform_id=blockchain_platform_id)
        return oci.util.to_dict(resp.data) or []

    # Get one orderer service node under its platform.
    def get(self, *, resource_id: str, blockchain_platform_id: str) -> Dict[str, Any]:
        resp = self.client.get_osn(blockchain_platform_id=blockchain_platform_id, osn_id=resource_id)
        return oci.util.to_dict(resp.data) or {}

    # Save OSN rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for OSN rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:  # pragma: no cover - placeholder
        _ = (resource_id, out_path)
        return False


class BlockchainPatchesResource:
    TABLE_NAME = "blockchain_platform_patches"
    COLUMNS = ["blockchain_platform_id", "version", "lifecycle_state", "time_released"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_blockchain_client(session=session, region=region)

    # List available patches for one blockchain platform.
    def list(self, *, blockchain_platform_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(
            self.client.list_blockchain_platform_patches,
            blockchain_platform_id=blockchain_platform_id,
        )
        return oci.util.to_dict(resp.data) or []

    # Patch rows are list-only in this enum flow.
    def get(self, *, resource_id: str, blockchain_platform_id: str = "") -> Dict[str, Any]:
        _ = (resource_id, blockchain_platform_id)
        return {}

    # Stable hash helper for list-only patch rows.
    def record_hash(self, row: Dict[str, Any], *, prefix: str = "") -> str:
        raw = json.dumps(row or {}, sort_keys=True, default=str, separators=(",", ":"))
        return hashlib.sha1((prefix + raw).encode("utf-8", errors="ignore")).hexdigest()

    # Save patch rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for patch rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:  # pragma: no cover - placeholder
        _ = (resource_id, out_path)
        return False


class BlockchainWorkRequestsResource:
    TABLE_NAME = "blockchain_work_requests"
    COLUMNS = ["id", "operation_type", "status", "blockchain_platform_id", "time_accepted", "time_finished"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_blockchain_client(session=session, region=region)

    # List blockchain work requests by platform scope.
    def list(self, *, compartment_id: str, blockchain_platform_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(
            self.client.list_work_requests,
            compartment_id=compartment_id,
            blockchain_platform_id=blockchain_platform_id,
        )
        return oci.util.to_dict(resp.data) or []

    # Get one blockchain work request.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_work_request(work_request_id=resource_id).data) or {}

    # Save work request rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for work request rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:  # pragma: no cover - placeholder
        _ = (resource_id, out_path)
        return False
