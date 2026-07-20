from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional

import oci
from ocinferno.core.resource import OciListResource
from ocinferno.core.utils.service_runtime import ResourceBase, _init_client


def build_blockchain_client(session, region: Optional[str] = None):
    """Initialize a Blockchain client with shared signer/proxy/session behavior."""
    return _init_client(
        oci.blockchain.BlockchainPlatformClient,
        session=session,
        service_name="Blockchain",
        region=region,
    )


class BlockchainPlatformsResource(OciListResource):
    CLIENT_CLS = oci.blockchain.BlockchainPlatformClient
    SERVICE_NAME = "Blockchain"
    TABLE_NAME = "blockchain_platforms"
    LIST_METHOD = "list_blockchain_platforms"
    GET_METHOD = "get_blockchain_platform"
    GET_ID_PARAM = "blockchain_platform_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "compartment_id", "time_created"]

class BlockchainPeersResource(OciListResource):
    # Nested under a blockchain platform: list_peers/get_peer are scoped by
    # blockchain_platform_id ALONE (no compartment_id), so LIST_SCOPE_KWARG remaps it.
    CLIENT_CLS = oci.blockchain.BlockchainPlatformClient
    SERVICE_NAME = "Blockchain"
    TABLE_NAME = "blockchain_peers"
    LIST_METHOD = "list_peers"
    GET_METHOD = "get_peer"
    GET_ID_PARAM = "peer_id"
    LIST_SCOPE_KWARG = "blockchain_platform_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "blockchain_platform_id", "time_created"]

class BlockchainOsnsResource(OciListResource):
    # Nested under a blockchain platform: list_osns/get_osn are scoped by
    # blockchain_platform_id ALONE (no compartment_id), so LIST_SCOPE_KWARG remaps it.
    CLIENT_CLS = oci.blockchain.BlockchainPlatformClient
    SERVICE_NAME = "Blockchain"
    TABLE_NAME = "blockchain_osns"
    LIST_METHOD = "list_osns"
    GET_METHOD = "get_osn"
    GET_ID_PARAM = "osn_id"
    LIST_SCOPE_KWARG = "blockchain_platform_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "blockchain_platform_id", "time_created"]

class BlockchainPatchesResource(OciListResource):
    # Nested under a blockchain platform, like peers/osns above; list-only (no
    # meaningful get) in this enum flow.
    CLIENT_CLS = oci.blockchain.BlockchainPlatformClient
    SERVICE_NAME = "Blockchain"
    TABLE_NAME = "blockchain_platform_patches"
    LIST_METHOD = "list_blockchain_platform_patches"
    LIST_SCOPE_KWARG = "blockchain_platform_id"
    COLUMNS = ["blockchain_platform_id", "version", "lifecycle_state", "time_released"]

    # Patch rows are list-only in this enum flow.
    def get(self, *, resource_id: str, blockchain_platform_id: str = "") -> Dict[str, Any]:
        _ = (resource_id, blockchain_platform_id)
        return {}

    # Stable hash helper for list-only patch rows.
    def record_hash(self, row: Dict[str, Any], *, prefix: str = "") -> str:
        raw = json.dumps(row or {}, sort_keys=True, default=str, separators=(",", ":"))
        return hashlib.sha1((prefix + raw).encode("utf-8", errors="ignore")).hexdigest()

    # No binary download endpoint for patch rows.

class BlockchainWorkRequestsResource(ResourceBase):
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

    # No binary download endpoint for work request rows.
