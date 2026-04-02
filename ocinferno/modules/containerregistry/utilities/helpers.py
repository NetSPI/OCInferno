from __future__ import annotations

from typing import Any, Dict, List, Optional

import oci
from ocinferno.core.utils.service_runtime import _init_client


def build_container_registry_client(session, region: Optional[str] = None):
    """Build a configured OCI Artifacts client for container registry resources."""
    client = _init_client(
        oci.artifacts.ArtifactsClient,
        session=session,
        service_name="Artifacts",
    )
    target_region = region or getattr(session, "region", None)
    if target_region:
        try:
            client.base_client.set_region(target_region)
        except Exception:
            pass
    return client


class ContainerRegistryRepositoriesResource:
    TABLE_NAME = "cr_repositories"
    COLUMNS = ["id", "display_name", "is_public", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_container_registry_client(session=session, region=region)

    # List repositories for a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(
            self.client.list_container_repositories,
            compartment_id=compartment_id,
        )
        return oci.util.to_dict(resp.data) or []

    # Get one repository by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_container_repository(repository_id=resource_id).data) or {}

    # Save repository rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)


class ContainerRegistryImagesResource:
    TABLE_NAME = "cr_images"
    COLUMNS = ["id", "display_name", "version", "digest", "lifecycle_state", "time_created", "repository_id"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_container_registry_client(session=session, region=region)

    # List repositories for image fan-out loops.
    def list_repositories(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(
            self.client.list_container_repositories,
            compartment_id=compartment_id,
        )
        return oci.util.to_dict(resp.data) or []

    # List images in a repository.
    def list(self, *, compartment_id: str, repository_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(
            self.client.list_container_images,
            compartment_id=compartment_id,
            repository_id=repository_id,
        )
        return oci.util.to_dict(resp.data) or []

    # Get one image by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_container_image(image_id=resource_id).data) or {}

    # Save image rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)
