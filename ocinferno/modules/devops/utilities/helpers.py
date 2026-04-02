from __future__ import annotations

from typing import Any, Dict, List, Optional

import oci
from ocinferno.core.utils.service_runtime import _init_client


def build_devops_client(session, region: Optional[str] = None):
    """Initialize a DevOps client with shared signer/proxy/session behavior."""
    client = _init_client(
        oci.devops.DevopsClient,
        session=session,
        service_name="DevOps",
    )
    target_region = region or getattr(session, "region", None)
    if target_region:
        try:
            client.base_client.set_region(target_region)
        except Exception:
            pass
    return client


class DevOpsProjectsResource:
    TABLE_NAME = "devops_projects"
    COLUMNS = ["id", "name", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_devops_client(session=session, region=region)

    # List projects in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_projects, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one project by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_project(project_id=resource_id).data) or {}

    # Save project rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for project rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:  # pragma: no cover - placeholder
        _ = (resource_id, out_path)
        return False


class DevOpsConnectionsResource:
    TABLE_NAME = "devops_connections"
    COLUMNS = ["id", "display_name", "connection_type", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_devops_client(session=session, region=region)

    # List connections in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_connections, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one connection by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_connection(connection_id=resource_id).data) or {}

    # Save connection rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for connection rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:  # pragma: no cover - placeholder
        _ = (resource_id, out_path)
        return False


class DevOpsRepositoriesResource:
    TABLE_NAME = "devops_repositories"
    COLUMNS = ["id", "name", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_devops_client(session=session, region=region)

    # List repositories in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_repositories, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one repository by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_repository(repository_id=resource_id).data) or {}

    # Save repository rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for repository rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:  # pragma: no cover - placeholder
        _ = (resource_id, out_path)
        return False


class DevOpsBuildPipelinesResource:
    TABLE_NAME = "devops_build_pipelines"
    COLUMNS = ["id", "display_name", "project_id", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_devops_client(session=session, region=region)

    # List build pipelines in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_build_pipelines, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one build pipeline by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_build_pipeline(build_pipeline_id=resource_id).data) or {}

    # Save build-pipeline rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for build-pipeline rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:  # pragma: no cover - placeholder
        _ = (resource_id, out_path)
        return False


class DevOpsDeployPipelinesResource:
    TABLE_NAME = "devops_deploy_pipelines"
    COLUMNS = ["id", "display_name", "lifecycle_state", "project_id"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_devops_client(session=session, region=region)

    # List projects in a compartment (used for project-scoped deploy pipeline loops).
    def list_projects(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_projects, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # List deploy pipelines for a project.
    def list(self, *, compartment_id: str, project_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(
            self.client.list_deploy_pipelines,
            compartment_id=compartment_id,
            project_id=project_id,
        )
        return oci.util.to_dict(resp.data) or []

    # Get one deploy pipeline by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_deploy_pipeline(deploy_pipeline_id=resource_id).data) or {}

    # Save deploy-pipeline rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for deploy-pipeline rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:  # pragma: no cover - placeholder
        _ = (resource_id, out_path)
        return False
