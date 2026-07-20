from __future__ import annotations

from typing import Any, Dict, List, Optional

import oci
from ocinferno.core.resource import OciListResource
from ocinferno.core.utils.module_helpers import write_response_stream_to_file
from ocinferno.core.utils.service_runtime import _init_client
from ocinferno.core.utils.service_runtime import ResourceBase


def build_resource_manager_client(session, region: Optional[str] = None):
    """Initialize a Resource Manager client with shared signer/proxy/session behavior."""
    return _init_client(
        oci.resource_manager.ResourceManagerClient,
        session=session,
        service_name="ResourceManager",
        region=region,
    )


def _write_blob(data: Any, out_path: str) -> bool:
    if not out_path:
        return False
    try:
        return write_response_stream_to_file(data, out_path)
    except Exception:
        return False

class ResourceManagerStacksResource(ResourceBase):
    TABLE_NAME = "resource_manager_stacks"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_resource_manager_client(session=session, region=region)

    # List stacks in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_stacks, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one stack by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_stack(stack_id=resource_id).data) or {}

    # Download Terraform config for one stack.
    def download(self, *, resource_id: str, out_path: str) -> bool:
        try:
            resp = self.client.get_stack_tf_config(stack_id=resource_id)
        except Exception:
            return False
        return _write_blob(getattr(resp, "data", None), out_path)

    # Download Terraform state for one stack.
    def download_tf_state(self, *, stack_id: str, out_path: str) -> bool:
        try:
            resp = self.client.get_stack_tf_state(stack_id=stack_id)
        except Exception:
            return False
        return _write_blob(getattr(resp, "data", None), out_path)


class ResourceManagerJobsResource(ResourceBase):
    TABLE_NAME = "resource_manager_jobs"
    COLUMNS = ["id", "display_name", "lifecycle_state", "operation", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_resource_manager_client(session=session, region=region)

    # List jobs in a compartment, optionally scoped to one stack.
    def list(self, *, compartment_id: str, stack_id: str = "") -> List[Dict[str, Any]]:
        kwargs: Dict[str, Any] = {"compartment_id": compartment_id}
        if stack_id:
            kwargs["stack_id"] = stack_id
        resp = oci.pagination.list_call_get_all_results(self.client.list_jobs, **kwargs)
        return oci.util.to_dict(resp.data) or []

    # Get one job by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_job(job_id=resource_id).data) or {}

    # Download job logs for one job.
    def download(self, *, resource_id: str, out_path: str) -> bool:
        try:
            resp = self.client.get_job_logs_content(job_id=resource_id)
        except Exception:
            return False
        return _write_blob(getattr(resp, "data", None), out_path)

    # Download detailed logs for one job.
    def download_detailed_logs(self, *, job_id: str, out_path: str) -> bool:
        try:
            resp = self.client.get_job_detailed_log_content(job_id=job_id)
        except Exception:
            return False
        return _write_blob(getattr(resp, "data", None), out_path)

    # Download Terraform config for one job.
    def download_tf_config(self, *, job_id: str, out_path: str) -> bool:
        try:
            resp = self.client.get_job_tf_config(job_id=job_id)
        except Exception:
            return False
        return _write_blob(getattr(resp, "data", None), out_path)

    # Download Terraform state for one job.
    def download_tf_state(self, *, job_id: str, out_path: str) -> bool:
        try:
            resp = self.client.get_job_tf_state(job_id=job_id)
        except Exception:
            return False
        return _write_blob(getattr(resp, "data", None), out_path)


class ResourceManagerPrivateEndpointsResource(OciListResource):
    CLIENT_CLS = oci.resource_manager.ResourceManagerClient
    SERVICE_NAME = "ResourceManager"
    TABLE_NAME = "resource_manager_private_endpoints"
    LIST_METHOD = "list_private_endpoints"
    GET_METHOD = "get_private_endpoint"
    GET_ID_PARAM = "private_endpoint_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created", "vcn_id", "subnet_id"]

class ResourceManagerConfigSourceProvidersResource(OciListResource):
    CLIENT_CLS = oci.resource_manager.ResourceManagerClient
    SERVICE_NAME = "ResourceManager"
    TABLE_NAME = "resource_manager_config_source_providers"
    LIST_METHOD = "list_configuration_source_providers"
    GET_METHOD = "get_configuration_source_provider"
    GET_ID_PARAM = "configuration_source_provider_id"
    # username/email/secret_id only appear on the full get_configuration_source_provider
    # response (list_configuration_source_providers' summary model omits them) -- run
    # with --get to populate them.
    COLUMNS = ["id", "display_name", "lifecycle_state", "config_source_provider_type", "username", "secret_id", "time_created"]


class ResourceManagerTemplatesResource(ResourceBase):
    TABLE_NAME = "resource_manager_templates"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_resource_manager_client(session=session, region=region)

    # List templates in a compartment (optional category filter is applied client-side).
    def list(self, *, compartment_id: str, template_category_id: Optional[str] = None) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_templates, compartment_id=compartment_id)
        rows = oci.util.to_dict(resp.data) or []
        if template_category_id:
            filtered = []
            for row in rows:
                if isinstance(row, dict) and row.get("template_category_id") == template_category_id:
                    filtered.append(row)
            return filtered
        return rows

    # Get one template by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_template(template_id=resource_id).data) or {}

    # Download Terraform config for one template.
    def download(self, *, resource_id: str, out_path: str) -> bool:
        try:
            resp = self.client.get_template_tf_config(template_id=resource_id)
        except Exception:
            return False
        return _write_blob(getattr(resp, "data", None), out_path)

    # Backwards-compatible alias used by enum module.
    def download_tf_config(self, *, template_id: str, out_path: str) -> bool:
        return self.download(resource_id=template_id, out_path=out_path)

    # Download template logo.
    def download_logo(self, *, template_id: str, out_path: str) -> bool:
        try:
            resp = self.client.get_template_logo(template_id=template_id)
        except Exception:
            return False
        return _write_blob(getattr(resp, "data", None), out_path)
