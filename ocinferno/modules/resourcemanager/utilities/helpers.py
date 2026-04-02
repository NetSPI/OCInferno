from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

import oci
from ocinferno.core.utils.service_runtime import _init_client


def build_resource_manager_client(session, region: Optional[str] = None):
    """Initialize a Resource Manager client with shared signer/proxy/session behavior."""
    client = _init_client(
        oci.resource_manager.ResourceManagerClient,
        session=session,
        service_name="ResourceManager",
    )
    target_region = region or getattr(session, "region", None)
    if target_region:
        try:
            client.base_client.set_region(target_region)
        except Exception:
            pass
    return client


class ResourceManagerStacksResource:
    TABLE_NAME = "resource_manager_stacks"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_resource_manager_client(session=session, region=region)

    @staticmethod
    def _write_blob(data: Any, out_path: str) -> bool:
        if not out_path:
            return False
        try:
            blob: Any = data
            for _ in range(3):
                if blob is None:
                    break
                if hasattr(blob, "read") and callable(getattr(blob, "read")):
                    blob = blob.read()
                    break
                if isinstance(blob, (bytes, bytearray, memoryview, str)):
                    break
                if hasattr(blob, "content"):
                    content = getattr(blob, "content", None)
                    if content is not None:
                        blob = content
                        continue
                if hasattr(blob, "data"):
                    nested = getattr(blob, "data", None)
                    if nested is not None and nested is not blob:
                        blob = nested
                        continue
                raw = getattr(blob, "raw", None)
                if raw is not None and hasattr(raw, "read") and callable(getattr(raw, "read")):
                    blob = raw.read()
                break

            if isinstance(blob, memoryview):
                blob = blob.tobytes()
            elif isinstance(blob, bytearray):
                blob = bytes(blob)
            if isinstance(blob, str):
                blob = blob.encode("utf-8", errors="ignore")
            if not isinstance(blob, (bytes, bytearray)):
                blob = str(blob).encode("utf-8", errors="ignore")
            target = Path(out_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(bytes(blob))
            return True
        except Exception:
            return False

    # List stacks in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_stacks, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one stack by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_stack(stack_id=resource_id).data) or {}

    # Save stack rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # Download Terraform config for one stack.
    def download(self, *, resource_id: str, out_path: str) -> bool:
        try:
            resp = self.client.get_stack_tf_config(stack_id=resource_id)
        except Exception:
            return False
        return self._write_blob(getattr(resp, "data", None), out_path)

    # Download Terraform state for one stack.
    def download_tf_state(self, *, stack_id: str, out_path: str) -> bool:
        try:
            resp = self.client.get_stack_tf_state(stack_id=stack_id)
        except Exception:
            return False
        return self._write_blob(getattr(resp, "data", None), out_path)


class ResourceManagerJobsResource:
    TABLE_NAME = "resource_manager_jobs"
    COLUMNS = ["id", "display_name", "lifecycle_state", "operation", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_resource_manager_client(session=session, region=region)

    @staticmethod
    def _write_blob(data: Any, out_path: str) -> bool:
        if not out_path:
            return False
        try:
            blob: Any = data
            for _ in range(3):
                if blob is None:
                    break
                if hasattr(blob, "read") and callable(getattr(blob, "read")):
                    blob = blob.read()
                    break
                if isinstance(blob, (bytes, bytearray, memoryview, str)):
                    break
                if hasattr(blob, "content"):
                    content = getattr(blob, "content", None)
                    if content is not None:
                        blob = content
                        continue
                if hasattr(blob, "data"):
                    nested = getattr(blob, "data", None)
                    if nested is not None and nested is not blob:
                        blob = nested
                        continue
                raw = getattr(blob, "raw", None)
                if raw is not None and hasattr(raw, "read") and callable(getattr(raw, "read")):
                    blob = raw.read()
                break

            if isinstance(blob, memoryview):
                blob = blob.tobytes()
            elif isinstance(blob, bytearray):
                blob = bytes(blob)
            if isinstance(blob, str):
                blob = blob.encode("utf-8", errors="ignore")
            if not isinstance(blob, (bytes, bytearray)):
                blob = str(blob).encode("utf-8", errors="ignore")
            target = Path(out_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(bytes(blob))
            return True
        except Exception:
            return False

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

    # Save job rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # Download job logs for one job.
    def download(self, *, resource_id: str, out_path: str) -> bool:
        try:
            resp = self.client.get_job_logs_content(job_id=resource_id)
        except Exception:
            return False
        return self._write_blob(getattr(resp, "data", None), out_path)

    # Download detailed logs for one job.
    def download_detailed_logs(self, *, job_id: str, out_path: str) -> bool:
        try:
            resp = self.client.get_job_detailed_log_content(job_id=job_id)
        except Exception:
            return False
        return self._write_blob(getattr(resp, "data", None), out_path)

    # Download Terraform config for one job.
    def download_tf_config(self, *, job_id: str, out_path: str) -> bool:
        try:
            resp = self.client.get_job_tf_config(job_id=job_id)
        except Exception:
            return False
        return self._write_blob(getattr(resp, "data", None), out_path)

    # Download Terraform state for one job.
    def download_tf_state(self, *, job_id: str, out_path: str) -> bool:
        try:
            resp = self.client.get_job_tf_state(job_id=job_id)
        except Exception:
            return False
        return self._write_blob(getattr(resp, "data", None), out_path)


class ResourceManagerPrivateEndpointsResource:
    TABLE_NAME = "resource_manager_private_endpoints"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created", "vcn_id", "subnet_id"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_resource_manager_client(session=session, region=region)

    # List private endpoints in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_private_endpoints, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one private endpoint by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_private_endpoint(private_endpoint_id=resource_id).data) or {}

    # Save private-endpoint rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for private-endpoint rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False


class ResourceManagerConfigSourceProvidersResource:
    TABLE_NAME = "resource_manager_config_source_providers"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_resource_manager_client(session=session, region=region)

    # List config source providers in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_configuration_source_providers, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one config source provider by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        resp = self.client.get_configuration_source_provider(configuration_source_provider_id=resource_id)
        return oci.util.to_dict(resp.data) or {}

    # Save config-source-provider rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # No binary download endpoint for config-source-provider rows.
    def download(self, *, resource_id: str, out_path: str) -> bool:
        _ = (resource_id, out_path)
        return False


class ResourceManagerTemplatesResource:
    TABLE_NAME = "resource_manager_templates"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_resource_manager_client(session=session, region=region)

    @staticmethod
    def _write_blob(data: Any, out_path: str) -> bool:
        if not out_path:
            return False
        try:
            blob: Any = data
            for _ in range(3):
                if blob is None:
                    break
                if hasattr(blob, "read") and callable(getattr(blob, "read")):
                    blob = blob.read()
                    break
                if isinstance(blob, (bytes, bytearray, memoryview, str)):
                    break
                if hasattr(blob, "content"):
                    content = getattr(blob, "content", None)
                    if content is not None:
                        blob = content
                        continue
                if hasattr(blob, "data"):
                    nested = getattr(blob, "data", None)
                    if nested is not None and nested is not blob:
                        blob = nested
                        continue
                raw = getattr(blob, "raw", None)
                if raw is not None and hasattr(raw, "read") and callable(getattr(raw, "read")):
                    blob = raw.read()
                break

            if isinstance(blob, memoryview):
                blob = blob.tobytes()
            elif isinstance(blob, bytearray):
                blob = bytes(blob)
            if isinstance(blob, str):
                blob = blob.encode("utf-8", errors="ignore")
            if not isinstance(blob, (bytes, bytearray)):
                blob = str(blob).encode("utf-8", errors="ignore")
            target = Path(out_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(bytes(blob))
            return True
        except Exception:
            return False

    # List templates in a compartment (optional category filter is applied client-side).
    def list(self, *, compartment_id: str, template_category_id: Optional[str] = None) -> List[Dict[str, Any]]:
        resp = self.client.list_templates(compartment_id=compartment_id)
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

    # Save template rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)

    # Download Terraform config for one template.
    def download(self, *, resource_id: str, out_path: str) -> bool:
        try:
            resp = self.client.get_template_tf_config(template_id=resource_id)
        except Exception:
            return False
        return self._write_blob(getattr(resp, "data", None), out_path)

    # Backwards-compatible alias used by enum module.
    def download_tf_config(self, *, template_id: str, out_path: str) -> bool:
        return self.download(resource_id=template_id, out_path=out_path)

    # Download template logo.
    def download_logo(self, *, template_id: str, out_path: str) -> bool:
        try:
            resp = self.client.get_template_logo(template_id=template_id)
        except Exception:
            return False
        return self._write_blob(getattr(resp, "data", None), out_path)
