#!/usr/bin/env python3
"""OCI Batch (BatchComputing) resources.

Batch tasks/jobs carry user-supplied container config — environment_variables,
command, and arguments — returned in plaintext on read (no is_secret masking),
the same credential-bearing surface as Functions and Container Instances.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import oci

from ocinferno.core.resource import OciListResource
from ocinferno.core.utils.service_runtime import ResourceBase, _init_client


class BatchJobsResource(OciListResource):
    CLIENT_CLS = oci.batch.BatchComputingClient
    SERVICE_NAME = "Batch"
    TABLE_NAME = "batch_jobs"
    LIST_METHOD = "list_batch_jobs"
    GET_METHOD = "get_batch_job"
    GET_ID_PARAM = "batch_job_id"
    # environment_variables is on the full object (populated on --get).
    COLUMNS = [
        "id", "display_name", "lifecycle_state", "compartment_id",
        "batch_job_pool_id", "batch_context_id", "environment_variables",
        "priority", "time_created",
    ]


class BatchTaskEnvironmentsResource(OciListResource):
    CLIENT_CLS = oci.batch.BatchComputingClient
    SERVICE_NAME = "Batch"
    TABLE_NAME = "batch_task_environments"
    LIST_METHOD = "list_batch_task_environments"
    GET_METHOD = "get_batch_task_environment"
    GET_ID_PARAM = "batch_task_environment_id"
    COLUMNS = [
        "id", "display_name", "lifecycle_state", "compartment_id",
        "image_url", "working_directory", "security_context", "time_created",
    ]


class BatchJobPoolsResource(OciListResource):
    CLIENT_CLS = oci.batch.BatchComputingClient
    SERVICE_NAME = "Batch"
    TABLE_NAME = "batch_job_pools"
    LIST_METHOD = "list_batch_job_pools"
    GET_METHOD = "get_batch_job_pool"
    GET_ID_PARAM = "batch_job_pool_id"
    COLUMNS = [
        "id", "display_name", "lifecycle_state", "compartment_id",
        "batch_context_id", "time_created",
    ]


class BatchTasksResource(ResourceBase):
    """Batch tasks — the richest secret surface (environment_variables + command +
    arguments). Listed per compartment; each task enriched via
    get_batch_task(batch_job_id, task_name) to pull the full ComputeTask spec."""

    TABLE_NAME = "batch_tasks"
    COLUMNS = [
        "name", "job_id", "type", "lifecycle_state", "environment_variables",
        "command", "arguments", "batch_task_environment_id",
        "batch_task_profile_id", "description", "compartment_id",
    ]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = _init_client(
            oci.batch.BatchComputingClient, session=session, service_name="Batch", region=region,
        )

    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(
            self.client.list_batch_tasks, compartment_id=compartment_id,
        )
        rows = oci.util.to_dict(resp.data) or []
        out: List[Dict[str, Any]] = []
        for r in rows:
            if not isinstance(r, dict):
                continue
            job_id = r.get("job_id")
            name = r.get("name")
            # Enrich with env/command/arguments from the full task object.
            if job_id and name:
                try:
                    full = self.client.get_batch_task(batch_job_id=job_id, task_name=name)
                    data = oci.util.to_dict(full.data) or {}
                    if isinstance(data, dict):
                        r.update(data)
                except Exception:
                    pass
            r.setdefault("compartment_id", compartment_id)
            out.append(r)
        return out

    def get(self, *, resource_id: str) -> Dict[str, Any]:
        _ = resource_id
        return {}
