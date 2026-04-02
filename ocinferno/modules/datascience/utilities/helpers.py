from __future__ import annotations

from typing import Any, Dict, List, Optional

import oci
from ocinferno.core.utils.service_runtime import _init_client


def build_data_science_client(session, region: Optional[str] = None):
    """Initialize a Data Science client with shared signer/proxy/session behavior."""
    client = _init_client(
        oci.data_science.DataScienceClient,
        session=session,
        service_name="DataScience",
    )
    target_region = region or getattr(session, "region", None)
    if target_region:
        try:
            client.base_client.set_region(target_region)
        except Exception:
            pass
    return client


class DataScienceProjectsResource:
    TABLE_NAME = "data_science_projects"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_data_science_client(session=session, region=region)

    # List projects in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_projects, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get a project by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_project(project_id=resource_id).data) or {}

    # Save project rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)


class DataScienceNotebookSessionsResource:
    TABLE_NAME = "data_science_notebook_sessions"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_data_science_client(session=session, region=region)

    # List notebook sessions in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_notebook_sessions, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get a notebook session by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_notebook_session(notebook_session_id=resource_id).data) or {}

    # Save notebook session rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)


class DataScienceModelsResource:
    TABLE_NAME = "data_science_models"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_data_science_client(session=session, region=region)

    # List models in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_models, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get a model by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_model(model_id=resource_id).data) or {}

    # Save model rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)


class DataScienceModelVersionSetsResource:
    TABLE_NAME = "data_science_model_version_sets"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_data_science_client(session=session, region=region)

    # List model version sets in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_model_version_sets, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get a model version set by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_model_version_set(model_version_set_id=resource_id).data) or {}

    # Save model version set rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)


class DataScienceModelGroupsResource:
    TABLE_NAME = "data_science_model_groups"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_data_science_client(session=session, region=region)

    # List model groups in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_model_groups, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get a model group by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_model_group(model_group_id=resource_id).data) or {}

    # Save model group rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)


class DataScienceModelDeploymentsResource:
    TABLE_NAME = "data_science_model_deployments"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_data_science_client(session=session, region=region)

    # List model deployments in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_model_deployments, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get a model deployment by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_model_deployment(model_deployment_id=resource_id).data) or {}

    # Save model deployment rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)


class DataScienceJobsResource:
    TABLE_NAME = "data_science_jobs"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_data_science_client(session=session, region=region)

    # List jobs in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_jobs, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get a job by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_job(job_id=resource_id).data) or {}

    # Save job rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)


class DataScienceJobRunsResource:
    TABLE_NAME = "data_science_job_runs"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_data_science_client(session=session, region=region)

    # List job runs in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_job_runs, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get a job run by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_job_run(job_run_id=resource_id).data) or {}

    # Save job run rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)


class DataSciencePipelinesResource:
    TABLE_NAME = "data_science_pipelines"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_data_science_client(session=session, region=region)

    # List pipelines in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_pipelines, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get a pipeline by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_pipeline(pipeline_id=resource_id).data) or {}

    # Save pipeline rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)


class DataSciencePipelineRunsResource:
    TABLE_NAME = "data_science_pipeline_runs"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_data_science_client(session=session, region=region)

    # List pipeline runs in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_pipeline_runs, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get a pipeline run by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_pipeline_run(pipeline_run_id=resource_id).data) or {}

    # Save pipeline run rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)


class DataScienceSchedulesResource:
    TABLE_NAME = "data_science_schedules"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_data_science_client(session=session, region=region)

    # List schedules in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_schedules, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get a schedule by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_schedule(schedule_id=resource_id).data) or {}

    # Save schedule rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)


class DataSciencePrivateEndpointsResource:
    TABLE_NAME = "data_science_private_endpoints"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_data_science_client(session=session, region=region)

    # List private endpoints in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(
            self.client.list_data_science_private_endpoints,
            compartment_id=compartment_id,
        )
        return oci.util.to_dict(resp.data) or []

    # Get one private endpoint by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_data_science_private_endpoint(data_science_private_endpoint_id=resource_id).data) or {}

    # Save private endpoint rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)


class DataScienceWorkRequestsResource:
    TABLE_NAME = "data_science_work_requests"
    COLUMNS = ["id", "operation_type", "status", "time_accepted", "time_finished"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_data_science_client(session=session, region=region)

    # List work requests in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_work_requests, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one work request by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_work_request(work_request_id=resource_id).data) or {}

    # Save work request rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)


class DataScienceMlApplicationsResource:
    TABLE_NAME = "data_science_ml_applications"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]

    def __init__(self, session, region: Optional[str] = None):
        self.session = session
        self.client = build_data_science_client(session=session, region=region)

    # List ML applications in a compartment.
    def list(self, *, compartment_id: str) -> List[Dict[str, Any]]:
        resp = oci.pagination.list_call_get_all_results(self.client.list_ml_applications, compartment_id=compartment_id)
        return oci.util.to_dict(resp.data) or []

    # Get one ML application by OCID.
    def get(self, *, resource_id: str) -> Dict[str, Any]:
        return oci.util.to_dict(self.client.get_ml_application(ml_application_id=resource_id).data) or {}

    # Save ML application rows.
    def save(self, rows: List[Dict[str, Any]]) -> None:
        self.session.save_resources(rows or [], self.TABLE_NAME)
