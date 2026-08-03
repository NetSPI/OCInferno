#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource
from ocinferno.core.utils.module_helpers import write_response_stream_to_file


class DataScienceProjectsResource(OciListResource):
    CLIENT_CLS = oci.data_science.DataScienceClient
    SERVICE_NAME = "DataScience"
    TABLE_NAME = "data_science_projects"
    LIST_METHOD = "list_projects"
    GET_METHOD = "get_project"
    GET_ID_PARAM = "project_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]


class DataScienceNotebookSessionsResource(OciListResource):
    CLIENT_CLS = oci.data_science.DataScienceClient
    SERVICE_NAME = "DataScience"
    TABLE_NAME = "data_science_notebook_sessions"
    LIST_METHOD = "list_notebook_sessions"
    GET_METHOD = "get_notebook_session"
    GET_ID_PARAM = "notebook_session_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]


class DataScienceModelsResource(OciListResource):
    CLIENT_CLS = oci.data_science.DataScienceClient
    SERVICE_NAME = "DataScience"
    TABLE_NAME = "data_science_models"
    LIST_METHOD = "list_models"
    GET_METHOD = "get_model"
    GET_ID_PARAM = "model_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]

    def download_artifact(self, *, resource_id, out_path) -> bool:
        """Export the developer-supplied model artifact (code/model binary) bytes."""
        resp = self.client.get_model_artifact_content(model_id=resource_id)
        return write_response_stream_to_file(getattr(resp, "data", None), out_path)


class DataScienceModelVersionSetsResource(OciListResource):
    CLIENT_CLS = oci.data_science.DataScienceClient
    SERVICE_NAME = "DataScience"
    TABLE_NAME = "data_science_model_version_sets"
    LIST_METHOD = "list_model_version_sets"
    GET_METHOD = "get_model_version_set"
    GET_ID_PARAM = "model_version_set_id"
    # ModelVersionSetSummary uses 'name', not 'display_name'.
    COLUMNS = ["id", "name", "lifecycle_state", "time_created"]


class DataScienceModelGroupsResource(OciListResource):
    CLIENT_CLS = oci.data_science.DataScienceClient
    SERVICE_NAME = "DataScience"
    TABLE_NAME = "data_science_model_groups"
    LIST_METHOD = "list_model_groups"
    GET_METHOD = "get_model_group"
    GET_ID_PARAM = "model_group_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]


class DataScienceModelDeploymentsResource(OciListResource):
    CLIENT_CLS = oci.data_science.DataScienceClient
    SERVICE_NAME = "DataScience"
    TABLE_NAME = "data_science_model_deployments"
    LIST_METHOD = "list_model_deployments"
    GET_METHOD = "get_model_deployment"
    GET_ID_PARAM = "model_deployment_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]


class DataScienceJobsResource(OciListResource):
    CLIENT_CLS = oci.data_science.DataScienceClient
    SERVICE_NAME = "DataScience"
    TABLE_NAME = "data_science_jobs"
    LIST_METHOD = "list_jobs"
    GET_METHOD = "get_job"
    GET_ID_PARAM = "job_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]

    def download_artifact(self, *, resource_id, out_path) -> bool:
        """Export the developer-supplied job artifact (code/script bundle) bytes."""
        resp = self.client.get_job_artifact_content(job_id=resource_id)
        return write_response_stream_to_file(getattr(resp, "data", None), out_path)


class DataScienceJobRunsResource(OciListResource):
    CLIENT_CLS = oci.data_science.DataScienceClient
    SERVICE_NAME = "DataScience"
    TABLE_NAME = "data_science_job_runs"
    LIST_METHOD = "list_job_runs"
    GET_METHOD = "get_job_run"
    GET_ID_PARAM = "job_run_id"
    # JobRunSummary has no 'time_created'; use 'time_accepted' instead.
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_accepted"]


class DataSciencePipelinesResource(OciListResource):
    CLIENT_CLS = oci.data_science.DataScienceClient
    SERVICE_NAME = "DataScience"
    TABLE_NAME = "data_science_pipelines"
    LIST_METHOD = "list_pipelines"
    GET_METHOD = "get_pipeline"
    GET_ID_PARAM = "pipeline_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]


class DataSciencePipelineRunsResource(OciListResource):
    CLIENT_CLS = oci.data_science.DataScienceClient
    SERVICE_NAME = "DataScience"
    TABLE_NAME = "data_science_pipeline_runs"
    LIST_METHOD = "list_pipeline_runs"
    GET_METHOD = "get_pipeline_run"
    GET_ID_PARAM = "pipeline_run_id"
    # PipelineRunSummary has no 'time_created'; use 'time_accepted' instead.
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_accepted"]


class DataScienceSchedulesResource(OciListResource):
    CLIENT_CLS = oci.data_science.DataScienceClient
    SERVICE_NAME = "DataScience"
    TABLE_NAME = "data_science_schedules"
    LIST_METHOD = "list_schedules"
    GET_METHOD = "get_schedule"
    GET_ID_PARAM = "schedule_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]


class DataSciencePrivateEndpointsResource(OciListResource):
    CLIENT_CLS = oci.data_science.DataScienceClient
    SERVICE_NAME = "DataScience"
    TABLE_NAME = "data_science_private_endpoints"
    LIST_METHOD = "list_data_science_private_endpoints"
    GET_METHOD = "get_data_science_private_endpoint"
    GET_ID_PARAM = "data_science_private_endpoint_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]


class DataScienceWorkRequestsResource(OciListResource):
    CLIENT_CLS = oci.data_science.DataScienceClient
    SERVICE_NAME = "DataScience"
    TABLE_NAME = "data_science_work_requests"
    LIST_METHOD = "list_work_requests"
    GET_METHOD = "get_work_request"
    GET_ID_PARAM = "work_request_id"
    COLUMNS = ["id", "operation_type", "status", "time_accepted", "time_finished"]


class DataScienceMlApplicationsResource(OciListResource):
    CLIENT_CLS = oci.data_science.DataScienceClient
    SERVICE_NAME = "DataScience"
    TABLE_NAME = "data_science_ml_applications"
    LIST_METHOD = "list_ml_applications"
    GET_METHOD = "get_ml_application"
    GET_ID_PARAM = "ml_application_id"
    # MlApplicationSummary uses 'name', not 'display_name'.
    COLUMNS = ["id", "name", "lifecycle_state", "time_created"]
