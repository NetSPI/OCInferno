#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.core.utils.service_runtime import resource_method_download
from ocinferno.modules.datascience.utilities.helpers import (
    DataScienceJobRunsResource,
    DataScienceJobsResource,
    DataScienceMlApplicationsResource,
    DataScienceModelDeploymentsResource,
    DataScienceModelGroupsResource,
    DataScienceModelsResource,
    DataScienceModelVersionSetsResource,
    DataScienceNotebookSessionsResource,
    DataSciencePipelineRunsResource,
    DataSciencePipelinesResource,
    DataSciencePrivateEndpointsResource,
    DataScienceProjectsResource,
    DataScienceSchedulesResource,
    DataScienceWorkRequestsResource,
)

_artifact_download = resource_method_download(
    method="download_artifact",
    service_name="datascience",
    subdir="artifacts",
    filename="artifact.zip",
    label="data science artifacts",
)


COMPONENTS = [
    Component("projects", DataScienceProjectsResource, help_text="Enumerate projects", cache_table="data_science_projects"),
    Component("notebook_sessions", DataScienceNotebookSessionsResource, help_text="Enumerate notebook sessions", cache_table="data_science_notebook_sessions"),
    Component("models", DataScienceModelsResource, help_text="Enumerate models", cache_table="data_science_models", download_fn=_artifact_download),
    Component("model_version_sets", DataScienceModelVersionSetsResource, help_text="Enumerate model version sets", cache_table="data_science_model_version_sets"),
    Component("model_groups", DataScienceModelGroupsResource, help_text="Enumerate model groups", cache_table="data_science_model_groups"),
    Component("model_deployments", DataScienceModelDeploymentsResource, help_text="Enumerate model deployments", cache_table="data_science_model_deployments"),
    Component("jobs", DataScienceJobsResource, help_text="Enumerate jobs", cache_table="data_science_jobs", download_fn=_artifact_download),
    Component("job_runs", DataScienceJobRunsResource, help_text="Enumerate job runs", cache_table="data_science_job_runs"),
    Component("pipelines", DataSciencePipelinesResource, help_text="Enumerate pipelines", cache_table="data_science_pipelines"),
    Component("pipeline_runs", DataSciencePipelineRunsResource, help_text="Enumerate pipeline runs", cache_table="data_science_pipeline_runs"),
    Component("schedules", DataScienceSchedulesResource, help_text="Enumerate schedules", cache_table="data_science_schedules"),
    Component("private_endpoints", DataSciencePrivateEndpointsResource, help_text="Enumerate Data Science private endpoints", cache_table="data_science_private_endpoints"),
    Component("work_requests", DataScienceWorkRequestsResource, help_text="Enumerate work requests", cache_table="data_science_work_requests"),
    Component("ml_applications", DataScienceMlApplicationsResource, help_text="Enumerate ML applications", cache_table="data_science_ml_applications"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_datascience",
        description="Enumerate OCI Data Science resources",
    )
