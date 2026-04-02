#!/usr/bin/env python3
from __future__ import annotations

import oci
from ocinferno.core.console import UtilityTools
from ocinferno.core.utils.module_helpers import fill_missing_fields
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
from ocinferno.core.utils.service_runtime import (
    append_cached_component_counts,
    parse_wrapper_args,
    resolve_selected_components,
)


COMPONENTS = [
    ("projects", "projects", "Enumerate projects"),
    ("notebook_sessions", "notebook_sessions", "Enumerate notebook sessions"),
    ("models", "models", "Enumerate models"),
    ("model_version_sets", "model_version_sets", "Enumerate model version sets"),
    ("model_groups", "model_groups", "Enumerate model groups"),
    ("model_deployments", "model_deployments", "Enumerate model deployments"),
    ("jobs", "jobs", "Enumerate jobs"),
    ("job_runs", "job_runs", "Enumerate job runs"),
    ("pipelines", "pipelines", "Enumerate pipelines"),
    ("pipeline_runs", "pipeline_runs", "Enumerate pipeline runs"),
    ("schedules", "schedules", "Enumerate schedules"),
    ("private_endpoints", "private_endpoints", "Enumerate Data Science private endpoints"),
    ("work_requests", "work_requests", "Enumerate work requests"),
    ("ml_applications", "ml_applications", "Enumerate ML applications"),
]


CACHE_TABLES = {
    "projects": ("data_science_projects", "compartment_id"),
    "notebook_sessions": ("data_science_notebook_sessions", "compartment_id"),
    "models": ("data_science_models", "compartment_id"),
    "model_version_sets": ("data_science_model_version_sets", "compartment_id"),
    "model_groups": ("data_science_model_groups", "compartment_id"),
    "model_deployments": ("data_science_model_deployments", "compartment_id"),
    "jobs": ("data_science_jobs", "compartment_id"),
    "job_runs": ("data_science_job_runs", "compartment_id"),
    "pipelines": ("data_science_pipelines", "compartment_id"),
    "pipeline_runs": ("data_science_pipeline_runs", "compartment_id"),
    "schedules": ("data_science_schedules", "compartment_id"),
    "private_endpoints": ("data_science_private_endpoints", "compartment_id"),
    "work_requests": ("data_science_work_requests", "compartment_id"),
    "ml_applications": ("data_science_ml_applications", "compartment_id"),
}


def _parse_args(user_args):
    return parse_wrapper_args(
        user_args,
        description="Enumerate OCI Data Science resources",
        components=COMPONENTS,
    )


def run_module(user_args, session):
    args, _ = _parse_args(user_args)
    debug = bool(getattr(session, "individual_run_debug", False) or getattr(session, "debug", False))

    component_order = [key for key, _suffix, _help in COMPONENTS]
    selected = resolve_selected_components(args, component_order)
    compartment_id = getattr(session, "compartment_id", None)
    if not compartment_id:
        raise ValueError("session.compartment_id is not set")
    resource_map = {
        "projects": DataScienceProjectsResource(session=session),
        "notebook_sessions": DataScienceNotebookSessionsResource(session=session),
        "models": DataScienceModelsResource(session=session),
        "model_version_sets": DataScienceModelVersionSetsResource(session=session),
        "model_groups": DataScienceModelGroupsResource(session=session),
        "model_deployments": DataScienceModelDeploymentsResource(session=session),
        "jobs": DataScienceJobsResource(session=session),
        "job_runs": DataScienceJobRunsResource(session=session),
        "pipelines": DataSciencePipelinesResource(session=session),
        "pipeline_runs": DataSciencePipelineRunsResource(session=session),
        "schedules": DataScienceSchedulesResource(session=session),
        "private_endpoints": DataSciencePrivateEndpointsResource(session=session),
        "work_requests": DataScienceWorkRequestsResource(session=session),
        "ml_applications": DataScienceMlApplicationsResource(session=session),
    }
    results = []
    for key, _method_suffix, _help_text in COMPONENTS:
        if not selected.get(key, False):
            continue
        resource = resource_map[key]
        try:
            rows = resource.list(compartment_id=compartment_id) or []
        except oci.exceptions.ServiceError as err:
            UtilityTools.dlog(
                True,
                f"list_{key} failed",
                status=getattr(err, "status", None),
                code=getattr(err, "code", None),
                msg=getattr(err, "message", str(err)),
            )
            results.append({"ok": False, key: 0, "saved": False, "get": bool(args.get)})
            continue

        rows = [row for row in rows if isinstance(row, dict)]
        for row in rows:
            row.setdefault("compartment_id", compartment_id)

        if args.get:
            for row in rows:
                resource_id = row.get("id")
                if not resource_id:
                    continue
                try:
                    meta = resource.get(resource_id=resource_id) or {}
                except Exception as err:
                    UtilityTools.dlog(debug, f"get_{key} failed", resource_id=resource_id, err=f"{type(err).__name__}: {err}")
                    continue
                fill_missing_fields(row, meta)

        if rows:
            UtilityTools.print_limited_table(rows, getattr(resource, "COLUMNS", []))

        if args.save:
            resource.save(rows)

        results.append({"ok": True, key: len(rows), "saved": bool(args.save), "get": bool(args.get)})

    append_cached_component_counts(
        results=results,
        session=session,
        selected=selected,
        component_order=component_order,
        cache_tables=CACHE_TABLES,
    )

    return {"ok": True, "components": results}
