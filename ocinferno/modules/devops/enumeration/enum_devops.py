#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, nested_list_fn, run_components
from ocinferno.core.utils.service_runtime import field_dump_download
from ocinferno.modules.devops.utilities.helpers import (
    DevOpsBuildPipelinesResource,
    DevOpsConnectionsResource,
    DevOpsDeployPipelinesResource,
    DevOpsProjectsResource,
    DevOpsRepositoriesResource,
)


def _add_extra_args(parser):
    parser.add_argument("--project-id", dest="project_id", default="",
                        help="Only enumerate deploy pipelines for this DevOps Project OCID")


COMPONENTS = [
    Component("projects", DevOpsProjectsResource,
              help_text="Enumerate projects", cache_table="devops_projects"),
    Component("connections", DevOpsConnectionsResource,
              help_text="Enumerate connections", cache_table="devops_connections"),
    Component("repositories", DevOpsRepositoriesResource,
              help_text="Enumerate repositories", cache_table="devops_repositories"),
    Component("build_pipelines", DevOpsBuildPipelinesResource,
              help_text="Enumerate build-pipelines", cache_table="devops_build_pipelines",
              download_fn=field_dump_download(
                  field="build_pipeline_parameters",
                  service_name="devops",
                  subdir="build-pipeline-params",
                  filename="parameters.json",
              )),
    Component("deploy_pipelines", DevOpsDeployPipelinesResource,
              help_text="Enumerate deploy-pipelines", cache_table="devops_deploy_pipelines",
              list_fn=nested_list_fn(
                  parent_resource_cls=DevOpsProjectsResource,
                  parent_id_field="project_id",
                  manual_parent_arg="project_id",
              ),
              download_fn=field_dump_download(
                  field="deploy_pipeline_parameters",
                  service_name="devops",
                  subdir="deploy-pipeline-params",
                  filename="parameters.json",
              )),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_devops",
        description="Enumerate DevOps resources",
        add_extra_args=_add_extra_args,
    )
