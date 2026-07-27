from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class DevOpsProjectsResource(OciListResource):
    CLIENT_CLS = oci.devops.DevopsClient
    SERVICE_NAME = "DevOps"
    TABLE_NAME = "devops_projects"
    LIST_METHOD = "list_projects"
    GET_METHOD = "get_project"
    GET_ID_PARAM = "project_id"
    COLUMNS = ["id", "name", "lifecycle_state", "time_created"]


class DevOpsConnectionsResource(OciListResource):
    CLIENT_CLS = oci.devops.DevopsClient
    SERVICE_NAME = "DevOps"
    TABLE_NAME = "devops_connections"
    LIST_METHOD = "list_connections"
    GET_METHOD = "get_connection"
    GET_ID_PARAM = "connection_id"
    COLUMNS = ["id", "display_name", "connection_type", "time_created"]


class DevOpsRepositoriesResource(OciListResource):
    CLIENT_CLS = oci.devops.DevopsClient
    SERVICE_NAME = "DevOps"
    TABLE_NAME = "devops_repositories"
    LIST_METHOD = "list_repositories"
    GET_METHOD = "get_repository"
    GET_ID_PARAM = "repository_id"
    COLUMNS = ["id", "name", "http_url", "compartment_id", "lifecycle_state", "time_created"]


class DevOpsBuildPipelinesResource(OciListResource):
    CLIENT_CLS = oci.devops.DevopsClient
    SERVICE_NAME = "DevOps"
    TABLE_NAME = "devops_build_pipelines"
    LIST_METHOD = "list_build_pipelines"
    GET_METHOD = "get_build_pipeline"
    GET_ID_PARAM = "build_pipeline_id"
    COLUMNS = ["id", "display_name", "project_id", "time_created"]


class DevOpsDeployPipelinesResource(OciListResource):
    # Nested under projects: list(compartment_id=, project_id=) fans out via
    # nested_list_fn; OciListResource forwards the extra project_id kwarg to the SDK.
    CLIENT_CLS = oci.devops.DevopsClient
    SERVICE_NAME = "DevOps"
    TABLE_NAME = "devops_deploy_pipelines"
    LIST_METHOD = "list_deploy_pipelines"
    GET_METHOD = "get_deploy_pipeline"
    GET_ID_PARAM = "deploy_pipeline_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "project_id"]
