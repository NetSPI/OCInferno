#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class GenerativeAiProjectsResource(OciListResource):
    CLIENT_CLS = oci.generative_ai.GenerativeAiClient
    SERVICE_NAME = "Generative AI"
    TABLE_NAME = "generative_ai_projects"
    LIST_METHOD = "list_generative_ai_projects"
    GET_METHOD = "get_generative_ai_project"
    GET_ID_PARAM = "generative_ai_project_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "description",
        "time_updated",
    ]


class GenerativeAiEndpointsResource(OciListResource):
    CLIENT_CLS = oci.generative_ai.GenerativeAiClient
    SERVICE_NAME = "Generative AI"
    TABLE_NAME = "generative_ai_endpoints"
    LIST_METHOD = "list_endpoints"
    GET_METHOD = "get_endpoint"
    GET_ID_PARAM = "endpoint_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "model_id",
        "dedicated_ai_cluster_id",
        "generative_ai_private_endpoint_id",
        "content_moderation_config",
        "description",
    ]


class GenerativeAiDedicatedAiClustersResource(OciListResource):
    CLIENT_CLS = oci.generative_ai.GenerativeAiClient
    SERVICE_NAME = "Generative AI"
    TABLE_NAME = "generative_ai_dedicated_ai_clusters"
    LIST_METHOD = "list_dedicated_ai_clusters"
    GET_METHOD = "get_dedicated_ai_cluster"
    GET_ID_PARAM = "dedicated_ai_cluster_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "type",
        "unit_shape",
        "unit_count",
        "capacity",
        "description",
    ]


class GenerativeAiApiKeysResource(OciListResource):
    CLIENT_CLS = oci.generative_ai.GenerativeAiClient
    SERVICE_NAME = "Generative AI"
    TABLE_NAME = "generative_ai_api_keys"
    LIST_METHOD = "list_api_keys"
    GET_METHOD = "get_api_key"
    GET_ID_PARAM = "api_key_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "description",
        "time_updated",
    ]
