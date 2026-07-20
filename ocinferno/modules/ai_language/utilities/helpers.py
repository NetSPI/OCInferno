#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class AILanguageProjectsResource(OciListResource):
    CLIENT_CLS = oci.ai_language.AIServiceLanguageClient
    SERVICE_NAME = "AI Language"
    TABLE_NAME = "ai_language_projects"
    LIST_METHOD = "list_projects"
    GET_METHOD = "get_project"
    GET_ID_PARAM = "project_id"
    COLUMNS = [
        "id",
        "display_name",
        "description",
        "lifecycle_state",
        "time_created",
        "compartment_id",
    ]


class AILanguageModelsResource(OciListResource):
    CLIENT_CLS = oci.ai_language.AIServiceLanguageClient
    SERVICE_NAME = "AI Language"
    TABLE_NAME = "ai_language_models"
    LIST_METHOD = "list_models"
    GET_METHOD = "get_model"
    GET_ID_PARAM = "model_id"
    COLUMNS = [
        "id",
        "display_name",
        "description",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "project_id",
        "version",
        "model_details",
    ]


class AILanguageEndpointsResource(OciListResource):
    CLIENT_CLS = oci.ai_language.AIServiceLanguageClient
    SERVICE_NAME = "AI Language"
    TABLE_NAME = "ai_language_endpoints"
    LIST_METHOD = "list_endpoints"
    GET_METHOD = "get_endpoint"
    GET_ID_PARAM = "endpoint_id"
    COLUMNS = [
        "id",
        "display_name",
        "description",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "project_id",
        "model_id",
        "inference_units",
        "alias",
    ]
