#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class DataSafeTargetDatabasesResource(OciListResource):
    CLIENT_CLS = oci.data_safe.DataSafeClient
    SERVICE_NAME = "Data Safe"
    TABLE_NAME = "data_safe_target_databases"
    LIST_METHOD = "list_target_databases"
    GET_METHOD = "get_target_database"
    GET_ID_PARAM = "target_database_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "database_type",
        "infrastructure_type",
        "associated_resource_ids",
        "lifecycle_details",
    ]


class DataSafeSecurityAssessmentsResource(OciListResource):
    CLIENT_CLS = oci.data_safe.DataSafeClient
    SERVICE_NAME = "Data Safe"
    TABLE_NAME = "data_safe_security_assessments"
    LIST_METHOD = "list_security_assessments"
    GET_METHOD = "get_security_assessment"
    GET_ID_PARAM = "security_assessment_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "type",
        "target_ids",
        "target_type",
        "is_baseline",
        "is_deviated_from_baseline",
        "statistics",
        "time_last_assessed",
    ]


class DataSafeUserAssessmentsResource(OciListResource):
    CLIENT_CLS = oci.data_safe.DataSafeClient
    SERVICE_NAME = "Data Safe"
    TABLE_NAME = "data_safe_user_assessments"
    LIST_METHOD = "list_user_assessments"
    GET_METHOD = "get_user_assessment"
    GET_ID_PARAM = "user_assessment_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "type",
        "target_ids",
        "target_type",
        "is_baseline",
        "is_deviated_from_baseline",
        "statistics",
        "time_last_assessed",
    ]


class DataSafeSensitiveDataModelsResource(OciListResource):
    CLIENT_CLS = oci.data_safe.DataSafeClient
    SERVICE_NAME = "Data Safe"
    TABLE_NAME = "data_safe_sensitive_data_models"
    LIST_METHOD = "list_sensitive_data_models"
    GET_METHOD = "get_sensitive_data_model"
    GET_ID_PARAM = "sensitive_data_model_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "target_id",
        "app_suite_name",
        "description",
        "time_updated",
    ]
