from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class FunctionsAppsResource(OciListResource):
    CLIENT_CLS = oci.functions.FunctionsManagementClient
    SERVICE_NAME = "Functions"
    TABLE_NAME = "functions_apps"
    LIST_METHOD = "list_applications"
    GET_METHOD = "get_application"
    GET_ID_PARAM = "application_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]


class FunctionsFunctionsResource(OciListResource):
    # Nested under applications: list_functions is scoped by application_id ALONE
    # (no compartment_id), so LIST_SCOPE_KWARG remaps the scope arg.
    CLIENT_CLS = oci.functions.FunctionsManagementClient
    SERVICE_NAME = "Functions"
    TABLE_NAME = "functions_functions"
    LIST_METHOD = "list_functions"
    GET_METHOD = "get_function"
    GET_ID_PARAM = "function_id"
    LIST_SCOPE_KWARG = "application_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "application_id", "time_created"]
