#!/usr/bin/env python3
from __future__ import annotations

import os
from typing import Optional, Tuple

import oci

from ocinferno.core.resource import OciListResource
from ocinferno.core.utils.module_helpers import write_response_stream_to_file
from ocinferno.core.utils.service_runtime import _init_client


def _parse_oci_uri(uri: str) -> Optional[Tuple[str, str, str]]:
    """Parse an OCI HDFS-connector URI into (namespace, bucket, object_name).

    Data Flow ``file_uri``/``archive_uri`` use the Object Storage URI form
    ``oci://<bucket>@<namespace>/<object-path>`` (see the OCI HDFS connector
    URI format). Returns ``None`` if the string is not that shape.
    """
    if not uri or not isinstance(uri, str) or not uri.startswith("oci://"):
        return None
    rest = uri[len("oci://"):]
    if "/" not in rest:
        return None
    authority, object_name = rest.split("/", 1)
    if "@" not in authority or not object_name:
        return None
    bucket, namespace = authority.split("@", 1)
    if not bucket or not namespace:
        return None
    return namespace, bucket, object_name


class DataFlowApplicationsResource(OciListResource):
    CLIENT_CLS = oci.data_flow.DataFlowClient
    SERVICE_NAME = "DataFlow"
    TABLE_NAME = "dataflow_applications"
    LIST_METHOD = "list_applications"
    GET_METHOD = "get_application"
    GET_ID_PARAM = "application_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]

    def download_script(self, *, resource_id: str, out_path_dir: str) -> int:
        """Export an application's developer-supplied Spark/PySpark script + archive.

        Fetches the application, resolves its ``file_uri`` (the driver script) and
        ``archive_uri`` (dependency bundle, if any) from their Object Storage
        ``oci://<bucket>@<namespace>/<object>`` URIs, downloads each object, and writes
        it to a file named after the object basename under ``out_path_dir``. Returns the
        number of files successfully written (0-2).
        """
        if not resource_id:
            return 0
        try:
            app = self.get(resource_id=resource_id) or {}
        except Exception:
            return 0
        if not isinstance(app, dict):
            return 0

        os_client = _init_client(
            oci.object_storage.ObjectStorageClient,
            session=self.session,
            service_name="data-flow",
        )

        written = 0
        for uri in (app.get("file_uri"), app.get("archive_uri")):
            parsed = _parse_oci_uri(uri)
            if not parsed:
                continue
            namespace, bucket, object_name = parsed
            basename = object_name.rsplit("/", 1)[-1] or "object"
            try:
                resp = os_client.get_object(
                    namespace_name=namespace, bucket_name=bucket, object_name=object_name,
                )
                out_path = os.path.join(out_path_dir, basename)
                if write_response_stream_to_file(getattr(resp, "data", None), out_path):
                    written += 1
            except Exception:
                continue
        return written


class DataFlowRunsResource(OciListResource):
    CLIENT_CLS = oci.data_flow.DataFlowClient
    SERVICE_NAME = "DataFlow"
    TABLE_NAME = "dataflow_runs"
    LIST_METHOD = "list_runs"
    GET_METHOD = "get_run"
    GET_ID_PARAM = "run_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]


class DataFlowPoolsResource(OciListResource):
    CLIENT_CLS = oci.data_flow.DataFlowClient
    SERVICE_NAME = "DataFlow"
    TABLE_NAME = "dataflow_pools"
    LIST_METHOD = "list_pools"
    GET_METHOD = "get_pool"
    GET_ID_PARAM = "pool_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]


class DataFlowPrivateEndpointsResource(OciListResource):
    CLIENT_CLS = oci.data_flow.DataFlowClient
    SERVICE_NAME = "DataFlow"
    TABLE_NAME = "dataflow_private_endpoints"
    LIST_METHOD = "list_private_endpoints"
    GET_METHOD = "get_private_endpoint"
    GET_ID_PARAM = "private_endpoint_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]


class DataFlowSqlEndpointsResource(OciListResource):
    CLIENT_CLS = oci.data_flow.DataFlowClient
    SERVICE_NAME = "DataFlow"
    TABLE_NAME = "dataflow_sql_endpoints"
    LIST_METHOD = "list_sql_endpoints"
    GET_METHOD = "get_sql_endpoint"
    GET_ID_PARAM = "sql_endpoint_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]


class DataFlowWorkRequestsResource(OciListResource):
    CLIENT_CLS = oci.data_flow.DataFlowClient
    SERVICE_NAME = "DataFlow"
    TABLE_NAME = "dataflow_work_requests"
    LIST_METHOD = "list_work_requests"
    GET_METHOD = "get_work_request"
    GET_ID_PARAM = "work_request_id"
    COLUMNS = ["id", "operation_type", "status", "time_accepted", "time_finished"]
