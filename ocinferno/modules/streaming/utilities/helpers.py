#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class StreamingStreamsResource(OciListResource):
    CLIENT_CLS = oci.streaming.StreamAdminClient
    SERVICE_NAME = "Streaming"
    TABLE_NAME = "streaming_streams"
    LIST_METHOD = "list_streams"
    GET_METHOD = "get_stream"
    GET_ID_PARAM = "stream_id"
    COLUMNS = [
        "id",
        "name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "partitions",
        "retention_in_hours",
        "messages_endpoint",
        "stream_pool_id",
    ]


class StreamingStreamPoolsResource(OciListResource):
    CLIENT_CLS = oci.streaming.StreamAdminClient
    SERVICE_NAME = "Streaming"
    TABLE_NAME = "streaming_stream_pools"
    LIST_METHOD = "list_stream_pools"
    GET_METHOD = "get_stream_pool"
    GET_ID_PARAM = "stream_pool_id"
    COLUMNS = [
        "id",
        "name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "endpoint_fqdn",
        "is_private",
        "kafka_settings",
        "custom_encryption_key",
    ]
