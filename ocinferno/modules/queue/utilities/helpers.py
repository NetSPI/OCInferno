#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class QueueQueuesResource(OciListResource):
    CLIENT_CLS = oci.queue.QueueAdminClient
    SERVICE_NAME = "Queue"
    TABLE_NAME = "queues"
    LIST_METHOD = "list_queues"
    GET_METHOD = "get_queue"
    GET_ID_PARAM = "queue_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "messages_endpoint",
        "retention_in_seconds",
        "visibility_in_seconds",
        "dead_letter_queue_delivery_count",
        "custom_encryption_key_id",
        "timeout_in_seconds",
    ]
