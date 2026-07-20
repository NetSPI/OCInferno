#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class ResourceSchedulesResource(OciListResource):
    CLIENT_CLS = oci.resource_scheduler.ScheduleClient
    SERVICE_NAME = "ResourceScheduler"
    TABLE_NAME = "resource_schedules"
    LIST_METHOD = "list_schedules"
    GET_METHOD = "get_schedule"
    GET_ID_PARAM = "schedule_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "time_created"]
