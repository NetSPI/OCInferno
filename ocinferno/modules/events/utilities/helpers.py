#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class EventsRulesResource(OciListResource):
    CLIENT_CLS = oci.events.EventsClient
    SERVICE_NAME = "Events"
    TABLE_NAME = "events_rules"
    LIST_METHOD = "list_rules"
    GET_METHOD = "get_rule"
    GET_ID_PARAM = "rule_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "condition",
        "is_enabled",
        "actions",
        "description",
    ]
