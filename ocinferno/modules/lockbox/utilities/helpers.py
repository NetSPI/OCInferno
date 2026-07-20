#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class LockboxLockboxesResource(OciListResource):
    CLIENT_CLS = oci.lockbox.LockboxClient
    SERVICE_NAME = "Lockbox"
    TABLE_NAME = "lockbox_lockboxes"
    LIST_METHOD = "list_lockboxes"
    GET_METHOD = "get_lockbox"
    GET_ID_PARAM = "lockbox_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "lockbox_partner",
        "resource_id",
        "approval_template_id",
        "max_access_duration",
        "partner_id",
    ]


class LockboxApprovalTemplatesResource(OciListResource):
    CLIENT_CLS = oci.lockbox.LockboxClient
    SERVICE_NAME = "Lockbox"
    TABLE_NAME = "lockbox_approval_templates"
    LIST_METHOD = "list_approval_templates"
    GET_METHOD = "get_approval_template"
    GET_ID_PARAM = "approval_template_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "approver_levels",
        "auto_approval_state",
        "time_updated",
    ]
