#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class GovernanceRulesRulesResource(OciListResource):
    CLIENT_CLS = oci.governance_rules_control_plane.GovernanceRuleClient
    SERVICE_NAME = "Governance Rules"
    TABLE_NAME = "governance_rules_rules"
    LIST_METHOD = "list_governance_rules"
    GET_METHOD = "get_governance_rule"
    GET_ID_PARAM = "governance_rule_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "type",
        "creation_option",
        "time_updated",
    ]


class GovernanceRulesTenancyAttachmentsResource(OciListResource):
    CLIENT_CLS = oci.governance_rules_control_plane.GovernanceRuleClient
    SERVICE_NAME = "Governance Rules"
    TABLE_NAME = "governance_rules_tenancy_attachments"
    LIST_METHOD = "list_tenancy_attachments"
    GET_METHOD = "get_tenancy_attachment"
    GET_ID_PARAM = "tenancy_attachment_id"
    COLUMNS = [
        "id",
        "lifecycle_state",
        "time_created",
        "compartment_id",
        "governance_rule_id",
        "tenancy_id",
        "time_updated",
        "time_last_attempted",
    ]
