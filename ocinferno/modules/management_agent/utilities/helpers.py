#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class ManagementAgentAgentsResource(OciListResource):
    CLIENT_CLS = oci.management_agent.ManagementAgentClient
    SERVICE_NAME = "Management Agent"
    TABLE_NAME = "management_agent_agents"
    LIST_METHOD = "list_management_agents"
    GET_METHOD = "get_management_agent"
    GET_ID_PARAM = "management_agent_id"
    COLUMNS = [
        "id",
        "display_name",
        "platform_type",
        "platform_name",
        "platform_version",
        "host",
        "host_id",
        "lifecycle_state",
        "availability_status",
        "time_last_heartbeat",
        "is_agent_auto_upgradable",
        "install_type",
        "version",
        "compartment_id",
    ]


class ManagementAgentInstallKeysResource(OciListResource):
    CLIENT_CLS = oci.management_agent.ManagementAgentClient
    SERVICE_NAME = "Management Agent"
    TABLE_NAME = "management_agent_install_keys"
    LIST_METHOD = "list_management_agent_install_keys"
    GET_METHOD = "get_management_agent_install_key"
    GET_ID_PARAM = "management_agent_install_key_id"
    COLUMNS = [
        "id",
        "display_name",
        "lifecycle_state",
        "created_by_principal_id",
        "time_created",
        "time_expires",
        "allowed_key_install_count",
        "current_key_install_count",
        "is_unlimited",
        "compartment_id",
    ]
