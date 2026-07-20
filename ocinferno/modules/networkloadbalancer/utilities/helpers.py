#!/usr/bin/env python3
from __future__ import annotations

import oci

from ocinferno.core.resource import OciListResource


class NetworkLoadBalancersResource(OciListResource):
    CLIENT_CLS = oci.network_load_balancer.NetworkLoadBalancerClient
    SERVICE_NAME = "Network Load Balancer"
    TABLE_NAME = "network_load_balancers"
    LIST_METHOD = "list_network_load_balancers"
    GET_METHOD = "get_network_load_balancer"
    GET_ID_PARAM = "network_load_balancer_id"
    COLUMNS = ["id", "display_name", "lifecycle_state", "subnet_id", "ip_addresses", "is_private"]
