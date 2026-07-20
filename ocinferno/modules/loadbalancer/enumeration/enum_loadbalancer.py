#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.loadbalancer.utilities.helpers import LoadBalancersResource

COMPONENTS = [
    Component("load_balancers", LoadBalancersResource, help_text="Enumerate load balancers", cache_table="load_balancers"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_loadbalancer",
        description="Enumerate Load Balancer resources",
    )
