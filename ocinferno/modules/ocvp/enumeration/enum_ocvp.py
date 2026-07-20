#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.ocvp.utilities.helpers import (
    OcvpClustersResource,
    OcvpDatastoresResource,
    OcvpSddcsResource,
)

COMPONENTS = [
    Component("sddcs", OcvpSddcsResource, help_text="Enumerate SDDCs", cache_table="ocvp_sddcs"),
    Component("datastores", OcvpDatastoresResource, help_text="Enumerate datastores", cache_table="ocvp_datastores"),
    Component("clusters", OcvpClustersResource, help_text="Enumerate clusters", cache_table="ocvp_clusters"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_ocvp",
        description="Enumerate VMware Solution resources",
    )
