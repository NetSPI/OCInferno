#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.bds.utilities.helpers import (
    BdsInstancesResource,
)

COMPONENTS = [
    Component("bds_instances", BdsInstancesResource, help_text="Enumerate BDS (Hadoop/Spark) instances", cache_table="bds_instances"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_bds",
        description="Enumerate Big Data resources",
    )
