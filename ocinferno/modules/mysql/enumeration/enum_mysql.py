#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.mysql.utilities.helpers import MysqlDbSystemsResource

COMPONENTS = [
    Component("db_systems", MysqlDbSystemsResource, help_text="Enumerate db-systems", cache_table="mysql_db_systems"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_mysql",
        description="Enumerate MySQL resources",
    )
