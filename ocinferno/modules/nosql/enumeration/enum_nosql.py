#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.nosql.utilities.helpers import NosqlTablesResource

COMPONENTS = [
    # NoSQL get_table needs both the table id/name and the compartment_id.
    Component(
        "tables", NosqlTablesResource, help_text="Enumerate tables", cache_table="nosql_tables",
        get_row_fn=lambda session, args, res: (
            lambda row: res.get(resource_id=row.get("id") or row.get("name"), compartment_id=session.compartment_id)
        ),
    ),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_nosql",
        description="Enumerate NoSQL resources",
    )
