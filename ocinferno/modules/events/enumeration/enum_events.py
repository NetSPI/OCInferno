#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.events.utilities.helpers import EventsRulesResource

COMPONENTS = [
    Component("rules", EventsRulesResource, help_text="Enumerate rules", cache_table="events_rules"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_events",
        description="Enumerate Events resources",
    )
