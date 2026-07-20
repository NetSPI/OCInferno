#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.queue.utilities.helpers import QueueQueuesResource

COMPONENTS = [
    Component("queues", QueueQueuesResource, help_text="Enumerate queues", cache_table="queues"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_queue",
        description="Enumerate Queue resources",
    )
