#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.streaming.utilities.helpers import (
    StreamingStreamPoolsResource,
    StreamingStreamsResource,
)

COMPONENTS = [
    Component("streams", StreamingStreamsResource, help_text="Enumerate streams", cache_table="streaming_streams"),
    Component("stream_pools", StreamingStreamPoolsResource, help_text="Enumerate stream-pools", cache_table="streaming_stream_pools"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_streaming",
        description="Enumerate Streaming resources",
    )
