#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.redis.utilities.helpers import RedisClustersResource

COMPONENTS = [
    Component("redis_clusters", RedisClustersResource, help_text="Enumerate redis-clusters", cache_table="redis_clusters"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_redis",
        description="Enumerate OCI Cache (Redis) resources",
    )
