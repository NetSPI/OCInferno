#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.core.utils.service_runtime import resource_method_download
from ocinferno.modules.containerinstances.utilities.helpers import ContainerInstancesResource


_container_configs_download = resource_method_download(
    method="download_container_configs",
    service_name="containerinstances",
    subdir="container-config",
    filename="container-config.json",
    label="container instance configs",
)


COMPONENTS = [
    Component("container_instances", ContainerInstancesResource, help_text="Enumerate container instances",
              cache_table="container_instances", download_fn=_container_configs_download),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_container_instances",
        description="Enumerate OCI Container Instances",
    )
