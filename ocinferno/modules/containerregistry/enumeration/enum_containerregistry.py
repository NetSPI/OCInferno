#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, nested_list_fn, run_components
from ocinferno.modules.containerregistry.utilities.helpers import (
    ContainerRegistryImagesResource,
    ContainerRegistryRepositoriesResource,
)


def _add_extra_args(parser):
    parser.add_argument("--repo-id", default="", help="Only enumerate images in this container repository OCID")


COMPONENTS = [
    Component("repositories", ContainerRegistryRepositoriesResource,
              help_text="Enumerate container repositories", cache_table="cr_repositories"),
    Component("images", ContainerRegistryImagesResource,
              help_text="Enumerate container images", cache_table="cr_images",
              list_fn=nested_list_fn(
                  parent_resource_cls=ContainerRegistryRepositoriesResource,
                  parent_id_field="repository_id",
                  manual_parent_arg="repo_id",
              )),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_containerregistry",
        description="Enumerate Container Registry resources",
        add_extra_args=_add_extra_args,
    )
