#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.lockbox.utilities.helpers import (
    LockboxApprovalTemplatesResource,
    LockboxLockboxesResource,
)

COMPONENTS = [
    Component("lockboxes", LockboxLockboxesResource, help_text="Enumerate lockboxes", cache_table="lockbox_lockboxes"),
    Component("approval_templates", LockboxApprovalTemplatesResource, help_text="Enumerate approval-templates", cache_table="lockbox_approval_templates"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_lockbox",
        description="Enumerate Lockbox resources",
    )
