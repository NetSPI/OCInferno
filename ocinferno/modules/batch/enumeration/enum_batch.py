#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.batch.utilities.helpers import (
    BatchJobPoolsResource,
    BatchJobsResource,
    BatchTaskEnvironmentsResource,
    BatchTasksResource,
)

COMPONENTS = [
    Component("jobs", BatchJobsResource, help_text="Enumerate batch jobs (env vars via --get)",
              cache_table="batch_jobs"),
    Component("tasks", BatchTasksResource, help_text="Enumerate batch tasks (env vars + command + arguments)",
              cache_table="batch_tasks"),
    Component("task_environments", BatchTaskEnvironmentsResource,
              help_text="Enumerate batch task environments (container image/working dir)",
              cache_table="batch_task_environments"),
    Component("job_pools", BatchJobPoolsResource, help_text="Enumerate batch job pools",
              cache_table="batch_job_pools"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_batch",
        description="Enumerate OCI Batch (jobs/tasks/environments/pools)",
    )
