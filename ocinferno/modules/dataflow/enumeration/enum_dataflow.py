#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.dataflow.utilities.helpers import (
    DataFlowApplicationsResource,
    DataFlowPoolsResource,
    DataFlowPrivateEndpointsResource,
    DataFlowRunsResource,
    DataFlowSqlEndpointsResource,
    DataFlowWorkRequestsResource,
)

def _applications_download(session, args, resource):
    def _dl(rows):
        from ocinferno.core.utils.download_budget import DownloadBudget
        budget = DownloadBudget(session, label="dataflow application scripts")
        written = 0
        for row in rows:
            if budget.exceeded():
                break
            rid = row.get("id")
            if not rid:
                continue
            comp = row.get("compartment_id") or getattr(session, "compartment_id", None) or "unknown"
            out_dir = session.get_download_save_path(
                service_name="dataflow", filename="_",
                compartment_id=comp, subdirs=["application-script", str(rid)],
            ).parent
            try:
                written += resource.download_script(resource_id=rid, out_path_dir=str(out_dir))
            except Exception:
                continue
        return written
    return _dl


COMPONENTS = [
    Component("applications", DataFlowApplicationsResource, help_text="Enumerate Data Flow applications", cache_table="dataflow_applications",
              download_fn=_applications_download),
    Component("runs", DataFlowRunsResource, help_text="Enumerate Data Flow runs", cache_table="dataflow_runs"),
    Component("pools", DataFlowPoolsResource, help_text="Enumerate Data Flow pools", cache_table="dataflow_pools"),
    Component("private_endpoints", DataFlowPrivateEndpointsResource, help_text="Enumerate Data Flow private endpoints", cache_table="dataflow_private_endpoints"),
    Component("sql_endpoints", DataFlowSqlEndpointsResource, help_text="Enumerate Data Flow SQL endpoints", cache_table="dataflow_sql_endpoints"),
    Component("work_requests", DataFlowWorkRequestsResource, help_text="Enumerate Data Flow work requests", cache_table="dataflow_work_requests"),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_dataflow",
        description="Enumerate OCI Data Flow resources",
    )
