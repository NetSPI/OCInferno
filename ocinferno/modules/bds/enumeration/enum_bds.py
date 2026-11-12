#!/usr/bin/env python3
from __future__ import annotations

from ocinferno.core.utils.enum_framework import Component, run_components
from ocinferno.modules.bds.utilities.helpers import (
    BdsInstancesResource,
)


def _bootstrap_download(session, args, resource):
    """Download each cluster's bootstrap script content (user-supplied node-init code
    that may carry secrets) from its bootstrap_script_url. Populated on --get."""
    def _dl(rows):
        from ocinferno.core.utils.download_budget import DownloadBudget
        from ocinferno.core.utils.module_helpers import download_url_to_file
        budget = DownloadBudget(session, label="BDS bootstrap")
        written = 0
        for row in rows:
            if budget.exceeded():
                break
            url = str(row.get("bootstrap_script_url") or "").strip()
            rid = row.get("id")
            if not url or not rid:
                continue
            comp_id = row.get("compartment_id") or getattr(session, "compartment_id", None) or "unknown"
            try:
                path = session.get_download_save_path(
                    service_name="BigDataService", filename="bootstrap_script.sh",
                    compartment_id=comp_id, subdirs=["bootstrap", str(rid)],
                )
                if download_url_to_file(url, str(path)):
                    written += 1
            except Exception:
                continue
        return written
    return _dl


COMPONENTS = [
    Component("bds_instances", BdsInstancesResource, help_text="Enumerate BDS (Hadoop/Spark) instances",
              cache_table="bds_instances", download_fn=_bootstrap_download),
]


def run_module(user_args, session):
    return run_components(
        user_args, session, COMPONENTS,
        module_name="enum_bds",
        description="Enumerate Big Data resources",
    )
