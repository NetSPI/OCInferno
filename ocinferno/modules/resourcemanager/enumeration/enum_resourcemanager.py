#!/usr/bin/env python3
from __future__ import annotations

import argparse

from ocinferno.core.console import UtilityTools
from ocinferno.core.utils.download_budget import DownloadBudget
from ocinferno.core.utils.module_helpers import fill_missing_fields
from ocinferno.modules.resourcemanager.utilities.helpers import (
    ResourceManagerConfigSourceProvidersResource,
    ResourceManagerJobsResource,
    ResourceManagerPrivateEndpointsResource,
    ResourceManagerStacksResource,
    ResourceManagerTemplatesResource,
)
from ocinferno.core.utils.service_runtime import (
    append_cached_component_counts,
    parse_wrapper_args,
    resolve_selected_components,
    run_standard_enum_component,
)


# Per-row artifact downloads for stacks/jobs. The Resource classes already
# implement these (download/download_tf_state/etc.) -- this just wires them
# into run_standard_enum_component's download_rows_fn hook, which stacks/jobs
# previously never received, so --download silently downloaded nothing for
# either component despite the underlying SDK calls being fully implemented.
def _download_stack_rows(rows, *, session, resource) -> int:
    budget = DownloadBudget(session, label="resource manager stacks")
    downloaded = 0
    for row in rows:
        if budget.exceeded():  # per-type --download-timeout cap: stop and move on
            break
        stack_id = row.get("id")
        if not stack_id:
            continue
        comp_id = row.get("compartment_id")
        subdirs = ["stacks", stack_id]
        tf_path = session.get_download_save_path(
            service_name="resource-manager", filename="tf_config.zip", compartment_id=comp_id, subdirs=subdirs,
        )
        if resource.download(resource_id=stack_id, out_path=tf_path):
            downloaded += 1
        state_path = session.get_download_save_path(
            service_name="resource-manager", filename="tf_state.json", compartment_id=comp_id, subdirs=subdirs,
        )
        if resource.download_tf_state(stack_id=stack_id, out_path=state_path):
            downloaded += 1
    return downloaded


def _download_job_rows(rows, *, session, resource) -> int:
    budget = DownloadBudget(session, label="resource manager jobs")
    downloaded = 0
    for row in rows:
        if budget.exceeded():
            break
        job_id = row.get("id")
        if not job_id:
            continue
        comp_id = row.get("compartment_id")
        subdirs = ["jobs", job_id]
        logs_path = session.get_download_save_path(
            service_name="resource-manager", filename="job_logs.txt", compartment_id=comp_id, subdirs=subdirs,
        )
        if resource.download(resource_id=job_id, out_path=logs_path):
            downloaded += 1
        detailed_logs_path = session.get_download_save_path(
            service_name="resource-manager", filename="detailed_logs.txt", compartment_id=comp_id, subdirs=subdirs,
        )
        if resource.download_detailed_logs(job_id=job_id, out_path=detailed_logs_path):
            downloaded += 1
        tf_path = session.get_download_save_path(
            service_name="resource-manager", filename="tf_config.zip", compartment_id=comp_id, subdirs=subdirs,
        )
        if resource.download_tf_config(job_id=job_id, out_path=tf_path):
            downloaded += 1
        state_path = session.get_download_save_path(
            service_name="resource-manager", filename="tf_state.json", compartment_id=comp_id, subdirs=subdirs,
        )
        if resource.download_tf_state(job_id=job_id, out_path=state_path):
            downloaded += 1
    return downloaded


_DOWNLOAD_ROW_FNS = {"stacks": _download_stack_rows, "jobs": _download_job_rows}


COMPONENTS = [
    ("stacks", "stacks", "Enumerate stacks"),
    ("jobs", "jobs", "Enumerate jobs"),
    ("private_endpoints", "private_endpoints", "Enumerate private-endpoints"),
    ("config_source_providers", "config_source_providers", "Enumerate config-source-providers"),
    ("templates", "templates", "Enumerate templates"),
]


CACHE_TABLES = {
    "stacks": ("resource_manager_stacks", "compartment_id"),
    "jobs": ("resource_manager_jobs", "compartment_id"),
    "templates": ("resource_manager_templates", "compartment_id"),
    "private_endpoints": ("resource_manager_private_endpoints", "compartment_id"),
    "config_source_providers": ("resource_manager_config_source_providers", "compartment_id"),
}


from ocinferno.core.utils.service_runtime import component_soft_skip_or_error


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--template-id", default="", help="Get a specific template by OCID")
        parser.add_argument("--template-category-id", default="", help="Filter templates by template category")
        parser.add_argument("--download-timeout", type=int, default=0, help="Per-download-type wall-clock cap in seconds (0 = unlimited)")

    return parse_wrapper_args(
        user_args=user_args,
        description="Enumerate ResourceManager resources",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
        include_download=True,
    )


def run_module(user_args, session):
    args, _ = _parse_args(user_args)
    debug = bool(getattr(session, "individual_run_debug", False) or getattr(session, "debug", False))

    session.download_time_budget = int(getattr(args, "download_timeout", 0) or 0)

    component_order = [key for key, _suffix, _help in COMPONENTS]
    selected = resolve_selected_components(args, component_order)

    resource_map = {
        "stacks": ResourceManagerStacksResource(session=session),
        "jobs": ResourceManagerJobsResource(session=session),
        "private_endpoints": ResourceManagerPrivateEndpointsResource(session=session),
        "config_source_providers": ResourceManagerConfigSourceProvidersResource(session=session),
        "templates": ResourceManagerTemplatesResource(session=session),
    }
    results = []
    for key, _method_suffix, _help_text in COMPONENTS:
        if not selected.get(key, False):
            continue
        try:
            if key == "templates":
                templates_resource = resource_map[key]
                template_id = str(getattr(args, "template_id", "") or "").strip()
                template_category_id = str(getattr(args, "template_category_id", "") or "").strip() or None
                compartment_id = getattr(session, "compartment_id", None)

                if not compartment_id and not template_id:
                    raise ValueError("session.compartment_id is not set (or provide --template-id)")

                if template_id:
                    row = templates_resource.get(resource_id=template_id) or {}
                    rows = [row] if row else []
                else:
                    rows = templates_resource.list(compartment_id=compartment_id, template_category_id=template_category_id) or []

                if isinstance(rows, dict):
                    rows = rows.get("items") or []
                rows = [row for row in rows if isinstance(row, dict)]

                # --get enrichment is best-effort on top of an already-successful list: a
                # permission gap on the per-template GET specifically must not discard
                # the rows already fetched.
                get_failed = 0
                if args.get:
                    for row in rows:
                        row_id = row.get("id")
                        if not row_id:
                            continue
                        try:
                            meta = templates_resource.get(resource_id=row_id) or {}
                        except Exception as get_err:
                            get_failed += 1
                            UtilityTools.dlog(
                                debug,
                                "get template failed for one row (non-fatal; row kept from list)",
                                id=row_id, err=f"{type(get_err).__name__}: {get_err}",
                            )
                            continue
                        fill_missing_fields(row, meta)
                if get_failed:
                    print(f"{UtilityTools.YELLOW}[-] enum_resourcemanager.templates: --get enrichment failed for "
                          f"{get_failed}/{len(rows)} row(s) (kept the listed rows; likely a permission gap on the "
                          f"GET operation specifically).{UtilityTools.RESET}")

                downloaded = 0
                if args.download:
                    budget = DownloadBudget(session, label="resource manager templates")
                    for row in rows:
                        if budget.exceeded():  # per-type --download-timeout cap: stop and move on
                            break
                        template_row_id = row.get("id")
                        if not template_row_id:
                            continue
                        row_compartment_id = row.get("compartment_id") or compartment_id
                        if not row_compartment_id:
                            continue

                        base_subdirs = ["template-content", template_row_id]
                        tf_path = session.get_download_save_path(
                            service_name="resource-manager",
                            filename="template_tf_config.zip",
                            compartment_id=row_compartment_id,
                            subdirs=base_subdirs,
                        )
                        if templates_resource.download_tf_config(template_id=template_row_id, out_path=tf_path):
                            downloaded += 1

                        logo_path = session.get_download_save_path(
                            service_name="resource-manager",
                            filename="template_logo",
                            compartment_id=row_compartment_id,
                            subdirs=base_subdirs,
                        )
                        if templates_resource.download_logo(template_id=template_row_id, out_path=logo_path):
                            downloaded += 1

                if rows:
                    UtilityTools.print_limited_table(rows, templates_resource.COLUMNS, title="Resourcemanager - Templates")

                templates_resource.save(rows)

                results.append(
                    {
                        "ok": True,
                        "templates": len(rows),
                        "saved": True,
                        "get": bool(args.get),
                        "download": bool(args.download),
                        "downloaded": int(downloaded),
                        "template_id": template_id,
                        "template_category_id": template_category_id or "",
                    }
                )
                continue

            resource = resource_map[key]
            download_fn = _DOWNLOAD_ROW_FNS.get(key)
            results.append(run_standard_enum_component(
                user_args=args, session=session, component_key=key,
                list_rows=lambda cid, r=resource: r.list(compartment_id=cid),
                get_row=lambda row, r=resource: r.get(resource_id=row.get("id")),
                save_rows_fn=resource.save,
                print_columns=resource.COLUMNS,
                module_name="enum_resourcemanager",
                download_rows_fn=(
                    (lambda rows, r=resource, fn=download_fn: fn(rows, session=session, resource=r))
                    if download_fn else None
                ),
            ))
        except Exception as err:
            results.append(component_soft_skip_or_error(err, component=key, module_name="enum_resourcemanager"))

    append_cached_component_counts(
        results=results,
        session=session,
        selected=selected,
        component_order=component_order,
        cache_tables=CACHE_TABLES,
    )

    return {"ok": True, "components": results}
