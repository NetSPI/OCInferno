#!/usr/bin/env python3
from __future__ import annotations

import argparse

from ocinferno.modules.apigateway.utilities.helpers import (
    ApiGatewayApisResource,
    ApiGatewayDeploymentsResource,
    ApiGatewayGatewaysResource,
    ApiGatewaySdksResource,
)
from ocinferno.core.console import UtilityTools
from ocinferno.core.utils.module_helpers import fill_missing_fields, guess_blob_ext, parse_csv_args, write_bytes_file
from ocinferno.core.utils.service_runtime import (
    append_cached_component_counts,
    parse_wrapper_args,
    resolve_selected_components,
)


COMPONENTS = [
    ("gateways", "gateways", "Enumerate gateways"),
    ("apis", "apis", "Enumerate APIs"),
    ("deployments", "deployments", "Enumerate deployments"),
    ("sdks", "sdks", "Enumerate SDKs"),
]

CACHE_TABLES = {
    "gateways": ("apigw_gateways", "compartment_id"),
    "apis": ("apigw_apis", "compartment_id"),
    "deployments": ("apigw_deployments", "compartment_id"),
    "sdks": None,
}


def _component_error_summary(err: Exception) -> str:
    status = getattr(err, "status", None)
    code = getattr(err, "code", None)
    msg = getattr(err, "message", None)
    if status is not None or code is not None:
        return f"status={status}, code={code}, message={msg or str(err)}"
    return f"{type(err).__name__}: {err}"


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--gateway-ids", action="append", default=[], help="Gateway OCID scope (repeatable, CSV supported)")
        parser.add_argument("--sdk-id", default="", help="SDK OCID scope")
        parser.add_argument("--api-ids", action="append", default=[], help="API OCID scope for SDK filtering (repeatable, CSV supported)")
        parser.add_argument("--curl-from-openapi", action="store_true", help="Generate curl templates from downloaded OpenAPI")
        parser.add_argument("--base-url", default="", help="Optional base URL for generated curl templates")

    return parse_wrapper_args(
        user_args=user_args,
        description="Enumerate API Gateway resources",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
        include_download=True,
    )


def run_module(user_args, session):
    args, _ = _parse_args(user_args)
    debug = bool(getattr(session, "debug", False) or getattr(session, "individual_run_debug", False))

    component_order = [key for key, _suffix, _help in COMPONENTS]
    selected = resolve_selected_components(args, component_order)

    comp_id = getattr(session, "compartment_id", None)

    results = []

    if selected.get("gateways", False):
        try:
            gateways_resource = ApiGatewayGatewaysResource(session=session)
            if not comp_id:
                raise ValueError("session.compartment_id is not set. Select a compartment first.")

            rows = [r for r in (gateways_resource.list(compartment_id=comp_id) or []) if isinstance(r, dict)]
            for row in rows:
                row.setdefault("compartment_id", comp_id)

            enriched = 0
            if args.get:
                for row in rows:
                    rid = row.get("id")
                    if not rid:
                        continue
                    meta = gateways_resource.get(resource_id=rid) or {}
                    if fill_missing_fields(row, meta):
                        enriched += 1

            if rows:
                UtilityTools.print_limited_table(rows, gateways_resource.COLUMNS)
            if args.save:
                gateways_resource.save(rows)

            results.append(
                {
                    "ok": True,
                    "gateways": len(rows),
                    "enriched": enriched,
                    "saved": bool(args.save),
                    "get": bool(args.get),
                }
            )
        except Exception as err:
            print(f"[*] enum_apigateway.gateways: skipped ({_component_error_summary(err)}).")
            results.append({"ok": False, "component": "gateways", "error": _component_error_summary(err)})

    if selected.get("apis", False):
        try:
            apis_resource = ApiGatewayApisResource(session=session)
            api_ids = parse_csv_args(args.api_ids)
            if not comp_id and not api_ids:
                raise ValueError("Need session.compartment_id unless using --api-ids")

            rows = [r for r in (apis_resource.list(compartment_id=comp_id or "", api_ids=api_ids) or []) if isinstance(r, dict)]
            for row in rows:
                if comp_id:
                    row.setdefault("compartment_id", comp_id)

            enriched = 0
            if args.get:
                for row in rows:
                    rid = row.get("id")
                    if not rid:
                        continue
                    meta = apis_resource.get(resource_id=rid) or {}
                    if fill_missing_fields(row, meta):
                        enriched += 1

            downloaded = 0
            download_bytes = 0
            downloaded_spec = 0
            download_spec_bytes = 0
            curl_templates_written = 0

            if args.download:
                comp_fallback = getattr(session, "compartment_id", None)
                for row in rows:
                    rid = row.get("id")
                    if not rid:
                        continue
                    row_comp_id = row.get("compartment_id") or comp_fallback
                    if not row_comp_id:
                        continue

                    blob = apis_resource.get_api_content(api_id=rid) or b""
                    if blob:
                        ext = guess_blob_ext(blob, default_ext="bin")
                        filename = f"api_content.{ext}"
                        out_path = session.get_download_save_path(
                            service_name="api-gateway",
                            filename=filename,
                            compartment_id=row_comp_id,
                            subdirs=["api-content", rid],
                        )
                        if write_bytes_file(out_path, blob):
                            downloaded += 1
                            download_bytes += len(blob)
                            row["api_content_summary"] = {"bytes": len(blob), "saved_as": filename}

                            if args.curl_from_openapi:
                                spec = apis_resource._parse_openapi_blob(blob)
                                if isinstance(spec, dict):
                                    script = apis_resource.build_curl_script(spec, base_url=(args.base_url or "").strip(), api_id=rid)
                                    curl_path = session.get_download_save_path(
                                        service_name="api-gateway",
                                        filename="curl_requests.sh",
                                        compartment_id=row_comp_id,
                                        subdirs=["api-content", rid],
                                    )
                                    if write_bytes_file(curl_path, script.encode("utf-8", errors="ignore")):
                                        curl_templates_written += 1
                                        row["curl_templates"] = {"saved_as": "curl_requests.sh"}

                    spec_blob = apis_resource.get_api_deployment_specification(api_id=rid) or b""
                    if spec_blob:
                        ext = guess_blob_ext(spec_blob, default_ext="json")
                        filename = f"deployment_spec.{ext}"
                        out_path = session.get_download_save_path(
                            service_name="api-gateway",
                            filename=filename,
                            compartment_id=row_comp_id,
                            subdirs=["api-spec", rid],
                        )
                        if write_bytes_file(out_path, spec_blob):
                            downloaded_spec += 1
                            download_spec_bytes += len(spec_blob)
                            row["deployment_spec_summary"] = {"bytes": len(spec_blob), "saved_as": filename}

            if rows:
                UtilityTools.print_limited_table(rows, apis_resource.COLUMNS)
            if args.save:
                apis_resource.save(rows)

            results.append(
                {
                    "ok": True,
                    "apis": len(rows),
                    "enriched": enriched,
                    "downloaded": downloaded,
                    "download_bytes": download_bytes,
                    "downloaded_spec": downloaded_spec,
                    "download_spec_bytes": download_spec_bytes,
                    "curl_templates_written": curl_templates_written,
                    "saved": bool(args.save),
                    "get": bool(args.get),
                    "download": bool(args.download),
                    "curl_from_openapi": bool(args.curl_from_openapi),
                    "api_ids": api_ids,
                }
            )
        except Exception as err:
            print(f"[*] enum_apigateway.apis: skipped ({_component_error_summary(err)}).")
            results.append({"ok": False, "component": "apis", "error": _component_error_summary(err)})

    if selected.get("deployments", False):
        try:
            deployments_resource = ApiGatewayDeploymentsResource(session=session)
            if not comp_id:
                raise ValueError("session.compartment_id is not set. Select a compartment first.")

            gateway_ids = deployments_resource.resolve_gateway_ids(args, comp_id, debug=debug)
            rows = [r for r in (deployments_resource.list(compartment_id=comp_id, gateway_ids=gateway_ids) or []) if isinstance(r, dict)]
            for row in rows:
                row.setdefault("compartment_id", comp_id)

            enriched = 0
            if args.get:
                for row in rows:
                    rid = row.get("id")
                    if not rid:
                        continue
                    meta = deployments_resource.get(resource_id=rid) or {}
                    if fill_missing_fields(row, meta):
                        enriched += 1

            if rows:
                UtilityTools.print_limited_table(rows, deployments_resource.COLUMNS)
            if args.save:
                deployments_resource.save(rows)

            results.append(
                {
                    "ok": True,
                    "deployments": len(rows),
                    "enriched": enriched,
                    "saved": bool(args.save),
                    "get": bool(args.get),
                    "gateway_ids": gateway_ids,
                }
            )
        except Exception as err:
            print(f"[*] enum_apigateway.deployments: skipped ({_component_error_summary(err)}).")
            results.append({"ok": False, "component": "deployments", "error": _component_error_summary(err)})

    if selected.get("sdks", False):
        try:
            sdks_resource = ApiGatewaySdksResource(session=session)
            sdk_id = str(getattr(args, "sdk_id", "") or "").strip()
            api_ids = [] if sdk_id else sdks_resource.resolve_sdk_api_ids(args, debug=debug)

            rows = []
            if sdk_id or api_ids:
                rows = [r for r in (sdks_resource.list(sdk_id=sdk_id, api_ids=api_ids) or []) if isinstance(r, dict)]

            enriched = 0
            if args.get:
                for row in rows:
                    rid = row.get("id")
                    if not rid:
                        continue
                    meta = sdks_resource.get(resource_id=rid) or {}
                    if fill_missing_fields(row, meta):
                        enriched += 1

            downloaded = 0
            if args.download:
                comp_fallback = getattr(session, "compartment_id", None) or "global"
                for row in rows:
                    sid = row.get("id")
                    if not sid:
                        continue
                    filename = sdks_resource.filename_for_sdk_artifact(row)
                    out_path = session.get_download_save_path(
                        service_name="api-gateway",
                        filename=filename,
                        compartment_id=(row.get("compartment_id") or comp_fallback),
                        subdirs=["sdks", sid],
                    )
                    if sdks_resource.download(sdk_row=row, out_path=out_path):
                        downloaded += 1
                        row["sdk_artifact_summary"] = {"saved_as": filename}

            if rows:
                UtilityTools.print_limited_table(rows, sdks_resource.COLUMNS)
            if args.save and rows:
                sdks_resource.save(rows)

            results.append(
                {
                    "ok": True,
                    "sdks": len(rows),
                    "api_ids": api_ids,
                    "enriched": enriched,
                    "downloaded": downloaded,
                    "saved": bool(args.save and bool(rows)),
                    "get": bool(args.get),
                    "download": bool(args.download),
                }
            )
        except Exception as err:
            print(f"[*] enum_apigateway.sdks: skipped ({_component_error_summary(err)}).")
            results.append({"ok": False, "component": "sdks", "error": _component_error_summary(err)})

    append_cached_component_counts(
        results=results,
        session=session,
        selected=selected,
        component_order=component_order,
        cache_tables=CACHE_TABLES,
    )

    return {"ok": True, "components": results}
