#!/usr/bin/env python3
"""process_download_cached: re-download content using data already in the DB.

Reads enumerated rows from the workspace DB and downloads their content without
re-running any live enumeration API calls. Covers every service that
``enum_all --download`` would hit:

  objectstorage    — objects in object_storage_bucket_objects
  apigateway       — API content blobs + SDK artifacts
  compute          — instance-agent command/execution merged files (pure DB)
  resourcemanager  — stack config zips + job config/state/log zips
  artifactregistry — generic artifacts
  vault            — secret bundles (re-fetched live by secret ID from DB)

Run ``enum_all`` (or the per-service module) first to populate the DB, then use
this module to recover downloads without re-enumerating.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from ocinferno.core.console import UtilityTools
from ocinferno.core.utils.download_budget import DownloadBudget
from ocinferno.core.utils.module_helpers import safe_path_component

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _root(session) -> Path:
    return session.get_workspace_output_root(mkdir=True)


def _dl_base(session, *parts: str) -> Path:
    base = _root(session) / session.OUTPUT_DIR_NAMES["downloads"]
    for p in parts:
        base = base / safe_path_component(p)
    return base


def _all_rows(session, table: str) -> list[dict]:
    rows = session.get_resource_fields(table) or []
    return [r for r in rows if isinstance(r, dict)]


# ---------------------------------------------------------------------------
# objectstorage
# ---------------------------------------------------------------------------

def _download_objectstorage(session, args, debug: bool) -> dict:
    from ocinferno.modules.objectstorage.utilities.helpers import (
        ObjectStorageObjectsResource,
        normalize_sse_c_key,
    )

    rows = _all_rows(session, "object_storage_bucket_objects")

    ns_filter = set(f.strip() for f in (getattr(args, "object_namespaces", None) or []))
    bk_filter = set(f.strip() for f in (getattr(args, "object_buckets",    None) or []))
    if ns_filter:
        rows = [r for r in rows if str(r.get("namespace")   or "") in ns_filter]
    if bk_filter:
        rows = [r for r in rows if str(r.get("bucket_name") or "") in bk_filter]

    print(f"[*] objectstorage: {len(rows):,} objects in DB")
    if not rows:
        return {"service": "objectstorage", "ok": True, "downloaded": 0, "failed": 0}

    sse_c_key_b64 = getattr(args, "sse_c_key_b64", None)
    if sse_c_key_b64:
        try:
            normalize_sse_c_key(sse_c_key_b64)
        except Exception as err:
            print(f"{UtilityTools.RED}[X] invalid --sse-c-key-b64: {err}{UtilityTools.RESET}")
            return {"service": "objectstorage", "ok": False, "error": str(err)}

    session.download_time_budget = int(getattr(args, "download_timeout", 0) or 0)
    resource = ObjectStorageObjectsResource(session=session)
    downloaded = failed = 0
    bucket_budgets: dict = {}
    total = len(rows)

    for idx, row in enumerate(rows, 1):
        namespace   = str(row.get("namespace")   or "").strip()
        bucket_name = str(row.get("bucket_name") or "").strip()
        object_name = str(row.get("name")        or "").strip()
        region      = str(row.get("region")      or getattr(session, "config_current_default_region", "") or "").strip()
        if not namespace or not bucket_name or not object_name:
            continue

        bucket_key = (region, namespace, bucket_name)
        budget = bucket_budgets.get(bucket_key)
        if budget is None:
            budget = DownloadBudget(session, label=f"bucket {bucket_name}")
            bucket_budgets[bucket_key] = budget
        if budget.exceeded():
            continue

        parts = [safe_path_component(p) for p in object_name.lstrip("/").split("/") if p]
        if not parts:
            parts = ["object.bin"]

        base = _dl_base(session, "objectstorage", namespace, bucket_name)
        if len(parts) > 1:
            base = base.joinpath(*[safe_path_component(p) for p in parts[:-1]])
        base.mkdir(parents=True, exist_ok=True)
        out_path = base / parts[-1]

        if idx % 100 == 1 or idx == total:
            print(f"    [{idx}/{total}] {bucket_name}/{object_name}", flush=True)

        ok = resource.download(
            namespace=namespace,
            bucket_name=bucket_name,
            object_name=object_name,
            out_path=out_path,
            sse_c_key_b64=sse_c_key_b64,
            region=region,
        )
        if ok:
            downloaded += 1
        else:
            failed += 1

    print(f"    done: {downloaded:,} downloaded, {failed:,} failed")
    return {"service": "objectstorage", "ok": True, "downloaded": downloaded, "failed": failed}


# ---------------------------------------------------------------------------
# apigateway
# ---------------------------------------------------------------------------

def _download_apigateway(session, args, debug: bool) -> dict:
    from ocinferno.modules.apigateway.utilities.helpers import (
        ApiGatewayApisResource,
        ApiGatewaySdksResource,
    )
    from ocinferno.core.utils.module_helpers import guess_blob_ext, write_bytes_file

    session.download_time_budget = int(getattr(args, "download_timeout", 0) or 0)
    apis_resource = ApiGatewayApisResource(session=session)
    sdks_resource = ApiGatewaySdksResource(session=session)

    api_rows = _all_rows(session, "apigw_apis")
    sdk_rows = _all_rows(session, "apigw_sdks")
    print(f"[*] apigateway: {len(api_rows):,} APIs, {len(sdk_rows):,} SDKs in DB")

    downloaded = failed = 0
    comp_fallback = getattr(session, "compartment_id", None) or "global"

    budget = DownloadBudget(session, label="API Gateway API content")
    for row in api_rows:
        if budget.exceeded():
            break
        rid = row.get("id")
        if not rid:
            continue
        comp_id = row.get("compartment_id") or comp_fallback
        try:
            blob = apis_resource.get_api_content(api_id=rid) or b""
        except Exception:
            blob = b""
        if blob:
            ext = guess_blob_ext(blob, default_ext="bin")
            out_path = session.get_download_save_path(
                service_name="api-gateway",
                filename=f"api_content.{ext}",
                compartment_id=comp_id,
                subdirs=["api-content", rid],
            )
            if write_bytes_file(out_path, blob):
                downloaded += 1
            else:
                failed += 1
        else:
            failed += 1

    budget2 = DownloadBudget(session, label="API Gateway SDK artifacts")
    for row in sdk_rows:
        if budget2.exceeded():
            break
        sid = row.get("id")
        if not sid:
            continue
        comp_id = row.get("compartment_id") or comp_fallback
        filename = sdks_resource.filename_for_sdk_artifact(row)
        out_path = session.get_download_save_path(
            service_name="api-gateway",
            filename=filename,
            compartment_id=comp_id,
            subdirs=["sdks", sid],
        )
        if sdks_resource.download(sdk_row=row, out_path=out_path):
            downloaded += 1
        else:
            failed += 1

    print(f"    done: {downloaded:,} downloaded, {failed:,} failed")
    return {"service": "apigateway", "ok": True, "downloaded": downloaded, "failed": failed}


# ---------------------------------------------------------------------------
# compute (instance-agent command merged files — pure DB, no live API)
# ---------------------------------------------------------------------------

def _download_compute(session, args, debug: bool) -> dict:
    from ocinferno.modules.core.utilities.helpers import _write_instance_agent_merged_files

    cmd_rows  = _all_rows(session, "compute_instance_agent_commands")
    exec_rows = _all_rows(session, "compute_instance_agent_command_executions")
    print(f"[*] compute: {len(cmd_rows):,} commands, {len(exec_rows):,} executions in DB")

    if not cmd_rows and not exec_rows:
        return {"service": "compute", "ok": True, "downloaded": 0, "failed": 0}

    # Group by compartment_id so merged files land in the right output path.
    comp_ids: set[str] = set()
    for r in cmd_rows + exec_rows:
        cid = str(r.get("compartment_id") or "").strip()
        if cid:
            comp_ids.add(cid)
    if not comp_ids:
        comp_ids = {str(getattr(session, "compartment_id", "") or "unknown")}

    total_files = 0
    for cid in sorted(comp_ids):
        c_cmds  = [r for r in cmd_rows  if str(r.get("compartment_id") or "") == cid]
        c_execs = [r for r in exec_rows if str(r.get("compartment_id") or "") == cid]
        result = _write_instance_agent_merged_files(
            session,
            compartment_id=cid,
            command_rows=c_cmds,
            execution_rows=c_execs,
        )
        total_files += int(result.get("files_written") or 0)

    print(f"    done: {total_files:,} merged files written")
    return {"service": "compute", "ok": True, "downloaded": total_files, "failed": 0}


# ---------------------------------------------------------------------------
# resourcemanager
# ---------------------------------------------------------------------------

def _download_resourcemanager(session, args, debug: bool) -> dict:
    from ocinferno.modules.resourcemanager.utilities.helpers import (
        ResourceManagerStacksResource,
        ResourceManagerJobsResource,
    )

    session.download_time_budget = int(getattr(args, "download_timeout", 0) or 0)
    stacks_resource = ResourceManagerStacksResource(session=session)
    jobs_resource   = ResourceManagerJobsResource(session=session)

    stack_rows = _all_rows(session, "resource_manager_stacks")
    job_rows   = _all_rows(session, "resource_manager_jobs")
    print(f"[*] resourcemanager: {len(stack_rows):,} stacks, {len(job_rows):,} jobs in DB")

    downloaded = failed = 0
    budget = DownloadBudget(session, label="Resource Manager content")

    for row in stack_rows:
        if budget.exceeded():
            break
        stack_id = str(row.get("id") or "").strip()
        if not stack_id:
            continue
        comp_id = str(row.get("compartment_id") or "").strip()
        out_path = session.get_download_save_path(
            service_name="resource-manager",
            filename="config.zip",
            compartment_id=comp_id,
            subdirs=["stacks", stack_id],
        )
        try:
            ok = stacks_resource.download(resource_id=stack_id, out_path=out_path)
        except Exception:
            ok = False
        if ok: downloaded += 1
        else:  failed += 1

    for row in job_rows:
        if budget.exceeded():
            break
        job_id  = str(row.get("id")           or "").strip()
        comp_id = str(row.get("compartment_id") or "").strip()
        if not job_id:
            continue
        for method, fname in [
            ("download",             "config.zip"),
            ("download_tf_state",    "tf.state"),
            ("download_tf_config",   "tf_config.zip"),
        ]:
            fn = getattr(jobs_resource, method, None)
            if fn is None:
                continue
            out_path = session.get_download_save_path(
                service_name="resource-manager",
                filename=fname,
                compartment_id=comp_id,
                subdirs=["jobs", job_id],
            )
            try:
                ok = fn(job_id=job_id, out_path=out_path)
            except Exception:
                ok = False
            if ok: downloaded += 1
            else:  failed += 1

    print(f"    done: {downloaded:,} downloaded, {failed:,} failed")
    return {"service": "resourcemanager", "ok": True, "downloaded": downloaded, "failed": failed}


# ---------------------------------------------------------------------------
# artifactregistry
# ---------------------------------------------------------------------------

def _download_artifactregistry(session, args, debug: bool) -> dict:
    from ocinferno.modules.artifactregistry.utilities.helpers import ArtifactRegistryResource

    session.download_time_budget = int(getattr(args, "download_timeout", 0) or 0)
    resource = ArtifactRegistryResource(session=session)
    rows = _all_rows(session, "ar_generic_artifact")
    print(f"[*] artifactregistry: {len(rows):,} artifacts in DB")
    if not rows:
        return {"service": "artifactregistry", "ok": True, "downloaded": 0, "failed": 0}

    downloaded = failed = 0
    budget = DownloadBudget(session, label="Artifact Registry content")
    comp_fallback = str(getattr(session, "compartment_id", "") or "global")

    for row in rows:
        if budget.exceeded():
            break
        artifact_id  = str(row.get("id")            or "").strip()
        repo_id      = str(row.get("repository_id") or "").strip()
        display_name = safe_path_component(str(row.get("display_name") or artifact_id))
        comp_id      = str(row.get("compartment_id") or comp_fallback).strip()
        if not artifact_id:
            continue
        out_path = session.get_download_save_path(
            service_name="artifact-registry",
            filename=f"{display_name}.bin",
            compartment_id=comp_id,
            subdirs=["artifacts", repo_id or "unknown-repo"],
        )
        try:
            ok = resource.download_by_id(artifact_id=artifact_id, out_file=out_path)
        except Exception:
            ok = False
        if ok: downloaded += 1
        else:  failed += 1

    print(f"    done: {downloaded:,} downloaded, {failed:,} failed")
    return {"service": "artifactregistry", "ok": True, "downloaded": downloaded, "failed": failed}


# ---------------------------------------------------------------------------
# vault (re-fetches secret bundle content live by secret ID from DB)
# ---------------------------------------------------------------------------

def _download_vault(session, args, debug: bool) -> dict:
    from ocinferno.modules.vault.utilities.helpers import VaultSecretsResource

    session.download_time_budget = int(getattr(args, "download_timeout", 0) or 0)
    resource = VaultSecretsResource(session=session)

    secret_rows = _all_rows(session, "vault_secret")
    print(f"[*] vault: {len(secret_rows):,} secrets in DB")
    if not secret_rows:
        return {"service": "vault", "ok": True, "downloaded": 0, "failed": 0}

    dump_dir = _dl_base(session, "vault", "secrets")
    dump_dir.mkdir(parents=True, exist_ok=True)

    secret_ids = [str(r.get("id") or "").strip() for r in secret_rows if r.get("id")]
    budget = DownloadBudget(session, label="Vault secret bundles")

    try:
        results = resource.dump(
            dump_dir=dump_dir,
            secret_ids=[s for s in secret_ids if s],
            expand_versions=False,
        )
        downloaded = len([r for r in (results or []) if r.get("saved")])
        failed = len([r for r in (results or []) if not r.get("saved")])
    except Exception as err:
        print(f"{UtilityTools.RED}[X] vault dump error: {err}{UtilityTools.RESET}")
        return {"service": "vault", "ok": False, "error": str(err)}

    print(f"    done: {downloaded:,} downloaded, {failed:,} failed")
    return {"service": "vault", "ok": True, "downloaded": downloaded, "failed": failed}


# ---------------------------------------------------------------------------
# Service registry
# ---------------------------------------------------------------------------

_SERVICES: dict[str, tuple[str, object]] = {
    "objectstorage":    ("Object Storage objects",               _download_objectstorage),
    "apigateway":       ("API Gateway content + SDK artifacts",  _download_apigateway),
    "compute":          ("Compute instance-agent command files", _download_compute),
    "resourcemanager":  ("Resource Manager stack/job files",     _download_resourcemanager),
    "artifactregistry": ("Artifact Registry generic artifacts",  _download_artifactregistry),
    "vault":            ("Vault secret bundles",                 _download_vault),
}

ALL_SERVICES = list(_SERVICES.keys())


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def run_module(user_args, session):
    parser = argparse.ArgumentParser(
        prog="process_download_cached",
        description=(
            "Re-download content from already-enumerated DB rows — no live enumeration. "
            f"Services: {', '.join(ALL_SERVICES)}"
        ),
    )
    parser.add_argument(
        "--services", "-s",
        default="all",
        help=f"Comma-separated services, or 'all' (default). Choices: {', '.join(ALL_SERVICES)}",
    )
    # Object storage extras
    parser.add_argument("--object-namespaces", action="append", default=[], dest="object_namespaces",
                        help="Restrict object storage download to these namespaces (repeatable, CSV)")
    parser.add_argument("--object-buckets", action="append", default=[], dest="object_buckets",
                        help="Restrict object storage download to these buckets (repeatable, CSV)")
    parser.add_argument("--sse-c-key-b64", default=None, dest="sse_c_key_b64",
                        help="Base64 AES-256 key for SSE-C encrypted objects")
    parser.add_argument("--download-timeout", type=int, default=0, dest="download_timeout",
                        help="Per-type wall-clock cap in seconds (0 = unlimited)")
    args = parser.parse_args(user_args)

    debug = bool(getattr(session, "individual_run_debug", False) or getattr(session, "debug", False))

    raw_services = str(args.services or "all").strip().lower()
    if raw_services == "all":
        selected = ALL_SERVICES
    else:
        selected = [s.strip() for s in raw_services.split(",") if s.strip()]
        unknown = [s for s in selected if s not in _SERVICES]
        if unknown:
            print(f"{UtilityTools.RED}[X] Unknown service(s): {', '.join(unknown)}. "
                  f"Valid: {', '.join(ALL_SERVICES)}{UtilityTools.RESET}")
            return {"ok": False, "error": f"unknown services: {unknown}"}

    out_root = _root(session) / session.OUTPUT_DIR_NAMES["downloads"]
    print(f"[*] process_download_cached: writing to {out_root}")

    results = []
    for svc in selected:
        label, fn = _SERVICES[svc]
        print(f"\n[*] {label} ...")
        try:
            result = fn(session, args, debug)
        except Exception as err:
            print(f"{UtilityTools.RED}[X] {svc}: {type(err).__name__}: {err}{UtilityTools.RESET}")
            result = {"service": svc, "ok": False, "error": str(err)}
        results.append(result)

    total_dl  = sum(r.get("downloaded", 0) for r in results)
    total_err = sum(r.get("failed",     0) for r in results)
    print(f"\n[*] done — {total_dl:,} files, {total_err:,} failed across {len(selected)} service(s)")

    return {"ok": True, "components": results}
