#!/usr/bin/env python3
"""process_download_cached: re-download content using data already in the DB.

Reads enumerated rows from the workspace DB and downloads their content without
re-running any live list/enumeration API calls. Accepts the same
``--download`` / ``--not-downloads`` token system as ``enum_all`` — same
categories, same individual tokens, same composition rules.

  --download                   # everything
  --download content           # heavy byte dumps (objects, vault, artifacts, ...)
  --download metadata          # light config/history (compute, functions, devops, ...)
  --download buckets           # single token
  --download content --not-downloads vault_secrets

Run ``enum_all`` (or the per-service module) first to populate the DB, then use
this module to recover downloads without re-enumerating.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Callable

from ocinferno.core.console import UtilityTools
from ocinferno.core.utils.download_budget import DownloadBudget
from ocinferno.core.utils.module_helpers import safe_path_component
from ocinferno.modules.everything.enumeration.enum_all import (
    DOWNLOAD_TOKEN_ALIASES,
    DOWNLOAD_TOKEN_CATEGORIES,
    DOWNLOAD_TOKEN_EXCLUSION_EXPANSIONS,
)

# ---------------------------------------------------------------------------
# Token resolution (mirrors enum_all logic)
# ---------------------------------------------------------------------------

_ALL_TOKENS: frozenset[str] = frozenset(
    t for cats in DOWNLOAD_TOKEN_CATEGORIES.values() for t in cats
)


def _resolve_token_set(raw_values: list[str] | None) -> frozenset[str]:
    if raw_values is None:
        return frozenset()
    tokens: set[str] = set()
    for item in raw_values:
        for part in item.replace(",", " ").split():
            part = part.strip().lower()
            if not part:
                continue
            if part == "all":
                tokens.update(_ALL_TOKENS)
            elif part in DOWNLOAD_TOKEN_CATEGORIES:
                tokens.update(DOWNLOAD_TOKEN_CATEGORIES[part])
            elif part in DOWNLOAD_TOKEN_ALIASES:
                tokens.add(DOWNLOAD_TOKEN_ALIASES[part])
            else:
                tokens.add(part)
    return frozenset(tokens)


def _active_tokens(download_raw, not_download_raw) -> frozenset[str]:
    if download_raw is None and not_download_raw is None:
        return frozenset()
    wanted = _resolve_token_set(download_raw) if download_raw else _ALL_TOKENS

    excluded: set[str] = set()
    for tok in _resolve_token_set(not_download_raw):
        expansion = DOWNLOAD_TOKEN_EXCLUSION_EXPANSIONS.get(tok)
        excluded.update(expansion if expansion else {tok})

    return frozenset(wanted - excluded)


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


def _field_dump(session, row: dict, *, field: str, service_name: str,
                subdir: str, filename: str,
                resource=None) -> bool:
    """Write a field from a DB row to disk.  If the field is missing and a
    resource instance is supplied, falls back to a live resource.get() call —
    matching field_dump_download(get_if_missing=True) behaviour."""
    rid = str(row.get("id") or "").strip()
    comp_id = str(row.get("compartment_id") or "").strip()
    if not rid:
        return False
    value = row.get(field)
    if value in (None, "", {}, []) and resource is not None:
        try:
            meta = resource.get(resource_id=rid) or {}
            value = meta.get(field) if isinstance(meta, dict) else None
        except Exception:
            value = None
    if value in (None, "", {}, []):
        return False
    out_path = session.get_download_save_path(
        service_name=service_name,
        filename=filename,
        compartment_id=comp_id,
        subdirs=[subdir, rid],
    )
    try:
        payload = (
            json.dumps(value, indent=2, default=str).encode()
            if isinstance(value, (dict, list))
            else str(value).encode()
        )
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        Path(out_path).write_bytes(payload)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# objectstorage  (tokens: buckets / objects / blobs / object_storage)
# ---------------------------------------------------------------------------

def _do_objectstorage(session, args, tokens: frozenset[str]) -> dict:
    from ocinferno.modules.objectstorage.utilities.helpers import ObjectStorageObjectsResource

    rows = _all_rows(session, "object_storage_bucket_objects")
    print(f"[*] objectstorage: {len(rows):,} objects in DB")
    if not rows:
        return {"service": "objectstorage", "downloaded": 0, "failed": 0}

    session.download_time_budget = int(getattr(args, "download_timeout", 0) or 0)
    resource = ObjectStorageObjectsResource(session=session)
    downloaded = failed = 0
    bucket_budgets: dict = {}
    total = len(rows)

    for idx, row in enumerate(rows, 1):
        ns   = str(row.get("namespace")   or "").strip()
        bk   = str(row.get("bucket_name") or "").strip()
        name = str(row.get("name")        or "").strip()
        reg  = str(row.get("region") or getattr(session, "config_current_default_region", "") or "").strip()
        if not ns or not bk or not name:
            continue
        key = (reg, ns, bk)
        budget = bucket_budgets.setdefault(key, DownloadBudget(session, label=f"bucket {bk}"))
        if budget.exceeded():
            continue
        parts = [safe_path_component(p) for p in name.lstrip("/").split("/") if p] or ["object.bin"]
        base = _dl_base(session, "objectstorage", ns, bk)
        if len(parts) > 1:
            base = base.joinpath(*[safe_path_component(p) for p in parts[:-1]])
        base.mkdir(parents=True, exist_ok=True)
        if idx % 100 == 1 or idx == total:
            print(f"    [{idx}/{total}] {bk}/{name}", flush=True)
        ok = resource.download(namespace=ns, bucket_name=bk, object_name=name,
                               out_path=base / parts[-1], region=reg)
        if ok: downloaded += 1
        else:  failed += 1

    print(f"    done: {downloaded:,} downloaded, {failed:,} failed")
    return {"service": "objectstorage", "downloaded": downloaded, "failed": failed}


# ---------------------------------------------------------------------------
# apigateway  (tokens: api_content / api_specs / sdks)
# ---------------------------------------------------------------------------

def _do_apigateway(session, args, tokens: frozenset[str]) -> dict:
    from ocinferno.modules.apigateway.utilities.helpers import (
        ApiGatewayApisResource,
        ApiGatewaySdksResource,
    )
    from ocinferno.core.utils.module_helpers import guess_blob_ext, write_bytes_file

    session.download_time_budget = int(getattr(args, "download_timeout", 0) or 0)
    comp_fallback = str(getattr(session, "compartment_id", "") or "global")
    downloaded = failed = 0

    if tokens & {"api_content", "api_specs"}:
        resource = ApiGatewayApisResource(session=session)
        rows = _all_rows(session, "apigw_apis")
        print(f"[*] apigateway apis: {len(rows):,} in DB")
        budget = DownloadBudget(session, label="API Gateway API content+spec")
        for row in rows:
            if budget.exceeded():
                break
            rid = row.get("id")
            if not rid:
                continue
            comp_id = row.get("compartment_id") or comp_fallback

            if "api_content" in tokens:
                try:
                    blob = resource.get_api_content(api_id=rid) or b""
                except Exception:
                    blob = b""
                if blob:
                    ext = guess_blob_ext(blob, default_ext="bin")
                    out_path = session.get_download_save_path(
                        service_name="api-gateway", filename=f"api_content.{ext}",
                        compartment_id=comp_id, subdirs=["api-content", rid])
                    if write_bytes_file(out_path, blob): downloaded += 1
                    else: failed += 1
                else:
                    failed += 1

            if "api_specs" in tokens:
                try:
                    spec_blob = resource.get_api_deployment_specification(api_id=rid) or b""
                except Exception:
                    spec_blob = b""
                if spec_blob:
                    ext = guess_blob_ext(spec_blob, default_ext="bin")
                    out_path = session.get_download_save_path(
                        service_name="api-gateway", filename=f"deployment_spec.{ext}",
                        compartment_id=comp_id, subdirs=["api-content", rid])
                    if write_bytes_file(out_path, spec_blob): downloaded += 1
                    else: failed += 1
                else:
                    failed += 1

    if "sdks" in tokens:
        resource = ApiGatewaySdksResource(session=session)
        rows = _all_rows(session, "apigw_sdks")
        print(f"[*] apigateway sdks: {len(rows):,} in DB")
        budget = DownloadBudget(session, label="API Gateway SDK artifacts")
        for row in rows:
            if budget.exceeded():
                break
            sid = row.get("id")
            if not sid:
                continue
            comp_id = row.get("compartment_id") or comp_fallback
            filename = resource.filename_for_sdk_artifact(row)
            out_path = session.get_download_save_path(
                service_name="api-gateway", filename=filename,
                compartment_id=comp_id, subdirs=["sdks", sid])
            if resource.download(sdk_row=row, out_path=out_path): downloaded += 1
            else: failed += 1

    print(f"    done: {downloaded:,} downloaded, {failed:,} failed")
    return {"service": "apigateway", "downloaded": downloaded, "failed": failed}


# ---------------------------------------------------------------------------
# compute  (token: compute)
# DB → OCIDs → live GET for each instance, command, and execution so the
# downloaded content is always fresh (not stale DB field values).
# ---------------------------------------------------------------------------

def _do_compute(session, args, tokens: frozenset[str]) -> dict:
    from ocinferno.modules.core.utilities.helpers import (
        ComputeInstancesResource,
        ComputeInstanceAgentResourceClient,
        _download_instance_metadata_payload,
        _download_instance_agent_execution_payload,
        _write_instance_agent_merged_files,
        _extract_command_id,
    )

    inst_rows = _all_rows(session, "compute_instances")
    cmd_rows  = _all_rows(session, "compute_instance_agent_commands")
    exec_rows = _all_rows(session, "compute_instance_agent_command_executions")
    print(f"[*] compute: {len(inst_rows):,} instances, {len(cmd_rows):,} commands, "
          f"{len(exec_rows):,} executions in DB")

    instances_res = ComputeInstancesResource(session=session)
    agent_client  = ComputeInstanceAgentResourceClient(session=session)
    total_files   = 0

    # 1. Live GET each instance → extract user-data / metadata and write to disk
    for row in inst_rows:
        iid = str(row.get("id") or "").strip()
        cid = str(row.get("compartment_id") or "").strip()
        if not iid or not cid:
            continue
        try:
            live = instances_res.get(resource_id=iid) or {}
            if not live.get("compartment_id"):
                live["compartment_id"] = cid
            result = _download_instance_metadata_payload(
                session, compartment_id=cid, instance_row=live)
            total_files += int(result.get("files_written") or 0)
        except Exception:
            pass

    # 2. Live GET each command (refreshes command text / source content)
    live_cmd_rows: list[dict] = []
    for row in cmd_rows:
        cmd_id = str(row.get("id") or "").strip()
        cid    = str(row.get("compartment_id") or "").strip()
        if not cmd_id:
            live_cmd_rows.append(row)
            continue
        try:
            live = agent_client.get_instance_agent_command(
                instance_agent_command_id=cmd_id) or {}
            if cid and not live.get("compartment_id"):
                live["compartment_id"] = cid
            live_cmd_rows.append(live)
        except Exception:
            live_cmd_rows.append(row)

    # 3. Live GET each execution (refreshes output text / exit code)
    live_exec_rows: list[dict] = []
    for row in exec_rows:
        cmd_id  = str(_extract_command_id(row) or "").strip()
        inst_id = str(row.get("instance_id") or "").strip()
        cid     = str(row.get("compartment_id") or "").strip()
        if not cmd_id or not inst_id:
            live_exec_rows.append(row)
            continue
        try:
            live = agent_client.get_instance_agent_command_execution(
                instance_agent_command_id=cmd_id,
                instance_id=inst_id) or {}
            if cid and not live.get("compartment_id"):
                live["compartment_id"] = cid
            live_exec_rows.append(live)
        except Exception:
            live_exec_rows.append(row)

    # 4. Per-execution payload files (details JSON + output text)
    for row in live_exec_rows:
        cid = str(row.get("compartment_id") or "").strip()
        if not cid:
            continue
        try:
            total_files += _download_instance_agent_execution_payload(
                session, compartment_id=cid, execution_row=row)
        except Exception:
            pass

    # 5. Merged per-instance command files
    comp_ids: set[str] = {
        str(r.get("compartment_id") or "").strip()
        for r in live_cmd_rows + live_exec_rows
        if str(r.get("compartment_id") or "").strip()
    }
    for cid in sorted(comp_ids):
        c_cmds  = [r for r in live_cmd_rows  if str(r.get("compartment_id") or "") == cid]
        c_execs = [r for r in live_exec_rows if str(r.get("compartment_id") or "") == cid]
        result = _write_instance_agent_merged_files(
            session, compartment_id=cid,
            command_rows=c_cmds, execution_rows=c_execs)
        total_files += int(result.get("files_written") or 0)

    print(f"    done: {total_files:,} files written")
    return {"service": "compute", "downloaded": total_files, "failed": 0}


# ---------------------------------------------------------------------------
# resourcemanager  (tokens: orm_variables / orm_jobs / orm_templates)
# ---------------------------------------------------------------------------

def _do_resourcemanager(session, args, tokens: frozenset[str]) -> dict:
    from ocinferno.modules.resourcemanager.utilities.helpers import (
        ResourceManagerStacksResource,
        ResourceManagerJobsResource,
        ResourceManagerTemplatesResource,
    )

    session.download_time_budget = int(getattr(args, "download_timeout", 0) or 0)
    downloaded = failed = 0
    budget = DownloadBudget(session, label="Resource Manager content")

    if tokens & {"orm_variables", "orm_templates"}:
        stacks_res = ResourceManagerStacksResource(session=session)
        rows = _all_rows(session, "resource_manager_stacks")
        print(f"[*] resourcemanager stacks: {len(rows):,} in DB")
        for row in rows:
            if budget.exceeded():
                break
            sid = str(row.get("id") or "").strip()
            cid = str(row.get("compartment_id") or "").strip()
            if not sid:
                continue
            tf_path = session.get_download_save_path(
                service_name="resource-manager", filename="tf_config.zip",
                compartment_id=cid, subdirs=["stacks", sid])
            try: ok = stacks_res.download(resource_id=sid, out_path=tf_path)
            except Exception: ok = False
            if ok: downloaded += 1
            else:  failed += 1

            state_path = session.get_download_save_path(
                service_name="resource-manager", filename="tf_state.json",
                compartment_id=cid, subdirs=["stacks", sid])
            try: ok = stacks_res.download_tf_state(stack_id=sid, out_path=state_path)
            except Exception: ok = False
            if ok: downloaded += 1
            else:  failed += 1

    if "orm_templates" in tokens:
        templates_res = ResourceManagerTemplatesResource(session=session)
        rows = _all_rows(session, "resource_manager_templates")
        print(f"[*] resourcemanager templates: {len(rows):,} in DB")
        for row in rows:
            if budget.exceeded():
                break
            tid = str(row.get("id") or "").strip()
            cid = str(row.get("compartment_id") or "").strip()
            if not tid:
                continue
            tf_path = session.get_download_save_path(
                service_name="resource-manager", filename="template_tf_config.zip",
                compartment_id=cid, subdirs=["templates", tid])
            try: ok = templates_res.download(resource_id=tid, out_path=tf_path)
            except Exception: ok = False
            if ok: downloaded += 1
            else:  failed += 1

    if "orm_jobs" in tokens:
        jobs_res = ResourceManagerJobsResource(session=session)
        rows = _all_rows(session, "resource_manager_jobs")
        print(f"[*] resourcemanager jobs: {len(rows):,} in DB")
        for row in rows:
            if budget.exceeded():
                break
            jid = str(row.get("id") or "").strip()
            cid = str(row.get("compartment_id") or "").strip()
            if not jid:
                continue
            for method, fname, kw in [
                ("download",               "job_logs.txt",      {"resource_id": jid}),
                ("download_detailed_logs", "detailed_logs.txt", {"job_id": jid}),
                ("download_tf_config",     "tf_config.zip",     {"job_id": jid}),
                ("download_tf_state",      "tf_state.json",     {"job_id": jid}),
            ]:
                fn = getattr(jobs_res, method, None)
                if fn is None:
                    continue
                out_path = session.get_download_save_path(
                    service_name="resource-manager", filename=fname,
                    compartment_id=cid, subdirs=["jobs", jid])
                try: ok = fn(out_path=out_path, **kw)
                except Exception: ok = False
                if ok: downloaded += 1
                else:  failed += 1

    print(f"    done: {downloaded:,} downloaded, {failed:,} failed")
    return {"service": "resourcemanager", "downloaded": downloaded, "failed": failed}


# ---------------------------------------------------------------------------
# artifactregistry  (token: artifacts)
# Prefers download_by_path (uses artifact_path+version from row); falls back to
# download_by_id.  Uses out_path_via_session for correct path layout.
# ---------------------------------------------------------------------------

def _do_artifactregistry(session, args, tokens: frozenset[str]) -> dict:
    from ocinferno.modules.artifactregistry.utilities.helpers import ArtifactRegistryArtifactsResource as ArtifactRegistryResource

    session.download_time_budget = int(getattr(args, "download_timeout", 0) or 0)
    resource = ArtifactRegistryResource(session=session)
    rows = _all_rows(session, "ar_generic_artifact")
    print(f"[*] artifactregistry: {len(rows):,} in DB")
    if not rows:
        return {"service": "artifactregistry", "downloaded": 0, "failed": 0}

    downloaded = failed = 0
    comp_fallback = str(getattr(session, "compartment_id", "") or "global")
    budget = DownloadBudget(session, label="Artifact Registry content")

    for row in rows:
        if budget.exceeded():
            break
        aid          = str(row.get("id") or "").strip()
        repo_id      = str(row.get("repository_id") or "").strip()
        artifact_path = str(row.get("artifact_path") or "").strip()
        version      = str(row.get("version") or "").strip()
        comp_id      = str(row.get("compartment_id") or comp_fallback).strip()
        if not aid:
            continue

        if repo_id and artifact_path and version:
            out_file = resource.out_path_via_session(
                session, repository_id=repo_id,
                artifact_path=artifact_path, version=version,
                compartment_id=comp_id)
            try: ok = resource.download_by_path(
                    repository_id=repo_id, artifact_path=artifact_path,
                    version=version, out_file=out_file)
            except Exception: ok = False
        else:
            display = safe_path_component(str(row.get("display_name") or aid))
            out_file = session.get_download_save_path(
                service_name="artifactregistry", filename=f"{display}.bin",
                compartment_id=comp_id,
                subdirs=["generic_artifacts", repo_id or "unknown-repo"])
            try: ok = resource.download_by_id(artifact_id=aid, out_file=out_file)
            except Exception: ok = False

        if ok: downloaded += 1
        else:  failed += 1

    print(f"    done: {downloaded:,} downloaded, {failed:,} failed")
    return {"service": "artifactregistry", "downloaded": downloaded, "failed": failed}


# ---------------------------------------------------------------------------
# vault  (token: vault_secrets)
# ---------------------------------------------------------------------------

def _do_vault(session, args, tokens: frozenset[str]) -> dict:
    from ocinferno.modules.vault.utilities.helpers import VaultSecretsResource

    session.download_time_budget = int(getattr(args, "download_timeout", 0) or 0)
    resource = VaultSecretsResource(session=session)
    rows = _all_rows(session, "vault_secret")
    secret_ids = [str(r.get("id") or "").strip() for r in rows if r.get("id")]
    print(f"[*] vault: {len(secret_ids):,} secrets in DB")
    if not secret_ids:
        return {"service": "vault", "downloaded": 0, "failed": 0}

    dump_dir = _dl_base(session, "vault", "secrets")
    dump_dir.mkdir(parents=True, exist_ok=True)
    try:
        results = resource.dump(dump_dir=dump_dir, secret_ids=secret_ids, expand_versions=False) or []
        downloaded = len([r for r in results if r.get("saved")])
        failed     = len([r for r in results if not r.get("saved")])
    except Exception as err:
        print(f"{UtilityTools.RED}[X] vault dump error: {err}{UtilityTools.RESET}")
        return {"service": "vault", "downloaded": 0, "failed": len(secret_ids)}

    print(f"    done: {downloaded:,} downloaded, {failed:,} failed")
    return {"service": "vault", "downloaded": downloaded, "failed": failed}


# ---------------------------------------------------------------------------
# certificates  (token: certificate_bundles)
# ---------------------------------------------------------------------------

def _do_certificates(session, args, tokens: frozenset[str]) -> dict:
    from ocinferno.modules.certificates.utilities.helpers import CertificatesResource

    session.download_time_budget = int(getattr(args, "download_timeout", 0) or 0)
    resource = CertificatesResource(session=session)
    rows = _all_rows(session, "certificates")
    print(f"[*] certificates: {len(rows):,} in DB")
    if not rows:
        return {"service": "certificates", "downloaded": 0, "failed": 0}

    downloaded = failed = 0
    budget = DownloadBudget(session, label="certificates certificate_bundles")
    for row in rows:
        if budget.exceeded():
            break
        rid = str(row.get("id") or "").strip()
        if not rid:
            continue
        comp_id = str(row.get("compartment_id") or getattr(session, "compartment_id", None) or "unknown").strip()
        path = session.get_download_save_path(
            service_name="certificates", filename="bundle.pem",
            compartment_id=comp_id, subdirs=["certificate-bundles", rid])
        try: ok = resource.download_bundle(resource_id=rid, out_path=path)
        except Exception: ok = False
        if ok: downloaded += 1
        else:  failed += 1

    print(f"    done: {downloaded:,} downloaded, {failed:,} failed")
    return {"service": "certificates", "downloaded": downloaded, "failed": failed}


# ---------------------------------------------------------------------------
# dataflow  (token: dataflow_scripts)
# ---------------------------------------------------------------------------

def _do_dataflow(session, args, tokens: frozenset[str]) -> dict:
    from ocinferno.modules.dataflow.utilities.helpers import DataFlowApplicationsResource as DataflowApplicationsResource

    session.download_time_budget = int(getattr(args, "download_timeout", 0) or 0)
    resource = DataflowApplicationsResource(session=session)
    rows = _all_rows(session, "dataflow_applications")
    print(f"[*] dataflow: {len(rows):,} applications in DB")
    if not rows:
        return {"service": "dataflow", "downloaded": 0, "failed": 0}

    downloaded = failed = 0
    budget = DownloadBudget(session, label="Dataflow scripts")
    for row in rows:
        if budget.exceeded():
            break
        rid = str(row.get("id") or "").strip()
        if not rid:
            continue
        comp_id = str(row.get("compartment_id") or getattr(session, "compartment_id", None) or "unknown").strip()
        out_dir = session.get_download_save_path(
            service_name="dataflow", filename="scripts",
            compartment_id=comp_id, subdirs=["applications", rid])
        try:
            written = resource.download_script(resource_id=rid, out_path_dir=str(out_dir))
            if written: downloaded += written
            else: failed += 1
        except Exception:
            failed += 1

    print(f"    done: {downloaded:,} downloaded, {failed:,} failed")
    return {"service": "dataflow", "downloaded": downloaded, "failed": failed}


# ---------------------------------------------------------------------------
# datascience  (token: datascience_artifacts)
# subdir and filename match resource_method_download spec in enum_datascience.
# ---------------------------------------------------------------------------

def _do_datascience(session, args, tokens: frozenset[str]) -> dict:
    from ocinferno.modules.datascience.utilities.helpers import (
        DataScienceModelsResource,
        DataScienceJobsResource,
    )

    session.download_time_budget = int(getattr(args, "download_timeout", 0) or 0)
    downloaded = failed = 0
    budget = DownloadBudget(session, label="data science artifacts")

    for resource_cls, table in [
        (DataScienceModelsResource, "data_science_models"),
        (DataScienceJobsResource,   "data_science_jobs"),
    ]:
        resource = resource_cls(session=session)
        rows = _all_rows(session, table)
        print(f"[*] datascience {table}: {len(rows):,} in DB")
        for row in rows:
            if budget.exceeded():
                break
            rid = str(row.get("id") or "").strip()
            if not rid:
                continue
            comp_id = str(row.get("compartment_id") or getattr(session, "compartment_id", None) or "unknown").strip()
            out_path = session.get_download_save_path(
                service_name="datascience", filename="artifact.zip",
                compartment_id=comp_id, subdirs=["artifacts", rid])
            try: ok = resource.download_artifact(resource_id=rid, out_path=out_path)
            except Exception: ok = False
            if ok: downloaded += 1
            else:  failed += 1

    print(f"    done: {downloaded:,} downloaded, {failed:,} failed")
    return {"service": "datascience", "downloaded": downloaded, "failed": failed}


# ---------------------------------------------------------------------------
# iot  (tokens: iot_models / iot_instances)
# filenames and subdirs match resource_method_download spec in enum_iot.
# ---------------------------------------------------------------------------

def _do_iot(session, args, tokens: frozenset[str]) -> dict:
    from ocinferno.modules.iot.utilities.helpers import (
        IotDigitalTwinModelsResource,
        IotDigitalTwinInstancesResource,
    )

    session.download_time_budget = int(getattr(args, "download_timeout", 0) or 0)
    downloaded = failed = 0
    budget = DownloadBudget(session, label="IoT digital twin content")

    specs = []
    if "iot_models" in tokens:
        specs.append((IotDigitalTwinModelsResource, "iot_digital_twin_models",
                      "digital-twin-models", "model_spec.json"))
    if "iot_instances" in tokens:
        specs.append((IotDigitalTwinInstancesResource, "iot_digital_twin_instances",
                      "digital-twin-instances", "instance_content.json"))

    for resource_cls, table, subdir, filename in specs:
        resource = resource_cls(session=session)
        rows = _all_rows(session, table)
        print(f"[*] iot {subdir}: {len(rows):,} in DB")
        for row in rows:
            if budget.exceeded():
                break
            rid = str(row.get("id") or "").strip()
            if not rid:
                continue
            comp_id = str(row.get("compartment_id") or getattr(session, "compartment_id", None) or "unknown").strip()
            out_path = session.get_download_save_path(
                service_name="iot", filename=filename,
                compartment_id=comp_id, subdirs=[subdir, rid])
            try: ok = resource.download(resource_id=rid, out_path=out_path)
            except Exception: ok = False
            if ok: downloaded += 1
            else:  failed += 1

    print(f"    done: {downloaded:,} downloaded, {failed:,} failed")
    return {"service": "iot", "downloaded": downloaded, "failed": failed}


# ---------------------------------------------------------------------------
# functions  (token: function_config)
# Mirrors field_dump_download(field="config", get_if_missing=True).
# Falls back to live resource.get() if config field absent from DB row.
# ---------------------------------------------------------------------------

def _do_functions(session, args, tokens: frozenset[str]) -> dict:
    from ocinferno.modules.functions.utilities.helpers import (
        FunctionsAppsResource,
        FunctionsFunctionsResource,
    )

    session.download_time_budget = int(getattr(args, "download_timeout", 0) or 0)
    downloaded = failed = 0
    budget = DownloadBudget(session, label="functions config")

    for resource_cls, table, subdir in [
        (FunctionsAppsResource,      "functions_apps",      "application-config"),
        (FunctionsFunctionsResource, "functions_functions", "function-config"),
    ]:
        resource = resource_cls(session=session)
        rows = _all_rows(session, table)
        print(f"[*] functions {table}: {len(rows):,} in DB")
        for row in rows:
            if budget.exceeded():
                break
            if _field_dump(session, row, field="config", service_name="functions",
                           subdir=subdir, filename="config.json", resource=resource):
                downloaded += 1
            elif row.get("id"):
                failed += 1

    print(f"    done: {downloaded:,} written, {failed:,} empty/failed")
    return {"service": "functions", "downloaded": downloaded, "failed": failed}


# ---------------------------------------------------------------------------
# container_env  (token: container_env)
# Matches resource_method_download spec in enum_container_instances.
# ---------------------------------------------------------------------------

def _do_container_env(session, args, tokens: frozenset[str]) -> dict:
    from ocinferno.modules.containerinstances.utilities.helpers import ContainerInstancesResource

    session.download_time_budget = int(getattr(args, "download_timeout", 0) or 0)
    resource = ContainerInstancesResource(session=session)
    rows = _all_rows(session, "container_instances")
    print(f"[*] containerinstances: {len(rows):,} in DB")
    if not rows:
        return {"service": "container_env", "downloaded": 0, "failed": 0}

    downloaded = failed = 0
    budget = DownloadBudget(session, label="container instance configs")
    for row in rows:
        if budget.exceeded():
            break
        rid = str(row.get("id") or "").strip()
        if not rid:
            continue
        comp_id = str(row.get("compartment_id") or getattr(session, "compartment_id", None) or "unknown").strip()
        out_path = session.get_download_save_path(
            service_name="containerinstances", filename="container-config.json",
            compartment_id=comp_id, subdirs=["container-config", rid])
        try: ok = resource.download_container_configs(resource_id=rid, out_path=out_path)
        except Exception: ok = False
        if ok: downloaded += 1
        else:  failed += 1

    print(f"    done: {downloaded:,} downloaded, {failed:,} failed")
    return {"service": "container_env", "downloaded": downloaded, "failed": failed}


# ---------------------------------------------------------------------------
# devops_pipeline_config  (token: devops_pipeline_config)
# Mirrors field_dump_download(get_if_missing=True) for build + deploy pipelines.
# ---------------------------------------------------------------------------

def _do_devops_pipeline_config(session, args, tokens: frozenset[str]) -> dict:
    from ocinferno.modules.devops.utilities.helpers import (
        DevOpsBuildPipelinesResource,
        DevOpsDeployPipelinesResource,
    )

    session.download_time_budget = int(getattr(args, "download_timeout", 0) or 0)
    downloaded = failed = 0
    budget = DownloadBudget(session, label="devops pipeline config")

    for resource_cls, table, field, subdir in [
        (DevOpsBuildPipelinesResource,  "devops_build_pipelines",  "build_pipeline_parameters",  "build-pipeline-params"),
        (DevOpsDeployPipelinesResource, "devops_deploy_pipelines", "deploy_pipeline_parameters", "deploy-pipeline-params"),
    ]:
        resource = resource_cls(session=session)
        rows = _all_rows(session, table)
        print(f"[*] devops {table}: {len(rows):,} in DB")
        for row in rows:
            if budget.exceeded():
                break
            if _field_dump(session, row, field=field, service_name="devops",
                           subdir=subdir, filename="parameters.json", resource=resource):
                downloaded += 1
            elif row.get("id"):
                failed += 1

    print(f"    done: {downloaded:,} written, {failed:,} empty/failed")
    return {"service": "devops_pipeline_config", "downloaded": downloaded, "failed": failed}


# ---------------------------------------------------------------------------
# devops_repos  (token: devops_repos)
# Git clones require a live API — cannot recover from DB metadata alone.
# ---------------------------------------------------------------------------

def _do_devops_repos(session, args, tokens: frozenset[str]) -> dict:
    print("[*] devops_repos: skipped — git clone requires a live API call, not cached DB data")
    return {"service": "devops_repos", "downloaded": 0, "failed": 0, "skipped": True}


# ---------------------------------------------------------------------------
# Token → handler mapping
# ---------------------------------------------------------------------------

_TOKEN_HANDLERS: dict[str, Callable] = {
    "buckets":                _do_objectstorage,
    "objects":                _do_objectstorage,
    "blobs":                  _do_objectstorage,
    "object_storage":         _do_objectstorage,
    "api_content":            _do_apigateway,
    "api_specs":              _do_apigateway,
    "sdks":                   _do_apigateway,
    "compute":                _do_compute,
    "orm_variables":          _do_resourcemanager,
    "orm_jobs":               _do_resourcemanager,
    "orm_templates":          _do_resourcemanager,
    "artifacts":              _do_artifactregistry,
    "vault_secrets":          _do_vault,
    "certificate_bundles":    _do_certificates,
    "dataflow_scripts":       _do_dataflow,
    "datascience_artifacts":  _do_datascience,
    "iot_models":             _do_iot,
    "iot_instances":          _do_iot,
    "function_config":        _do_functions,
    "container_env":          _do_container_env,
    "devops_pipeline_config": _do_devops_pipeline_config,
    "devops_repos":           _do_devops_repos,
}


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def run_module(user_args, session):
    all_tokens = sorted(_TOKEN_HANDLERS)
    parser = argparse.ArgumentParser(
        prog="process_download_cached",
        description=(
            "Re-download content using already-enumerated DB rows — no live list calls.\n"
            "Uses the same --download / --not-downloads token system as enum_all."
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--download", nargs="*", default=None,
        help=(
            "Download categories/tokens (space or comma separated). Same as enum_all.\n"
            "  --download                # all\n"
            "  --download content        # heavy: objects, vault, artifacts, certs, ...\n"
            "  --download metadata       # light: compute, functions, devops, ...\n"
            "  --download buckets        # single token\n"
            f"Tokens: {', '.join(all_tokens)}"
        ),
    )
    parser.add_argument(
        "--not-downloads", dest="not_downloads", nargs="*", default=None,
        help="Exclude categories/tokens (space or comma separated). Same as enum_all.",
    )
    parser.add_argument("--download-timeout", type=int, default=0, dest="download_timeout",
                        help="Per-service wall-clock cap in seconds (0 = unlimited)")
    args = parser.parse_args(user_args)

    tokens = _active_tokens(args.download, args.not_downloads)
    if not tokens:
        print(
            f"{UtilityTools.YELLOW}[!] Nothing selected. Pass --download (or --download <token>) "
            f"to choose what to re-download.\n"
            f"    Available tokens: {', '.join(all_tokens)}{UtilityTools.RESET}"
        )
        return {"ok": True, "components": []}

    out_root = _root(session) / session.OUTPUT_DIR_NAMES["downloads"]
    print(f"[*] process_download_cached: writing to {out_root}")
    print(f"[*] active tokens: {', '.join(sorted(tokens))}")

    seen_handlers: set[int] = set()
    results = []
    for tok in sorted(tokens):
        handler = _TOKEN_HANDLERS.get(tok)
        if handler is None:
            print(f"{UtilityTools.YELLOW}[!] no handler for token '{tok}' — skipped{UtilityTools.RESET}")
            continue
        hid = id(handler)
        if hid in seen_handlers:
            continue
        seen_handlers.add(hid)
        try:
            result = handler(session, args, tokens)
        except Exception as err:
            print(f"{UtilityTools.RED}[X] {tok}: {type(err).__name__}: {err}{UtilityTools.RESET}")
            result = {"service": tok, "downloaded": 0, "failed": 0, "error": str(err)}
        results.append(result)

    total_dl  = sum(r.get("downloaded", 0) for r in results)
    total_err = sum(r.get("failed",     0) for r in results)
    print(f"\n[*] done — {total_dl:,} files, {total_err:,} failed")
    return {"ok": True, "components": results}
