#!/usr/bin/env python3

import argparse
import base64
import json
from datetime import datetime, timezone
from typing import Any, Dict, Sequence

import oci
from ocinferno.core.console import UtilityTools
from ocinferno.modules.core.utilities.compute_helpers import (
    ComputeResourceClient,
    ImageResourceClient,
    ComputeInstanceAgentResourceClient,
    _command_preview_15,
    _display_text,
    _download_instance_agent_execution_payload,
    _download_instance_metadata_payload,
    _extract_command_id,
    _extract_command_text,
    _extract_execution_output_text,
    _write_instance_agent_merged_files,
)
from ocinferno.modules.core.utilities.compute_management_helpers import ComputeManagementResourceClient
from ocinferno.core.utils.module_helpers import fill_missing_fields, cached_table_count, save_rows, resolve_component_flags


def _parse_args(user_args: Sequence[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Enumerate OCI Core Compute Resources", allow_abbrev=False)

    # resource selectors
    p.add_argument("--instances", action="store_true", help="Enumerate compute instances")
    p.add_argument("--images", action="store_true", help="Enumerate compute images")
    p.add_argument("--instance-configs", dest="instance_configs", action="store_true", help="Enumerate instance configurations")
    p.add_argument("--instance-pools", dest="instance_pools", action="store_true", help="Enumerate instance pools")
    p.add_argument("--cluster-networks", dest="cluster_networks", action="store_true", help="Enumerate cluster networks")
    p.add_argument("--compute-clusters", dest="compute_clusters", action="store_true", help="Enumerate compute clusters")
    p.add_argument(
        "--instance-agent-commands",
        dest="instance_agent_commands",
        action="store_true",
        help="Enumerate instance-agent commands; with --get/--download also pulls status/output and writes merged per-instance command files",
    )
    p.add_argument(
        "--instance-agent-command-executions",
        dest="instance_agent_command_executions",
        action="store_true",
        help="Enumerate per-instance execution/status rows (use when you want execution-history artifacts)",
    )
    p.add_argument("--instance-agent-plugins", dest="instance_agent_plugins", action="store_true", help="Enumerate compute instance-agent plugin status per instance")

    # --get/--save/--download are runner-level common flags; parse module-specific args only.
    args, _ = p.parse_known_args(list(user_args))
    raw_args = {str(x) for x in (list(user_args) if user_args is not None else [])}
    args.get = "--get" in raw_args
    args.save = "--save" in raw_args
    args.download = "--download" in raw_args

    return args




def run_module(user_args, session) -> Dict[str, Any]:
    args = _parse_args(user_args)
    debug = bool(getattr(session, "debug", False) or getattr(session, "individual_run_debug", False))

    comp_id = getattr(session, "compartment_id", None)
    if not comp_id:
        raise ValueError("session.compartment_id is not set. Select a compartment first.")

    flags = resolve_component_flags(
        args,
        [
            "instances",
            "images",
            "instance_configs",
            "instance_pools",
            "cluster_networks",
            "compute_clusters",
            "instance_agent_commands",
            "instance_agent_command_executions",
            "instance_agent_plugins",
        ],
    )
    summary: Dict[str, int] = {}
    instance_rows_for_agent = []
    command_text_by_id: Dict[str, str] = {}
    command_rows_for_merge: list[Dict[str, Any]] = []
    execution_rows_for_merge: list[Dict[str, Any]] = []
    downloaded_execution_keys = set()
    instance_agent_download_files = 0

    # Resource loop: compute instances (base inventory + optional metadata/download enrichment).
    if flags["instances"]:
        ops = ComputeResourceClient(session=session)
        try:
            rows = ops.list_instances(compartment_id=comp_id) or []
        except oci.exceptions.ServiceError as e:
            UtilityTools.dlog(True, "list_instances failed", status=getattr(e, "status", None), code=getattr(e, "code", None))
            rows = []
        except Exception as e:
            UtilityTools.dlog(True, "list_instances failed", err=f"{type(e).__name__}: {e}")
            rows = []

        if rows:
            if args.get or args.download:
                for inst in UtilityTools.progress_iter(rows, label="GET instances"):
                    inst_id = (inst or {}).get("id")
                    if not inst_id:
                        continue
                    try:
                        meta = ops.get_instance(instance_id=inst_id) or {}
                    except Exception as e:
                        UtilityTools.dlog(debug, "get_instance failed", id=inst_id, err=f"{type(e).__name__}: {e}")
                        continue
                    if isinstance(meta, dict):
                        meta["get_run"] = True
                        fill_missing_fields(inst, meta)

            if args.download:
                metadata_download_files = 0
                metadata_rows = []
                for inst in rows:
                    inst_compartment_id = (inst or {}).get("compartment_id") or comp_id
                    try:
                        dl_meta = _download_instance_metadata_payload(
                            session,
                            compartment_id=inst_compartment_id,
                            instance_row=(inst or {}),
                        )
                    except Exception as e:
                        UtilityTools.dlog(
                            debug,
                            "download instance metadata payload failed",
                            instance_id=(inst or {}).get("id"),
                            err=f"{type(e).__name__}: {e}",
                        )
                        continue
                    metadata_download_files += int(dl_meta.get("files_written") or 0)
                    metadata_rows.append(
                        {
                            "instance_id": dl_meta.get("instance_id"),
                            "user_data_path": dl_meta.get("user_data_path"),
                            "additional_metadata_path": dl_meta.get("additional_metadata_path"),
                        }
                    )
                if metadata_rows:
                    UtilityTools.print_limited_table(
                        metadata_rows,
                        [
                            "instance_id",
                            "user_data_path",
                            "additional_metadata_path",
                        ],
                    )
                summary["instance_metadata_download_files"] = metadata_download_files

                # Export instance-agent Run Command history (commands + execution output)
                # for each enumerated instance when available.
                try:
                    ia_ops = ComputeInstanceAgentResourceClient(session=session)
                    all_commands = ia_ops.list_instance_agent_commands(compartment_id=comp_id) or []
                    all_commands = [c for c in all_commands if isinstance(c, dict)]
                except Exception as e:
                    UtilityTools.dlog(debug, "list_instance_agent_commands failed", compartment_id=comp_id, err=f"{type(e).__name__}: {e}")
                    all_commands = []

                command_rows_for_save = []
                execution_rows_for_save = []
                run_command_export_files = 0
                run_command_export_commands = 0
                run_command_export_executions = 0

                if all_commands:
                    commands_by_instance = {}
                    for cmd in all_commands:
                        target = (cmd.get("target") or {}) if isinstance(cmd.get("target"), dict) else {}
                        inst_id = (target.get("instance_id") or "").strip()
                        if not inst_id:
                            continue
                        commands_by_instance.setdefault(inst_id, []).append(cmd)

                    for inst in UtilityTools.progress_iter(rows, label="EXPORT instance-agent run-command history"):
                        inst_id = (inst or {}).get("id")
                        if not inst_id:
                            continue
                        region = inst.get("region") or ""
                        name = inst.get("display_name") or inst_id
                        inst_compartment_id = inst.get("compartment_id") or comp_id
                        inst_commands = commands_by_instance.get(inst_id) or []

                        normalized_commands = []
                        normalized_executions = []

                        for cmd in inst_commands:
                            cmd_id = _extract_command_id(cmd)
                            if cmd_id:
                                try:
                                    full_cmd = ia_ops.get_instance_agent_command(instance_agent_command_id=cmd_id) or {}
                                    if isinstance(full_cmd, dict):
                                        fill_missing_fields(cmd, full_cmd)
                                except Exception as e:
                                    UtilityTools.dlog(debug, "get_instance_agent_command failed", instance_agent_command_id=cmd_id, err=f"{type(e).__name__}: {e}")
                            norm_cmd = ia_ops.normalize_command_row(
                                cmd,
                                source="enum_core_compute_download",
                            )
                            normalized_commands.append(norm_cmd)
                            command_rows_for_save.append(norm_cmd)

                            if not cmd_id:
                                continue
                            try:
                                exec_row = ia_ops.get_instance_agent_command_execution(
                                    instance_agent_command_id=cmd_id,
                                    instance_id=inst_id,
                                ) or {}
                            except Exception:
                                continue
                            if not isinstance(exec_row, dict) or not exec_row:
                                continue

                            norm_exec = ia_ops.normalize_execution_row(
                                exec_row,
                                instance_agent_command_id=cmd_id,
                                instance_id=inst_id,
                                source="enum_core_compute_download",
                            )
                            normalized_executions.append(norm_exec)
                            execution_rows_for_save.append(norm_exec)

                        if not normalized_commands and not normalized_executions:
                            continue

                        run_command_export_commands += len(normalized_commands)
                        run_command_export_executions += len(normalized_executions)

                        out_path = session.get_download_save_path(
                            service_name="compute",
                            filename=f"{region}_{name}_run_command_history.json",
                            compartment_id=inst_compartment_id,
                            subdirs=["instance_agent_run_command"],
                        )
                        payload = {
                            "exported_at_utc": datetime.now(timezone.utc).isoformat(),
                            "instance_id": inst_id,
                            "instance_name": name,
                            "compartment_id": inst_compartment_id,
                            "region": region,
                            "commands": normalized_commands,
                            "executions": normalized_executions,
                        }
                        out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
                        run_command_export_files += 1

                if args.save:
                    if command_rows_for_save:
                        save_rows(session, ComputeInstanceAgentResourceClient.TABLE_COMMANDS, command_rows_for_save)
                    if execution_rows_for_save:
                        save_rows(session, ComputeInstanceAgentResourceClient.TABLE_EXECUTIONS, execution_rows_for_save)

                summary["instance_agent_run_command_files"] = run_command_export_files
                summary["instance_agent_run_command_commands"] = run_command_export_commands
                summary["instance_agent_run_command_executions"] = run_command_export_executions

            UtilityTools.print_limited_table(
                rows,
                ["id", "display_name", "lifecycle_state", "shape", "availability_domain"],
            )

            if args.save:
                ops.save_instances(rows)
            instance_rows_for_agent = [r for r in rows if isinstance(r, dict)]

        summary["instances"] = len(rows)
    else:
        summary["instances"] = cached_table_count(
            session,
            table_name="compute_instances",
            compartment_id=comp_id,
            compartment_field="compartment_id",
        ) or 0

    # Images
    if flags["images"]:
        img_ops = ImageResourceClient(session=session)
        try:
            rows = img_ops.list_images(compartment_id=comp_id) or []
        except oci.exceptions.ServiceError as e:
            UtilityTools.dlog(True, "list_images failed", status=getattr(e, "status", None), code=getattr(e, "code", None))
            rows = []
        except Exception as e:
            UtilityTools.dlog(True, "list_images failed", err=f"{type(e).__name__}: {e}")
            rows = []

        if rows and args.get:
            for img in UtilityTools.progress_iter(rows, label="GET images"):
                img_id = (img or {}).get("id")
                if not img_id:
                    continue
                try:
                    full = img_ops.get_image(image_id=img_id) or {}
                except Exception as e:
                    UtilityTools.dlog(debug, "get_image failed", image_id=img_id, err=f"{type(e).__name__}: {e}")
                    continue
                if isinstance(full, dict):
                    full["get_run"] = True
                    fill_missing_fields(img, full)

        if rows:
            UtilityTools.print_limited_table(
                rows,
                ["id", "display_name", "lifecycle_state", "operating_system", "operating_system_version"],
            )
            if args.save:
                save_rows(session, img_ops.TABLE_COMPUTE_IMAGES, rows)

        summary["images"] = len(rows)
    else:
        summary["images"] = cached_table_count(
            session,
            table_name="compute_images",
            compartment_id=comp_id,
            compartment_field="compartment_id",
        ) or 0

    # Compute Management (instance configs/pools/cluster networks/compute clusters)
    cm_ops = ComputeManagementResourceClient(session=session)

    if flags["instance_configs"]:
        try:
            rows = cm_ops.list_instance_configurations(compartment_id=comp_id) or []
        except Exception as e:
            UtilityTools.dlog(True, "list_instance_configurations failed", err=f"{type(e).__name__}: {e}")
            rows = []

        if rows and args.get:
            for r in UtilityTools.progress_iter(rows, label="GET instance configs"):
                rid = (r or {}).get("id")
                if not rid:
                    continue
                try:
                    meta = cm_ops.get_instance_configuration(instance_configuration_id=rid) or {}
                except Exception as e:
                    UtilityTools.dlog(debug, "get_instance_configuration failed", instance_configuration_id=rid, err=f"{type(e).__name__}: {e}")
                    continue
                if isinstance(meta, dict):
                    meta["get_run"] = True
                    fill_missing_fields(r, meta)

        if rows:
            UtilityTools.print_limited_table(rows, ["id", "display_name", "lifecycle_state", "time_created"])
            if args.save:
                save_rows(session, cm_ops.TABLE_INSTANCE_CONFIGS, rows)
        summary["instance_configs"] = len(rows)
    else:
        summary["instance_configs"] = cached_table_count(
            session,
            table_name="compute_instance_configurations",
            compartment_id=comp_id,
            compartment_field="compartment_id",
        ) or 0

    if flags["instance_pools"]:
        try:
            rows = cm_ops.list_instance_pools(compartment_id=comp_id) or []
        except Exception as e:
            UtilityTools.dlog(True, "list_instance_pools failed", err=f"{type(e).__name__}: {e}")
            rows = []

        if rows and args.get:
            for r in UtilityTools.progress_iter(rows, label="GET instance pools"):
                rid = (r or {}).get("id")
                if not rid:
                    continue
                try:
                    meta = cm_ops.get_instance_pool(instance_pool_id=rid) or {}
                except Exception as e:
                    UtilityTools.dlog(debug, "get_instance_pool failed", instance_pool_id=rid, err=f"{type(e).__name__}: {e}")
                    continue
                if isinstance(meta, dict):
                    meta["get_run"] = True
                    fill_missing_fields(r, meta)

        if rows:
            UtilityTools.print_limited_table(rows, ["id", "display_name", "lifecycle_state", "size", "instance_configuration_id"])
            if args.save:
                save_rows(session, cm_ops.TABLE_INSTANCE_POOLS, rows)
        summary["instance_pools"] = len(rows)
    else:
        summary["instance_pools"] = cached_table_count(
            session,
            table_name="compute_instance_pools",
            compartment_id=comp_id,
            compartment_field="compartment_id",
        ) or 0

    if flags["cluster_networks"]:
        try:
            rows = cm_ops.list_cluster_networks(compartment_id=comp_id) or []
        except Exception as e:
            UtilityTools.dlog(True, "list_cluster_networks failed", err=f"{type(e).__name__}: {e}")
            rows = []

        if rows and args.get:
            for r in UtilityTools.progress_iter(rows, label="GET cluster networks"):
                rid = (r or {}).get("id")
                if not rid:
                    continue
                try:
                    meta = cm_ops.get_cluster_network(cluster_network_id=rid) or {}
                except Exception as e:
                    UtilityTools.dlog(debug, "get_cluster_network failed", cluster_network_id=rid, err=f"{type(e).__name__}: {e}")
                    continue
                if isinstance(meta, dict):
                    meta["get_run"] = True
                    fill_missing_fields(r, meta)

        if rows:
            UtilityTools.print_limited_table(rows, ["id", "display_name", "lifecycle_state", "time_created"])
            if args.save:
                save_rows(session, cm_ops.TABLE_CLUSTER_NETWORKS, rows)
        summary["cluster_networks"] = len(rows)
    else:
        summary["cluster_networks"] = cached_table_count(
            session,
            table_name="compute_cluster_networks",
            compartment_id=comp_id,
            compartment_field="compartment_id",
        ) or 0

    if flags["compute_clusters"]:
        try:
            rows = cm_ops.list_compute_clusters(compartment_id=comp_id) or []
        except Exception as e:
            UtilityTools.dlog(True, "list_compute_clusters failed", err=f"{type(e).__name__}: {e}")
            rows = []

        if rows and args.get:
            for r in UtilityTools.progress_iter(rows, label="GET compute clusters"):
                rid = (r or {}).get("id")
                if not rid:
                    continue
                try:
                    meta = cm_ops.get_compute_cluster(compute_cluster_id=rid) or {}
                except Exception as e:
                    UtilityTools.dlog(debug, "get_compute_cluster failed", compute_cluster_id=rid, err=f"{type(e).__name__}: {e}")
                    continue
                if isinstance(meta, dict):
                    meta["get_run"] = True
                    fill_missing_fields(r, meta)

        if rows:
            UtilityTools.print_limited_table(rows, ["id", "display_name", "lifecycle_state", "time_created"])
            if args.save:
                save_rows(session, cm_ops.TABLE_COMPUTE_CLUSTERS, rows)
        summary["compute_clusters"] = len(rows)
    else:
        summary["compute_clusters"] = cached_table_count(
            session,
            table_name="compute_compute_clusters",
            compartment_id=comp_id,
            compartment_field="compartment_id",
        ) or 0

    # Instance Agent Commands (compartment scope)
    if flags["instance_agent_commands"]:
        ia_ops = ComputeInstanceAgentResourceClient(session=session)
        command_rows = []
        status_lookup_attempted = 0
        status_lookup_succeeded = 0
        status_lookup_failed = 0
        status_lookup_last_error = ""
        try:
            raw_commands = ia_ops.list_instance_agent_commands(compartment_id=comp_id) or []
        except oci.exceptions.ServiceError as e:
            UtilityTools.dlog(True, "list_instance_agent_commands failed", status=getattr(e, "status", None), code=getattr(e, "code", None))
            raw_commands = []
        except Exception as e:
            UtilityTools.dlog(True, "list_instance_agent_commands failed", err=f"{type(e).__name__}: {e}")
            raw_commands = []

        for cmd in raw_commands:
            if not isinstance(cmd, dict):
                continue
            exec_status = {}
            target_instance_id = ""
            cmd_id = ""
            if args.get or args.download:
                cmd_id = _extract_command_id(cmd)
                if cmd_id:
                    try:
                        full = ia_ops.get_instance_agent_command(instance_agent_command_id=cmd_id) or {}
                        if isinstance(full, dict):
                            fill_missing_fields(cmd, full)
                    except Exception as e:
                        UtilityTools.dlog(debug, "get_instance_agent_command failed", instance_agent_command_id=cmd_id, err=f"{type(e).__name__}: {e}")
                target_obj = cmd.get("target") if isinstance(cmd.get("target"), dict) else {}
                target_instance_id = str(
                    (target_obj.get("instance_id") or target_obj.get("instanceagent_id") or "")
                ).strip()
                # Always try status GET here so command rows can reflect execution state
                # even when list_instance_agent_command_executions is incomplete.
                if cmd_id and target_instance_id:
                    status_lookup_attempted += 1
                    try:
                        exec_status = ia_ops.get_instance_agent_command_execution(
                            instance_agent_command_id=cmd_id,
                            instance_id=target_instance_id,
                        ) or {}
                        if isinstance(exec_status, dict) and exec_status:
                            status_lookup_succeeded += 1
                        else:
                            status_lookup_failed += 1
                    except Exception as e:
                        status_lookup_failed += 1
                        status_lookup_last_error = f"{type(e).__name__}: {e}"
                        UtilityTools.dlog(
                            debug,
                            "get_instance_agent_command_execution failed",
                            instance_agent_command_id=cmd_id,
                            instance_id=target_instance_id,
                            err=f"{type(e).__name__}: {e}",
                        )

            command_rows.append(
                ia_ops.normalize_command_row(
                    cmd,
                    source="enum_core_compute",
                )
            )
            cmd_row = command_rows[-1]
            raw_cmd_text = _extract_command_text(cmd_row)
            cmd_text = _display_text(raw_cmd_text)
            cmd_row["command_text"] = cmd_text
            cmd_row["command_preview_15"] = _command_preview_15(cmd_text)
            if isinstance(exec_status, dict) and exec_status:
                if not cmd_row.get("lifecycle_state"):
                    cmd_row["lifecycle_state"] = exec_status.get("lifecycle_state")
                if not cmd_row.get("delivery_state"):
                    cmd_row["delivery_state"] = exec_status.get("delivery_state")
                exec_output_text = _extract_execution_output_text(exec_status)
                if exec_output_text:
                    cmd_row["output_text"] = exec_output_text
                try:
                    execution_rows_for_merge.append(
                        ia_ops.normalize_execution_row(
                            exec_status,
                            instance_agent_command_id=cmd_id or _extract_command_id(cmd_row),
                            instance_id=target_instance_id or str(cmd_row.get("target_instance_id") or ""),
                            source="enum_core_compute_status",
                        )
                    )
                except Exception:
                    pass
            command_rows_for_merge.append(cmd_row)
            cmd_id = _extract_command_id(cmd_row)
            if cmd_id:
                command_text_by_id[cmd_id] = cmd_text

        if command_rows:
            UtilityTools.print_limited_table(
                command_rows,
                [
                    "display_name",
                    "id",
                    "target_instance_id",
                    "command_preview_15",
                    "command_text",
                    "lifecycle_state",
                    "delivery_state",
                    "time_created",
                ],
            )
            if args.save:
                save_rows(session, ia_ops.TABLE_COMMANDS, command_rows)
            if args.get or args.download:
                print(
                    f"[*] Command status lookups: attempted={status_lookup_attempted} "
                    f"succeeded={status_lookup_succeeded} failed={status_lookup_failed}"
                )
                if status_lookup_failed and status_lookup_last_error:
                    print(
                        f"[*] Last status lookup error: {status_lookup_last_error} "
                        "(check INSTANCE_AGENT_COMMAND_EXECUTION_READ permissions)"
                    )
        else:
            print("[*] No instance-agent command rows.")
        summary["instance_agent_commands"] = len(command_rows)
    else:
        summary["instance_agent_commands"] = cached_table_count(
            session,
            table_name="compute_instance_agent_commands",
            compartment_id=comp_id,
            compartment_field="compartment_id",
        ) or 0

    # Instance Agent Command Executions (per-instance)
    if flags["instance_agent_command_executions"]:
        ia_ops = ComputeInstanceAgentResourceClient(session=session)
        command_details_cache: Dict[str, Dict[str, Any]] = {}
        if not command_text_by_id:
            try:
                cached_cmds = ia_ops.list_instance_agent_commands(compartment_id=comp_id) or []
            except Exception:
                cached_cmds = []
            for cmd in cached_cmds:
                if not isinstance(cmd, dict):
                    continue
                cmd_id = _extract_command_id(cmd)
                if not cmd_id:
                    continue
                if args.get or args.download:
                    try:
                        full_cmd = ia_ops.get_instance_agent_command(
                            instance_agent_command_id=cmd_id
                        ) or {}
                        if isinstance(full_cmd, dict):
                            fill_missing_fields(cmd, full_cmd)
                            command_details_cache[cmd_id] = full_cmd
                    except Exception as e:
                        UtilityTools.dlog(
                            debug,
                            "get_instance_agent_command failed",
                            instance_agent_command_id=cmd_id,
                            err=f"{type(e).__name__}: {e}",
                        )
                cmd_text = ""
                content = cmd.get("content")
                if isinstance(content, dict):
                    source = content.get("source")
                    if isinstance(source, dict):
                        cmd_text = str((source.get("text") or "")).strip()
                cmd_text = " ".join(cmd_text.split()) if cmd_text else ""
                command_text_by_id[cmd_id] = cmd_text
        target_instances = [r for r in (instance_rows_for_agent or []) if isinstance(r, dict)]
        if not target_instances:
            target_instances = session.get_resource_fields(
                "compute_instances",
                where_conditions={"compartment_id": comp_id},
            ) or []
            target_instances = [r for r in target_instances if isinstance(r, dict)]
        if not target_instances:
            try:
                target_instances = ComputeResourceClient(session=session).list_instances(compartment_id=comp_id) or []
                target_instances = [r for r in target_instances if isinstance(r, dict)]
            except Exception:
                target_instances = []

        execution_rows = []
        for inst in UtilityTools.progress_iter(target_instances, label="LIST instance-agent command executions"):
            inst_id = (inst or {}).get("id")
            if not inst_id:
                continue
            try:
                rows = ia_ops.list_instance_agent_command_executions(
                    compartment_id=comp_id,
                    instance_id=inst_id,
                ) or []
            except oci.exceptions.ServiceError as e:
                UtilityTools.dlog(
                    True,
                    "list_instance_agent_command_executions failed",
                    instance_id=inst_id,
                    status=getattr(e, "status", None),
                    code=getattr(e, "code", None),
                )
                continue
            except Exception as e:
                UtilityTools.dlog(True, "list_instance_agent_command_executions failed", instance_id=inst_id, err=f"{type(e).__name__}: {e}")
                continue

            for row in rows:
                if not isinstance(row, dict):
                    continue
                command_id = (
                    row.get("instance_agent_command_id")
                    or row.get("instanceagent_command_id")
                    or row.get("command_id")
                    or "unknown-command"
                )
                command_id = str(command_id)
                if (args.get or args.download) and command_id and command_id != "unknown-command":
                    try:
                        full_exec = ia_ops.get_instance_agent_command_execution(
                            instance_agent_command_id=command_id,
                            instance_id=inst_id,
                        ) or {}
                        if isinstance(full_exec, dict):
                            fill_missing_fields(row, full_exec)
                    except Exception as e:
                        UtilityTools.dlog(
                            debug,
                            "get_instance_agent_command_execution failed",
                            instance_id=inst_id,
                            instance_agent_command_id=command_id,
                            err=f"{type(e).__name__}: {e}",
                        )
                cmd_text = (command_text_by_id.get(command_id) or "").strip()
                if not cmd_text and command_id and command_id != "unknown-command" and (args.get or args.download):
                    cmd_detail = command_details_cache.get(command_id)
                    if cmd_detail is None:
                        try:
                            cmd_detail = ia_ops.get_instance_agent_command(
                                instance_agent_command_id=command_id
                            ) or {}
                            if isinstance(cmd_detail, dict):
                                command_details_cache[command_id] = cmd_detail
                        except Exception as e:
                            UtilityTools.dlog(
                                debug,
                                "get_instance_agent_command failed",
                                instance_agent_command_id=command_id,
                                err=f"{type(e).__name__}: {e}",
                            )
                            cmd_detail = {}
                    if isinstance(cmd_detail, dict):
                        c = cmd_detail.get("content")
                        if isinstance(c, dict):
                            s = c.get("source")
                            if isinstance(s, dict):
                                cmd_text = str((s.get("text") or "")).strip()
                        if cmd_text:
                            command_text_by_id[command_id] = cmd_text
                cmd_text = _display_text(cmd_text)
                norm_exec = ia_ops.normalize_execution_row(
                    row,
                    instance_agent_command_id=command_id,
                    instance_id=inst_id,
                    source="enum_core_compute",
                )
                norm_exec["command_text"] = cmd_text
                norm_exec["command_preview_15"] = _command_preview_15(cmd_text)
                execution_rows.append(
                    norm_exec
                )
                execution_rows_for_merge.append(norm_exec)
                if args.download:
                    exec_key = str(
                        norm_exec.get("execution_key")
                        or f"{command_id}:{inst_id}:{norm_exec.get('sequence_number') or norm_exec.get('time_updated') or 'latest'}"
                    )
                    if exec_key not in downloaded_execution_keys:
                        downloaded_execution_keys.add(exec_key)
                        try:
                            instance_agent_download_files += _download_instance_agent_execution_payload(
                                session,
                                compartment_id=comp_id,
                                execution_row=norm_exec,
                            )
                        except Exception as e:
                            UtilityTools.dlog(
                                debug,
                                "download execution payload failed",
                                execution_key=exec_key,
                                err=f"{type(e).__name__}: {e}",
                            )

        if execution_rows:
            UtilityTools.print_limited_table(
                execution_rows,
                [
                    "instance_id",
                    "instance_agent_command_id",
                    "command_preview_15",
                    "command_text",
                    "lifecycle_state",
                    "delivery_state",
                    "exit_code",
                    "time_updated",
                ],
            )
            if args.save:
                save_rows(session, ia_ops.TABLE_EXECUTIONS, execution_rows)
        else:
            print("[*] No instance-agent command execution rows.")
        summary["instance_agent_command_executions"] = len(execution_rows)
    else:
        summary["instance_agent_command_executions"] = cached_table_count(
            session,
            table_name="compute_instance_agent_command_executions",
            compartment_id=comp_id,
            compartment_field="compartment_id",
        ) or 0

    if args.download and (flags["instance_agent_commands"] or flags["instance_agent_command_executions"]):
        merged_files = _write_instance_agent_merged_files(
            session,
            compartment_id=comp_id,
            command_rows=command_rows_for_merge,
            execution_rows=execution_rows_for_merge,
        )
        if merged_files.get("download_rows"):
            UtilityTools.print_limited_table(
                merged_files.get("download_rows") or [],
                ["instance_id", "command_count", "file_path"],
            )
        instance_agent_download_files += int(merged_files.get("files_written") or 0)
        summary["instance_agent_merged_command_records"] = int(merged_files.get("merged_record_count") or 0)

    # Instance Agent Plugins (per-instance capability visibility)
    if flags["instance_agent_plugins"]:
        ia_ops = ComputeInstanceAgentResourceClient(session=session)
        target_instances = [r for r in (instance_rows_for_agent or []) if isinstance(r, dict)]

        if not target_instances:
            target_instances = session.get_resource_fields(
                "compute_instances",
                where_conditions={"compartment_id": comp_id},
            ) or []
            target_instances = [r for r in target_instances if isinstance(r, dict)]

        if not target_instances:
            try:
                target_instances = ComputeResourceClient(session=session).list_instances(compartment_id=comp_id) or []
                target_instances = [r for r in target_instances if isinstance(r, dict)]
            except Exception:
                target_instances = []

        plugin_rows = []
        for inst in UtilityTools.progress_iter(target_instances, label="LIST instance-agent plugins"):
            inst_id = (inst or {}).get("id")
            if not inst_id:
                continue
            inst_name = (inst or {}).get("display_name") or inst_id
            try:
                rows = ia_ops.list_instance_agent_plugins(compartment_id=comp_id, instance_id=inst_id) or []
            except oci.exceptions.ServiceError as e:
                UtilityTools.dlog(
                    True,
                    "list_instance_agent_plugins failed",
                    instance_id=inst_id,
                    status=getattr(e, "status", None),
                    code=getattr(e, "code", None),
                )
                continue
            except Exception as e:
                UtilityTools.dlog(True, "list_instance_agent_plugins failed", instance_id=inst_id, err=f"{type(e).__name__}: {e}")
                continue

            for row in rows:
                if not isinstance(row, dict):
                    continue
                if args.get:
                    plugin_name = row.get("name") or row.get("plugin_name")
                    if plugin_name:
                        try:
                            full = ia_ops.get_instance_agent_plugin(
                                compartment_id=comp_id,
                                instance_id=inst_id,
                                plugin_name=plugin_name,
                            ) or {}
                            if isinstance(full, dict):
                                fill_missing_fields(row, full)
                        except Exception as e:
                            UtilityTools.dlog(debug, "get_instance_agent_plugin failed", instance_id=inst_id, plugin_name=plugin_name, err=f"{type(e).__name__}: {e}")
                plugin_rows.append(
                    ia_ops.normalize_plugin_row(
                        row,
                        instance_id=inst_id,
                        compartment_id=comp_id,
                        instance_name=inst_name,
                        source="enum_core_compute",
                    )
                )

        if plugin_rows:
            UtilityTools.print_limited_table(
                plugin_rows,
                ["instance_name", "instance_id", "name", "status", "desired_state", "time_last_update_utc"],
            )
            if args.save:
                save_rows(session, ia_ops.TABLE_PLUGINS, plugin_rows)
        else:
            print("[*] No instance-agent plugin rows.")

        summary["instance_agent_plugins"] = len(plugin_rows)
    else:
        summary["instance_agent_plugins"] = cached_table_count(
            session,
            table_name="compute_instance_agent_plugins",
            compartment_id=comp_id,
            compartment_field="compartment_id",
        ) or 0

    if args.download:
        summary["instance_agent_download_files"] = instance_agent_download_files

    return {"ok": True, **summary}
