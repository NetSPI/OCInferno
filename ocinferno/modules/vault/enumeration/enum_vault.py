#!/usr/bin/env python3
from __future__ import annotations

import argparse
from typing import Any, Dict, List

from ocinferno.modules.vault.utilities.helpers import (
    VaultKeysResource,
    VaultSecretsResource,
    VaultVaultsResource,
)
from ocinferno.core.console import UtilityTools
from ocinferno.core.utils.module_helpers import dedupe_strs
from ocinferno.core.utils.service_runtime import (
    append_cached_component_counts,
    parse_wrapper_args,
    resolve_selected_components,
)


COMPONENTS = [
    ("vaults", "vaults", "Enumerate vaults"),
    ("keys", "keys", "Enumerate keys"),
    ("secrets", "secrets", "Enumerate secrets"),
]

CACHE_TABLES = {
    "vaults": ("vault_vaults", "compartment_id"),
    "keys": ("vault_keys", "compartment_id"),
    "secrets": ("vault_secret", "compartment_id"),
}


def _parse_args(user_args):
    def _add_extra_args(parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--vault-id", action="append", default=[], help="Vault OCID scope (repeatable).")
        parser.add_argument("--vault-endpoint", default=None, help="Vault management endpoint for manual --vault-id")
        parser.add_argument("--key-id", action="append", default=[], help="Key OCID scope (repeatable).")
        parser.add_argument("--key-versions", action="store_true", help="Enumerate key versions")
        parser.add_argument("--persist-manual-ids", action="store_true", help="Persist minimal manual IDs when provided")

        parser.add_argument("--secret-id", action="append", default=[], help="Secret OCID scope (repeatable).")
        parser.add_argument("--versions", action="store_true", help="List secret versions")
        parser.add_argument("--get-requests", action="store_true", help="Also GET each secret version")
        parser.add_argument("--dump", action="store_true", help="Dump secret plaintext to disk (never printed)")
        parser.add_argument("--dump-all-versions", action="store_true", help="Force dump of all versions")
        parser.add_argument("--secret-name", default=None, help="Dump-by-name flow (requires exactly one vault_id)")
        parser.add_argument("--stage", default=None, help="Secret stage for retrieval (e.g., CURRENT)")
        parser.add_argument("--secret-version-name", default=None, help="Secret version name label for retrieval")
        parser.add_argument("--version-number", default=None, help="Secret version number for retrieval (int)")
        parser.add_argument("--version-range", default=None, help="Version range list for retrieval, e.g. 1-5 or 1,3,5-7")

    return parse_wrapper_args(
        user_args=user_args,
        description="Enumerate Vault resources",
        components=COMPONENTS,
        add_extra_args=_add_extra_args,
        include_download=True,
    )


def run_module(user_args, session):
    args, _ = _parse_args(user_args)
    debug = bool(getattr(session, "individual_run_debug", False) or getattr(session, "debug", False))

    component_order = [key for key, _suffix, _help in COMPONENTS]
    selected = resolve_selected_components(args, component_order)

    vaults_resource = VaultVaultsResource(session=session)
    keys_resource = VaultKeysResource(session=session)
    secrets_resource = VaultSecretsResource(session=session)

    results: List[Dict[str, Any]] = []
    runtime_vault_ids: List[str] = dedupe_strs([v for v in (args.vault_id or []) if isinstance(v, str) and v])

    if selected.get("vaults", False):
        vault_rows = [r for r in (vaults_resource.list() or []) if isinstance(r, dict)]
        if vault_rows:
            UtilityTools.print_limited_table(vault_rows, vaults_resource.COLUMNS, resource_type="Vaults")
            if args.save:
                vaults_resource.save(vault_rows)
            runtime_vault_ids = dedupe_strs([r.get("id") for r in vault_rows if isinstance(r.get("id"), str)])

        results.append(
            {
                "ok": True,
                "component": "vaults",
                "vaults": vault_rows,
                "saved": bool(args.save),
            }
        )

    if selected.get("keys", False):
        vault_ids = keys_resource.resolve_vault_ids(vault_ids=runtime_vault_ids or (args.vault_id or []), vault_endpoint=args.vault_endpoint)

        if args.save and args.persist_manual_ids and (args.vault_id or []):
            try:
                keys_resource.save_manual_vaults(vault_ids=(args.vault_id or []), vault_endpoint=args.vault_endpoint)
            except Exception as e:
                UtilityTools.dlog(debug, "persist-manual vault failed (non-fatal)", err=f"{type(e).__name__}: {e}")

        key_ids = dedupe_strs([k for k in (args.key_id or []) if isinstance(k, str) and k])
        keys: List[Dict[str, Any]] = []
        vault_id_by_key_id: Dict[str, str] = {}

        if key_ids:
            if len(vault_ids) == 1:
                for kid in key_ids:
                    vault_id_by_key_id[kid] = vault_ids[0]
            if args.save and args.persist_manual_ids:
                try:
                    keys_resource.save_manual_keys(
                        key_ids=key_ids,
                        fallback_vault_id=(vault_ids[0] if len(vault_ids) == 1 else None),
                    )
                except Exception as e:
                    UtilityTools.dlog(debug, "persist-manual key failed (non-fatal)", err=f"{type(e).__name__}: {e}")
        elif vault_ids:
            keys = [r for r in (keys_resource.list(vault_ids=vault_ids) or []) if isinstance(r, dict)]
            if keys:
                UtilityTools.print_limited_table(keys, keys_resource.COLUMNS, resource_type="Keys")
                if args.save:
                    keys_resource.save(keys)
                key_ids = dedupe_strs([k.get("id") for k in keys if isinstance(k.get("id"), str)])
                for row in keys:
                    kid = row.get("id")
                    vid = row.get("vault_id")
                    if isinstance(kid, str) and kid and isinstance(vid, str) and vid:
                        vault_id_by_key_id[kid] = vid

        key_versions: List[Dict[str, Any]] = []
        if args.key_versions and key_ids:
            key_versions = [
                r for r in (keys_resource.list_versions(key_ids=key_ids, vault_id_by_key_id=vault_id_by_key_id or None) or [])
                if isinstance(r, dict)
            ]
            if key_versions:
                UtilityTools.print_limited_table(key_versions, keys_resource.VERSION_COLUMNS, resource_type="Key Versions")
                if args.save:
                    try:
                        keys_resource.save_versions(key_versions)
                    except Exception as e:
                        UtilityTools.dlog(debug, "save_key_versions failed (non-fatal)", err=f"{type(e).__name__}: {e}")

        results.append(
            {
                "ok": True,
                "component": "keys",
                "vault_ids": vault_ids,
                "keys": keys,
                "key_versions": key_versions,
                "saved": bool(args.save),
            }
        )

    if selected.get("secrets", False):
        try:
            version_number = int(args.version_number) if args.version_number is not None else None
        except Exception:
            raise ValueError("--version-number must be an integer")

        version_range = str(args.version_range or "").strip()
        if version_range and (version_number is not None or args.secret_version_name or args.stage):
            raise ValueError("--version-range cannot be combined with --version-number, --secret-version-name, or --stage")

        do_dump = bool(args.dump or args.download)
        vault_ids = secrets_resource.resolve_vault_ids(vault_ids=runtime_vault_ids or (args.vault_id or []))
        secret_ids = dedupe_strs([s for s in (args.secret_id or []) if isinstance(s, str) and s])

        if do_dump and args.secret_name and len(vault_ids) != 1:
            raise ValueError("--dump/--download with --secret-name requires exactly one vault_id (from --vault-id or DB).")

        secrets: List[Dict[str, Any]] = []
        if vault_ids:
            secrets = [r for r in (secrets_resource.list(vault_ids=vault_ids) or []) if isinstance(r, dict)]
            if secrets:
                UtilityTools.print_limited_table(secrets, secrets_resource.COLUMNS, resource_type="Secrets")
                if args.save:
                    secrets_resource.save(secrets)
                if not secret_ids:
                    secret_ids = dedupe_strs([s.get("id") for s in secrets if isinstance(s.get("id"), str)])
        elif not secret_ids and not (do_dump and args.secret_name):
            if do_dump:
                print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Can't download due to missing vault scope for secrets.{UtilityTools.RESET}")
                print(f"{UtilityTools.BRIGHT_BLACK}    Provide --vault-id, run enum_vault --vaults --save, or provide --secret-id.{UtilityTools.RESET}")
            else:
                print(f"{UtilityTools.RED}{UtilityTools.BOLD}[X] Secrets listing requires vault scope.{UtilityTools.RESET}")
                print(f"{UtilityTools.BRIGHT_BLACK}    Provide --vault-id, run enum_vault --vaults --save, or provide --secret-id.{UtilityTools.RESET}")

        secret_versions: List[Dict[str, Any]] = []
        if args.versions and secret_ids:
            secret_versions = [
                r for r in (secrets_resource.list_versions(secret_ids=secret_ids, do_get_requests=bool(args.get_requests)) or [])
                if isinstance(r, dict)
            ]
            if secret_versions:
                UtilityTools.print_limited_table(secret_versions, secrets_resource.VERSION_COLUMNS, resource_type="Secret Versions")
                if args.save:
                    secrets_resource.save_versions(secret_versions)

        if args.save:
            try:
                secrets_resource.save_bundle_metadata(secrets=secrets, secret_versions=secret_versions)
            except Exception as e:
                UtilityTools.dlog(debug, "save_secret_bundle_metadata failed (non-fatal)", err=f"{type(e).__name__}: {e}")

        dumped: List[Dict[str, Any]] = []
        if do_dump:
            explicit_selector = bool(args.stage or args.secret_version_name or version_number is not None or version_range)
            expand_versions = bool(args.dump_all_versions or not explicit_selector)
            dump_dir = session.get_workspace_output_root(mkdir=True) / "downloads" / "vault"
            dump_dir.mkdir(parents=True, exist_ok=True)

            dumped = [
                r
                for r in (
                    secrets_resource.dump(
                        dump_dir=dump_dir,
                        secrets=secrets if secrets else None,
                        secret_ids=secret_ids if secret_ids else None,
                        secret_name=args.secret_name,
                        vault_id_for_name=(vault_ids[0] if vault_ids else None),
                        stage=args.stage,
                        secret_version_name=args.secret_version_name,
                        version_number=version_number,
                        version_range_spec=(version_range or None),
                        expand_versions=expand_versions,
                    )
                    or []
                )
                if isinstance(r, dict)
            ]

            print("[*] Download layout: <output_root>/<workspace>/downloads/vault/<vault_id>/secrets/<secret_bundle_id>_values.txt")
            print("[*] Default output root is ./ocinferno_output (override with OCINFERNO_OUTPUT_ROOT).")
            print(f"[*] Dumped {len(dumped)} secret values to disk (see File_path column for exact files).")

            if dumped:
                dumped_display: List[Dict[str, Any]] = []
                for row in dumped:
                    out_row = dict(row)
                    if isinstance(out_row.get("file_path"), str):
                        out_row["file_path"] = secrets_resource.display_path(out_row.get("file_path"))
                    dumped_display.append(out_row)
                UtilityTools.print_limited_table(dumped_display, secrets_resource.DUMP_COLUMNS, resource_type="Secret Bundle Values")

            if args.save and dumped:
                try:
                    secrets_resource.save_dump_artifacts(dumped)
                except Exception as e:
                    UtilityTools.dlog(debug, "save_secret_dump_artifacts failed (non-fatal)", err=f"{type(e).__name__}: {e}")

        results.append(
            {
                "ok": True,
                "component": "secrets",
                "vault_ids": vault_ids,
                "secrets": secrets,
                "secret_versions": secret_versions,
                "dumped": dumped,
                "saved": bool(args.save),
            }
        )

    append_cached_component_counts(
        results=results,
        session=session,
        selected=selected,
        component_order=component_order,
        cache_tables=CACHE_TABLES,
    )

    return {"ok": True, "components": results}
