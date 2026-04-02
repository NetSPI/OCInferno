from __future__ import annotations

import argparse
import hashlib
import json
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

import oci

from ocinferno.core.console import UtilityTools
from ocinferno.core.utils.module_helpers import cached_table_count, fill_missing_fields, save_rows


ComponentSpec = Tuple[str, str, str]  # (key, method_suffix, help_text)
CacheTables = Mapping[str, Optional[Tuple[str, Optional[str]]]]


def _init_client(client_cls, *args, session, service_name: str, **kwargs):
    creds = getattr(session, "credentials", None)
    region_override = (
        getattr(session, "config_current_default_region", None)
        or getattr(session, "region", None)
        or None
    )
    if not (isinstance(creds, dict) and isinstance(creds.get("config"), dict)):
        raise ValueError(
            f"Invalid session.credentials for {service_name}: expected "
            "{'config': <dict>, 'signer': <object|None>}"
        )

    cfg = dict(creds.get("config") or {})
    if region_override:
        cfg["region"] = region_override

    signer = creds.get("signer")
    if signer is None:
        client = client_cls(cfg, *args, **kwargs)
    else:
        client = client_cls(cfg, *args, signer=signer, **kwargs)

    try:
        session.add_proxy_config(client)
    except Exception:
        pass

    return client


def parse_wrapper_args(
    user_args: Sequence[str],
    *,
    description: str,
    components: Sequence[ComponentSpec],
    add_extra_args: Optional[Callable[[argparse.ArgumentParser], None]] = None,
    include_get: bool = True,
    include_save: bool = True,
    include_download: bool = False,
):
    parser = argparse.ArgumentParser(description=description, allow_abbrev=False)

    for key, _suffix, help_text in components:
        parser.add_argument(f"--{key.replace('_', '-')}", dest=key, action="store_true", help=help_text)

    if include_get:
        parser.add_argument("--get", action="store_true", help="Pass through --get to selected components")
    if include_save:
        parser.add_argument("--save", action="store_true", help="Pass through --save to selected components")
    if include_download:
        parser.add_argument("--download", action="store_true", help="Pass through --download to selected components")

    if callable(add_extra_args):
        add_extra_args(parser)

    args, remainder = parser.parse_known_args(list(user_args))
    return args, remainder


def resolve_selected_components(args: argparse.Namespace, component_keys: Sequence[str]) -> Dict[str, bool]:
    keys = list(component_keys or [])
    any_selected = any(getattr(args, key, False) for key in keys)
    return {key: (bool(getattr(args, key, False)) if any_selected else True) for key in keys}


def append_cached_component_counts(
    *,
    results: List[Dict[str, Any]],
    session: Any,
    selected: Mapping[str, bool],
    component_order: Sequence[str],
    cache_tables: CacheTables,
) -> None:
    comp_id = getattr(session, "compartment_id", None)
    module_name = str(getattr(session, "active_module_name", "") or "").strip()
    recommended_module_name = module_name if module_name and module_name != "enum_all" else ""
    any_selected = any(bool(selected.get(k, False)) for k in component_order)
    download_requested = any(
        bool(r.get("download", False))
        for r in (results or [])
        if isinstance(r, dict)
    )

    for key in component_order:
        if selected.get(key, False):
            continue

        table_info = cache_tables.get(key)
        if not table_info:
            results.append({"ok": True, "cached": True, "component": key, "count": None})
            continue

        table_name, compartment_field = table_info
        count = cached_table_count(
            session,
            table_name=table_name,
            compartment_id=comp_id,
            compartment_field=compartment_field,
        )
        results.append({"ok": True, "cached": True, "component": key, "table": table_name, "count": count})
        if any_selected and isinstance(count, int) and count == 0 and recommended_module_name:
            flag = f"--{str(key).replace('_', '-')}"
            print(f"[*] Missing cached data for '{key}' (table: {table_name}).")
            if download_requested:
                print(f"    Can't download due to missing prerequisite data for '{key}'.")
            print(f"    Run: modules run {recommended_module_name} {flag} --save")


def _flag_enabled(user_args: Any, flag_name: str) -> bool:
    """Return True when a boolean CLI flag is present on either argv or parsed args."""
    if isinstance(user_args, argparse.Namespace):
        return bool(getattr(user_args, flag_name, False))
    flag = f"--{str(flag_name).replace('_', '-')}"
    try:
        return flag in set(str(x) for x in (list(user_args) if user_args is not None else []))
    except Exception:
        return False


def run_standard_enum_component(
    *,
    user_args: Any,
    session: Any,
    component_key: str,
    list_rows: Callable[[str], List[Dict[str, Any]]],
    get_row: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
    save_rows_fn: Optional[Callable[[List[Dict[str, Any]]], None]] = None,
    print_columns: Optional[List[str]] = None,
    attach_compartment_id: bool = True,
    empty_message: str = "[*] No resources found.",
) -> Dict[str, Any]:
    """Shared list/get/save table flow used by thin service dispatchers."""
    debug = bool(getattr(session, "individual_run_debug", False) or getattr(session, "debug", False))
    do_get = _flag_enabled(user_args, "get")
    do_save = _flag_enabled(user_args, "save")

    comp_id = getattr(session, "compartment_id", None)
    if not comp_id:
        raise ValueError("session.compartment_id is not set")

    try:
        rows = list_rows(comp_id) or []
    except oci.exceptions.ServiceError as e:
        UtilityTools.dlog(
            True,
            f"list_{component_key} failed",
            status=getattr(e, "status", None),
            code=getattr(e, "code", None),
            msg=getattr(e, "message", str(e)),
        )
        return {"ok": False, component_key: 0, "saved": False, "get": do_get}
    except Exception as e:
        UtilityTools.dlog(True, f"list_{component_key} failed", err=f"{type(e).__name__}: {e}")
        return {"ok": False, component_key: 0, "saved": False, "get": do_get}

    clean_rows: List[Dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        if attach_compartment_id:
            row.setdefault("compartment_id", comp_id)
        clean_rows.append(row)
    rows = clean_rows

    if do_get and callable(get_row):
        for row in rows:
            try:
                meta = get_row(row) or {}
            except Exception as e:
                UtilityTools.dlog(debug, f"get_{component_key} failed", err=f"{type(e).__name__}: {e}")
                continue
            if isinstance(meta, dict):
                fill_missing_fields(row, meta)

    if rows:
        UtilityTools.print_limited_table(rows, print_columns or [])
    else:
        print(empty_message)

    if do_save and callable(save_rows_fn):
        save_rows_fn(rows)

    return {"ok": True, component_key: len(rows), "saved": do_save, "get": do_get}


class ServiceEnumOpsBase:
    """Shared helpers for service enumeration wrappers."""

    def __init__(self, session):
        self.session = session
        self.debug = bool(getattr(session, "individual_run_debug", False) or getattr(session, "debug", False))

    def _set_client_region(self, client: Any, region: Optional[str] = None) -> None:
        if not client:
            return
        target = region or getattr(self.session, "region", None)
        if not target:
            return
        try:
            client.base_client.set_region(target)
        except Exception:
            pass

    def _require_compartment(self) -> str:
        cid = getattr(self.session, "compartment_id", None)
        if cid:
            return cid
        raise ValueError(
            "session.compartment_id is not set.\n"
            "Select a compartment in the module runner (or run via module_actions prompt)."
        )

    @staticmethod
    def _parse_component_args(
        user_args: Sequence[str],
        *,
        description: str,
        add_get: bool = True,
        add_save: bool = True,
        extra_args: Optional[Callable[[argparse.ArgumentParser], None]] = None,
    ) -> argparse.Namespace:
        p = argparse.ArgumentParser(description=description, allow_abbrev=False)
        if add_get:
            p.add_argument("--get", action="store_true", help="Call get_* per row and fill missing fields.")
        if add_save:
            p.add_argument("--save", action="store_true", help="Save results into DB (service tables).")
        if callable(extra_args):
            extra_args(p)
        args, _ = p.parse_known_args(list(user_args))
        return args

    @staticmethod
    def _list_all(method: Callable[..., Any], **kwargs) -> List[Dict[str, Any]]:
        paginator = oci.pagination.list_call_get_all_results
        resp = paginator(method, **kwargs)
        return oci.util.to_dict(resp.data) or []

    @staticmethod
    def _to_dict(resp: Any) -> Dict[str, Any]:
        return oci.util.to_dict(resp.data) or {}

    @staticmethod
    def _record_hash(row: Dict[str, Any], *, prefix: str = "") -> str:
        raw = json.dumps(row or {}, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha1((prefix + raw).encode("utf-8")).hexdigest()

    def _save_rows(self, rows: List[Dict[str, Any]], *, table_name: str) -> None:
        save_rows(self.session, table_name, rows)

    def _enum_component(
        self,
        user_args: Sequence[str],
        *,
        description: str,
        component_key: str,
        list_fn: Callable[[str], List[Dict[str, Any]]],
        get_fn: Optional[Callable[..., Dict[str, Any]]],
        get_id_param: Optional[str],
        save_table: str,
        print_columns: List[str],
        empty_msg_prefix: str = "",
    ) -> Dict[str, Any]:
        args = self._parse_component_args(user_args, description=description)
        debug = bool(getattr(self.session, "debug", False))
        cid = self._require_compartment()

        try:
            rows: List[Dict[str, Any]] = list_fn(cid) or []
        except oci.exceptions.ServiceError as e:
            print(f"{UtilityTools.RED}[X] list_{component_key} failed: {e.status} {e.message}{UtilityTools.RESET}")
            return {"ok": False, component_key: 0, "saved": False, "get": bool(getattr(args, "get", False))}

        if not rows:
            label = f"{empty_msg_prefix}{component_key}" if empty_msg_prefix else component_key
            UtilityTools.dlog(debug, f"No {label} found", compartment_id=cid)
            return {"ok": True, component_key: 0, "saved": False, "get": bool(getattr(args, "get", False))}

        for r in rows:
            if isinstance(r, dict) and "compartment_id" not in r:
                r["compartment_id"] = cid

        if getattr(args, "get", False) and get_fn and get_id_param:
            for r in rows:
                if not isinstance(r, dict):
                    continue
                rid = r.get("id")
                if not rid:
                    continue
                try:
                    meta = get_fn(**{get_id_param: rid})
                except oci.exceptions.ServiceError as e:
                    UtilityTools.dlog(debug, f"get_{component_key} failed", id=rid, status=e.status, error_message=e.message)
                    continue
                except Exception as e:
                    UtilityTools.dlog(debug, f"get_{component_key} failed", id=rid, err=f"{type(e).__name__}: {e}")
                    continue
                if isinstance(meta, dict):
                    fill_missing_fields(r, meta)

        UtilityTools.print_limited_table(rows, print_columns)

        if getattr(args, "save", False):
            self._save_rows(rows, table_name=save_table)

        return {
            "ok": True,
            "cid": cid,
            component_key: len(rows),
            "saved": bool(getattr(args, "save", False)),
            "get": bool(getattr(args, "get", False)),
        }


__all__ = [
    "ComponentSpec",
    "CacheTables",
    "_init_client",
    "append_cached_component_counts",
    "parse_wrapper_args",
    "resolve_selected_components",
    "run_standard_enum_component",
    "ServiceEnumOpsBase",
]
