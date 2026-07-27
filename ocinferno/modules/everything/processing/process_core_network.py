#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from typing import Any, Dict

from ocinferno.core.console import UtilityTools


def _parse_args(user_args) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Correlate saved network resources (cross-compartment denormalization)",
        allow_abbrev=False,
    )
    p.add_argument(
        "--security-lists",
        dest="security_lists",
        action="store_true",
        default=True,
        help="Backfill attached_subnet_ids onto security lists (default: on)",
    )
    p.add_argument(
        "--no-security-lists",
        dest="security_lists",
        action="store_false",
        help="Skip security-list backfill",
    )
    p.add_argument(
        "--route-tables",
        dest="route_tables",
        action="store_true",
        default=True,
        help="Backfill attached_subnet_ids onto route tables (default: on)",
    )
    p.add_argument(
        "--no-route-tables",
        dest="route_tables",
        action="store_false",
        help="Skip route-table backfill",
    )
    return p.parse_args(list(user_args) if user_args else [])


def _safe_lifecycle(val: Any) -> str:
    return (val or "").upper().strip()


def _load_subnet_rows(session) -> list:
    return session.get_resource_fields(
        "virtual_network_subnets",
        columns=["id", "security_list_ids", "route_table_id", "lifecycle_state"],
    ) or []


def _backfill_sl_attachments(session, subnet_rows: list) -> int:
    """Invert subnet→security-list relationship, write attached_subnet_ids on each SL row."""
    sl_to_subnets: Dict[str, list] = {}
    for sn in subnet_rows:
        if _safe_lifecycle(sn.get("lifecycle_state")) in ("TERMINATED", "TERMINATING"):
            continue
        sn_id = sn.get("id") or ""
        raw = sn.get("security_list_ids") or "[]"
        try:
            ids = json.loads(raw) if isinstance(raw, str) else (raw if isinstance(raw, list) else [])
        except Exception:
            ids = []
        for sid in ids:
            sid = str(sid).strip()
            if sid:
                sl_to_subnets.setdefault(sid, []).append(sn_id)

    sl_rows = session.get_resource_fields("virtual_network_security_lists") or []
    if not sl_rows:
        return 0
    updated = []
    for sl in sl_rows:
        sl["attached_subnet_ids"] = json.dumps(sl_to_subnets.get(sl.get("id") or "", []))
        updated.append(sl)
    session.save_resources(updated, "virtual_network_security_lists")
    return len(sl_rows)


def _backfill_rt_attachments(session, subnet_rows: list) -> int:
    """Invert subnet→route-table relationship, write attached_subnet_ids on each RT row."""
    rt_to_subnets: Dict[str, list] = {}
    for sn in subnet_rows:
        if _safe_lifecycle(sn.get("lifecycle_state")) in ("TERMINATED", "TERMINATING"):
            continue
        sn_id = sn.get("id") or ""
        rt_id = (sn.get("route_table_id") or "").strip()
        if rt_id:
            rt_to_subnets.setdefault(rt_id, []).append(sn_id)

    rt_rows = session.get_resource_fields("virtual_network_route_tables") or []
    if not rt_rows:
        return 0
    updated = []
    for rt in rt_rows:
        rt["attached_subnet_ids"] = json.dumps(rt_to_subnets.get(rt.get("id") or "", []))
        updated.append(rt)
    session.save_resources(updated, "virtual_network_route_tables")
    return len(rt_rows)


def run_module(user_args, session) -> Dict[str, Any]:
    args = _parse_args(user_args)

    subnet_rows = _load_subnet_rows(session)
    if not subnet_rows:
        print(UtilityTools.YELLOW + "[!] No subnet rows found — run enum_core_network first." + UtilityTools.RESET)
        return {"ok": True, "security_lists_updated": 0, "route_tables_updated": 0}

    sl_count = rt_count = 0

    if args.security_lists:
        sl_count = _backfill_sl_attachments(session, subnet_rows)
        if sl_count:
            print(f"{UtilityTools.GREEN}[+] Security lists: backfilled attached_subnet_ids on {sl_count} rows.{UtilityTools.RESET}")
        else:
            print(f"{UtilityTools.YELLOW}[!] Security lists: no rows found.{UtilityTools.RESET}")

    if args.route_tables:
        rt_count = _backfill_rt_attachments(session, subnet_rows)
        if rt_count:
            print(f"{UtilityTools.GREEN}[+] Route tables: backfilled attached_subnet_ids on {rt_count} rows.{UtilityTools.RESET}")
        else:
            print(f"{UtilityTools.YELLOW}[!] Route tables: no rows found.{UtilityTools.RESET}")

    return {
        "ok": True,
        "security_lists_updated": sl_count,
        "route_tables_updated": rt_count,
    }
